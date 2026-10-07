"""Who created a durable-nonce account? Read-only, from transaction history.

Method: walk getSignaturesForAddress back to the oldest signature, then fetch the oldest successful
transactions (getTransaction, maxSupportedTransactionVersion 0, raw `json` encoding) and find the
System-program instruction that created or initialized this account. The instruction data is decoded
here, not taken from the RPC's jsonParsed view.

System instruction tags (solana-program system_instruction.rs, bincode u32 LE):
    0 CreateAccount            accounts [funding, new]          data u32 tag, u64 lamports, u64 space, Pubkey owner
    3 CreateAccountWithSeed    accounts [funding, new, (base)]
    6 InitializeNonceAccount   accounts [nonce, RecentBlockhashes, Rent]   data u32 tag, Pubkey authority

Anything short of "found the creating instruction in a finalized, successful transaction" is reported
as `unavailable` (could not look) or `unverified` (looked, could not prove it). Neither is ever clean.
"""

import datetime as _dt

from .base58 import b58decode, b58encode
from .decode import SYSTEM_PROGRAM
from .rpc import RpcError, RpcUnavailable

PAGE_LIMIT = 1000
MAX_PAGES = 10  # 10,000 signatures; a longer history is reported unavailable, not guessed
OLDEST_CANDIDATES = 3  # how many of the oldest successful transactions to inspect for the creation

SYS_CREATE_ACCOUNT = 0
SYS_CREATE_ACCOUNT_WITH_SEED = 3
SYS_INITIALIZE_NONCE = 6


def _iso(ts):
    if ts is None:
        return None
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat()


def oldest_signatures(client, account, max_pages=MAX_PAGES):
    """All signature records for `account`, newest first, or raises ValueError if the walk can't finish."""
    out, before = [], None
    for _ in range(max_pages):
        opts = {"limit": PAGE_LIMIT, "commitment": "finalized"}
        if before:
            opts["before"] = before
        page = client.call("getSignaturesForAddress", [account, opts])
        if not isinstance(page, list):
            raise ValueError("unexpected getSignaturesForAddress shape")
        out.extend(page)
        if len(page) < PAGE_LIMIT:
            return out
        before = page[-1]["signature"]
    raise ValueError(f"history longer than {max_pages * PAGE_LIMIT} signatures; oldest transaction not reached")


def _account_keys(tx):
    msg = tx["transaction"]["message"]
    keys = list(msg["accountKeys"])
    loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
    return keys + list(loaded.get("writable", [])) + list(loaded.get("readonly", []))


def creation_events(tx, account):
    """System-program instructions in `tx` (top level and inner/CPI) that create or initialize `account`."""
    keys = _account_keys(tx)
    ixs = list(tx["transaction"]["message"]["instructions"])
    for inner in (tx.get("meta") or {}).get("innerInstructions") or []:
        ixs.extend(inner.get("instructions", []))
    events = []
    for ix in ixs:
        if keys[ix["programIdIndex"]] != SYSTEM_PROGRAM:
            continue
        data = b58decode(ix["data"]) if ix.get("data") else b""
        if len(data) < 4:
            continue
        tag = int.from_bytes(data[:4], "little")
        accts = [keys[i] for i in ix.get("accounts", [])]
        if tag in (SYS_CREATE_ACCOUNT, SYS_CREATE_ACCOUNT_WITH_SEED) and len(accts) >= 2 and accts[1] == account:
            events.append({"kind": "create_account", "funder": accts[0]})
        elif tag == SYS_INITIALIZE_NONCE and accts and accts[0] == account and len(data) >= 36:
            events.append({"kind": "initialize_nonce", "authority": b58encode(data[4:36])})
    return events


def classify(pv, watched):
    """Classify an ok provenance record against the current watched set ({pubkey: label}), in place.

    The FUNDER (who paid the rent, i.e. who actually created the account) and the INITIAL nonce authority are
    decisive: either one outside the watched keys -> creator "outside" (high). A fee payer outside on its own
    is a sponsored/relayed fee: reported separately (medium), not as an outside creator. (independent review.)
    """
    fee_payer, funder, init_auth = pv.get("fee_payer"), pv.get("funder"), pv.get("initial_authority")
    outside = sorted({k for k in (funder, init_auth) if k and k not in watched})
    pv.update(
        creator="outside" if outside else "watched",
        outside_keys=outside,
        fee_payer_watched=watched.get(fee_payer),
        fee_payer_outside=bool(fee_payer) and fee_payer not in watched,
        funder_watched=watched.get(funder) if funder else None,
    )
    return pv


def nonce_provenance(client, account, watched):
    """watched: {pubkey: label}. Returns a provenance dict; status is ok / unavailable / unverified."""
    try:
        sigs = oldest_signatures(client, account)
    except (RpcError, RpcUnavailable, ValueError, KeyError, TypeError) as e:
        return {"status": "unavailable", "error": f"signature history: {e}"}
    if not sigs:
        return {"status": "unavailable", "error": "RPC returned no transaction history for this account (pruned or not indexed)"}
    ok_sigs = [s for s in reversed(sigs) if s.get("err") is None][:OLDEST_CANDIDATES]
    if not ok_sigs:
        return {"status": "unverified", "error": "no successful transaction in the visible history"}
    for rec in ok_sigs:
        sig = rec["signature"]
        try:
            tx = client.call("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0,
                                                      "commitment": "finalized"}])
        except (RpcError, RpcUnavailable) as e:
            return {"status": "unavailable", "error": f"getTransaction {sig}: {e}"}
        if not tx:
            return {"status": "unavailable", "error": f"transaction {sig} not returned (pruned from this RPC's ledger)"}
        try:
            if tx["transaction"]["signatures"][0] != sig:
                return {"status": "unverified", "error": f"RPC returned a different transaction for {sig}"}
            if (tx.get("meta") or {}).get("err") is not None:
                continue
            events = creation_events(tx, account)
            fee_payer = tx["transaction"]["message"]["accountKeys"][0]
        except (KeyError, IndexError, TypeError, ValueError) as e:
            return {"status": "unverified", "error": f"could not decode transaction {sig}: {e}"}
        if not events:
            continue
        funder = next((e["funder"] for e in events if e["kind"] == "create_account"), None)
        init_auth = next((e["authority"] for e in events if e["kind"] == "initialize_nonce"), None)
        if funder is None:
            # Only the InitializeNonceAccount is visible (the CreateAccount was in an earlier, pruned or unseen
            # transaction). Whoever paid for the account is unknown, so this is not a verified creator.
            return {"status": "unverified", "signature": sig, "initial_authority": init_auth, "fee_payer": fee_payer,
                    "error": f"funder unknown: {sig} initializes the nonce but no CreateAccount for it is visible"}
        if init_auth is None:
            # Symmetric guard (independent review 2026-10-06): the CreateAccount is visible but the
            # InitializeNonceAccount is not (split across transactions). The initial authority is the field that
            # matters most for a staged nonce, so an unseen one is not a verified creator either.
            return {"status": "unverified", "signature": sig, "funder": funder, "fee_payer": fee_payer,
                    "error": f"initial authority unknown: {sig} creates the account but no InitializeNonceAccount is visible"}
        return classify({
            "status": "ok",
            "signature": sig,
            "slot": tx.get("slot", rec.get("slot")),
            "created_at": _iso(tx.get("blockTime", rec.get("blockTime"))),
            "fee_payer": fee_payer,
            "funder": funder,
            "initial_authority": init_auth,
            "history_signatures": len(sigs),
        }, watched)
    return {"status": "unverified",
            "error": f"none of the {len(ok_sigs)} oldest visible transaction(s) creates this account; the creation is "
                     "probably older than this RPC's history"}
