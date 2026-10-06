"""Read-only enumeration of the standing powers attached to a set of keys.

A check that could not run is reported as `unavailable`, never as "nothing
found": an empty answer from an RPC that silently refused the query must not
look like a clean bill of health.
"""

import datetime as _dt

from . import __version__
from .base58 import require_pubkey
from .decode import (
    LOADER_V4,
    NON_UPGRADEABLE_LOADERS,
    NONCE_ACCOUNT_SIZE,
    NONCE_AUTHORITY_OFFSET,
    PROGRAMDATA_HEADER_SIZE,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    UPGRADEABLE_LOADER,
    account_bytes,
    decode_nonce,
    decode_program,
    decode_programdata_header,
)
from .rpc import RPC_ENV_VAR, RpcError, RpcUnavailable

GPA_ADVICE = (
    "This RPC endpoint would not serve getProgramAccounts on the System program, which is the only "
    "way to find nonce accounts by authority. Use a provider/own node that allows it and pass it via "
    f"--rpc or the {RPC_ENV_VAR} environment variable (the URL is never printed). Until then, nonce "
    "coverage for these keys is UNKNOWN, not clean."
)

# Bricked nonce accounts whose authority is the System program itself. Their authority can
# never change again, so "authority == 11111111111111111111111111111111" must always return
# at least one account. If it returns none, the endpoint is silently filtering the query.
CANARY_AUTHORITY = SYSTEM_PROGRAM


def _now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _err(exc):
    return {"status": "unavailable", "error": str(exc)}


def nonce_filters(authority):
    return [
        {"dataSize": NONCE_ACCOUNT_SIZE},
        {"memcmp": {"offset": NONCE_AUTHORITY_OFFSET, "bytes": authority}},
    ]


def check_nonce_canary(client):
    """True if the endpoint really serves System-program GPA (see CANARY_AUTHORITY)."""
    try:
        res = client.call(
            "getProgramAccounts",
            [
                SYSTEM_PROGRAM,
                {"encoding": "base64", "filters": nonce_filters(CANARY_AUTHORITY)},
            ],
        )
    except (RpcError, RpcUnavailable) as e:
        return {"status": "unavailable", "error": str(e), "advice": GPA_ADVICE}
    if not isinstance(res, list) or len(res) == 0:
        return {
            "status": "unavailable",
            "error": "canary query returned no accounts; endpoint appears to filter System-program GPA",
            "advice": GPA_ADVICE,
        }
    # Decode, don't just count: an endpoint that returns entries in a form we cannot verify
    # (wrong encoding, truncated data) must not pass the canary.
    for entry in res:
        try:
            acct = entry["account"]
            if acct.get("owner") != SYSTEM_PROGRAM or decode_nonce(account_bytes(acct))["authority"] != CANARY_AUTHORITY:
                raise ValueError("canary entry failed local verification")
        except (KeyError, TypeError, ValueError) as e:
            return {"status": "unavailable", "error": f"canary entries could not be verified locally: {e}", "advice": GPA_ADVICE}
    return {"status": "ok", "canary_hits": len(res)}


def scan_nonces(client, authority):
    try:
        res = client.call(
            "getProgramAccounts",
            [SYSTEM_PROGRAM, {"encoding": "base64", "filters": nonce_filters(authority)}],
        )
    except (RpcError, RpcUnavailable) as e:
        out = _err(e)
        out["advice"] = GPA_ADVICE
        return out
    if not isinstance(res, list):
        return {"status": "unavailable", "error": "unexpected getProgramAccounts shape", "advice": GPA_ADVICE}
    items, rejected = [], 0
    for entry in res:
        acct = entry.get("account", {})
        if acct.get("owner") != SYSTEM_PROGRAM:
            rejected += 1
            continue
        try:
            dec = decode_nonce(account_bytes(acct))
        except ValueError:
            dec = None
        # Defence in depth: never trust the server-side filter alone.
        if dec is None or dec["authority"] != authority:
            rejected += 1
            continue
        items.append({"account": entry["pubkey"], "lamports": acct.get("lamports"), **dec})
    items.sort(key=lambda x: x["account"])
    out = {"status": "ok", "items": items}
    if rejected:
        # The endpoint answered our query with accounts that fail local verification. Its answer
        # cannot be trusted, so "nothing found" is not "clean" (independent review 2026-10-06).
        out.update(status="unverified", rejected_entries=rejected,
                   error=f"{rejected} returned account(s) failed local verification; endpoint result untrusted")
    return out


def _token_item(entry, program):
    info = entry["account"]["data"]["parsed"]["info"]
    delegated = info.get("delegatedAmount") or {}
    return {
        "account": entry["pubkey"],
        "program": program,
        "mint": info.get("mint"),
        "owner": info.get("owner"),
        "state": info.get("state"),
        "delegate": info.get("delegate"),
        "delegated_amount": delegated.get("amount"),
        "delegated_ui": delegated.get("uiAmountString"),
        "close_authority": info.get("closeAuthority"),
    }


def scan_token_accounts(client, owner):
    """Token accounts (both programs) that carry a delegate, a foreign close authority, or are frozen."""
    items, errors, mints_2022 = [], [], set()
    program_status = {}
    for program in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        program_status[program] = "unavailable"
        try:
            res = client.call(
                "getTokenAccountsByOwner",
                [owner, {"programId": program}, {"encoding": "jsonParsed"}],
            )
            for entry in res.get("value", []):
                it = _token_item(entry, program)
                if it["owner"] != owner:
                    continue
                if program == TOKEN_2022_PROGRAM and it["mint"]:
                    mints_2022.add(it["mint"])
                if it["delegate"] or (it["close_authority"] and it["close_authority"] != owner) or it["state"] == "frozen":
                    items.append(it)
            program_status[program] = "ok"
        except (RpcError, RpcUnavailable, KeyError, TypeError, AttributeError) as e:
            errors.append(f"{program}: {e}")
    items.sort(key=lambda x: x["account"])
    out = {
        "status": "ok" if not errors else ("partial" if len(errors) == 1 else "unavailable"),
        "program_status": program_status,
        "items": items,
    }
    if errors:
        out["errors"] = errors
    return out, sorted(mints_2022)


def _mint_info(value):
    parsed = value["data"]["parsed"]
    if parsed.get("type") != "mint":
        return None
    info = parsed["info"]
    exts = {e.get("extension"): e.get("state") or {} for e in info.get("extensions", [])}
    return {
        "program": value.get("owner"),
        "mint_authority": info.get("mintAuthority"),
        "freeze_authority": info.get("freezeAuthority"),
        "permanent_delegate": exts.get("permanentDelegate", {}).get("delegate"),
        "close_authority": exts.get("mintCloseAuthority", {}).get("closeAuthority"),
        "transfer_hook_program": exts.get("transferHook", {}).get("programId"),
        "transfer_hook_authority": exts.get("transferHook", {}).get("authority"),
    }


def scan_permanent_delegates(client, mints):
    """Token-2022 mints whose permanent delegate can move any holder's balance."""
    found, errors = {}, []
    for i in range(0, len(mints), 100):
        chunk = mints[i : i + 100]
        try:
            res = client.call("getMultipleAccounts", [chunk, {"encoding": "jsonParsed"}])
            values = res.get("value", [])
            if len(values) != len(chunk):
                raise ValueError(f"getMultipleAccounts returned {len(values)} values for {len(chunk)} mints")
            for mint, value in zip(chunk, values):
                if not value:
                    continue
                mi = _mint_info(value)
                if mi and mi["permanent_delegate"]:
                    found[mint] = mi["permanent_delegate"]
        except (RpcError, RpcUnavailable, KeyError, TypeError, AttributeError, ValueError) as e:
            errors.append(str(e))
    return found, errors


def scan_mint(client, mint):
    try:
        res = client.call("getAccountInfo", [mint, {"encoding": "jsonParsed"}])
    except (RpcError, RpcUnavailable) as e:
        return {"mint": mint, **_err(e)}
    value = (res or {}).get("value")
    if not value:
        return {"mint": mint, "status": "missing"}
    if value.get("owner") not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        return {"mint": mint, "status": "not_a_mint", "owner_program": value.get("owner")}
    try:
        mi = _mint_info(value)
    except (KeyError, TypeError):
        mi = None
    if mi is None:
        return {"mint": mint, "status": "not_a_mint", "owner_program": value.get("owner")}
    return {"mint": mint, "status": "ok", **mi}


def scan_program(client, program_id):
    try:
        res = client.call(
            "getAccountInfo", [program_id, {"encoding": "base64", "dataSlice": {"offset": 0, "length": 36}}]
        )
    except (RpcError, RpcUnavailable) as e:
        return {"program": program_id, **_err(e)}
    value = (res or {}).get("value")
    if not value:
        return {"program": program_id, "status": "missing"}
    loader = value.get("owner")
    if loader in NON_UPGRADEABLE_LOADERS:
        return {"program": program_id, "status": "ok", "loader": loader, "upgradeable": False, "upgrade_authority": None}
    if loader == LOADER_V4:
        return {"program": program_id, "status": "unsupported_loader", "loader": loader}
    if loader != UPGRADEABLE_LOADER or not value.get("executable"):
        return {"program": program_id, "status": "not_a_program", "loader": loader}
    pd_addr = decode_program(account_bytes(value))
    if not pd_addr:
        return {"program": program_id, "status": "not_a_program", "loader": loader}
    try:
        pd = client.call(
            "getAccountInfo",
            [pd_addr, {"encoding": "base64", "dataSlice": {"offset": 0, "length": PROGRAMDATA_HEADER_SIZE}}],
        )
    except (RpcError, RpcUnavailable) as e:
        return {"program": program_id, "programdata": pd_addr, **_err(e)}
    pv = (pd or {}).get("value")
    if not pv or pv.get("owner") != UPGRADEABLE_LOADER:
        return {"program": program_id, "status": "unavailable", "error": "programdata account missing or foreign"}
    hdr = decode_programdata_header(account_bytes(pv))
    if hdr is None:
        return {"program": program_id, "status": "unavailable", "error": "programdata header did not decode"}
    return {
        "program": program_id,
        "status": "ok",
        "loader": loader,
        "upgradeable": hdr["upgrade_authority"] is not None,
        "programdata": pd_addr,
        "upgrade_authority": hdr["upgrade_authority"],
        "last_deploy_slot": hdr["slot"],
    }


def run_scan(client, wallets, mints=(), programs=()):
    """wallets: list of {"pubkey", "label"}; returns a JSON-serialisable report."""
    for w in wallets:
        require_pubkey(w["pubkey"], "wallet public key")
    for m in mints:
        require_pubkey(m, "mint address")
    for p in programs:
        require_pubkey(p, "program id")

    report = {
        "tool": "nonce-watchtower",
        "version": __version__,
        "scanned_at": _now(),
        "rpc": client.display,
        "nonce_coverage": check_nonce_canary(client) if wallets else {"status": "skipped"},
        "wallets": [],
        "mints": [],
        "programs": [],
    }
    for w in wallets:
        pk = w["pubkey"]
        nonces = scan_nonces(client, pk)
        if nonces["status"] == "ok" and report["nonce_coverage"]["status"] != "ok" and not nonces["items"]:
            # An empty result from an endpoint that failed the canary proves nothing.
            nonces = {
                "status": "unverified",
                "items": [],
                "error": "empty result from an endpoint that failed the nonce canary",
                "advice": GPA_ADVICE,
            }
        tokens, mints_2022 = scan_token_accounts(client, pk)
        perm, perm_err = scan_permanent_delegates(client, mints_2022)
        tokens["permanent_delegates"] = [{"mint": m, "delegate": d} for m, d in sorted(perm.items()) if d != pk]
        tokens["permanent_delegates_status"] = "ok" if not perm_err and tokens["program_status"][TOKEN_2022_PROGRAM] == "ok" else "unavailable"
        if perm_err:
            tokens.setdefault("errors", []).extend(perm_err)
            if tokens["status"] == "ok":
                tokens["status"] = "partial"
        report["wallets"].append({"pubkey": pk, "label": w.get("label") or "", "nonces": nonces, "token_accounts": tokens})

    watched = {w["pubkey"]: (w.get("label") or w["pubkey"]) for w in wallets}
    for m in mints:
        r = scan_mint(client, m)
        r["held_by_watched"] = sorted(
            {f"{role}:{watched[r[role]]}" for role in ("mint_authority", "freeze_authority", "permanent_delegate", "close_authority") if r.get(role) in watched}
        )
        report["mints"].append(r)
    for p in programs:
        r = scan_program(client, p)
        r["held_by_watched"] = [watched[r["upgrade_authority"]]] if r.get("upgrade_authority") in watched else []
        report["programs"].append(r)

    report["findings"] = findings(report)
    report["complete"] = is_complete(report)
    return report


def is_complete(report):
    for w in report["wallets"]:
        if w["nonces"]["status"] != "ok" or w["token_accounts"]["status"] != "ok":
            return False
    for m in report["mints"]:
        if m["status"] not in ("ok", "missing", "not_a_mint"):
            return False
    for p in report["programs"]:
        if p["status"] not in ("ok", "missing", "not_a_program"):
            return False
    return True


def findings(report):
    out = []

    def add(sev, kind, subject, detail, wallet=""):
        out.append({"severity": sev, "kind": kind, "wallet": wallet, "subject": subject, "detail": detail})

    for w in report["wallets"]:
        who = w["label"] or w["pubkey"]
        n = w["nonces"]
        if n["status"] != "ok":
            add("warn", "coverage_gap", w["pubkey"], f"nonce check {n['status']}: {n.get('error', '')}", who)
        for it in n.get("items", []):
            add(
                "high",
                "nonce_account",
                it["account"],
                f"durable nonce account with authority {it['authority']} ({it['version']}). Anything this key "
                "signs against it stays valid until the nonce is advanced. Confirm you created it; if not, "
                "advance or withdraw it now.",
                who,
            )
        t = w["token_accounts"]
        if t["status"] != "ok":
            add("warn", "coverage_gap", w["pubkey"], f"token-account check {t['status']}: {'; '.join(t.get('errors', []))}", who)
        for it in t.get("items", []):
            if it["delegate"]:
                live = it["delegated_amount"] not in (None, "0")
                add(
                    "high" if live else "medium",
                    "token_delegate",
                    it["account"],
                    f"delegate {it['delegate']} may move {it['delegated_ui'] or it['delegated_amount']} of mint {it['mint']}",
                    who,
                )
            if it["close_authority"] and it["close_authority"] != w["pubkey"]:
                add("medium", "foreign_close_authority", it["account"], f"close authority {it['close_authority']} on mint {it['mint']}", who)
            if it["state"] == "frozen":
                add("info", "frozen_account", it["account"], f"token account for mint {it['mint']} is frozen", who)
        for pd in t.get("permanent_delegates", []):
            add("medium", "mint_permanent_delegate", pd["mint"], f"Token-2022 permanent delegate {pd['delegate']} can move this wallet's balance of the mint", who)
    for m in report["mints"]:
        if m["status"] not in ("ok",):
            add("warn" if m["status"] == "unavailable" else "info", "mint_" + m["status"], m["mint"], m.get("error", ""))
            continue
        add("info", "mint_authorities", m["mint"],
            f"mint={m['mint_authority']} freeze={m['freeze_authority']} permanent_delegate={m['permanent_delegate']}"
            + (f" held_by_watched={m['held_by_watched']}" if m["held_by_watched"] else ""))
    for p in report["programs"]:
        if p["status"] != "ok":
            add("warn" if p["status"] in ("unavailable", "unsupported_loader") else "info", "program_" + p["status"], p["program"], p.get("error", p.get("loader", "")))
            continue
        add("info", "upgrade_authority", p["program"],
            f"upgrade_authority={p['upgrade_authority']} last_deploy_slot={p.get('last_deploy_slot')}"
            + (f" held_by_watched={p['held_by_watched']}" if p["held_by_watched"] else ""))
    return out
