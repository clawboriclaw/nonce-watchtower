import base64
import copy
import json
import os
import struct
import time

from watchtower.base58 import b58decode

FIX = os.path.join(os.path.dirname(__file__), "fixtures")

NONCE_AUTH = "2AynC3HALoStAcHjbxH5rs1kpUFDiRfDc2gsxMgMFEbL"  # holds 5 real nonce accounts
DELEGATOR = "6zJDcmmaGhYCzFLboS8e7VDwQi67Jh6US9uApttNyTHP"  # has live delegates
EMPTY = "1nc1nerator11111111111111111111111111111111"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
PYUSD = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
JUP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
JUP_PD = "4Ec7ZxZS6Sbdg5UGSLHbAnM7GQHp2eFd4KYWRexAipQT"
SPL = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
T22 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
SYS = "11111111111111111111111111111111"
SQUADS_V4_MS = "51smH7pBDKJDgmVnVks3gMWaPQFfmQ5s4Fc223yHcjuH"  # Exponent Finance upgrade multisig, 3-of-5
SQUADS_V4_VAULT0 = "2tX7aHkV1r7am6bnTPqQJNBbEkbqDpNWHBYPahSQb9TP"  # its vault 0 = on-chain upgrade authority of Exponent
SQUADS_V3_MS = "6x3BDkL2n7VjBWxRD95EsbQi2R2E4zxrvcz1VA6pihnK"  # Phoenix upgrade multisig (Squads v3)
NONCE_CREATE_SIG = "3BxRHV8L9rAE79jTxUdcSYY45wiiYy8p2qnn9nkphKRd6CWEoAL6W6he3r4DwdacJU1pHt14qHceV2Gmr5ySckBp"
NONCE_USE_SIG = "2qnC1mFfNeMuKG6YuGkwXZgh37tFWQza9NqBFgoLdqyxxu2wiPVbbyHSdGRun92p9mfv7aiyAEoRnHMXP9BsW2m5"  # advances 2HYc...
NONCE_ACCOUNTS = [
    "2HYcWwR6ZzVeHfoSB2Z1MtytZwXMbMRpTqC36wJHfJHn",
    "2bq82QLzZr2u1b7udPyH6x95NvkrR3Zipvs37gT5GE5Q",
    "82FQGbm5h1DC89F3h8LLzgtLRG4xw2TiMFmUA37G7jZs",
    "9nnX6BEZ8SURh9WscvxtCWuDhwzaTazkqrs2P6LnxLTn",
    "HZa8Hb8F4EZJZiqTMn9Vb9SWekpuFLUwnAu2MQM5CxrS",
]


# Order of the mints in fixtures/layout_mints_*.json (tools: see fixtures/README.md).
LAYOUT_MINTS = [
    USDC, PYUSD, "pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn",
    "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN", "So11111111111111111111111111111111111111112",
    "jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL", "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R",
    "DriFtupJYLTosbwoN8koMbEYSx54aFAVLddWsbksjwg7",
]
DELEGATOR_SPL_MINTS = set(LAYOUT_MINTS[3:])


# --- jsonParsed fixture -> account bytes -------------------------------------------------------------------------
# The scanner requests base64 for token accounts and mints (security scan 2026-11-08, finding 1). The recorded
# 2026-10-06 fixtures are jsonParsed, so the fake RPC re-encodes their parsed fields into the SPL byte layout. The
# layout itself is pinned by tests/test_spl.py against base64 + jsonParsed answers recorded together from mainnet.

def _coption(key):
    return bytes(36) if not key else (1).to_bytes(4, "little") + b58decode(key)


def _key_or_zero(key):
    return b58decode(key) if key else bytes(32)


def encode_token_account(info, space=165):
    native = info.get("rentExemptReserve") if info.get("isNative") else None
    raw = (b58decode(info["mint"]) + b58decode(info["owner"])
           + int(info["tokenAmount"]["amount"]).to_bytes(8, "little") + _coption(info.get("delegate"))
           + bytes([{"initialized": 1, "frozen": 2}[info["state"]]])
           + (bytes(12) if native is None else (1).to_bytes(4, "little") + int(native["amount"]).to_bytes(8, "little"))
           + int((info.get("delegatedAmount") or {}).get("amount", 0)).to_bytes(8, "little")
           + _coption(info.get("closeAuthority")))
    if info.get("extensions") is not None:
        raw += b"\x02"
        for e in info["extensions"]:
            if e["extension"] == "immutableOwner":
                raw += struct.pack("<HH", 7, 0)
            elif e["extension"] == "transferHookAccount":
                raw += struct.pack("<HHB", 15, 1, int(e["state"]["transferring"]))
    return raw.ljust(space, b"\x00")


def encode_mint(info, space=82):
    raw = (_coption(info.get("mintAuthority")) + int(info["supply"]).to_bytes(8, "little")
           + bytes([info["decimals"], 1 if info.get("isInitialized", True) else 0]) + _coption(info.get("freezeAuthority")))
    if info.get("extensions") is not None:
        raw = raw.ljust(165, b"\x00") + b"\x01"
        for e in info["extensions"]:
            st = e.get("state") or {}
            if e["extension"] == "mintCloseAuthority":
                raw += struct.pack("<HH", 3, 32) + _key_or_zero(st.get("closeAuthority"))
            elif e["extension"] == "permanentDelegate":
                raw += struct.pack("<HH", 12, 32) + _key_or_zero(st.get("delegate"))
            elif e["extension"] == "transferHook":
                raw += struct.pack("<HH", 14, 64) + _key_or_zero(st.get("authority")) + _key_or_zero(st.get("programId"))
    return raw.ljust(space, b"\x00")


def _encode_account(acct):
    data = acct.get("data")
    if not (isinstance(data, dict) and "parsed" in data):
        return acct
    parsed, space = data["parsed"], data.get("space", acct.get("space"))
    raw = (encode_mint(parsed["info"], space) if parsed["type"] == "mint"
           else encode_token_account(parsed["info"], space))
    return dict(acct, data=[base64.b64encode(raw).decode(), "base64"])


def as_base64(resp):
    """A recorded jsonParsed RPC response with every parsed token account / mint re-encoded as base64 bytes."""
    resp = copy.deepcopy(resp)
    res = resp.get("result") if isinstance(resp, dict) else None
    val = res.get("value") if isinstance(res, dict) else None
    if isinstance(val, dict):
        res["value"] = _encode_account(val)
    elif isinstance(val, list):
        res["value"] = [
            (dict(v, account=_encode_account(v["account"])) if isinstance(v, dict) and "account" in v
             else _encode_account(v) if isinstance(v, dict) else v)
            for v in val
        ]
    return resp


def _asks_base64(method, params):
    at = {"getTokenAccountsByOwner": 2, "getMultipleAccounts": 1, "getAccountInfo": 1}.get(method)
    return at is not None and len(params) > at and (params[at] or {}).get("encoding") == "base64"


def load(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


def empty_tabo():
    return {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": []}}


class FixtureRpc:
    """Routes read-only calls to recorded responses. `overrides[(method, key)]` wins."""

    def __init__(self, overrides=None, gpa_refused=False, gpa_silent_empty=False, slot=1, gpa_slot=1, gpa_context=True,
                 block_age=5.0):
        self.overrides = overrides or {}
        self.gpa_refused = gpa_refused
        self.gpa_silent_empty = gpa_silent_empty
        self.slot = slot          # what getSlot answers (the endpoint's finalized slot)
        self.gpa_slot = gpa_slot  # context slot of getProgramAccounts answers (lower = a lagging index)
        self.gpa_context = gpa_context  # False: an endpoint that ignores withContext
        self.block_age = block_age      # seconds behind wall clock that getBlockTime reports (large = node behind)
        self.calls = []

    def __call__(self, method, params):
        self.calls.append((method, params))
        if method == "getSlot" and ("getSlot", None) not in self.overrides:
            return {"jsonrpc": "2.0", "id": 1, "result": self.slot() if callable(self.slot) else self.slot}
        if method == "getBlockTime" and ("getBlockTime", None) not in self.overrides:
            return {"jsonrpc": "2.0", "id": 1, "result": int(time.time() - self.block_age)}
        resp = self._route(method, params)
        if _asks_base64(method, params):
            resp = as_base64(resp)  # recorded jsonParsed token/mint fixtures, re-encoded into their byte layout
        # Real nodes wrap getProgramAccounts in {context, value} when asked withContext.
        if (method == "getProgramAccounts" and isinstance(resp, dict) and isinstance(resp.get("result"), list)
                and (params[1] or {}).get("withContext") and self.gpa_context):
            resp = dict(resp, result={"context": {"slot": self.gpa_slot}, "value": resp["result"]})
        return resp

    def _route(self, method, params):
        key = self._key(method, params)
        if (method, key) in self.overrides:
            v = self.overrides[(method, key)]
            if isinstance(v, Exception):
                raise v
            return copy.deepcopy(v)
        if method == "getProgramAccounts":
            if self.gpa_refused:
                return load("rpc_error_excluded.json")
            if self.gpa_silent_empty:
                return load("gpa_nonce_empty.json")
            if key == SYS:
                return load("gpa_canary.json")
            if key == NONCE_AUTH:
                return load("gpa_nonce_real.json")
            return load("gpa_nonce_empty.json")
        if method == "getTokenAccountsByOwner":
            owner, prog = params[0], params[1]["programId"]
            if owner == DELEGATOR:
                return load("tabo_spl_delegates.json" if prog == SPL else "tabo_t22_delegates.json")
            return empty_tabo()
        if method == "getMultipleAccounts":
            base = load("t22_mints.json")
            # Mints of the delegator's SPL accounts, recorded in base64 (see fixtures/README.md, layout_*).
            spl_mints = dict(zip(LAYOUT_MINTS, load("layout_mints_base64.json")["result"]["value"]))
            vals = []
            for m in params[0]:
                if m == PYUSD:
                    vals.append(load("mint_pyusd_t22.json")["result"]["value"])
                elif m == USDC:
                    vals.append(load("mint_usdc.json")["result"]["value"])
                elif m == base_mint(base):
                    vals.append(base["result"]["value"][0])
                elif m in DELEGATOR_SPL_MINTS:
                    vals.append(spl_mints[m])
                else:
                    vals.append(None)
            base["result"]["value"] = vals
            return base
        if method == "getSignaturesForAddress":
            if key in NONCE_ACCOUNTS:
                return load(f"sigs_{key}.json")
            return {"jsonrpc": "2.0", "id": 1, "result": []}
        if method == "getTransaction":
            if key == NONCE_CREATE_SIG:
                return load("tx_nonce_create_3BxRHV8L.json")
            if key == NONCE_USE_SIG:
                return load("tx_nonce_use_2qnC1mFf.json")
            return {"jsonrpc": "2.0", "id": 1, "result": None}
        if method == "getAccountInfo":
            table = {USDC: "mint_usdc.json", PYUSD: "mint_pyusd_t22.json", JUP: "program_jup.json", JUP_PD: "programdata_jup.json",
                     SQUADS_V4_MS: "squads_v4_exponent.json", SQUADS_V3_MS: "squads_v3_phoenix.json"}
            if key in table:
                return load(table[key])
            return {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": None}}
        raise AssertionError(f"unexpected method {method}")

    @staticmethod
    def _key(method, params):
        if method == "getProgramAccounts":
            for f in params[1].get("filters", []):
                if "memcmp" in f:
                    return f["memcmp"]["bytes"]
        if method in ("getTokenAccountsByOwner", "getAccountInfo", "getSignaturesForAddress", "getTransaction"):
            return params[0]
        return None


def base_mint(t22_fixture):
    return "pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn"
