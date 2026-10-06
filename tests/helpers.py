import copy
import json
import os

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


def load(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


def empty_tabo():
    return {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": []}}


class FixtureRpc:
    """Routes read-only calls to recorded responses. `overrides[(method, key)]` wins."""

    def __init__(self, overrides=None, gpa_refused=False, gpa_silent_empty=False):
        self.overrides = overrides or {}
        self.gpa_refused = gpa_refused
        self.gpa_silent_empty = gpa_silent_empty
        self.calls = []

    def __call__(self, method, params):
        self.calls.append((method, params))
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
            vals = []
            for m in params[0]:
                if m == PYUSD:
                    vals.append(load("mint_pyusd_t22.json")["result"]["value"])
                elif m == base_mint(base):
                    vals.append(base["result"]["value"][0])
                else:
                    vals.append(None)
            base["result"]["value"] = vals
            return base
        if method == "getAccountInfo":
            table = {USDC: "mint_usdc.json", PYUSD: "mint_pyusd_t22.json", JUP: "program_jup.json", JUP_PD: "programdata_jup.json"}
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
        if method in ("getTokenAccountsByOwner", "getAccountInfo"):
            return params[0]
        return None


def base_mint(t22_fixture):
    return "pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn"
