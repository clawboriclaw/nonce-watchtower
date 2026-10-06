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
