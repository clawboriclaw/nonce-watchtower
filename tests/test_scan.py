import unittest

from watchtower.rpc import RpcClient, RpcUnavailable
from watchtower.scan import run_scan

from .helpers import DELEGATOR, EMPTY, JUP, NONCE_AUTH, PYUSD, SPL, T22, USDC, FixtureRpc


def scan(wallets, mints=(), programs=(), **kw):
    rpc = FixtureRpc(**kw)
    rep = run_scan(RpcClient(transport=rpc), [{"pubkey": w, "label": ""} for w in wallets], list(mints), list(programs))
    return rep, rpc


class NonceScanTests(unittest.TestCase):
    def test_finds_real_nonce_accounts_with_correct_filter(self):
        rep, rpc = scan([NONCE_AUTH])
        self.assertEqual(rep["nonce_coverage"]["status"], "ok")
        n = rep["wallets"][0]["nonces"]
        self.assertEqual(n["status"], "ok")
        self.assertEqual(len(n["items"]), 5)
        gpa = [p for m, p in rpc.calls if m == "getProgramAccounts" and p[1]["filters"][1]["memcmp"]["bytes"] == NONCE_AUTH][0]
        self.assertEqual(gpa[0], "11111111111111111111111111111111")
        self.assertEqual(gpa[1]["filters"], [{"dataSize": 80}, {"memcmp": {"offset": 8, "bytes": NONCE_AUTH}}])
        self.assertEqual(sum(f["kind"] == "nonce_account" for f in rep["findings"]), 5)
        self.assertTrue(rep["complete"])

    def test_empty_wallet_is_clean_and_complete(self):
        rep, _ = scan([EMPTY])
        self.assertEqual(rep["wallets"][0]["nonces"], {"status": "ok", "items": []})
        self.assertEqual(rep["wallets"][0]["token_accounts"]["items"], [])
        self.assertTrue(rep["complete"])
        self.assertFalse([f for f in rep["findings"] if f["severity"] != "info"])

    def test_refused_gpa_is_unavailable_not_clean(self):
        rep, _ = scan([EMPTY], gpa_refused=True)
        n = rep["wallets"][0]["nonces"]
        self.assertEqual(n["status"], "unavailable")
        self.assertIn("-32010", n["error"])
        self.assertIn("WATCHTOWER_RPC_URL", n["advice"])
        self.assertFalse(rep["complete"])
        self.assertTrue(any(f["kind"] == "coverage_gap" for f in rep["findings"]))

    def test_silently_empty_gpa_fails_canary(self):
        rep, _ = scan([EMPTY], gpa_silent_empty=True)
        self.assertEqual(rep["nonce_coverage"]["status"], "unavailable")
        self.assertEqual(rep["wallets"][0]["nonces"]["status"], "unverified")
        self.assertFalse(rep["complete"])

    def test_server_side_filter_is_not_trusted(self):
        # A malicious/buggy RPC returns another key's nonce accounts for our query.
        from .helpers import load
        rep, _ = scan([EMPTY], overrides={("getProgramAccounts", EMPTY): load("gpa_nonce_real.json")})
        n = rep["wallets"][0]["nonces"]
        self.assertEqual(n["items"], [])
        self.assertEqual(n["rejected_entries"], 5)
        # Rejected entries mean the endpoint's answer is untrusted: never report clean.
        self.assertEqual(n["status"], "unverified")
        self.assertFalse(rep["complete"])
        self.assertTrue(any(f["kind"] == "coverage_gap" for f in rep["findings"]))

    def test_canary_with_unverifiable_entries_fails(self):
        from .helpers import load
        bad = load("gpa_canary.json")
        for e in bad["result"]:
            e["account"]["data"] = ["", "base64"]
        rep, _ = scan([EMPTY], overrides={("getProgramAccounts", "11111111111111111111111111111111"): bad})
        self.assertEqual(rep["nonce_coverage"]["status"], "unavailable")
        self.assertFalse(rep["complete"])


class TokenScanTests(unittest.TestCase):
    def test_delegates_both_programs(self):
        rep, _ = scan([DELEGATOR])
        t = rep["wallets"][0]["token_accounts"]
        self.assertEqual(t["status"], "ok")
        progs = {i["program"] for i in t["items"]}
        self.assertEqual(progs, {SPL, T22})
        self.assertEqual(len(t["items"]), 5)  # 4 SPL with delegate + 1 Token-2022
        self.assertTrue(all(i["delegate"] == JUP for i in t["items"]))
        t22 = [i for i in t["items"] if i["program"] == T22][0]
        self.assertEqual(t22["delegated_amount"], "1189944224")
        self.assertEqual(sum(f["kind"] == "token_delegate" and f["severity"] == "high" for f in rep["findings"]), 5)

    def test_one_program_failing_is_partial(self):
        rep, _ = scan([DELEGATOR], overrides={("getTokenAccountsByOwner", DELEGATOR): RpcUnavailable("getTokenAccountsByOwner", "HTTP 503")})
        t = rep["wallets"][0]["token_accounts"]
        self.assertEqual(t["status"], "unavailable")
        self.assertFalse(rep["complete"])

    def test_permanent_delegate_flagged(self):
        from .helpers import load
        tabo = load("tabo_t22_delegates.json")
        tabo["result"]["value"][0]["account"]["data"]["parsed"]["info"]["mint"] = PYUSD
        rpc = FixtureRpc()
        orig = rpc.__call__

        def route(m, p):
            if m == "getTokenAccountsByOwner" and p[1]["programId"] == T22:
                return tabo
            return orig(m, p)

        rep = run_scan(RpcClient(transport=route), [{"pubkey": DELEGATOR, "label": "x"}])
        pds = rep["wallets"][0]["token_accounts"]["permanent_delegates"]
        self.assertEqual(pds, [{"mint": PYUSD, "delegate": "2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk"}])


class AuthorityScanTests(unittest.TestCase):
    def test_mints_and_programs(self):
        rep, _ = scan([EMPTY], mints=[USDC, PYUSD], programs=[JUP])
        usdc, pyusd = rep["mints"]
        self.assertEqual(usdc["mint_authority"], "BJE5MMbqXjVwjAF7oxwPYXnTXDyspzZyt4vwenNw5ruG")
        self.assertEqual(usdc["freeze_authority"], "7dGbd2QZcCKcTndnHcTL8q7SMVXAkp688NTQYwrRCrar")
        self.assertIsNone(usdc["permanent_delegate"])
        self.assertEqual(pyusd["permanent_delegate"], "2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk")
        prog = rep["programs"][0]
        self.assertEqual(prog["upgrade_authority"], "CvQZZ23qYDWF2RUpxYJ8y9K4skmuvYEEjH7fK58jtipQ")
        self.assertTrue(prog["upgradeable"])

    def test_held_by_watched(self):
        holder = "BJE5MMbqXjVwjAF7oxwPYXnTXDyspzZyt4vwenNw5ruG"
        rpc = FixtureRpc()
        rep = run_scan(RpcClient(transport=rpc), [{"pubkey": holder, "label": "ops"}], [USDC], [])
        self.assertEqual(rep["mints"][0]["held_by_watched"], ["mint_authority:ops"])

    def test_missing_accounts(self):
        rep, _ = scan([], mints=[EMPTY], programs=[EMPTY])
        self.assertEqual(rep["mints"][0]["status"], "missing")
        self.assertEqual(rep["programs"][0]["status"], "missing")

    def test_invalid_pubkey_rejected(self):
        with self.assertRaises(ValueError):
            scan(["not-a-key"])
