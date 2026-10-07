"""A lagging RPC index must be a coverage gap, never "clean" (review residual, round 4)."""

import io
import os
import shutil
import tempfile
import unittest
from unittest import mock

from watchtower.cli import main, watch_cycle
from watchtower.config import ConfigError, load_config
from watchtower.rpc import FreshnessGuard, RpcClient, RpcStale, RpcUnavailable
from watchtower.scan import confirm_missing_nonces, run_scan

from .helpers import JUP, NONCE_AUTH, SQUADS_V4_MS, USDC, FixtureRpc, load

USDC_CTX = 453929676  # context slot recorded in tests/fixtures/mint_usdc.json
NEWEST_CTX = 454045362  # highest context slot among the account fixtures (squads_v4_exponent.json)


def scan(rpc, **kw):
    return run_scan(RpcClient(transport=rpc), [{"pubkey": NONCE_AUTH}], **kw)


class RequestShapeTests(unittest.TestCase):
    def test_every_guarded_read_is_finalized_and_preceded_by_a_fresh_getslot(self):
        rpc = FixtureRpc()
        run_scan(RpcClient(transport=rpc), [{"pubkey": NONCE_AUTH}], [USDC], [JUP])
        guarded = 0
        for i, (m, p) in enumerate(rpc.calls):
            if m in ("getProgramAccounts", "getAccountInfo", "getTokenAccountsByOwner", "getMultipleAccounts"):
                guarded += 1
                self.assertEqual(p[-1]["commitment"], "finalized")
                if m == "getProgramAccounts":
                    self.assertTrue(p[1]["withContext"])
                j = i - 1
                while rpc.calls[j][0] == "getBlockTime":
                    j -= 1
                self.assertEqual(rpc.calls[j], ("getSlot", [{"commitment": "finalized"}]), (i, m))
        self.assertGreater(guarded, 5)


class NonceLagTests(unittest.TestCase):
    def test_lagging_gpa_marks_nonces_unverified(self):
        r = scan(FixtureRpc(slot=1000, gpa_slot=900))
        n = r["wallets"][0]["nonces"]
        self.assertEqual(n["status"], "unverified")
        self.assertIn("100 slots behind", n["error"])
        self.assertFalse(r["complete"])

    def test_lag_within_limit_is_ok_and_limit_is_configurable(self):
        self.assertEqual(scan(FixtureRpc(slot=1000, gpa_slot=950))["wallets"][0]["nonces"]["status"], "ok")
        self.assertEqual(scan(FixtureRpc(slot=1000, gpa_slot=950), max_slot_lag=10)["wallets"][0]["nonces"]["status"],
                         "unverified")

    def test_no_context_or_no_reference_slot_is_unverified(self):
        self.assertEqual(scan(FixtureRpc(gpa_context=False))["wallets"][0]["nonces"]["status"], "unverified")
        rpc = FixtureRpc(overrides={("getSlot", None): RpcUnavailable("getSlot", "timeout")})
        self.assertEqual(scan(rpc)["wallets"][0]["nonces"]["status"], "unverified")

    def test_new_nonce_hidden_by_a_lagging_index_raises_a_gap(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "w.toml")
        with open(p, "w") as f:
            f.write(f'[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        cfg = load_config(p)
        empty = {("getProgramAccounts", NONCE_AUTH): load("gpa_nonce_empty.json")}
        with mock.patch("sys.stderr", io.StringIO()):
            watch_cycle(cfg, RpcClient(transport=FixtureRpc(overrides=dict(empty))), cfg["state_file"], None, out=io.StringIO())
            # A nonce was just created; this node's index lags and still answers "none" (canary passes).
            res = {}
            a = watch_cycle(cfg, RpcClient(transport=FixtureRpc(overrides=dict(empty), slot=5000, gpa_slot=10)),
                            cfg["state_file"], None, out=io.StringIO(), result=res)
        self.assertEqual(res["snap"]["coverage"][f"nonces:{NONCE_AUTH}"], "unverified")
        self.assertIn(("coverage_lost", f"nonces:{NONCE_AUTH}"), {(x["kind"], x["subject"]) for x in a})

    def test_cli_scan_exit_code_and_flag(self):
        with mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc(slot=1000, gpa_slot=900))), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(["scan", NONCE_AUTH]) & 2, 2)
            self.assertEqual(main(["scan", "1nc1nerator11111111111111111111111111111111", "--max-slot-lag", "2000"]), 0)
            self.assertEqual(main(["scan", NONCE_AUTH, "--max-slot-lag", "-1"]), 64)


class AccountLagTests(unittest.TestCase):
    def test_lagging_mint_program_and_multisig_reads_are_gaps(self):
        r = run_scan(RpcClient(transport=FixtureRpc(slot=NEWEST_CTX + 1000)), [], [USDC], [JUP], squads=[SQUADS_V4_MS])
        self.assertEqual(r["mints"][0]["status"], "unavailable")
        self.assertIn("behind", r["mints"][0]["error"])
        self.assertEqual(r["programs"][0]["status"], "unavailable")
        self.assertEqual(r["multisigs"][0]["status"], "unavailable")
        self.assertFalse(r["complete"])
        ok = run_scan(RpcClient(transport=FixtureRpc(slot=USDC_CTX)), [], [USDC], [JUP])
        self.assertEqual(ok["mints"][0]["status"], "ok")

    def test_stale_read_cannot_confirm_a_nonce_is_gone(self):
        g = load("gpa_nonce_real.json")["result"][0]
        prev = {"nonces": {g["pubkey"]: {"wallet": NONCE_AUTH, "authority": NONCE_AUTH, "nonce": "x", "version": "current"}}}
        snap = {"nonces": {}, "coverage": {f"nonces:{NONCE_AUTH}": "ok"}}
        stale_gone = {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 10}, "value": None}}
        rpc = FixtureRpc(overrides={("getAccountInfo", g["pubkey"]): stale_gone}, slot=5000)
        carried = confirm_missing_nonces(FreshnessGuard(RpcClient(transport=rpc)), prev, snap)
        self.assertEqual(carried, [g["pubkey"]])
        self.assertEqual(snap["coverage"][f"nonces:{NONCE_AUTH}"], "unverified")

    def test_watch_does_not_accept_a_stale_disappearance(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "w.toml")
        with open(p, "w") as f:
            f.write(f'[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        cfg = load_config(p)
        with mock.patch("sys.stderr", io.StringIO()):
            watch_cycle(cfg, RpcClient(transport=FixtureRpc()), cfg["state_file"], None, out=io.StringIO())
            g = load("gpa_nonce_real.json")
            gone = g["result"].pop(0)["pubkey"]
            stale = {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": None}}
            rpc = FixtureRpc(overrides={("getProgramAccounts", NONCE_AUTH): g, ("getAccountInfo", gone): stale},
                             slot=5000, gpa_slot=5000)
            res = {}
            a = watch_cycle(cfg, RpcClient(transport=rpc), cfg["state_file"], None, out=io.StringIO(), result=res)
        self.assertIn(gone, res["snap"]["nonces"])
        self.assertEqual(res["snap"]["coverage"][f"nonces:{NONCE_AUTH}"], "unverified")
        self.assertNotIn("nonce_account_gone", [x["kind"] for x in a])

    def test_guard_raises_stale_without_context(self):
        c = FreshnessGuard(RpcClient(transport=lambda m, p: {"result": 7 if m == "getSlot" else {"value": None}}))
        with self.assertRaises(RpcStale):
            c.call("getAccountInfo", ["x", {}])


class RefreshPerReadTests(unittest.TestCase):
    """Round-5 finding 1: the reference is refreshed before EVERY read, not reused from an earlier GPA."""

    def advancing(self, rpc, read):
        # Reference at 100 when the scan starts; the endpoint has advanced to 1000 by the time of `read`.
        state = {"n": 0}

        def slot():
            state["n"] += 1
            return 100 if state["n"] == 1 else 1000
        rpc.slot = slot
        return rpc

    def test_each_read_type_with_a_stale_context_is_rejected(self):
        g = FreshnessGuard(RpcClient(transport=FixtureRpc()))
        stale = {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 100}, "value": None}}
        for method, params in (("getAccountInfo", ["Acct", {}]), ("getMultipleAccounts", [["Acct"], {}]),
                               ("getTokenAccountsByOwner", ["Owner", {"programId": "P"}, {}])):
            rpc = FixtureRpc(overrides={(method, params[0] if method != "getMultipleAccounts" else None): stale})
            if method == "getMultipleAccounts":
                rpc._route = lambda m, p, r=rpc: stale if m == "getMultipleAccounts" else FixtureRpc._route(r, m, p)
            g = FreshnessGuard(RpcClient(transport=self.advancing(rpc, method)))
            g.reference_slot()  # reference taken at 100 (e.g. by an earlier GPA)
            with self.assertRaises(RpcStale, msg=method):
                g.call(method, params)

    def test_multisig_and_upgrade_authority_reads_after_the_chain_moved(self):
        rpc = FixtureRpc()
        rpc.slot = lambda: NEWEST_CTX if not getattr(rpc, "_moved", False) else NEWEST_CTX + 5000
        orig = rpc._route

        def route(m, p):
            if m == "getProgramAccounts":
                rpc._moved = True  # after the nonce query the endpoint advances, account answers stay old
            return orig(m, p)
        rpc._route = route
        rpc.gpa_slot = NEWEST_CTX
        r = run_scan(RpcClient(transport=rpc), [{"pubkey": NONCE_AUTH}], [USDC], [JUP], squads=[SQUADS_V4_MS])
        self.assertEqual(r["multisigs"][0]["status"], "ok")  # read first, before the chain moved: really fresh
        self.assertEqual(r["programs"][0]["status"], "unavailable")  # upgrade authority read after the move
        self.assertEqual(r["mints"][0]["status"], "unavailable")
        # The multisig read itself, after an earlier reference (the reviewer's scenario): rejected.
        from watchtower.squads import resolve_multisig
        rpc2 = FixtureRpc()
        calls = {"n": 0}

        def slot():
            calls["n"] += 1
            return NEWEST_CTX if calls["n"] == 1 else NEWEST_CTX + 5000
        rpc2.slot = slot
        g = FreshnessGuard(RpcClient(transport=rpc2))
        g.reference_slot()
        self.assertEqual(resolve_multisig(g, SQUADS_V4_MS)["status"], "unavailable")


class AbsoluteAgeTests(unittest.TestCase):
    """Round-5 finding 4: a node uniformly behind the chain is caught by its finalized block's age."""

    def test_uniformly_behind_node_is_stale(self):
        rpc = FixtureRpc(slot=10, gpa_slot=10, block_age=5000)
        r = scan(rpc)
        n = r["wallets"][0]["nonces"]
        self.assertEqual(n["status"], "unverified")
        self.assertIn("old", n["error"])
        self.assertFalse(r["complete"])

    def test_recent_block_passes_and_limit_is_configurable(self):
        self.assertEqual(scan(FixtureRpc(block_age=30))["wallets"][0]["nonces"]["status"], "ok")
        self.assertEqual(scan(FixtureRpc(block_age=30), max_block_age=20)["wallets"][0]["nonces"]["status"], "unverified")

    def test_missing_block_time_is_stale(self):
        rpc = FixtureRpc(overrides={("getBlockTime", None): {"jsonrpc": "2.0", "id": 1, "result": None}})
        self.assertEqual(scan(rpc)["wallets"][0]["nonces"]["status"], "unverified")

    def test_age_check_is_cached_only_while_provably_valid(self):
        t = {"m": 0.0}
        rpc = FixtureRpc(block_age=100)
        g = FreshnessGuard(RpcClient(transport=rpc), max_block_age=120, monotonic=lambda: t["m"])
        g.reference_slot()
        n0 = sum(1 for m, _ in rpc.calls if m == "getBlockTime")
        t["m"] = 10.0
        g.reference_slot()  # 100 + 10 <= 120: reused
        self.assertEqual(sum(1 for m, _ in rpc.calls if m == "getBlockTime"), n0)
        t["m"] = 30.0
        g.reference_slot()  # 100 + 30 > 120: re-checked
        self.assertEqual(sum(1 for m, _ in rpc.calls if m == "getBlockTime"), n0 + 1)

    def test_independent_reference_rpc(self):
        primary = FixtureRpc(slot=1000, gpa_slot=1000)
        ahead = RpcClient(transport=FixtureRpc(slot=5000))
        r = scan(primary, reference_client=ahead)
        self.assertEqual(r["wallets"][0]["nonces"]["status"], "unverified")
        self.assertIn("reference RPC", r["wallets"][0]["nonces"]["error"])
        level = RpcClient(transport=FixtureRpc(slot=1010))
        self.assertEqual(scan(FixtureRpc(slot=1000, gpa_slot=1000), reference_client=level)["wallets"][0]["nonces"]["status"],
                         "ok")
        down = RpcClient(transport=FixtureRpc(overrides={("getSlot", None): RpcUnavailable("getSlot", "timeout")}))
        self.assertEqual(scan(FixtureRpc(), reference_client=down)["wallets"][0]["nonces"]["status"], "unverified")

    def test_reference_rpc_comes_from_env_and_is_redacted(self):
        from watchtower import cli
        url = "https://ref.example.org/v1/RefSecretKeyQ8w9e7?api-key=RefQuerySecret"
        with mock.patch.dict(os.environ, {"WATCHTOWER_REFERENCE_RPC_URL": url}):
            c = cli._reference_client("WATCHTOWER_REFERENCE_RPC_URL")
        self.assertIsNotNone(c)
        from watchtower.redact import scrub
        out = scrub(f"failed talking to {url}; key RefSecretKeyQ8w9e7")
        self.assertNotIn("RefSecretKeyQ8w9e7", out)
        self.assertNotIn("RefQuerySecret", out)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "w.toml")
        with open(p, "w") as f:
            f.write(f'reference_rpc_url = "{url}"\n[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        with self.assertRaises(ConfigError) as cm:
            load_config(p)
        self.assertIn("reference_rpc_url_env", str(cm.exception))  # refused as an inline credential, pointed to env
        self.assertNotIn("RefSecretKeyQ8w9e7", str(cm.exception))


class ConfigTests(unittest.TestCase):
    def test_max_slot_lag_config(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "w.toml")
        for body, ok in (("max_slot_lag = 10", True), ("max_slot_lag = -1", False), ('max_slot_lag = "x"', False),
                         ("max_block_age = 0", False), ("max_slot_lag = 10\nmax_block_age = 60", True)):
            with open(p, "w") as f:
                f.write(body + f'\n[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
            if ok:
                self.assertEqual(load_config(p)["max_slot_lag"], 10)
            else:
                with self.assertRaises(ConfigError):
                    load_config(p)


if __name__ == "__main__":
    unittest.main()
