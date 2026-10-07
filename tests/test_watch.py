import copy
import io
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

from watchtower import alerts as alerts_mod
from watchtower.cli import main, watch_cycle
from watchtower.config import ConfigError, load_config
from watchtower.diff import diff, snapshot
from watchtower.rpc import RpcClient
from watchtower.scan import run_scan

from .helpers import DELEGATOR, EMPTY, JUP, NONCE_AUTH, USDC, FixtureRpc, load


def report(rpc, wallets=(NONCE_AUTH, DELEGATOR), mints=(USDC,), programs=(JUP,)):
    return run_scan(RpcClient(transport=rpc), [{"pubkey": w, "label": ""} for w in wallets], list(mints), list(programs))


def kinds(alerts):
    return sorted(a["kind"] for a in alerts)


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.base = snapshot(report(FixtureRpc()))

    def test_baseline_reports_standing_risk(self):
        a = diff(None, self.base)
        self.assertEqual(kinds(a).count("existing_nonce_account"), 5)
        self.assertEqual(kinds(a).count("existing_delegate"), 5)
        self.assertIn("mint_baseline", kinds(a))
        self.assertTrue(all(x.get("baseline") for x in a))

    def test_no_change_no_alerts(self):
        again = snapshot(report(FixtureRpc()), self.base)
        self.assertEqual(diff(self.base, again), [])

    def test_new_nonce_is_critical(self):
        empty_gpa = load("gpa_nonce_empty.json")
        before = snapshot(report(FixtureRpc(overrides={("getProgramAccounts", NONCE_AUTH): empty_gpa})))
        a = diff(before, self.base)
        new = [x for x in a if x["kind"] == "new_nonce_account"]
        self.assertEqual(len(new), 5)
        self.assertTrue(all(x["severity"] == "critical" for x in new))
        self.assertEqual(a[0]["severity"], "critical")  # sorted most severe first

    def test_nonce_advanced(self):
        g = load("gpa_nonce_real.json")
        import base64
        raw = bytearray(base64.b64decode(g["result"][0]["account"]["data"][0]))
        raw[40:72] = b"\x09" * 32
        g["result"][0]["account"]["data"][0] = base64.b64encode(bytes(raw)).decode()
        after = snapshot(report(FixtureRpc(overrides={("getProgramAccounts", NONCE_AUTH): g})), self.base)
        self.assertEqual(kinds(diff(self.base, after)), ["nonce_advanced"])

    def test_outage_holds_state_and_warns(self):
        down = snapshot(report(FixtureRpc(gpa_refused=True)), self.base)
        self.assertEqual(down["nonces"], self.base["nonces"])  # carried forward
        a = diff(self.base, down)
        self.assertNotIn("nonce_account_gone", kinds(a))
        self.assertTrue(all(x["kind"] == "coverage_lost" for x in a))
        self.assertEqual(len(a), 2)  # one coverage_lost per wallet nonce check
        # Once restored with identical data: only coverage_restored.
        up = snapshot(report(FixtureRpc()), down)
        self.assertEqual(set(kinds(diff(down, up))), {"coverage_restored"})

    def test_delegate_changes(self):
        t = load("tabo_spl_delegates.json")
        info = t["result"]["value"][0]["account"]["data"]["parsed"]["info"]
        info["delegatedAmount"]["amount"] = "99999999999"
        t["result"]["value"][1]["account"]["data"]["parsed"]["info"]["delegate"] = EMPTY
        t["result"]["value"][1]["account"]["data"]["parsed"]["info"]["delegatedAmount"] = {"amount": "5", "uiAmountString": "5"}
        rpc = FixtureRpc()
        orig = rpc.__call__

        def route(m, p):
            if m == "getTokenAccountsByOwner" and p[0] == DELEGATOR and p[1]["programId"].startswith("Tokenkeg"):
                return copy.deepcopy(t)
            return orig(m, p)

        after = snapshot(run_scan(RpcClient(transport=route), [{"pubkey": NONCE_AUTH}, {"pubkey": DELEGATOR}], [USDC], [JUP]), self.base)
        self.assertEqual(kinds(diff(self.base, after)), ["delegate_allowance_increased", "new_delegate"])

    def test_authority_changes(self):
        mint = load("mint_usdc.json")
        mint["result"]["value"]["data"]["parsed"]["info"]["freezeAuthority"] = None
        pd = load("programdata_jup.json")
        import base64
        raw = bytearray(base64.b64decode(pd["result"]["value"]["data"][0]))
        raw[13:45] = b"\x07" * 32
        pd["result"]["value"]["data"][0] = base64.b64encode(bytes(raw)).decode()
        from .helpers import JUP_PD
        after = snapshot(report(FixtureRpc(overrides={("getAccountInfo", USDC): mint, ("getAccountInfo", JUP_PD): pd})), self.base)
        a = diff(self.base, after)
        self.assertEqual(kinds(a), ["freeze_authority_changed", "upgrade_authority_changed"])
        self.assertTrue(all(x["severity"] == "critical" for x in a))


class WatchCycleTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg_path = os.path.join(self.dir, "wallets.toml")
        with open(self.cfg_path, "w") as f:
            f.write(f'mints = ["{USDC}"]\n\n[[wallets]]\nlabel = "council-1"\npubkey = "{NONCE_AUTH}"\n')
        self.cfg = load_config(self.cfg_path)

    def test_cycle_persists_state_0600_and_second_cycle_is_quiet(self):
        out = io.StringIO()
        client = RpcClient(transport=FixtureRpc())
        a1 = watch_cycle(self.cfg, client, self.cfg["state_file"], None, out=out)
        self.assertEqual(kinds(a1).count("existing_nonce_account"), 5)
        self.assertIn("mint_baseline", kinds(a1))
        self.assertIn("[council-1]", out.getvalue())
        mode = stat.S_IMODE(os.stat(self.cfg["state_file"]).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(watch_cycle(self.cfg, client, self.cfg["state_file"], None, out=io.StringIO()), [])

    def test_webhook_failure_queues_then_flushes(self):
        client = RpcClient(transport=FixtureRpc())
        with mock.patch.object(alerts_mod, "post_webhook", return_value=(False, "down")):
            with mock.patch("watchtower.cli.post_webhook", return_value=(False, "down")):
                a1 = watch_cycle(self.cfg, client, self.cfg["state_file"], "https://hooks.example.com/x", out=io.StringIO())
        with open(self.cfg["state_file"]) as f:
            st = json.load(f)
        self.assertEqual(len(st["pending_webhook"]), len(a1))
        sent = []
        with mock.patch("watchtower.cli.post_webhook", side_effect=lambda url, al: sent.append(al) or (True, "ok")):
            watch_cycle(self.cfg, client, self.cfg["state_file"], "https://hooks.example.com/x", out=io.StringIO())
        self.assertEqual(len(sent[0]), len(a1))
        with open(self.cfg["state_file"]) as f:
            self.assertEqual(json.load(f)["pending_webhook"], [])

    def test_config_rejects_inline_secrets_and_bad_keys(self):
        p = os.path.join(self.dir, "bad.toml")
        trap = '[[wallets]]\npubkey = "%s"\nmints = ["%s"]\n' % (EMPTY, USDC)
        for body in (trap, 'rpc_url = "https://x?api-key=1"\nwallets=["%s"]' % EMPTY, 'wallets = ["nope"]', ""):
            with open(p, "w") as f:
                f.write(body)
            with self.assertRaises(ConfigError):
                load_config(p)


class VanishedNonceTests(unittest.TestCase):
    """Round-2 finding 4: a nonce missing from an otherwise-ok scan is confirmed before it counts as gone."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        p = os.path.join(self.dir, "wallets.toml")
        with open(p, "w") as f:
            f.write(f'[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        self.cfg = load_config(p)
        watch_cycle(self.cfg, RpcClient(transport=FixtureRpc()), self.cfg["state_file"], None, out=io.StringIO())
        g = load("gpa_nonce_real.json")
        self.missing = g["result"][0]
        g["result"] = g["result"][1:]
        self.partial_gpa = g

    def cycle(self, account_info):
        rpc = FixtureRpc(overrides={("getProgramAccounts", NONCE_AUTH): self.partial_gpa,
                                    ("getAccountInfo", self.missing["pubkey"]): account_info})
        res = {}
        with mock.patch("sys.stderr", io.StringIO()):
            a = watch_cycle(self.cfg, RpcClient(transport=rpc), self.cfg["state_file"], None, out=io.StringIO(), result=res)
        return a, res["snap"]

    def test_still_existing_account_is_kept_and_scan_marked_unverified(self):
        a, snap = self.cycle({"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": self.missing["account"]}})
        self.assertIn(self.missing["pubkey"], snap["nonces"])
        self.assertEqual(snap["coverage"][f"nonces:{NONCE_AUTH}"], "unverified")
        self.assertNotIn("nonce_account_gone", kinds(a))
        self.assertIn("coverage_lost", kinds(a))

    def test_failed_direct_read_is_not_a_disappearance(self):
        from watchtower.rpc import RpcUnavailable
        a, snap = self.cycle(RpcUnavailable("getAccountInfo", "timeout"))
        self.assertIn(self.missing["pubkey"], snap["nonces"])
        self.assertEqual(snap["coverage"][f"nonces:{NONCE_AUTH}"], "unverified")

    def test_confirmed_gone_is_gone(self):
        a, snap = self.cycle({"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 1}, "value": None}})
        self.assertNotIn(self.missing["pubkey"], snap["nonces"])
        self.assertEqual(snap["coverage"][f"nonces:{NONCE_AUTH}"], "ok")
        self.assertIn("nonce_account_gone", kinds(a))


class WebhookTests(unittest.TestCase):
    def test_payload_and_https_only(self):
        ok, msg = alerts_mod.post_webhook("http://hooks.example.com/secret", [{"severity": "high", "kind": "k", "subject": "s", "detail": "d"}])
        self.assertFalse(ok)
        self.assertNotIn("secret", msg)
        p = alerts_mod.webhook_payload([{"severity": "critical", "kind": "new_nonce_account", "subject": "A", "detail": "d"}])
        self.assertIn("CRIT new_nonce_account", p["text"])
        self.assertLessEqual(len(p["content"]), 2000)

    def test_post_uses_injected_opener(self):
        seen = {}

        class Resp:
            status = 204

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(req, timeout):
            seen["body"] = json.loads(req.data)
            return Resp()

        ok, msg = alerts_mod.post_webhook("https://hooks.example.com/T/B/secret", [{"severity": "high", "kind": "k", "subject": "s", "detail": "d"}], opener=opener)
        self.assertTrue(ok)
        self.assertNotIn("secret", msg)
        self.assertEqual(seen["body"]["alerts"][0]["kind"], "k")


class CliTests(unittest.TestCase):
    def test_bad_pubkey_exit_64(self):
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(["scan", "zzz"]), 64)

    def test_scan_exit_codes(self):
        with mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc())), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(main(["scan", EMPTY]), 0)
            self.assertEqual(main(["scan", NONCE_AUTH, "--json"]), 1)
        with mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc(gpa_refused=True))), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(main(["scan", EMPTY]), 2)
