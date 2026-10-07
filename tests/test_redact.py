"""Secrets never leave through any channel: stdout, stderr, state file, alert sinks (review blocker, round 4).

Each test injects text carrying every kind of configured secret into an exception, through the real watch
and stream code paths, and checks every output channel.
"""

import io
import json
import os
import shutil
import tempfile
import unittest
import urllib.request
from unittest import mock

from watchtower import redact
from watchtower.cli import main, watch_cycle
from watchtower.config import load_config, save_state
from watchtower.notify import DiscordSink, TelegramSink, WebhookSink
from watchtower.rpc import RpcClient, RpcError
from watchtower.ws import WsError

from .helpers import NONCE_ACCOUNTS, NONCE_AUTH, FixtureRpc
from .test_stream import FakeConn, Harness, ticks

TOKEN = "987654321:AAFakeTelegramTokenValue_0123456789abcd"
DISCORD = "https://discord.com/api/webhooks/112233445566/DiscordPathSecret_zyxwvu987654"
WEBHOOK = "https://hooks.example.com/services/T000/B000/WebhookPathSecretXYZ123"
RPC = "https://rpc.example.com/v2/RpcPathKeyAbc123456?api-key=RpcQuerySecret999"
WS = "wss://ws.example.com/ws/WsPathKey77777xyz?token=WsQueryToken55"
USERINFO = "https://alice:UserinfoPassw0rd@rpc2.example.com/"
UNREGISTERED = "https://other.example.net/keys/UnregisteredPathKey42?apikey=UnregQuery42"
NEEDLES = ["AAFakeTelegramTokenValue", "DiscordPathSecret", "WebhookPathSecretXYZ", "RpcPathKeyAbc", "RpcQuerySecret",
           "WsPathKey77777", "WsQueryToken55", "UserinfoPassw0rd", "UnregisteredPathKey42", "UnregQuery42"]
# Bare fragments (no URL around them) are caught only because the component that owns them registered them.
BARE = "RpcPathKeyAbc123456 DiscordPathSecret_zyxwvu987654 WebhookPathSecretXYZ123"
BOOM = f"boom: {TOKEN} {DISCORD} {WEBHOOK} {RPC} {WS} {USERINFO} {UNREGISTERED} {BARE}"


class Capture:
    """urllib opener that records every request body sent to a sink."""

    def __init__(self):
        self.bodies = []

    def __call__(self, req, timeout):
        self.bodies.append(req.data.decode() if req.data else "")

        class R:
            status = 200

            def read(self, n=-1):
                return b'{"ok": true}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return R()


class Base(unittest.TestCase):
    def assertClean(self, *texts):
        for t in texts:
            for n in NEEDLES:
                self.assertNotIn(n, t)

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.cfg_path = os.path.join(self.dir, "wallets.toml")
        with open(self.cfg_path, "w") as f:
            f.write(f'[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        self.env = {"WATCHTOWER_RPC_URL": RPC, "WATCHTOWER_WS_URL": WS, "WATCHTOWER_TELEGRAM_BOT_TOKEN": TOKEN,
                    "WATCHTOWER_TELEGRAM_CHAT_ID": "-100123", "WATCHTOWER_DISCORD_WEBHOOK_URL": DISCORD,
                    "WATCHTOWER_WEBHOOK_URL": WEBHOOK}


class ScrubUnitTests(Base):
    def test_every_secret_kind(self):
        redact.register(TOKEN)
        for u in (DISCORD, WEBHOOK, RPC, WS, USERINFO):
            redact.register_url(u)
        out = redact.scrub(BOOM)
        self.assertClean(out)
        self.assertIn("https://rpc.example.com", out)  # hosts stay, for diagnosis
        self.assertIn("other.example.net", out)

    def test_unregistered_patterns(self):
        for s in ("123456789:ABCdefGHIjklMNOpqrSTUvwxYZ0123456789", "x?api_key=abcdef123456 y", "access_token=abc12345def",
                  "https://u:pw123456@h.example.com/a/b?c=d", "POST /api/webhooks/99999/TokTokTok-123 failed"):
            out = redact.scrub(s)
            for frag in ("ABCdefGHI", "abcdef123456", "abc12345def", "pw123456", "TokTokTok"):
                self.assertNotIn(frag, out)

    def test_state_scrub_never_corrupts_numbers_or_words(self):
        redact.register_url("https://discord.com/api/webhooks/123456789012/SecretTokenAbc123")
        obj = {"slot": 123456789012, "detail": "webhooks are fine", "nested": ["SecretTokenAbc123", 5]}
        out = redact.scrub_obj(obj)
        self.assertEqual(out["slot"], 123456789012)
        self.assertEqual(out["detail"], "webhooks are fine")
        self.assertEqual(out["nested"], [redact.MASK, 5])

    def test_save_state_scrubs(self):
        p = os.path.join(self.dir, "s.json")
        save_state(p, {"error": BOOM, "n": 7})
        with open(p) as f:
            raw = f.read()
        self.assertClean(raw)
        self.assertEqual(json.loads(raw)["n"], 7)


class OutputPointTests(Base):
    """Each output function scrubs on its own, so no single layer is load-bearing."""

    def setUp(self):
        super().setUp()
        redact.register(TOKEN)
        for u in (DISCORD, WEBHOOK, RPC, WS, USERINFO):
            redact.register_url(u)
        self.alert = {"severity": "high", "kind": "k", "subject": "s", "detail": BOOM}

    def test_stdout(self):
        from watchtower.alerts import emit_stdout
        for as_json in (False, True):
            out = io.StringIO()
            emit_stdout([self.alert], as_json=as_json, stream=out)
            self.assertClean(out.getvalue())

    def test_stderr(self):
        from watchtower.cli import _err
        with mock.patch("sys.stderr", io.StringIO()) as err:
            _err(BOOM)
        self.assertClean(err.getvalue())

    def test_stream_log(self):
        from watchtower.stream import StreamWatcher
        got = []
        w = StreamWatcher({"wallets": [], "mints": [], "programs": [], "squads": []}, None, "x", "wss://x", None, None,
                          log=got.append)
        w.log(BOOM)
        self.assertClean(*got)

    def test_chat_sink_body(self):
        cap = Capture()
        TelegramSink(TOKEN, "-100123", opener=cap, sleep=lambda s: None).deliver([self.alert])
        self.assertClean(*cap.bodies)

    def test_webhook_body(self):
        from watchtower import alerts
        cap = Capture()
        alerts.post_webhook(WEBHOOK, [self.alert], opener=cap)
        self.assertClean(*cap.bodies)

    def test_ws_url_registered_on_connect(self):
        from watchtower import ws

        def refuse(addr, timeout):
            raise ConnectionRefusedError()
        with self.assertRaises(WsError):
            ws.connect("wss://ws9.example.com/k/WsOnlyPathKey9a8b7c?x=1", sock_factory=refuse)
        self.assertNotIn("WsOnlyPathKey9a8b7c", redact.scrub("bare WsOnlyPathKey9a8b7c"))


class IdentifierSafetyTests(Base):
    """Round-5 findings 2 and 3: redaction never hides or rewrites a public on-chain identifier."""

    def test_rpc_url_path_equal_to_watched_pubkey_and_nonce(self):
        nonce = NONCE_ACCOUNTS[0]
        url = f"https://rpc.example.com/{NONCE_AUTH}/{nonce}?api-key=KeyBesideIds123"
        RpcClient(url)  # registers, as the CLI does
        text = f"durable nonce account {nonce} with authority {NONCE_AUTH}; fetched from {url}"
        out = redact.scrub(text)
        self.assertIn(f"account {nonce} with authority {NONCE_AUTH};", out)
        self.assertNotIn("KeyBesideIds123", out)
        self.assertIn("https://rpc.example.com/<redacted>", out)
        # Through a real cycle: the alert and the state file keep both identities.
        cfg = load_config(self.cfg_path)
        with mock.patch("sys.stderr", io.StringIO()):
            alerts = watch_cycle(cfg, RpcClient(url, transport=FixtureRpc()), cfg["state_file"], None, out=io.StringIO())
        self.assertIn(nonce, {a["subject"] for a in alerts})
        with open(cfg["state_file"]) as f:
            state = json.load(f)
        self.assertIn(nonce, state["snapshot"]["nonces"])
        self.assertEqual(state["snapshot"]["nonces"][nonce]["authority"], NONCE_AUTH)
        self.assertIn(f"nonces:{NONCE_AUTH}", state["snapshot"]["coverage"])

    def test_identifiers_never_masked_outside_a_url(self):
        sig = "3BxRHV8L9rAE79jTxUdcSYY45wiiYy8p2qnn9nkphKRd6CWEoAL6W6he3r4DwdacJU1pHt14qHceV2Gmr5ySckBp"
        redact.register(NONCE_AUTH, sig)  # even if someone registers them, they are refused as bare secrets
        out = redact.scrub(f"authority {NONCE_AUTH} sig {sig}")
        self.assertIn(NONCE_AUTH, out)
        self.assertIn(sig, out)

    def test_fragment_inside_an_address_is_not_replaced(self):
        redact.register("ynC3HALoSt")  # a credential that happens to be a substring of an address
        self.assertIn(NONCE_AUTH, redact.scrub(f"wallet {NONCE_AUTH}"))
        self.assertNotIn("ynC3HALoSt", redact.scrub("key ynC3HALoSt here"))

    def test_state_keys_are_never_rewritten(self):
        redact.register("ZZsecretKey9")
        obj = {NONCE_AUTH: {"x": 1}, "ZZsecretKey9": 2, "detail": "ZZsecretKey9"}
        out = redact.scrub_obj(obj)
        self.assertIn(NONCE_AUTH, out)
        self.assertIn("ZZsecretKey9", out)  # keys are identities: never rewritten by literal masking
        self.assertEqual(out["detail"], redact.MASK)  # values still are

    def test_token_and_auth_keep_an_address_but_mask_secrets(self):
        out = redact.scrub(f"token={NONCE_AUTH} auth={NONCE_AUTH}")
        self.assertEqual(out.count(NONCE_AUTH), 2)
        for kv in ("token=Sup3rSecretV4lue", "auth=hunter22hunter", "TOKEN=Sup3rSecretV4lue", "x?auth=hunter22hunter&y"):
            out = redact.scrub(kv)
            self.assertNotIn("Sup3rSecretV4lue", out)
            self.assertNotIn("hunter22hunter", out)

    def test_explicit_credential_keys_mask_identifier_shaped_values(self):
        # Round-6 finding: some providers issue keys shaped like a base58 address or signature.
        sig = "3BxRHV8L9rAE79jTxUdcSYY45wiiYy8p2qnn9nkphKRd6CWEoAL6W6he3r4DwdacJU1pHt14qHceV2Gmr5ySckBp"
        self.assertTrue(redact.is_chain_identifier(NONCE_AUTH) and redact.is_chain_identifier(sig))
        for key, val in (("api_key", NONCE_AUTH), ("apikey", NONCE_AUTH), ("api-key", NONCE_AUTH), ("x-api-key", NONCE_AUTH),
                         ("access_token", NONCE_AUTH), ("auth_token", NONCE_AUTH), ("client_secret", NONCE_AUTH),
                         ("secret", sig), ("password", sig), ("passwd", NONCE_AUTH), ("private" + "_key", sig),
                         ("API_KEY", NONCE_AUTH)):
            out = redact.scrub(f"failed with {key}={val} at slot 5")
            self.assertNotIn(val, out, key)
            self.assertIn(f"{key}={redact.MASK}", out)

    def test_credential_field_forms_through_exc_text(self):
        # Round-7 counterexamples: quoted, JSON, colon, HTTP auth headers; through the real exc_text() path.
        sec = "Pr0viderS3cretValue"
        forms = [f'api_key="{sec}"', f"api_key='{sec}'", f'{{"api_key": "{sec}"}}', f"api_key: {sec}",
                 f"Authorization: Bearer {sec}", f"Authorization: Basic {sec}", f"Authorization: Token {sec}",
                 f'"Authorization": "Bearer {sec}"', f"Bearer {sec}", f'{{"password":"{sec}"}}', f"client_secret = {sec}",
                 f'{{"secret": "{NONCE_AUTH}"}}', f"token: {sec}", f'{{"auth": "{sec}"}}', f"TOKEN='{sec}'"]
        for f in forms:
            out = redact.exc_text(RuntimeError(f"request failed: {f}"))
            self.assertNotIn(sec, out, f)
            if "secret" in f and NONCE_AUTH in f:
                self.assertNotIn(NONCE_AUTH, out, f)  # explicit credential key: masked whatever its shape

    def test_scrub_obj_masks_values_under_credential_keys_only(self):
        sec = "Pr0viderS3cretValue"
        obj = {"api_key": sec, "Authorization": f"Bearer {sec}", "nested": [{"password": 1234, "token": sec}],
               "token": NONCE_AUTH, NONCE_AUTH: {"authority": NONCE_AUTH, "mint": NONCE_AUTH}}
        out = redact.scrub_obj(obj)
        self.assertNotIn(sec, json.dumps(out))
        self.assertEqual(out["nested"][0]["password"], redact.MASK)
        self.assertEqual(out["token"], NONCE_AUTH)  # ambiguous key, identifier value: kept
        self.assertEqual(out[NONCE_AUTH], {"authority": NONCE_AUTH, "mint": NONCE_AUTH})  # address KEY untouched

    def test_identifier_fields_stay_intact(self):
        for t in (f'{{"authority": "{NONCE_AUTH}"}}', f'"mint": "{NONCE_AUTH}"', f"token: {NONCE_AUTH}",
                  f'auth="{NONCE_AUTH}"', f"close authority {NONCE_AUTH}", "token account for mint X is frozen",
                  "Token-2022 permanent delegate", "the bearer of bad news"):
            self.assertEqual(redact.scrub(t), t)

    def test_alert_test_status_line_is_scrubbed(self):
        class Leaky:
            name = "leaky"

            def deliver(self, alerts, stamp=None):
                return False, f"leaky -> failed at {RPC}", []
        with mock.patch.dict(os.environ, self.env), mock.patch("watchtower.cli.build_sinks", lambda *a, **k: [Leaky()]), \
                mock.patch("sys.stdout", io.StringIO()) as out:
            main(["alert-test", "--config", self.cfg_path])
        self.assertIn("leaky: FAILED", out.getvalue())
        self.assertClean(out.getvalue())


class WatchPathTests(Base):
    def run_watch(self, exc):
        cap = Capture()
        with mock.patch.dict(os.environ, self.env), mock.patch.object(urllib.request, "urlopen", cap), \
                mock.patch("watchtower.cli.watch_cycle", side_effect=exc), \
                mock.patch("sys.stdout", io.StringIO()) as out, mock.patch("sys.stderr", io.StringIO()) as err:
            code = main(["watch", "--config", self.cfg_path, "--once"])
        return code, out.getvalue(), err.getvalue(), cap.bodies

    def test_injected_exception_with_every_secret(self):
        code, out, err, bodies = self.run_watch(RuntimeError(BOOM))
        self.assertEqual(code, 2)
        self.assertIn("scan_failed", out)
        self.assertEqual(len(bodies), 3)  # telegram, discord, webhook all got the scan_failed alert
        self.assertClean(out, err, *bodies)

    def test_alert_dicts_handed_to_sinks_are_clean(self):
        got = []

        class Rec:
            name = "rec"

            def deliver(self, alerts, stamp=None):
                got.append(json.dumps(alerts))
                return True, "ok", list(alerts)
        with mock.patch.dict(os.environ, self.env), mock.patch("watchtower.cli.build_sinks", lambda *a, **k: [Rec()]), \
                mock.patch("watchtower.cli.watch_cycle", side_effect=RuntimeError(BOOM)), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            main(["watch", "--config", self.cfg_path, "--once"])
        self.assertTrue(got)
        self.assertClean(*got)

    def test_rpc_error_with_keyed_url_never_leaks_through_scan_failed(self):
        exc = RpcError("getProgramAccounts", -32000, f"upstream {RPC} rejected the request")
        code, out, err, bodies = self.run_watch(exc)
        self.assertEqual(code, 2)
        self.assertTrue(bodies)
        self.assertClean(out, err, *bodies)
        self.assertIn("rpc.example.com", out)

    def test_error_text_in_report_never_reaches_state_or_stdout(self):
        # A provenance lookup failure stores its error text in the snapshot (state file) and the alert detail.
        redact.register_url(RPC)
        exc = RpcError("getSignaturesForAddress", -32000, f"proxy {RPC} said no; token {TOKEN}")
        rpc = FixtureRpc(overrides={("getSignaturesForAddress", a): exc for a in NONCE_ACCOUNTS})
        cfg = load_config(self.cfg_path)
        rec = []

        class Sink:
            name = "rec"

            def deliver(self, alerts, stamp=None):
                rec.append(json.dumps(alerts))
                return True, "ok", list(alerts)
        out = io.StringIO()
        with mock.patch("sys.stderr", io.StringIO()) as err:
            watch_cycle(cfg, RpcClient(transport=rpc), cfg["state_file"], None, out=out, sinks=[Sink()])
        with open(cfg["state_file"]) as f:
            state = f.read()
        self.assertIn("unavailable", state)
        self.assertClean(state, out.getvalue(), err.getvalue())


class StreamPathTests(Base):
    def test_injected_exception_with_every_secret(self):
        cap = Capture()
        hooks = []
        sinks = [TelegramSink(TOKEN, "-100123", opener=cap, sleep=lambda s: None),
                 DiscordSink(DISCORD, opener=cap, sleep=lambda s: None),
                 WebhookSink(WEBHOOK, post=lambda url, al: hooks.append(json.dumps(al)) or (True, "ok"))]
        h = Harness(self, [], sinks=sinks, rpc_url=RPC, fail_exc=RuntimeError(BOOM), resync_interval=60.0)
        h.fail_next = 2
        h.conns = [FakeConn(h.clock, ticks(40) + [h.stop] + ticks(2))]
        h.run()
        with open(h.cfg["state_file"]) as f:
            state = f.read()
        self.assertTrue(any("scan_failed" in b for b in cap.bodies))
        self.assertTrue(any("stream_gap" in b for b in hooks))  # the gap (whose reason held the text) was delivered
        self.assertClean(h.out.getvalue(), "\n".join(h.logs), state, *cap.bodies, *hooks)
        for batch in h.alerts:
            self.assertClean(json.dumps(batch))

    def test_ws_error_with_secret_url_never_leaks(self):
        cap = Capture()
        sinks = [TelegramSink(TOKEN, "-100123", opener=cap, sleep=lambda s: None)]
        h = Harness(self, [WsError(f"cannot connect to {WS} ({USERINFO})")], sinks=sinks, rpc_url=RPC)
        h.conns.append(FakeConn(h.clock, ticks(2) + [h.stop] + ticks(2)))
        h.run()
        with open(h.cfg["state_file"]) as f:
            state = f.read()
        self.assertTrue(any("stream_gap" in b for b in cap.bodies))
        self.assertClean(h.out.getvalue(), "\n".join(h.logs), state, *cap.bodies)
        for batch in h.alerts:  # the alert dicts themselves, as any sink receives them
            self.assertClean(json.dumps(batch))

    def test_rpc_error_with_keyed_url_never_leaks_through_scan_failed(self):
        cap = Capture()
        sinks = [DiscordSink(DISCORD, opener=cap, sleep=lambda s: None)]
        exc = RpcError("getProgramAccounts", -32000, f"upstream {RPC} rejected the request")
        h = Harness(self, [], sinks=sinks, rpc_url=RPC, fail_exc=exc)
        h.fail_next = 1
        h.conns = [FakeConn(h.clock, ticks(10) + [h.stop] + ticks(2))]
        h.run()
        self.assertTrue(any("scan_failed" in b for b in cap.bodies))
        self.assertClean(h.out.getvalue(), "\n".join(h.logs), *cap.bodies)


class UncaughtTests(Base):
    def test_unexpected_crash_prints_no_traceback_secret(self):
        with mock.patch.dict(os.environ, self.env), \
                mock.patch("watchtower.cli.cmd_watch", side_effect=RuntimeError(BOOM)), \
                mock.patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(main(["watch", "--config", self.cfg_path, "--once"]), 70)
        self.assertIn("internal error", err.getvalue())
        self.assertClean(err.getvalue())


if __name__ == "__main__":
    unittest.main()
