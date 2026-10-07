"""Native alerts: Telegram, Discord, dedup, retry, queueing, secret hygiene. Offline: HTTP is mocked."""

import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

from watchtower import notify
from watchtower.cli import main, watch_cycle
from watchtower.config import ConfigError, load_config
from watchtower.notify import DiscordSink, SinkConfigError, TelegramSink, WebhookSink, build_sinks, deliver_all, dedup_key
from watchtower.rpc import RpcClient

from .helpers import NONCE_AUTH, USDC, FixtureRpc

TOKEN = "123456789:AAHsecretSECRETsecretSECRETsecret_xyz"
CHAT = "-1001234567890"
DISCORD = "https://discord.com/api/webhooks/1234567890/DiscordSecretTokenValue_abcdef"


def alert(i=0, sev="high", kind="new_delegate", at="2026-10-06T00:00:00+00:00", **kw):
    a = {"severity": sev, "kind": kind, "subject": f"Acct{i}", "detail": f"detail {i}", "at": at}
    a.update(kw)
    return a


class Resp:
    def __init__(self, status=200, body=b'{"ok": true}'):
        self.status = status
        self._body = body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(url, code, body=b"{}", headers=None):
    return urllib.error.HTTPError(url, code, "err", headers or {}, io.BytesIO(body))


class Opener:
    """Scripted urlopen: each entry is a Resp, an exception, or a callable(req) -> Resp."""

    def __init__(self, *script, default=None):
        self.script = list(script)
        self.default = default
        self.requests = []

    def __call__(self, req, timeout):
        self.requests.append(req)
        item = self.script.pop(0) if self.script else (self.default or Resp())
        if callable(item) and not isinstance(item, Resp):
            item = item(req)
        if isinstance(item, BaseException):
            raise item
        return item


def tg(opener, **kw):
    return TelegramSink(TOKEN, CHAT, opener=opener, sleep=kw.pop("sleep", lambda s: None), **kw)


def dc(opener, **kw):
    return DiscordSink(DISCORD, opener=opener, sleep=kw.pop("sleep", lambda s: None), **kw)


class TelegramTests(unittest.TestCase):
    def test_request_shape(self):
        op = Opener(Resp())
        ok, msg, sent = tg(op).deliver([alert(1, sev="critical", kind="new_nonce_account")])
        self.assertTrue(ok)
        self.assertEqual(len(sent), 1)
        req = op.requests[0]
        self.assertEqual(req.full_url, f"https://api.telegram.org/bot{TOKEN}/sendMessage")
        body = json.loads(req.data)
        self.assertEqual(body["chat_id"], CHAT)
        self.assertIn("CRIT new_nonce_account", body["text"])
        self.assertNotIn("parse_mode", body)  # plain text: on-chain strings cannot inject markup

    def test_ok_false_is_a_failure(self):
        ok, msg, sent = tg(Opener(Resp(200, b'{"ok": false, "description": "chat not found"}'))).deliver([alert()])
        self.assertFalse(ok)
        self.assertEqual(sent, [])
        self.assertIn("chat not found", msg)

    def test_transient_errors_are_retried(self):
        sleeps = []
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        op = Opener(http_error(url, 502), urllib.error.URLError(TimeoutError()), Resp())
        ok, msg, sent = tg(op, sleep=sleeps.append).deliver([alert()])
        self.assertTrue(ok)
        self.assertEqual(len(op.requests), 3)
        self.assertEqual(sleeps, [1, 2])

    def test_429_retry_after_is_honoured(self):
        sleeps = []
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        op = Opener(http_error(url, 429, b'{"ok": false, "parameters": {"retry_after": 7}}'), Resp())
        ok, _, _ = tg(op, sleep=sleeps.append).deliver([alert()])
        self.assertTrue(ok)
        self.assertEqual(sleeps, [7.0])

    def test_auth_error_is_not_retried_and_says_why(self):
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        op = Opener(http_error(url, 401))
        ok, msg, _ = tg(op).deliver([alert()])
        self.assertFalse(ok)
        self.assertEqual(len(op.requests), 1)
        self.assertIn("401", msg)
        self.assertIn("token rejected", msg)

    def test_gives_up_after_attempts(self):
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        op = Opener(*[http_error(url, 503) for _ in range(5)])
        ok, msg, _ = tg(op).deliver([alert()])
        self.assertFalse(ok)
        self.assertEqual(len(op.requests), 3)
        self.assertIn("after 3 attempts", msg)

    def test_token_never_in_messages_or_repr(self):
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        cases = [http_error(url, 401), http_error(url, 500), urllib.error.URLError(OSError(f"cannot reach {url}")),
                 Resp(200, json.dumps({"ok": False, "description": f"echo {TOKEN}"}).encode())]
        for c in cases:
            s = tg(Opener(c, c, c))
            ok, msg, _ = s.deliver([alert()])
            self.assertFalse(ok)
            self.assertNotIn(TOKEN, msg)
            self.assertNotIn(TOKEN.split(":")[1], msg)
            self.assertNotIn(TOKEN, repr(s))

    def test_malformed_config_fails_loud(self):
        with self.assertRaises(SinkConfigError):
            TelegramSink("not-a-token", CHAT)
        with self.assertRaises(SinkConfigError):
            TelegramSink(TOKEN, "chat; DROP")
        try:
            TelegramSink(TOKEN[:-1] + "!", CHAT)
        except SinkConfigError as e:
            self.assertNotIn(TOKEN[:20], str(e))


class TelegramThreadTests(unittest.TestCase):
    """Forum topics: message_thread_id on every Telegram message."""

    ENV = {"WATCHTOWER_TELEGRAM_BOT_TOKEN": TOKEN, "WATCHTOWER_TELEGRAM_CHAT_ID": CHAT, "WATCHTOWER_TELEGRAM_THREAD_ID": "42"}

    def cfg(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "wallets.toml")
        with open(p, "w") as f:
            f.write(f'[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        return p, load_config(p)

    def test_thread_id_on_every_message_including_split_ones(self):
        op = Opener(default=Resp())
        s = TelegramSink(TOKEN, CHAT, thread_id="42", opener=op, sleep=lambda s: None)
        ok, _, _ = s.deliver([alert(i, detail="t" * 900) for i in range(12)])
        self.assertTrue(ok)
        self.assertGreater(len(op.requests), 1)
        self.assertTrue(all(json.loads(r.data)["message_thread_id"] == 42 for r in op.requests))

    def test_no_thread_id_unless_set(self):
        op = Opener(default=Resp())
        TelegramSink(TOKEN, CHAT, opener=op, sleep=lambda s: None).deliver([alert()])
        self.assertNotIn("message_thread_id", json.loads(op.requests[0].data))

    def test_thread_id_validated(self):
        for bad in ("0", "-3", "abc", "4.2", "1e3", "\u0663", "99999999999999999999"):
            with self.assertRaises(SinkConfigError, msg=bad):
                TelegramSink(TOKEN, CHAT, thread_id=bad)
        _, cfg = self.cfg()
        with self.assertRaises(SinkConfigError):
            build_sinks(cfg, {**self.ENV, "WATCHTOWER_TELEGRAM_THREAD_ID": "-1"})
        with self.assertRaises(SinkConfigError):  # a topic without a bot is a half-configured sink
            build_sinks(cfg, {"WATCHTOWER_TELEGRAM_THREAD_ID": "42"})

    def test_thread_id_from_env_reaches_direct_scan_failed_and_alert_test(self):
        _, cfg = self.cfg()
        op = Opener(default=Resp())
        sinks = build_sinks(cfg, self.ENV, opener=op, sleep=lambda s: None)
        notify.deliver_direct(sinks, [alert(kind="scan_failed")], T0)
        self.assertEqual(json.loads(op.requests[-1].data)["message_thread_id"], 42)
        path, _ = self.cfg()
        op2 = Opener(default=Resp())
        with mock.patch.dict(os.environ, self.ENV), mock.patch("watchtower.notify.urllib.request.urlopen", op2), \
                mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(main(["alert-test", "--config", path]), 0)
        body = json.loads(op2.requests[0].data)
        self.assertEqual(body["message_thread_id"], 42)
        self.assertIn("alert_test", body["text"])


class DiscordTests(unittest.TestCase):
    def test_request_shape_and_no_mentions(self):
        op = Opener(Resp(204, b""))
        ok, _, _ = dc(op).deliver([alert(kind="x", detail="@everyone look")])
        self.assertTrue(ok)
        body = json.loads(op.requests[0].data)
        self.assertEqual(body["allowed_mentions"], {"parse": []})
        self.assertLessEqual(len(body["content"]), 2000)
        self.assertEqual(op.requests[0].full_url, DISCORD)

    def test_url_validation(self):
        for bad in ("http://discord.com/api/webhooks/1/x", "https://evil.example.com/api/webhooks/1/x",
                    "https://discord.com/other/1/x"):
            with self.assertRaises(SinkConfigError):
                DiscordSink(bad)

    def test_retry_after_and_secret_hygiene(self):
        sleeps = []
        op = Opener(http_error(DISCORD, 429, b'{"retry_after": 1.5}'), http_error(DISCORD, 404))
        s = dc(op, sleep=sleeps.append)
        ok, msg, _ = s.deliver([alert()])
        self.assertFalse(ok)
        self.assertEqual(sleeps, [1.5])
        self.assertIn("404", msg)
        for secret in ("DiscordSecretTokenValue", "1234567890"):
            self.assertNotIn(secret, msg)
            self.assertNotIn(secret, repr(s))


class ChunkingTests(unittest.TestCase):
    def test_long_batches_split_without_losing_alerts(self):
        op = Opener(default=Resp(204, b""))
        al = [alert(i, detail="x" * 150) for i in range(60)]
        ok, msg, sent = dc(op, max_messages=50).deliver(al)
        self.assertTrue(ok)
        self.assertEqual(len(sent), 60)
        texts = [json.loads(r.data)["content"] for r in op.requests]
        self.assertGreater(len(texts), 1)
        self.assertTrue(all(len(t) <= 2000 for t in texts))
        joined = "\n".join(texts)
        for i in range(60):
            self.assertEqual(joined.count(f" Acct{i}:"), 1)

    def test_cap_counts_real_sends_not_groups(self):
        # Review finding 3: each 3000-char alert is hard-split into 2 Discord messages; a cap of 3 sends
        # allows one alert (2 sends) and holds the rest whole for the next cycle.
        op = Opener(default=Resp(204, b""))
        al = [alert(i, detail="z" * 3000) for i in range(3)]
        ok, msg, sent = dc(op, max_messages=3).deliver(al)
        self.assertTrue(ok)
        self.assertLessEqual(len(op.requests), 3)
        self.assertEqual(len(op.requests), 2)
        self.assertEqual([a["subject"] for a in sent], ["Acct0"])
        self.assertIn("held for the next cycle", msg)

    def test_single_alert_longer_than_the_cap_is_still_sent_whole(self):
        op = Opener(default=Resp(204, b""))
        ok, _, sent = dc(op, max_messages=2).deliver([alert(detail="w" * 5000)])
        self.assertTrue(ok)
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(op.requests), 3)

    def test_single_huge_alert_is_split_not_dropped(self):
        op = Opener(default=Resp(204, b""))
        ok, _, sent = dc(op).deliver([alert(detail="y" * 5000)])
        self.assertTrue(ok)
        texts = [json.loads(r.data)["content"] for r in op.requests]
        self.assertTrue(all(len(t) <= 2000 for t in texts))
        self.assertEqual(sum(t.count("y") for t in texts), 5000)

    def test_message_cap_holds_the_rest_for_next_cycle(self):
        op = Opener(default=Resp(204, b""))
        al = [alert(i, detail="x" * 150) for i in range(60)]
        ok, msg, sent = dc(op, max_messages=2).deliver(al)
        self.assertTrue(ok)
        self.assertEqual(len(op.requests), 2)
        self.assertLess(len(sent), 60)
        self.assertIn("or the next cycle", json.loads(op.requests[-1].data)["content"])
        state = {}
        deliver_all([dc(Opener(default=Resp(204, b"")), max_messages=2)], al, state, "2026-10-06T00:00:00+00:00",
                    now=1_791_244_800)
        self.assertEqual(len(state["pending_discord"]), 60 - len(sent))


class Recorder:
    """A sink that records deliveries; `fail` makes it refuse."""

    def __init__(self, name, fail=False, fail_after=None):
        self.name = name
        self.fail = fail
        self.batches = []

    def deliver(self, alerts, stamp=None):
        if self.fail:
            return False, f"{self.name} -> HTTP 503", []
        self.batches.append(list(alerts))
        return True, "ok", list(alerts)

    def sent(self):
        return [a for b in self.batches for a in b]


T0 = "2026-10-06T00:00:00+00:00"
T1 = "2026-10-06T00:05:00+00:00"
T2 = "2026-10-06T02:00:00+00:00"
NOW0 = 1_791_244_800  # 2026-10-06T00:00:00Z


class DedupRetryTests(unittest.TestCase):
    def test_duplicate_suppressed_within_window_and_resent_after(self):
        s, state = Recorder("telegram"), {}
        deliver_all([s], [alert(1, at=T0)], state, T0, dedup_seconds=1800, now=NOW0)
        deliver_all([s], [alert(1, at=T1)], state, T1, dedup_seconds=1800, now=NOW0 + 300)
        self.assertEqual(len(s.sent()), 1)
        deliver_all([s], [alert(1, at=T2)], state, T2, dedup_seconds=1800, now=NOW0 + 7200)
        self.assertEqual(len(s.sent()), 2)

    def test_critical_always_sends(self):
        # Review finding 1: dedup must never swallow a critical alert, even an identical repeat.
        s, state = Recorder("telegram"), {}
        for i in range(3):
            deliver_all([s], [alert(1, sev="critical", kind="multisig_member_added", at=T0)], state, T0, now=NOW0 + i)
        self.assertEqual(len(s.sent()), 3)

    def test_a_b_a_refires_at_every_severity(self):
        # Review finding 1: add X, remove X, re-add X within the window -> the re-add is NOT a duplicate.
        for sev in ("critical", "high", "warn", "medium", "info"):
            s, state = Recorder("discord"), {}
            seq = [alert(1, sev=sev, kind="multisig_member_added", before=None, after="X"),
                   alert(1, sev=sev, kind="multisig_member_removed", before="X", after=None),
                   alert(1, sev=sev, kind="multisig_member_added", before=None, after="X")]
            for i, a in enumerate(seq):
                deliver_all([s], [a], state, T0, now=NOW0 + i)
            self.assertEqual([a["kind"] for a in s.sent()], [a["kind"] for a in seq], sev)

    def test_coverage_flap_refires(self):
        s, state = Recorder("telegram"), {}
        seq = [alert(0, sev="warn", kind="coverage_lost", subject="nonces:K", before="ok", after="unavailable"),
               alert(0, sev="info", kind="coverage_restored", subject="nonces:K", before="unavailable", after="ok"),
               alert(0, sev="warn", kind="coverage_lost", subject="nonces:K", before="ok", after="unavailable")]
        for i, a in enumerate(seq):
            deliver_all([s], [a], state, T0, now=NOW0 + i)
        self.assertEqual(len(s.sent()), 3)

    def test_a_b_a_inside_one_batch_refires(self):
        s, state = Recorder("telegram"), {}
        deliver_all([s], [alert(1, kind="x"), alert(1, kind="y"), alert(1, kind="x")], state, T0, now=NOW0)
        self.assertEqual(len(s.sent()), 3)

    def test_changed_content_is_not_a_duplicate(self):
        s, state = Recorder("telegram"), {}
        deliver_all([s], [alert(1, kind="nonce_advanced", before="a", after="b", at=T0)], state, T0, now=NOW0)
        deliver_all([s], [alert(1, kind="nonce_advanced", before="b", after="c", at=T1)], state, T1, now=NOW0 + 60)
        self.assertEqual(len(s.sent()), 2)

    def test_duplicates_inside_one_batch_collapse(self):
        s, state = Recorder("discord"), {}
        deliver_all([s], [alert(1), alert(1)], state, T0, now=NOW0)
        self.assertEqual(len(s.sent()), 1)

    def test_dedup_key_ignores_timestamp_only(self):
        self.assertEqual(dedup_key(alert(1, at=T0)), dedup_key(alert(1, at=T1)))
        self.assertNotEqual(dedup_key(alert(1)), dedup_key(alert(2)))

    def test_failed_sink_queues_others_unaffected_and_failure_surfaced(self):
        bad, good, state = Recorder("telegram", fail=True), Recorder("discord"), {}
        failures, _, _ = deliver_all([bad, good], [alert(1), alert(2)], state, T0, now=NOW0)
        self.assertEqual(len(failures), 1)
        self.assertIn("telegram", failures[0])
        self.assertEqual(len(state["pending_telegram"]), 2)
        self.assertEqual(state["pending_discord"], [])
        kinds = [a["kind"] for a in good.sent()]
        self.assertEqual(kinds.count("new_delegate"), 2)
        self.assertEqual(kinds.count("alert_delivery_failed"), 1)  # surfaced through the working sink
        # Next cycle telegram recovers: the queue is flushed, discord gets nothing twice.
        bad.fail = False
        failures, _, _ = deliver_all([bad, good], [], state, T1, now=NOW0 + 300)
        self.assertEqual(failures, [])
        self.assertEqual(sorted(a["subject"] for a in bad.sent()), ["Acct1", "Acct2"])
        self.assertEqual(state["pending_telegram"], [])
        # Cycle 1: the alerts, then the failure notice. Cycle 2: nothing new for discord.
        self.assertEqual([len(b) for b in good.batches], [2, 1, 0])

    def test_repeated_failure_notice_is_deduplicated(self):
        bad, good, state = Recorder("telegram", fail=True), Recorder("discord"), {}
        for i in range(3):
            deliver_all([bad, good], [alert(i)], state, T0, now=NOW0 + i)
        self.assertEqual([a["kind"] for a in good.sent()].count("alert_delivery_failed"), 1)
        self.assertEqual(len(state["pending_telegram"]), 3)

    def test_mid_batch_failure_requeues_only_unsent(self):
        url = DISCORD
        op = Opener(Resp(204, b""), *[http_error(url, 500)] * 3)
        s = dc(op, max_messages=10)
        al = [alert(i, detail="x" * 150) for i in range(30)]
        state = {}
        failures, _, _ = deliver_all([s], al, state, T0, now=NOW0)
        self.assertEqual(len(failures), 1)
        first = json.loads(op.requests[0].data)["content"]
        sent_n = sum(1 for i in range(30) if f" Acct{i}:" in first)
        self.assertGreater(sent_n, 0)
        self.assertEqual(len(state["pending_discord"]), 30 - sent_n)
        self.assertEqual({a["subject"] for a in state["pending_discord"]} & {f"Acct{i}" for i in range(sent_n)}, set())


class OverflowTests(unittest.TestCase):
    """Round-2 finding 2: a full queue must never lose an alert silently."""

    def test_overflow_replaced_by_persistent_alert_and_reported(self):
        bad, state = Recorder("telegram", fail=True), {}
        al = [alert(i, at=f"2026-10-06T00:{i // 60:02d}:{i % 60:02d}+00:00") for i in range(501)]
        failures, _, _ = deliver_all([bad], al, state, T0, now=NOW0)
        q = state["pending_telegram"]
        self.assertEqual(q[0]["kind"], "alert_queue_overflow")
        self.assertEqual(q[0]["dropped"], 1)
        self.assertEqual(q[0]["oldest_dropped"], al[0]["at"])
        self.assertEqual(len(q), 501)  # 500 kept + the overflow record
        self.assertNotIn("Acct0", {a["subject"] for a in q[1:]})
        self.assertTrue(any("DROPPED" in f for f in failures))

    def test_overflow_record_merges_and_is_never_trimmed(self):
        bad, state = Recorder("telegram", fail=True), {}
        deliver_all([bad], [alert(i) for i in range(510)], state, T0, now=NOW0)
        deliver_all([bad], [alert(1000 + i) for i in range(20)], state, T1, now=NOW0 + 1)
        q = state["pending_telegram"]
        self.assertEqual([a["kind"] for a in q].count("alert_queue_overflow"), 1)
        self.assertEqual(q[0]["dropped"], 30)
        self.assertEqual(len(q), 501)
        # Delivered first once the sink recovers.
        bad.fail = False
        deliver_all([bad], [], state, T2, now=NOW0 + 2)
        self.assertEqual(bad.sent()[0]["kind"], "alert_queue_overflow")

    def test_critical_alerts_are_kept_over_non_critical(self):
        bad, state = Recorder("telegram", fail=True), {}
        al = [alert(0, sev="critical", kind="multisig_member_added")] + [alert(i) for i in range(1, 505)]
        deliver_all([bad], al, state, T0, now=NOW0)
        q = state["pending_telegram"]
        self.assertIn(("Acct0", "critical"), {(a["subject"], a["severity"]) for a in q})
        self.assertEqual(q[0]["severity"], "high")  # no critical alert was dropped
        al2 = [alert(i, sev="critical", kind="c") for i in range(600)]
        state2 = {}
        deliver_all([bad], al2, state2, T0, now=NOW0)
        self.assertEqual(state2["pending_telegram"][0]["severity"], "critical")  # critical ones had to go: says so

    def test_watch_once_exits_2_and_says_dropped_on_overflow(self):
        d = tempfile.mkdtemp()
        cfg_path = os.path.join(d, "wallets.toml")
        with open(cfg_path, "w") as f:
            f.write(f'[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        op = Opener(default=Resp())

        def fake_build(cfg, environ, **kw):
            s = TelegramSink(TOKEN, CHAT, opener=op, sleep=lambda s: None, max_messages=1)
            s.limit = 600
            return [s]

        with mock.patch.object(notify, "MAX_PENDING", 2), mock.patch("watchtower.cli.build_sinks", fake_build), \
                mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc())), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()) as err:
            code = main(["watch", "--config", cfg_path, "--once"])
        self.assertEqual(code, 2)
        self.assertIn("DROPPED", err.getvalue())
        with open(os.path.join(d, "wallets.state.json")) as f:
            self.assertEqual(json.load(f)["pending_telegram"][0]["kind"], "alert_queue_overflow")


class CycleFailureTests(unittest.TestCase):
    """Round-2 finding 1 (watch mode): a failed cycle reaches the sinks, not only stderr."""

    def test_failed_cycle_alerts_sinks_directly_and_exits_2(self):
        d = tempfile.mkdtemp()
        cfg_path = os.path.join(d, "wallets.toml")
        with open(cfg_path, "w") as f:
            f.write(f'[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        rec = Recorder("discord")
        with mock.patch("watchtower.cli.build_sinks", lambda *a, **k: [rec]), \
                mock.patch("watchtower.cli.watch_cycle", side_effect=OSError("No space left on device")), \
                mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc())), \
                mock.patch("sys.stdout", io.StringIO()) as out, mock.patch("sys.stderr", io.StringIO()):
            code = main(["watch", "--config", cfg_path, "--once"])
        self.assertEqual(code, 2)
        self.assertEqual([a["kind"] for a in rec.sent()], ["scan_failed"])
        self.assertIn("No space left", rec.sent()[0]["detail"])
        self.assertIn("scan_failed", out.getvalue())


class WatchRealertTests(unittest.TestCase):
    def test_long_watch_outage_alerts_every_cycle_not_once(self):
        d = tempfile.mkdtemp()
        cfg_path = os.path.join(d, "wallets.toml")
        with open(cfg_path, "w") as f:
            f.write(f'[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        rec, sleeps = Recorder("discord"), []

        def fake_sleep(s):
            sleeps.append(s)
            if len(sleeps) >= 4:
                raise KeyboardInterrupt

        with mock.patch("watchtower.cli.build_sinks", lambda *a, **k: [rec]), \
                mock.patch("watchtower.cli.watch_cycle", side_effect=OSError("No space left on device")), \
                mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc())), \
                mock.patch("watchtower.cli.time.sleep", fake_sleep), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(["watch", "--config", cfg_path, "--interval", "300"]), 0)
        got = [a for a in rec.sent() if a["kind"] == "scan_failed"]
        self.assertEqual(len(got), 4)  # one per failed cycle = at least one per --interval
        self.assertIn("STILL FAILING", got[-1]["detail"])
        self.assertEqual(len({a["before"] for a in got}), 1)  # same gap start: one open gap throughout


class ConfigAndCliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg_path = os.path.join(self.dir, "wallets.toml")
        with open(self.cfg_path, "w") as f:
            f.write(f'mints = ["{USDC}"]\n\n[[wallets]]\nlabel = "council-1"\npubkey = "{NONCE_AUTH}"\n')
        self.cfg = load_config(self.cfg_path)

    def write(self, body):
        p = os.path.join(self.dir, "c.toml")
        with open(p, "w") as f:
            f.write(body + f'\n[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        return p

    def test_inline_secrets_refused(self):
        for k in ("telegram_bot_token", "discord_webhook_url", "ws_url"):
            with self.assertRaises(ConfigError) as cm:
                load_config(self.write(f'{k} = "x"'))
            self.assertNotIn('"x"', str(cm.exception))
        with self.assertRaises(ConfigError):
            load_config(self.write("alert_dedup_seconds = -1"))
        cfg = load_config(self.write('telegram_chat_id = -100123\ntelegram_bot_token_env = "MY_TOKEN"'))
        self.assertEqual(cfg["telegram_chat_id"], "-100123")
        self.assertEqual(cfg["telegram_bot_token_env"], "MY_TOKEN")

    def test_half_configured_telegram_is_an_error(self):
        with self.assertRaises(SinkConfigError):
            build_sinks(self.cfg, {"WATCHTOWER_TELEGRAM_BOT_TOKEN": TOKEN})
        with self.assertRaises(SinkConfigError):
            build_sinks(self.cfg, {"WATCHTOWER_TELEGRAM_CHAT_ID": CHAT})
        sinks = build_sinks(self.cfg, {"WATCHTOWER_TELEGRAM_BOT_TOKEN": TOKEN, "WATCHTOWER_TELEGRAM_CHAT_ID": CHAT,
                                       "WATCHTOWER_DISCORD_WEBHOOK_URL": DISCORD})
        self.assertEqual([s.name for s in sinks], ["telegram", "discord"])
        self.assertEqual(build_sinks(self.cfg, {}), [])

    def test_watch_cycle_delivers_natively_and_state_has_no_secret(self):
        op = Opener(default=Resp())
        sinks = [TelegramSink(TOKEN, CHAT, opener=op, sleep=lambda s: None)]
        client = RpcClient(transport=FixtureRpc())
        with mock.patch("sys.stderr", io.StringIO()) as err:
            a1 = watch_cycle(self.cfg, client, self.cfg["state_file"], None, out=io.StringIO(), sinks=sinks)
        self.assertTrue(a1)
        self.assertGreaterEqual(len(op.requests), 1)
        text = "\n".join(json.loads(r.data)["text"] for r in op.requests)
        self.assertIn("existing_nonce_account", text)
        with open(self.cfg["state_file"]) as f:
            raw = f.read()
        self.assertNotIn(TOKEN, raw)
        self.assertNotIn(TOKEN, err.getvalue())
        self.assertEqual(json.loads(raw)["pending_telegram"], [])

    def test_watch_once_exit_2_and_loud_on_delivery_failure(self):
        env = {"WATCHTOWER_TELEGRAM_BOT_TOKEN": TOKEN, "WATCHTOWER_TELEGRAM_CHAT_ID": CHAT}
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        op = Opener(*[http_error(url, 401)] * 3)

        def fake_build(cfg, environ, **kw):
            return [TelegramSink(TOKEN, CHAT, opener=op, sleep=lambda s: None)]

        with mock.patch.dict(os.environ, env), mock.patch("watchtower.cli.build_sinks", fake_build), \
                mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc())), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()) as err:
            code = main(["watch", "--config", self.cfg_path, "--once"])
        self.assertEqual(code, 2)
        self.assertIn("ALERT DELIVERY FAILED", err.getvalue())
        self.assertNotIn(TOKEN, err.getvalue())
        with open(self.cfg["state_file"]) as f:
            self.assertTrue(json.load(f)["pending_telegram"])

    def test_watch_once_exit_2_when_message_cap_holds_alerts(self):
        # Review finding 2: alerts held "for the next cycle" in a one-shot run must not be a silent success.
        op = Opener(default=Resp())

        def fake_build(cfg, environ, **kw):
            s = TelegramSink(TOKEN, CHAT, opener=op, sleep=lambda s: None, max_messages=1)
            s.limit = 600
            return [s]

        with mock.patch("watchtower.cli.build_sinks", fake_build), \
                mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc())), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()) as err:
            code = main(["watch", "--config", self.cfg_path, "--once"])
        self.assertEqual(code, 2)
        self.assertEqual(len(op.requests), 1)
        self.assertIn("ALERTS NOT YET DELIVERED", err.getvalue())
        with open(self.cfg["state_file"]) as f:
            self.assertTrue(json.load(f)["pending_telegram"])

    def test_watch_once_exit_0_when_delivered(self):
        op = Opener(default=Resp())

        def fake_build(cfg, environ, **kw):
            return [TelegramSink(TOKEN, CHAT, opener=op, sleep=lambda s: None)]

        with mock.patch("watchtower.cli.build_sinks", fake_build), \
                mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc())), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(["watch", "--config", self.cfg_path, "--once"]), 0)

    def test_half_configured_sink_is_usage_error(self):
        with mock.patch.dict(os.environ, {"WATCHTOWER_TELEGRAM_BOT_TOKEN": TOKEN}, clear=False), \
                mock.patch("sys.stderr", io.StringIO()) as err:
            os.environ.pop("WATCHTOWER_TELEGRAM_CHAT_ID", None)
            self.assertEqual(main(["watch", "--config", self.cfg_path, "--once"]), 64)
        self.assertIn("half-configured", err.getvalue())
        self.assertNotIn(TOKEN, err.getvalue())

    def test_alert_test_command(self):
        op = Opener(Resp())

        def fake_build(cfg, environ, **kw):
            return [TelegramSink(TOKEN, CHAT, opener=op, sleep=lambda s: None), Recorder("discord", fail=True)]

        with mock.patch("watchtower.cli.build_sinks", fake_build), mock.patch("sys.stdout", io.StringIO()) as out:
            self.assertEqual(main(["alert-test", "--config", self.cfg_path]), 2)
        self.assertIn("telegram: OK", out.getvalue())
        self.assertIn("discord: FAILED", out.getvalue())
        self.assertIn("alert_test", json.loads(op.requests[0].data)["text"])
        with mock.patch("watchtower.cli.build_sinks", lambda *a, **k: []), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(["alert-test", "--config", self.cfg_path]), 64)

    def test_legacy_webhook_sink_still_queues(self):
        s = WebhookSink("https://hooks.example.com/x", post=lambda u, a: (False, "down"))
        state = {}
        failures, _, _ = deliver_all([s], [alert(1)], state, T0, now=NOW0)
        self.assertTrue(failures)
        self.assertEqual(len(state["pending_webhook"]), 1)


if __name__ == "__main__":
    unittest.main()
