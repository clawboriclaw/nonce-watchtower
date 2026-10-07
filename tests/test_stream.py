"""Streaming mode: reconnect/backoff, re-sync after reconnect, loud coverage gaps. Offline: fake clock + fake PubSub."""

import base64
import datetime as dt
import io
import os
import shutil
import tempfile
import unittest
from unittest import mock

from watchtower.cli import main, watch_cycle
from watchtower.config import load_config, load_state
from watchtower.rpc import RpcClient
from watchtower.stream import StreamWatcher, subscription_targets
from watchtower.ws import WsClosed, WsError

from .helpers import JUP, JUP_PD, NONCE_ACCOUNTS, NONCE_AUTH, SQUADS_V4_MS, SQUADS_V4_VAULT0, USDC, FixtureRpc, load

SYS = "11111111111111111111111111111111"
T22 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
EPOCH = dt.datetime(2026, 10, 6, tzinfo=dt.timezone.utc)


class Clock:
    def __init__(self):
        self.t = 1000.0
        self.sleeps = []

    def __call__(self):
        return self.t

    def sleep(self, d):
        self.sleeps.append(d)
        self.t += d

    def now(self):
        return EPOCH + dt.timedelta(seconds=self.t)


class FakeConn:
    """Scripted PubSub. Subscribe requests are answered automatically (sub id = request id + 1000) unless `reject`
    matches. Script items: "tick" (silence for the whole timeout), a dict (message), an exception (raised), or a
    callable(conn) returning a message or None (for side effects)."""

    display = "wss://fake"

    def __init__(self, clock, script=(), reject=lambda method, params: False, answer=True, dead=False):
        self.clock = clock
        self.script = list(script)
        self.reject = reject
        self.answer = answer
        self.dead = dead
        self.inbox = []
        self.requests = []
        self.pings = 0
        self.last_frame_at = clock()
        self.closed = False
        self._id = 0

    def request(self, method, params):
        self._id += 1
        self.requests.append((self._id, method, params))
        if self.answer:
            if self.reject(method, params):
                self.inbox.append({"jsonrpc": "2.0", "id": self._id, "error": {"code": -32601, "message": "not allowed"}})
            else:
                self.inbox.append({"jsonrpc": "2.0", "id": self._id, "result": self._id + 1000})
        return self._id

    def sub_id(self, method, owner, key=None):
        for rid, m, p in self.requests:
            if m == method and p[0] == owner and (key is None or key in str(p[1])):
                return rid + 1000
        raise AssertionError("no such subscription")

    def ping(self):
        self.pings += 1
        if not self.dead:
            self.last_frame_at = self.clock()

    def recv(self, timeout):
        if self.inbox:
            self.last_frame_at = self.clock()
            return self.inbox.pop(0)
        while self.script:
            item = self.script.pop(0)
            if item == "tick":
                self.clock.t += timeout
                return None
            if isinstance(item, BaseException):
                raise item
            if callable(item):
                item = item(self)
                if item is None:
                    continue
            self.last_frame_at = self.clock()
            return item
        raise WsClosed("script ended")

    def close(self):
        self.closed = True


def nonce_notification(sub, pubkey, slot=99):
    entry = load("gpa_nonce_real.json")["result"][0]
    return {"jsonrpc": "2.0", "method": "programNotification",
            "params": {"subscription": sub, "result": {"context": {"slot": slot},
                                                       "value": {"pubkey": pubkey, "account": entry["account"]}}}}


class Harness:
    def __init__(self, test, conns, rpc=None, cfg_body=None, prev_state=None, rpc_url=None, fail_exc=None, **kw):
        self.dir = tempfile.mkdtemp()
        test.addCleanup(shutil.rmtree, self.dir, True)
        cfg_path = os.path.join(self.dir, "wallets.toml")
        with open(cfg_path, "w") as f:
            f.write(cfg_body or f'[[wallets]]\nlabel = "council-1"\npubkey = "{NONCE_AUTH}"\n')
        self.cfg = load_config(cfg_path)
        self.rpc = rpc or FixtureRpc()
        self.client = RpcClient(rpc_url, transport=self.rpc) if rpc_url else RpcClient(transport=self.rpc)
        self.fail_exc = fail_exc or OSError("No space left on device")
        self.clock = Clock()
        self.conns = list(conns)
        self.connect_times = []
        self.alerts = []      # per poll: (reason-unknown, alerts)
        self.out = io.StringIO()
        self.cycle_log = []
        self.stopped = False
        if prev_state is not None:
            from watchtower.config import save_state
            save_state(self.cfg["state_file"], prev_state)

        def connect(url):
            self.connect_times.append(self.clock())
            if not self.conns:
                self.stopped = True
                raise WsError("no more scripted connections")
            c = self.conns.pop(0)
            if isinstance(c, BaseException):
                raise c
            if callable(c) and not isinstance(c, FakeConn):
                c = c()
            self.current = c
            return c

        self.fail_next = 0

        def cycle(*a, **k):
            w = self.watcher
            self.cycle_log.append({"connected": w.connected, "pending_subs": len(w.pending_req),
                                   "coverage": dict(k.get("extra_coverage") or {}), "t": self.clock()})
            if self.fail_next:
                self.fail_next -= 1
                raise self.fail_exc
            out = watch_cycle(*a, **k)
            self.alerts.append(out)
            return out

        opts = dict(resync_interval=300.0, debounce=3.0, min_gap=10.0, ping_interval=30.0, idle_timeout=90.0,
                    subscribe_timeout=15.0, backoff_base=1.0, backoff_max=60.0, stable_after=60.0, rand=lambda: 1.0)
        opts.update(kw)
        self.watcher = StreamWatcher(
            self.cfg, self.client, self.cfg["state_file"], "wss://fake", cycle=cycle, connect=connect,
            out=self.out, clock=self.clock, sleep=self.clock.sleep, now=self.clock.now, log=self.log,
            should_stop=lambda: self.stopped, prev_state=load_state(self.cfg["state_file"]), **opts)
        self.logs = []

    def log(self, m):
        self.logs.append(m)

    def stop(self, conn=None):
        """Script item: end the run cleanly while connected (no trailing disconnect)."""
        self.stopped = True

    def run(self):
        with mock.patch("sys.stderr", io.StringIO()):
            self.watcher.run()
        return self

    def all_alerts(self):
        return [a for batch in self.alerts for a in batch]

    def kinds(self, i=None):
        src = self.all_alerts() if i is None else self.alerts[i]
        return [a["kind"] for a in src]


def ticks(n):
    return ["tick"] * n


class ReconnectTests(unittest.TestCase):
    def test_reconnect_resyncs_and_catches_change_made_during_outage(self):
        empty = load("gpa_nonce_empty.json")
        rpc = FixtureRpc(overrides={("getProgramAccounts", NONCE_AUTH): empty})
        clock_holder = {}

        def third():
            # The nonce accounts are created while the stream is down, after the fallback scan.
            rpc.overrides.clear()
            return FakeConn(clock_holder["c"], ticks(2) + [clock_holder["stop"]] + ticks(5))

        h = Harness(self, [None, WsError("refused"), third], rpc=rpc)
        clock_holder["c"], clock_holder["stop"] = h.clock, h.stop
        h.conns[0] = FakeConn(h.clock, ticks(3) + [WsClosed("server went away")])
        h.run()

        reasons = [r for r, ok in h.watcher.polls]
        self.assertEqual(reasons[0], "resync")
        self.assertIn("fallback", reasons)
        self.assertEqual(reasons.count("resync"), 2)
        # Every resync scan ran only after the subscriptions were confirmed.
        for entry, (reason, _) in zip(h.cycle_log, h.watcher.polls):
            if reason == "resync":
                self.assertTrue(entry["connected"])
                self.assertEqual(entry["pending_subs"], 0)
        resync2 = [i for i, (r, _) in enumerate(h.watcher.polls) if r == "resync"][1]
        k = h.kinds(resync2)
        self.assertEqual(k.count("new_nonce_account"), 5)  # caught by the re-sync scan
        self.assertIn("stream_gap", k)
        gap = next(a for a in h.alerts[resync2] if a["kind"] == "stream_gap")
        self.assertEqual(gap["severity"], "warn")
        self.assertTrue(gap["before"] and gap["after"] and gap["before"] < gap["after"])
        self.assertIn("coverage_restored", k)
        # The outage itself was reported loudly, never as clean.
        lost = [a for a in h.all_alerts() if a["kind"] == "coverage_lost" and a["subject"] == "stream"]
        self.assertEqual(len(lost), 1)
        self.assertEqual(lost[0]["after"], "disconnected")
        self.assertIn("only the periodic scan is running", lost[0]["detail"])
        self.assertIsNone(h.watcher.gap)

    def test_backoff_grows_caps_and_has_jitter_bounds(self):
        h = Harness(self, [WsError("down")] * 9, resync_interval=1000.0)
        h.run()
        self.assertEqual(h.watcher.delays, [1, 2, 4, 8, 16, 32, 60, 60, 60])
        # The wait really happens (fake clock): connect attempts are spaced by the delays.
        gaps = [round(b - a, 6) for a, b in zip(h.connect_times, h.connect_times[1:])]
        self.assertEqual(gaps, [1, 2, 4, 8, 16, 32, 60, 60, 60])
        h2 = Harness(self, [WsError("down")] * 3, rand=lambda: 0.0, resync_interval=1000.0)
        h2.run()
        self.assertEqual(h2.watcher.delays, [0.5, 1, 2])

    def test_backoff_resets_after_a_stable_connection(self):
        h = Harness(self, [WsError("a"), WsError("b"), WsError("c")], resync_interval=1000.0)
        h.conns.append(None)
        h.conns.append(WsError("d"))
        h.conns[3] = FakeConn(h.clock, ticks(20) + [WsClosed("x")])  # stays up > stable_after (60 s)
        h.run()
        self.assertEqual(h.watcher.delays[:3], [1, 2, 4])
        self.assertEqual(h.watcher.delays[3], 1)  # after a connection that stayed up: reset, not 8

    def test_flapping_connection_does_not_reset_backoff(self):
        h = Harness(self, [], resync_interval=1000.0)
        # Each connection subscribes, serves for ~10 s (well under stable_after) and drops.
        h.conns = [FakeConn(h.clock, ticks(2) + [WsClosed("x")]) for _ in range(4)]
        h.run()
        self.assertEqual(h.watcher.delays[:4], [1, 2, 4, 8])

    def test_stale_connection_detected_and_replaced(self):
        h = Harness(self, [], resync_interval=1000.0)
        h.conns = [FakeConn(h.clock, ticks(100), dead=True), FakeConn(h.clock, ticks(2))]
        h.run()
        self.assertEqual(h.watcher.connects, 2)
        self.assertTrue(any("stale" in m for m in h.logs))
        self.assertTrue(any(a["kind"] == "stream_gap" for a in h.all_alerts()))

    def test_unresolved_gap_is_loud_and_stays_open_until_a_complete_scan(self):
        rpc = FixtureRpc()
        holder = {}

        def second():
            rpc.gpa_refused = True  # re-sync after reconnect cannot see nonces

            def fix(conn):
                rpc.gpa_refused = False
            return FakeConn(holder["c"], ticks(70) + [fix] + ticks(70) + [holder["stop"]] + ticks(3))

        h = Harness(self, [None, second], rpc=rpc, resync_interval=60.0)
        holder["c"], holder["stop"] = h.clock, h.stop
        h.conns[0] = FakeConn(h.clock, [WsClosed("x")])
        h.run()
        k = h.kinds()
        self.assertIn("stream_gap_unresolved", k)
        self.assertEqual(k.count("stream_gap_unresolved"), 1)  # once, not every cycle
        first_unresolved = k.index("stream_gap_unresolved")
        self.assertIn("stream_gap", k[first_unresolved:])  # closed only after a complete scan
        unresolved = next(a for a in h.all_alerts() if a["kind"] == "stream_gap_unresolved")
        self.assertIn("NOT verified", unresolved["detail"])
        self.assertIsNone(h.watcher.gap)

    def test_disconnected_watcher_keeps_polling(self):
        h = Harness(self, [WsError("down")] * 12, resync_interval=60.0)
        h.run()
        fallback = [r for r, ok in h.watcher.polls if r == "fallback"]
        self.assertGreaterEqual(len(fallback), 4)
        self.assertTrue(all(c["coverage"] == {"stream": "disconnected"} for c in h.cycle_log))
        lost = [a for a in h.all_alerts() if a["kind"] == "coverage_lost" and a["subject"] == "stream"]
        self.assertEqual(len(lost), 1)  # first scan with no prior state: reported, then held
        self.assertIsNotNone(h.watcher.gap)  # never connected: the gap is still open, not "clean"

    def test_restart_is_reported_as_a_gap(self):
        prev = {"tool": "nonce-watchtower", "version": "0.2.0", "updated_at": "2026-10-05T12:00:00+00:00",
                "snapshot": None}
        h = Harness(self, [], prev_state=prev)
        h.conns = [FakeConn(h.clock, ticks(2))]
        h.run()
        gap = next(a for a in h.all_alerts() if a["kind"] == "stream_gap")
        self.assertEqual(gap["before"], "2026-10-05T12:00:00+00:00")
        self.assertIn("not running", gap["detail"])


class SubscriptionTests(unittest.TestCase):
    def test_targets(self):
        cfg = {"wallets": [{"pubkey": NONCE_AUTH, "label": ""}], "mints": [], "programs": [JUP], "squads": [SQUADS_V4_MS]}
        snap = {"nonces": {a: {} for a in NONCE_ACCOUNTS},
                "multisigs": {SQUADS_V4_MS: {"watched_keys": [[SQUADS_V4_VAULT0, "vault 0"]]}}}
        t = subscription_targets(cfg, snap)
        m, p = t[f"nonces:{NONCE_AUTH}"]
        self.assertEqual((m, p[0]), ("programSubscribe", SYS))
        self.assertEqual(p[1]["commitment"], "finalized")
        self.assertEqual(p[1]["filters"], [{"dataSize": 80}, {"memcmp": {"offset": 8, "bytes": NONCE_AUTH}}])
        self.assertEqual(t[f"tokens2022:{NONCE_AUTH}"][1][0], T22)
        self.assertIn(f"nonces:{SQUADS_V4_VAULT0}", t)  # members/vault from the snapshot are streamed too
        for a in NONCE_ACCOUNTS:
            self.assertEqual(t[f"nonce_account:{a}"][0], "accountSubscribe")
        self.assertEqual(t[f"programdata:{JUP}"][1][0], JUP_PD)  # derived PDA matches the real ProgramData
        self.assertIn(f"squads:{SQUADS_V4_MS}", t)

    def test_rejected_subscription_is_a_coverage_gap(self):
        h = Harness(self, [])
        h.conns = [FakeConn(h.clock, ticks(2), reject=lambda m, p: p[0] == T22)]
        h.run()
        lost = {a["subject"]: a for a in h.all_alerts() if a["kind"] == "coverage_lost"}
        self.assertIn(f"stream:tokens2022:{NONCE_AUTH}", lost)
        self.assertIn("stream", lost)
        self.assertEqual(lost["stream"]["after"], "partial")
        self.assertTrue(any("REJECTED" in m for m in h.logs))

    def test_unanswered_subscription_is_a_coverage_gap(self):
        h = Harness(self, [])
        h.conns = [FakeConn(h.clock, ticks(30), answer=False)]  # outlives the 15 s subscribe timeout
        h.run()
        self.assertEqual(h.watcher.connects, 0)  # nothing accepted: not "connected"
        self.assertTrue(any("no subscription was accepted" in m for m in h.logs))
        self.assertTrue(all(c["coverage"] == {"stream": "disconnected"} for c in h.cycle_log))

    def test_new_nonce_accounts_get_subscribed_after_a_scan(self):
        h = Harness(self, [])
        conn = FakeConn(h.clock, ticks(3) + [h.stop] + ticks(3))
        h.conns = [conn]
        h.run()
        subscribed = {p[0] for _, m, p in conn.requests if m == "accountSubscribe"}
        self.assertEqual(subscribed, set(NONCE_ACCOUNTS))
        self.assertTrue(all(h.watcher.subs[f"nonce_account:{a}"]["status"] == "ok" for a in NONCE_ACCOUNTS))


class UnsubscribeTests(unittest.TestCase):
    def test_targets_that_leave_the_snapshot_are_unsubscribed(self):
        # Review finding 4: the subscription set must shrink, not only grow.
        rpc = FixtureRpc()
        h = Harness(self, [], rpc=rpc)

        def nonces_closed(conn):
            rpc.overrides[("getProgramAccounts", NONCE_AUTH)] = load("gpa_nonce_empty.json")
            return {"jsonrpc": "2.0", "method": "programNotification",
                    "params": {"subscription": conn.sub_id("programSubscribe", SYS, NONCE_AUTH),
                               "result": {"context": {"slot": 2}, "value": {}}}}
        conn = FakeConn(h.clock, ticks(3) + [nonces_closed] + ticks(8) + [h.stop] + ticks(3))
        h.conns = [conn]
        h.run()
        sub_ids = {p[0]: rid + 1000 for rid, m, p in conn.requests if m == "accountSubscribe"}
        unsubs = [p[0] for _, m, p in conn.requests if m == "accountUnsubscribe"]
        self.assertEqual(sorted(unsubs), sorted(sub_ids[a] for a in NONCE_ACCOUNTS))
        self.assertFalse(any(n.startswith("nonce_account:") for n in h.watcher.subs))
        self.assertFalse(set(unsubs) & set(h.watcher.by_sub))
        # The unsubscribe answers are expected replies, not events: they trigger no extra scan.
        self.assertEqual([r for r, _ in h.watcher.polls].count("event"), 1)
        self.assertFalse(h.watcher.unsub_req)


class Sink:
    def __init__(self, name="telegram", fail=0):
        self.name, self.fail, self.got = name, fail, []

    def deliver(self, alerts, stamp=None):
        if self.fail:
            self.fail -= 1
            return False, f"{self.name} -> HTTP 503", []
        self.got.extend(alerts)
        return True, "ok", list(alerts)


class ScanFailureTests(unittest.TestCase):
    """Round-2 finding 1: a failing cycle is a persistent coverage gap delivered to the sinks."""

    def test_failed_scan_opens_gap_alerts_sinks_and_recovers(self):
        sink = Sink()
        h = Harness(self, [], sinks=[sink], resync_interval=60.0)
        h.fail_next = 2
        h.conns = [FakeConn(h.clock, ticks(80) + [h.stop] + ticks(2))]
        h.run()
        reasons = h.watcher.polls
        self.assertEqual([ok for _, ok in reasons[:3]], [False, False, True])
        # Direct alert, once per episode, at the first failure.
        self.assertEqual([a["kind"] for a in sink.got].count("scan_failed"), 1)
        self.assertEqual(sink.got[0]["kind"], "scan_failed")
        # While failing, coverage() does not say ok.
        self.assertEqual(h.cycle_log[1]["coverage"]["stream"], "scan_failed")
        self.assertEqual(h.cycle_log[2]["coverage"]["stream"], "scan_failed")
        # The recovering cycle persists and delivers the gap through the normal path.
        rec = h.alerts[0]
        self.assertIn(("coverage_lost", "scan_failed"), {(a["kind"], a.get("after")) for a in rec})
        self.assertIn("stream_gap", [a["kind"] for a in rec])
        self.assertIn("stream_gap", [a["kind"] for a in sink.got])
        # Later cycles are clean again.
        self.assertEqual(h.cycle_log[-1]["coverage"]["stream"], "ok")
        self.assertIsNone(h.watcher.scan_failure)
        self.assertIsNone(h.watcher.gap)

    def test_failure_alert_retried_for_a_sink_that_missed_it(self):
        sink = Sink(fail=1)
        h = Harness(self, [], sinks=[sink], resync_interval=1000.0)  # long: no periodic re-alert in this window
        h.fail_next = 3
        h.conns = [FakeConn(h.clock, ticks(30) + [h.stop] + ticks(2))]
        h.run()
        self.assertEqual([a["kind"] for a in sink.got].count("scan_failed"), 1)
        self.assertTrue(any("ALERT DELIVERY FAILED" in m for m in h.logs))

    def test_persistent_failure_keeps_gap_open(self):
        h = Harness(self, [], sinks=[Sink()], resync_interval=60.0)
        h.fail_next = 10 ** 6
        h.conns = [FakeConn(h.clock, ticks(60) + [h.stop] + ticks(2))]
        h.run()
        self.assertGreater(len(h.watcher.polls), 3)  # keeps retrying
        self.assertEqual(h.watcher.coverage()["stream"], "scan_failed")
        self.assertIsNotNone(h.watcher.gap)


class ScanBackoffTests(unittest.TestCase):
    """Retries after consecutive scan failures back off (capped at resync_interval), reset on success, keep the
    gap open, and still deliver a scan_failed at least once per resync interval."""

    def run_failing(self, fails, extra=()):
        sink = Sink()
        sink_times = []
        orig = sink.deliver

        def deliver(alerts, stamp=None):
            for a in alerts:
                if a["kind"] == "scan_failed":
                    sink_times.append(h.clock())
            return orig(alerts, stamp)
        sink.deliver = deliver
        h = Harness(self, [], sinks=[sink], resync_interval=300.0, min_gap=10.0)
        h.fail_next = fails
        h.conns = [FakeConn(h.clock, ticks(500) + list(extra) + [h.stop] + ticks(2))]
        h.run()
        return h, sink, sink_times

    def test_retries_back_off_and_cap_at_resync_interval(self):
        h, _, _ = self.run_failing(8)
        t = [c["t"] for c in h.cycle_log[:9]]
        gaps = [round(b - a, 3) for a, b in zip(t, t[1:])]
        self.assertEqual(gaps, [10, 20, 40, 80, 160, 300, 300, 300])
        # The gap is open and reported on every failed attempt, then closed by the first success.
        self.assertTrue(all(c["coverage"]["stream"] == "scan_failed" for c in h.cycle_log[1:9]))
        self.assertEqual([ok for _, ok in h.watcher.polls[:9]], [False] * 8 + [True])
        self.assertIsNone(h.watcher.gap)

    def test_backoff_resets_after_a_successful_cycle(self):
        holder = {}

        def fail_again(conn):
            holder["h"].fail_next = 2
            return {"jsonrpc": "2.0", "method": "mystery"}  # triggers a scan
        sink = Sink()
        h = Harness(self, [], sinks=[sink], resync_interval=300.0, min_gap=10.0)
        holder["h"] = h
        h.fail_next = 5
        h.conns = [FakeConn(h.clock, ticks(250) + [fail_again] + ticks(100) + [h.stop] + ticks(2))]
        h.run()
        oks = [ok for _, ok in h.watcher.polls]
        second = [i for i in range(1, len(oks)) if not oks[i] and oks[i - 1]][0]  # first failure of episode 2
        t = [c["t"] for c in h.cycle_log]
        self.assertEqual(round(t[second + 1] - t[second], 3), 10)  # back to min_gap, not 300
        self.assertEqual(h.watcher.scan_failures, 0)

    def test_scan_failed_delivered_at_least_once_per_resync_interval(self):
        h, sink, times = self.run_failing(10 ** 6)
        span = h.cycle_log[-1]["t"] - h.cycle_log[0]["t"]
        self.assertGreater(span, 1000)
        spacing = [b - a for a, b in zip(times, times[1:])]
        self.assertTrue(spacing and max(spacing) <= 300, spacing)
        self.assertGreaterEqual(len(times), int(span // 300) + 1)
        self.assertIn("STILL FAILING", [a for a in sink.got if a["kind"] == "scan_failed"][-1]["detail"])
        self.assertEqual(h.watcher.coverage()["stream"], "scan_failed")
        self.assertIsNotNone(h.watcher.gap)


class UndecodableTests(unittest.TestCase):
    """Round-2 finding 3: an undecodable nonce notification is never silent."""

    def run_with(self, make):
        h = Harness(self, [])
        h.conns = [FakeConn(h.clock, ticks(3) + [make] + ticks(8) + [h.stop] + ticks(2))]
        h.run()
        return h

    def garbage(self, pubkey):
        def make(conn):
            n = nonce_notification(conn.sub_id("programSubscribe", SYS, NONCE_AUTH), pubkey)
            n["params"]["result"]["value"]["account"]["data"] = [base64.b64encode(b"\x01" * 10).decode(), "base64"]
            return n
        return make

    def test_undecodable_unexplained_notification_alerts(self):
        ghost = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
        h = self.run_with(self.garbage(ghost))
        hits = [a for a in h.all_alerts() if a["kind"] == "nonce_notification_undecodable"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["subject"], ghost)
        self.assertEqual(hits[0]["severity"], "high")

    def test_undecodable_but_explained_by_the_scan_is_quiet(self):
        h = self.run_with(self.garbage(NONCE_ACCOUNTS[0]))
        self.assertNotIn("nonce_notification_undecodable", h.kinds())

    def test_shape_errors_and_unparseable_messages_alert(self):
        def no_value(conn):
            return {"jsonrpc": "2.0", "method": "programNotification",
                    "params": {"subscription": conn.sub_id("programSubscribe", SYS, NONCE_AUTH), "result": {}}}
        self.assertIn("nonce_notification_undecodable", self.run_with(no_value).kinds())
        self.assertIn("nonce_notification_undecodable", self.run_with(lambda conn: {"_malformed": True}).kinds())


class VanishedNonceStreamTests(unittest.TestCase):
    def test_partial_answer_does_not_unsubscribe_a_live_nonce(self):
        """Round-2 finding 4 (stream): confirmed live -> kept subscribed, nonce check unverified, stream not clean."""
        rpc = FixtureRpc()
        h = Harness(self, [], rpc=rpc)
        g = load("gpa_nonce_real.json")
        missing = g["result"].pop(0)

        def partial(conn):
            rpc.overrides[("getProgramAccounts", NONCE_AUTH)] = g
            rpc.overrides[("getAccountInfo", missing["pubkey"])] = {
                "jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 2}, "value": missing["account"]}}
            return {"jsonrpc": "2.0", "method": "programNotification",
                    "params": {"subscription": conn.sub_id("programSubscribe", SYS, NONCE_AUTH),
                               "result": {"context": {"slot": 2}, "value": {}}}}
        conn = FakeConn(h.clock, ticks(3) + [partial] + ticks(8) + [h.stop] + ticks(2))
        h.conns = [conn]
        h.run()
        self.assertFalse([p for _, m, p in conn.requests if m == "accountUnsubscribe"])
        self.assertEqual(h.watcher.subs[f"nonce_account:{missing['pubkey']}"]["status"], "ok")
        self.assertEqual(h.watcher.last_snap["coverage"][f"nonces:{NONCE_AUTH}"], "unverified")
        self.assertNotIn("nonce_account_gone", h.kinds())


class NotificationTests(unittest.TestCase):
    def test_notifications_are_debounced_into_one_scan(self):
        h = Harness(self, [])

        def notif(conn):
            return {"jsonrpc": "2.0", "method": "programNotification",
                    "params": {"subscription": conn.sub_id("programSubscribe", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
                               "result": {"context": {"slot": 1}, "value": {}}}}
        h.conns = [FakeConn(h.clock, ticks(3) + [notif, notif, notif] + ticks(8))]
        h.run()
        reasons = [r for r, _ in h.watcher.polls]
        self.assertEqual(reasons.count("event"), 1)
        self.assertEqual(h.watcher.notifications, 3)

    def test_mint_supply_only_change_does_not_trigger_but_authority_change_does(self):
        cfg = f'mints = ["{USDC}"]\n[[wallets]]\npubkey = "{NONCE_AUTH}"\n'
        h = Harness(self, [], cfg_body=cfg)
        base = load("mint_usdc.json")["result"]["value"]
        raw = bytes(82)

        def note(supply, freeze=b"\x00" * 36):
            data = bytearray(raw)
            data[36:44] = supply.to_bytes(8, "little")
            data[46:82] = freeze
            acct = {"owner": base["owner"], "lamports": 1, "data": [base64.b64encode(bytes(data)).decode(), "base64"]}

            def item(conn):
                return {"jsonrpc": "2.0", "method": "accountNotification",
                        "params": {"subscription": conn.sub_id("accountSubscribe", USDC), "result": {"context": {"slot": 1},
                                                                                                     "value": acct}}}
            return item
        h.conns = [FakeConn(h.clock, ticks(3) + [note(1)] + ticks(8) + [note(2), note(3)] + ticks(8)
                            + [note(3, b"\x01\x00\x00\x00" + b"\x09" * 32)] + ticks(8) + [h.stop] + ticks(2))]
        h.run()
        self.assertEqual([r for r, _ in h.watcher.polls].count("event"), 2)  # first sighting + the authority change
        self.assertEqual(h.watcher.ignored, 2)

    def test_unexplained_message_triggers_a_scan(self):
        for msg in ({"jsonrpc": "2.0", "method": "mystery"}, {"jsonrpc": "2.0", "id": 999, "result": 1}, {"_malformed": True}):
            h = Harness(self, [])
            h.conns = [FakeConn(h.clock, ticks(3) + [msg] + ticks(8))]
            h.run()
            self.assertEqual([r for r, _ in h.watcher.polls].count("event"), 1, msg)

    def test_nonce_seen_live_but_gone_by_the_scan_is_critical(self):
        h = Harness(self, [])
        ghost = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"  # any valid key not among the scanned nonces

        def seen(conn):
            return nonce_notification(conn.sub_id("programSubscribe", SYS, NONCE_AUTH), ghost)

        def seen_real(conn):
            return nonce_notification(conn.sub_id("programSubscribe", SYS, NONCE_AUTH), NONCE_ACCOUNTS[0])
        h.conns = [FakeConn(h.clock, ticks(3) + [seen, seen_real] + ticks(8))]
        h.run()
        live = [a for a in h.all_alerts() if a["kind"] == "nonce_seen_live"]
        self.assertEqual(len(live), 1)
        self.assertEqual(live[0]["subject"], ghost)
        self.assertEqual(live[0]["severity"], "critical")
        self.assertEqual(live[0]["wallet"], "council-1")

    def test_sighting_with_foreign_authority_is_not_trusted(self):
        h = Harness(self, [])
        ghost = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"

        def forged(conn):
            n = nonce_notification(conn.sub_id("programSubscribe", SYS, NONCE_AUTH), ghost)
            acct = n["params"]["result"]["value"]["account"]
            raw = bytearray(base64.b64decode(acct["data"][0]))
            raw[8:40] = b"\x05" * 32  # authority is NOT the watched key: server-side filter lied
            acct["data"][0] = base64.b64encode(bytes(raw)).decode()
            return n
        h.conns = [FakeConn(h.clock, ticks(3) + [forged] + ticks(8))]
        h.run()
        self.assertNotIn("nonce_seen_live", h.kinds())
        self.assertEqual([r for r, _ in h.watcher.polls].count("event"), 1)  # still re-scanned


class StreamCliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg_path = os.path.join(self.dir, "wallets.toml")
        with open(self.cfg_path, "w") as f:
            f.write(f'[[wallets]]\npubkey = "{NONCE_AUTH}"\n')

    def test_plain_ws_to_remote_host_refused_without_leaking(self):
        with mock.patch.dict(os.environ, {"WATCHTOWER_WS_URL": "ws://rpc.example.com/?api-key=SECRET9"}), \
                mock.patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(main(["stream", "--config", self.cfg_path]), 64)
        self.assertNotIn("SECRET9", err.getvalue())

    def test_resync_interval_floor(self):
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(["stream", "--config", self.cfg_path, "--resync-interval", "5"]), 64)
            self.assertEqual(main(["stream", "--config", self.cfg_path, "--min-gap", "1"]), 64)

    def test_stream_wires_watcher(self):
        seen = {}

        class W:
            def __init__(self, cfg, client, state_path, ws_url, **kw):
                seen.update(ws_url=ws_url, kw=kw)

            def run(self):
                return 0
        env = {"WATCHTOWER_RPC_URL": "https://rpc.example.com/?api-key=SECRET9"}
        with mock.patch.dict(os.environ, env), mock.patch("watchtower.cli.StreamWatcher", W), \
                mock.patch("watchtower.cli.signal.signal"), mock.patch("sys.stderr", io.StringIO()) as err:
            os.environ.pop("WATCHTOWER_WS_URL", None)
            self.assertEqual(main(["stream", "--config", self.cfg_path, "--resync-interval", "120"]), 0)
        self.assertEqual(seen["ws_url"], "wss://rpc.example.com/?api-key=SECRET9")
        self.assertEqual(seen["kw"]["resync_interval"], 120.0)
        self.assertNotIn("SECRET9", err.getvalue())


if __name__ == "__main__":
    unittest.main()
