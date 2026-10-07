"""Streaming mode: Solana PubSub subscriptions as a low-latency trigger for the normal scan.

Design (tested in tests/test_stream.py):
  * A notification is a TRIGGER, not a verdict. Every notification (debounced) runs the same
    full read-only scan -> diff -> alert cycle that `watch` uses, so streaming and polling
    can never disagree about what is risky. The stream only makes the cycle run sooner.
  * Subscriptions, all at `finalized` commitment. The follow-up scan reads at `finalized` too, and
    rpc.FreshnessGuard bounds how old its answers can be (context slot vs a fresh getSlot, the
    finalized block's age vs this clock, optionally a second RPC); beyond those bounds the check is
    `unverified`, a coverage gap. Inside them a node can still trail the notification by a few
    slots: a nonce seen live but missing from the follow-up scan raises `nonce_seen_live`:
      - programSubscribe System program, dataSize 80 + authority memcmp, per watched key:
        a nonce account created for, or re-authorized to, a watched key. The authority is
        instruction DATA, not an account key, so a logs/mentions subscription would miss a
        nonce staged by an outside key: that is why this is a program subscription.
      - programSubscribe SPL Token / Token-2022, owner memcmp, per watched key: delegate
        approvals, close authorities, freezes.
      - accountSubscribe on every known nonce account (advance, close, authority moved away),
        every Squads multisig account, watched mint, program account and ProgramData account.
  * A full poll still runs every `resync_interval` seconds while connected (a WebSocket can
    drop notifications without closing), and keeps running while disconnected.
  * Reconnect with exponential backoff and jitter. After every (re)connect the subscriptions
    are confirmed FIRST and then a full re-sync poll runs, so nothing between "poll" and
    "subscribed" can fall through.
  * Coverage gaps are loud and never "clean": while the stream is down the `stream` check
    reports `disconnected` (-> coverage_lost); a rejected subscription reports
    `subscribe_failed`; after reconnect a `stream_gap` alert states the window. The gap is
    closed only by a re-sync poll whose every check ran; otherwise `stream_gap_unresolved`
    is raised and the gap stays open.
  * A nonce account seen on the stream with a watched authority but absent from the
    follow-up scan raises `nonce_seen_live` (critical): it was closed, re-authorized away, or
    the RPC is lagging, and none of those may pass silently.
"""

import datetime as _dt
import hashlib
import random
import sys
import time

from .base58 import b58decode
from .decode import SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM, UPGRADEABLE_LOADER, account_bytes, decode_nonce
from .alerts import emit_stdout
from .diff import COVERAGE_OK
from .notify import deliver_direct
from .redact import exc_text, scrub
from .pda import find_program_address
from .scan import nonce_filters
from .ws import WsError

SUB_OPTS = {"commitment": "finalized", "encoding": "base64"}
# SPL/Token-2022 mint: supply is a u64 at bytes 36..44 of the base layout. It changes on every mint/burn,
# which says nothing about who controls the mint; every other byte (authorities, extensions) still triggers.
MINT_SUPPLY = slice(36, 44)
TOKEN_OWNER_OFFSET = 32
TOKEN_ACCOUNT_SIZE = 165
UNSUBSCRIBE = {"accountSubscribe": "accountUnsubscribe", "programSubscribe": "programUnsubscribe"}
ORDER = {"critical": 0, "high": 1, "warn": 2, "medium": 3, "info": 4}


def _iso(dt):
    return dt.replace(microsecond=0).isoformat()


def _utcnow():
    return _dt.datetime.now(_dt.timezone.utc)


def watched_keys_of(cfg, snap):
    keys = [w["pubkey"] for w in cfg["wallets"]]
    for m in ((snap or {}).get("multisigs") or {}).values():
        keys += [k for k, _ in m.get("watched_keys", [])]
    return list(dict.fromkeys(keys))


def subscription_targets(cfg, snap):
    """{stable name: (method, params)} for everything watched, given the latest snapshot."""
    t = {}
    for k in watched_keys_of(cfg, snap):
        t[f"nonces:{k}"] = ("programSubscribe", [SYSTEM_PROGRAM, {**SUB_OPTS, "filters": nonce_filters(k)}])
        t[f"tokens:{k}"] = ("programSubscribe", [TOKEN_PROGRAM, {**SUB_OPTS, "filters": [
            {"dataSize": TOKEN_ACCOUNT_SIZE}, {"memcmp": {"offset": TOKEN_OWNER_OFFSET, "bytes": k}}]}])
        # Token-2022 accounts carry extensions, so their size varies: owner filter only.
        t[f"tokens2022:{k}"] = ("programSubscribe", [TOKEN_2022_PROGRAM, {**SUB_OPTS, "filters": [
            {"memcmp": {"offset": TOKEN_OWNER_OFFSET, "bytes": k}}]}])
    for a in sorted(((snap or {}).get("nonces") or {})):
        t[f"nonce_account:{a}"] = ("accountSubscribe", [a, dict(SUB_OPTS)])
    for a in cfg.get("squads", []):
        t[f"squads:{a}"] = ("accountSubscribe", [a, dict(SUB_OPTS)])
    for m in cfg["mints"]:
        t[f"mint:{m}"] = ("accountSubscribe", [m, dict(SUB_OPTS)])
    for p in cfg["programs"]:
        t[f"program:{p}"] = ("accountSubscribe", [p, dict(SUB_OPTS)])
        pd = find_program_address([b58decode(p)], UPGRADEABLE_LOADER)[0]
        t[f"programdata:{p}"] = ("accountSubscribe", [pd, dict(SUB_OPTS)])
    return t


class StreamWatcher:
    def __init__(self, cfg, client, state_path, ws_url, cycle, connect, sinks=(), as_json=False, out=None,
                 resync_interval=300.0, debounce=3.0, min_gap=10.0, ping_interval=30.0, idle_timeout=90.0,
                 subscribe_timeout=15.0, backoff_base=1.0, backoff_max=60.0, stable_after=60.0,
                 clock=time.monotonic, sleep=time.sleep, now=_utcnow, rand=random.random, log=None,
                 should_stop=None, prev_state=None):
        self.cfg, self.client, self.state_path, self.ws_url = cfg, client, state_path, ws_url
        self.cycle, self.connect, self.sinks = cycle, connect, list(sinks)
        self.as_json, self.out = as_json, out
        self.resync_interval, self.debounce, self.min_gap = resync_interval, debounce, min_gap
        self.ping_interval, self.idle_timeout, self.subscribe_timeout = ping_interval, idle_timeout, subscribe_timeout
        self.backoff_base, self.backoff_max, self.stable_after = backoff_base, backoff_max, stable_after
        self.clock, self.sleep, self.now, self.rand = clock, sleep, now, rand
        sink_log = log or (lambda m: print(f"watchtower: {m}", file=sys.stderr, flush=True))
        self.log = lambda m: sink_log(scrub(m))  # every log line is scrubbed, whoever receives it
        self.should_stop = should_stop or (lambda: False)

        self.conn = None
        self.connected = False
        self.connected_at = None
        self.attempt = 0
        self.subs = {}          # name -> {"status": ok|pending|subscribe_failed, ...}
        self.pending_req = {}   # request id -> (name, sent_at)
        self.by_sub = {}        # subscription id -> name
        self.unsub_req = {}     # request id -> ("unsub", name) | ("late", name, method): answers we expect, not events
        self.dirty_since = None
        self.sightings = {}     # nonce account -> {"authority", "slot"}
        self.undecodable = []   # nonce notifications we could not decode: explained by the next scan, or alerted
        self.scan_failure = None    # {"since", "error"} while the scan/alert/state cycle keeps failing
        self.failure_notice = None  # {"alert", "missing": sink names, "raised_at"} until every sink has it
        self.scan_failures = 0      # consecutive failed cycles (drives the retry backoff)
        self.retry_hold_until = float("-inf")  # no retry scan before this (monotonic), while failing
        self.fingerprints = {}  # mint subscription name -> fingerprint of its authority-relevant bytes
        self.ignored = 0        # notifications that changed nothing we check (mint supply only)
        self.last_poll = float("-inf")
        self.last_snap = (prev_state or {}).get("snapshot")
        # Stats, for logs and tests.
        self.polls = []         # (reason, ok)
        self.notifications = 0
        self.connects = 0
        self.delays = []
        # A watcher that was not running is a coverage gap too (process restart, host down).
        prev_at = (prev_state or {}).get("updated_at")
        self.gap = {"start": prev_at, "reason": "watcher was not running", "unresolved_reported": False} if prev_at else None

    # ---- coverage / alerts -------------------------------------------------------------
    def coverage(self):
        if not self.connected:
            cov = {"stream": "disconnected"}
        else:
            cov = {f"stream:{n}": s["status"] for n, s in self.subs.items() if s["status"] != "pending"}
            cov["stream"] = "ok" if all(v == "ok" for v in cov.values()) else "partial"
        if self.scan_failure is not None:
            cov["stream"] = "scan_failed"  # a live socket is worthless while the cycle behind it is failing
        return cov

    def _open_gap(self, start, reason):
        if self.gap is None:
            self.gap = {"start": start, "reason": reason, "unresolved_reported": False}

    def _after_snapshot(self, decision):
        def hook(snap, report):
            out = []
            for acct, s in sorted(self.sightings.items()):
                if acct not in snap["nonces"]:
                    out.append({
                        "severity": "critical", "kind": "nonce_seen_live", "subject": acct, "wallet": s["authority"],
                        "detail": f"durable nonce account with authority {s['authority']} was seen on the live stream at slot "
                                  f"{s['slot']} but is not in the follow-up scan: it was closed, its authority moved off "
                                  "the watched keys, or the RPC is lagging. Pre-signed transactions may have used it. Verify.",
                    })
            for u in self.undecodable:
                if u["pubkey"] and u["pubkey"] in snap["nonces"]:
                    continue  # the scan read that account itself: the notification is explained
                out.append({
                    "severity": "high", "kind": "nonce_notification_undecodable", "subject": u["pubkey"] or u["subscription"],
                    **({"wallet": u["authority"]} if u.get("authority") else {}),
                    "detail": f"a live notification on {u['subscription']} (slot {u['slot']}) could not be decoded "
                              f"({u['why']}) and the follow-up scan does not explain it: a nonce account created and "
                              "closed in between would be invisible. Verify on-chain.",
                })
            if self.gap is not None and self.connected:
                blind = sorted(k for k, v in snap["coverage"].items() if not k.startswith("stream") and v not in COVERAGE_OK)
                end = _iso(self.now())
                if not blind:
                    out.append({
                        "severity": "warn", "kind": "stream_gap", "subject": "stream",
                        "detail": f"live coverage was down ({self.gap['reason']}). A full re-sync scan ran after reconnecting "
                                  "and its net changes are alerted separately; a change that happened AND reverted inside "
                                  "the gap cannot be seen.",
                        "before": self.gap["start"], "after": end,
                    })
                    decision["close_gap"] = True
                elif not self.gap["unresolved_reported"]:
                    out.append({
                        "severity": "warn", "kind": "stream_gap_unresolved", "subject": "stream",
                        "detail": f"stream reconnected but the re-sync scan is INCOMPLETE ({len(blind)} check(s) not running: "
                                  f"{', '.join(blind[:5])}{'…' if len(blind) > 5 else ''}). Changes during the gap since "
                                  f"{self.gap['start']} are NOT verified; retrying every cycle.",
                        "before": self.gap["start"], "after": None,
                    })
                    decision["reported_unresolved"] = True
            return out
        return hook

    def poll(self, reason):
        decision, res = {}, {}
        try:
            self.cycle(self.cfg, self.client, self.state_path, None, as_json=self.as_json, out=self.out, sinks=self.sinks,
                       extra_coverage=self.coverage(), after_snapshot=self._after_snapshot(decision), result=res)
        except Exception as e:  # keep watching, but a failed cycle is a coverage gap, never a quiet log line
            self.polls.append((reason, False))
            self.last_poll = self.clock()
            self._scan_failed(reason, e)
            return False
        self.polls.append((reason, True))
        self.last_poll = self.clock()
        self.last_snap = res.get("snap", self.last_snap)
        self.sightings.clear()
        self.undecodable.clear()
        self.dirty_since = None
        self.scan_failures, self.retry_hold_until = 0, float("-inf")
        if self.scan_failure is not None:
            self.log(f"scan recovered after failing since {self.scan_failure['since']}")
            # The cycle that just succeeded persisted stream=scan_failed and delivered its coverage_lost through
            # the normal (queued, persisted) path; the next cycle reports coverage_restored.
            self.scan_failure = None
            self.failure_notice = None
        if decision.get("close_gap"):
            self.gap = None
        elif decision.get("reported_unresolved") and self.gap is not None:
            self.gap["unresolved_reported"] = True
        if self.connected:
            self._subscribe_new()
        return True

    def retry_delay(self):
        """Backoff after consecutive failed cycles: min_gap, doubling, capped at resync_interval."""
        return min(self.resync_interval, self.min_gap * (2 ** max(0, self.scan_failures - 1)))

    def _scan_failed(self, reason, exc):
        err = exc_text(exc)
        now = _iso(self.now())
        self.scan_failures += 1
        delay = self.retry_delay()
        self.retry_hold_until = self.clock() + delay
        self.log(f"{reason} scan FAILED ({self.scan_failures} in a row): {err}; retrying in {delay:.0f}s")
        self._open_gap(now, f"scan failed: {err}")
        first = self.scan_failure is None
        if first:
            self.scan_failure = {"since": now, "error": err}
        # One scan_failed per episode, and again whenever the NEXT retry would land more than one resync interval
        # after the last one raised, so delivered scan_failed alerts are never further apart than resync_interval
        # and a long outage is never a single alert. Each repeat is a new alert sent directly (no queue, no dedup
        # ledger) whose text changes (count, latest error), so nothing can absorb it.
        n = self.failure_notice
        if first or n is None or self.clock() - n["raised_at"] + delay >= self.resync_interval:
            since = self.scan_failure["since"]
            alert = {"severity": "high", "kind": "scan_failed", "subject": "stream", "at": now,
                     "detail": (f"the scan/alert/state cycle FAILED ({err}). " if first else
                                f"the scan/alert/state cycle is STILL FAILING ({self.scan_failures} attempts, latest: {err}). ")
                               + f"Changes are NOT being detected, delivered or recorded until a scan succeeds; retrying "
                                 f"with backoff (next in {delay:.0f}s). Coverage gap since {since}.",
                     "before": since, "after": now}
            try:
                emit_stdout([alert], as_json=self.as_json, stream=self.out)
            except Exception:
                pass
            self.failure_notice = {"alert": alert, "missing": {s.name for s in self.sinks}, "raised_at": self.clock()}
        self._push_failure_notice()
        self.mark_dirty()  # retried once retry_hold_until has passed

    def _push_failure_notice(self):
        """Send the scan_failed alert straight to every sink that does not have it yet (no queue, no state)."""
        n = self.failure_notice
        if not n or not n["missing"]:
            return
        res = deliver_direct([s for s in self.sinks if s.name in n["missing"]], [n["alert"]], n["alert"]["at"])
        for name, (ok, msg) in res.items():
            if ok:
                n["missing"].discard(name)
            else:
                self.log(f"ALERT DELIVERY FAILED: scan_failed alert did not reach {name} ({msg}); retrying")

    # ---- subscriptions -----------------------------------------------------------------
    def _request(self, name, method, params):
        rid = self.conn.request(method, params)
        self.pending_req[rid] = (name, self.clock())
        self.subs[name] = {"status": "pending", "method": method}

    def _subscribe_new(self):
        """Bring the live subscription set in line with the latest snapshot: add new targets, drop old ones."""
        targets = subscription_targets(self.cfg, self.last_snap)
        for name, (m, p) in targets.items():
            if name not in self.subs:
                self._request(name, m, p)
        for name in [n for n in self.subs if n not in targets]:
            sub = self.subs.pop(name)
            if sub.get("status") == "ok":
                self.by_sub.pop(sub["sub_id"], None)
                rid = self.conn.request(UNSUBSCRIBE[sub["method"]], [sub["sub_id"]])
                self.unsub_req[rid] = ("unsub", name)
            # A still-pending subscribe for a dropped target: cancel it when its answer arrives (handle()).
            for rid, (n, _) in list(self.pending_req.items()):
                if n == name:
                    del self.pending_req[rid]
                    self.unsub_req[rid] = ("late", name, sub.get("method"))

    def _expire_pending(self):
        now = self.clock()
        for rid, (name, at) in list(self.pending_req.items()):
            if now - at >= self.subscribe_timeout:
                del self.pending_req[rid]
                self.subs[name] = {"status": "subscribe_failed", "error": "no answer to subscribe request"}
                self.mark_dirty()

    def mark_dirty(self):
        if self.dirty_since is None:
            self.dirty_since = self.clock()

    def handle(self, msg):
        if not isinstance(msg, dict) or msg.get("_malformed"):
            # It may have been a nonce notification: never explainable, so it is alerted after the re-scan.
            self.log("stream: malformed message; re-scanning to be safe")
            self.undecodable.append({"subscription": "unparseable PubSub message", "pubkey": None, "slot": None,
                                     "why": "not valid JSON"})
            self.mark_dirty()
            return
        rid = msg.get("id")
        if rid is not None and rid in self.unsub_req:
            entry = self.unsub_req.pop(rid)
            res = msg.get("result")
            if entry[0] == "late" and isinstance(res, int) and not isinstance(res, bool) and entry[2] in UNSUBSCRIBE:
                self.unsub_req[self.conn.request(UNSUBSCRIBE[entry[2]], [res])] = ("unsub", entry[1])
            elif entry[0] == "unsub" and msg.get("error"):
                self.log(f"stream: unsubscribe of {entry[1]} refused (harmless: at worst extra re-scans)")
            return
        if rid is not None and rid in self.pending_req:
            name, _ = self.pending_req.pop(rid)
            err = msg.get("error")
            if err:
                emsg = str(err.get("message", err) if isinstance(err, dict) else err)[:200]
                self.subs[name] = {"status": "subscribe_failed", "error": emsg}
                self.log(f"stream: subscription {name} REJECTED: {emsg}")
            elif isinstance(msg.get("result"), int) and not isinstance(msg.get("result"), bool):
                self.subs[name] = {"status": "ok", "sub_id": msg["result"], "method": self.subs[name].get("method")}
                self.by_sub[msg["result"]] = name
            else:
                self.subs[name] = {"status": "subscribe_failed", "error": "unexpected subscribe answer"}
            return
        if msg.get("method") in ("accountNotification", "programNotification"):
            params = msg.get("params") or {}
            name = self.by_sub.get(params.get("subscription"))
            self.notifications += 1
            if name and name.startswith(("nonces:", "nonce_account:")):
                self._record_sighting(name, params.get("result"))
            if name and name.startswith("mint:") and self._mint_unchanged(name, params.get("result")):
                self.ignored += 1
                return
            self.mark_dirty()
            return
        self.mark_dirty()  # unknown id or method: never ignore what we cannot explain

    def _mint_unchanged(self, name, result):
        """True only if this mint notification differs from the previous one in supply alone."""
        try:
            acct = result["value"]
            raw = bytearray(account_bytes(acct))
        except (KeyError, TypeError, ValueError):
            return False
        if len(raw) >= MINT_SUPPLY.stop:
            raw[MINT_SUPPLY] = bytes(MINT_SUPPLY.stop - MINT_SUPPLY.start)
        fp = hashlib.sha256(str(acct.get("owner")).encode() + b"|" + bytes(raw)).hexdigest()
        prev, self.fingerprints[name] = self.fingerprints.get(name), fp
        return prev == fp

    def _record_sighting(self, name, result):
        """Decode a nonce notification locally. Never silent: a notification we cannot decode is recorded, and
        alerted after the next scan unless that scan read the same account itself."""
        kind, target = name.split(":", 1)
        pubkey, slot = (target if kind == "nonce_account" else None), None
        try:
            slot = (result.get("context") or {}).get("slot")
            value = result["value"]
            if kind == "nonces":
                pubkey, acct = value["pubkey"], value["account"]
            else:
                acct = value
                if acct is None or acct.get("lamports") == 0:
                    return  # closed: the scan reports it (after confirming with a direct read)
            if acct.get("owner") != SYSTEM_PROGRAM:
                raise ValueError(f"owner {acct.get('owner')} is not the System program")
            dec = decode_nonce(account_bytes(acct))
            if dec is None:
                raise ValueError("not an initialized 80-byte nonce account")
            if kind == "nonces" and dec["authority"] == target:  # verified locally; the server filter is not trusted
                self.sightings[pubkey] = {"authority": target, "slot": slot}
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            self.undecodable.append({"subscription": name, "pubkey": pubkey if isinstance(pubkey, str) else None,
                                     "slot": slot, "why": scrub(str(e))[:120] or type(e).__name__,
                                     "authority": target if kind == "nonces" else None})

    # ---- connection lifecycle ----------------------------------------------------------
    def connect_and_subscribe(self):
        self.subs, self.pending_req, self.by_sub, self.unsub_req = {}, {}, {}, {}
        self.conn = self.connect(self.ws_url)
        for name, (m, p) in subscription_targets(self.cfg, self.last_snap).items():
            self._request(name, m, p)
        deadline = self.clock() + self.subscribe_timeout
        while self.pending_req and self.clock() < deadline:
            msg = self.conn.recv(min(1.0, max(0.0, deadline - self.clock())))
            if msg is not None:
                self.handle(msg)
        for rid, (name, _) in list(self.pending_req.items()):
            self.subs[name] = {"status": "subscribe_failed", "error": "no answer to subscribe request"}
            del self.pending_req[rid]
        ok = sum(1 for s in self.subs.values() if s["status"] == "ok")
        if not ok:
            raise WsError("no subscription was accepted")
        failed = len(self.subs) - ok
        self.connected, self.connected_at = True, self.clock()
        self.connects += 1
        self.log(f"stream: connected to {self.conn.display}, {ok}/{len(self.subs)} subscription(s) live"
                 + (f", {failed} REJECTED (those changes are seen only by polling)" if failed else ""))

    def serve(self):
        conn = self.conn
        last_ping = self.clock()
        while not self.should_stop():
            now = self.clock()
            waits = [self.ping_interval - (now - last_ping), self.resync_interval - (now - self.last_poll), 5.0]
            if self.dirty_since is not None:
                waits.append(max(self.debounce - (now - self.dirty_since), self.min_gap - (now - self.last_poll),
                                 self.retry_hold_until - now))
            if self.pending_req:
                waits.append(1.0)
            msg = conn.recv(max(0.05, min(waits)))
            if msg is not None:
                self.handle(msg)
            now = self.clock()
            if now - conn.last_frame_at > self.idle_timeout:
                raise WsError(f"no frame (not even a pong) for {int(now - conn.last_frame_at)}s: connection is stale")
            if now - last_ping >= self.ping_interval:
                conn.ping()
                last_ping = now
            self._expire_pending()
            if self.attempt and now - self.connected_at >= self.stable_after:
                self.attempt = 0
            held = now < self.retry_hold_until  # failing: retries back off
            if (self.dirty_since is not None and now - self.dirty_since >= self.debounce
                    and now - self.last_poll >= self.min_gap and not held):
                self.poll("event")
            elif now - self.last_poll >= self.resync_interval and not held:
                self.poll("periodic")

    def backoff(self):
        d = min(self.backoff_max, self.backoff_base * (2 ** self.attempt))
        self.attempt += 1
        return d * (0.5 + 0.5 * self.rand())

    def wait(self, seconds):
        """Sleep before reconnecting, but keep polling: a dead stream must not mean a dead watcher."""
        deadline = self.clock() + seconds
        while not self.should_stop():
            now = self.clock()
            held = now < self.retry_hold_until
            if self.dirty_since is not None and now - self.last_poll >= self.min_gap and not held:
                self.poll("fallback")
            elif now - self.last_poll >= self.resync_interval and not held:
                self.poll("fallback")
            now = self.clock()
            if now >= deadline:
                return
            nxt = min(deadline - now, max(0.05, self.resync_interval - (now - self.last_poll)))
            if self.dirty_since is not None:
                nxt = min(nxt, max(0.05, self.min_gap - (now - self.last_poll), self.retry_hold_until - now))
            self.sleep(nxt)

    def run(self):
        if self.gap is None:
            self.mark_dirty()  # nothing known yet: scan as soon as possible, connected or not
        while not self.should_stop():
            reason = None
            try:
                self.connect_and_subscribe()
                self.poll("resync")  # only AFTER subscriptions are confirmed
                self.serve()
            except WsError as e:
                reason = scrub(str(e))
            finally:
                if self.conn is not None:
                    self.conn.close()
            if self.should_stop():
                break
            now = self.now()
            if self.connected:
                stale_for = max(0.0, self.clock() - self.conn.last_frame_at)
                self._open_gap(_iso(now - _dt.timedelta(seconds=stale_for)), f"disconnected: {reason}")
                if self.clock() - self.connected_at >= self.stable_after:
                    self.attempt = 0
                self.connected = False
                self.log(f"stream: LIVE COVERAGE LOST ({reason}); polling every {int(self.resync_interval)}s until reconnected")
            else:
                self._open_gap(_iso(now), f"stream not connected: {reason}")
                self.log(f"stream: connect failed ({reason})")
            self.mark_dirty()  # scan soon: reports the lost coverage loudly and catches changes near the drop
            delay = self.backoff()
            self.delays.append(delay)
            self.log(f"stream: reconnecting in {delay:.1f}s")
            self.wait(delay)
        return 0
