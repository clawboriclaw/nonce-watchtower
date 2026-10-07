"""Native alert delivery: Telegram and Discord, plus the generic JSON webhook.

Rules (tested in tests/test_notify.py):
  * Secrets (bot token, webhook URLs) come from environment variables named in the config,
    never from the config file itself. They are never printed: a sink's repr, every status
    message and every exception text show only the sink name and an HTTP status.
  * Delivery is at-least-once per sink. Alerts that could not be delivered stay queued in
    the state file (per sink) and are retried next cycle. A sink that fails never blocks
    the others, and its failure is surfaced on stderr, through the sinks that still work,
    and in `watch --once`'s exit code.
  * Duplicates are suppressed per sink: an alert whose content (everything except its
    timestamp) was delivered within `dedup_seconds` is not sent again. stdout always gets
    every alert.
  * Nothing is dropped for being long: alerts are split over several messages. At most
    `max_messages` messages go out per sink per cycle; the rest stay queued (that is a
    backlog, not a failure).
"""

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__
from .alerts import format_alert, post_webhook
from .redact import register, register_url, scrub
from .rpc import validate_http_url

TELEGRAM_TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{30,}$")
TELEGRAM_CHAT_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")
DISCORD_HOSTS = ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com")
RETRYABLE = (429, 500, 502, 503, 504)
MAX_PENDING = 500
DEFAULT_DEDUP_SECONDS = 1800
MAX_RETRY_AFTER = 30.0
TAIL_RESERVE = 80  # chars kept free in each message for the "+N more" tail


class SinkConfigError(ValueError):
    pass


def dedup_key(alert):
    """Content identity of an alert: everything except when it was raised."""
    body = {k: v for k, v in alert.items() if k != "at"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:24]


def _line(alert, stamp):
    s = format_alert(alert)
    if stamp and alert.get("at") and alert["at"] != stamp:
        s += f" (raised {alert['at']}, delivery was delayed)"
    return s


def chunk_lines(lines, limit, header):
    """Pack lines into messages of at most `limit` chars; an over-long line is hard-split, never dropped."""
    msgs, cur = [], header
    for ln in lines:
        pieces = [ln[i: i + limit - len(header) - 1] for i in range(0, len(ln), limit - len(header) - 1)] or [""]
        for p in pieces:
            if len(cur) + 1 + len(p) > limit:
                msgs.append(cur)
                cur = header
            cur += "\n" + p
    if cur != header:
        msgs.append(cur)
    return msgs


class _HttpSink:
    """Shared retry loop for chat sinks. Subclasses build the request and judge the response."""

    name = "?"
    limit = 2000

    def __init__(self, opener=None, sleep=time.sleep, timeout=10.0, attempts=3, max_messages=10):
        self._opener = opener or urllib.request.urlopen
        self._sleep = sleep
        self.timeout = timeout
        self.attempts = attempts
        self.max_messages = max_messages

    def __repr__(self):
        return f"<{type(self).__name__} {self.name}>"

    def _request(self, text):  # pragma: no cover - abstract
        raise NotImplementedError

    def _scrub(self, msg):
        for s in self._secrets():
            if s:
                msg = msg.replace(s, "<redacted>")
        return scrub(msg)

    def _secrets(self):
        return ()

    def send_text(self, text):
        """(ok, message). Retries transient failures (network, 429, 5xx); a 4xx answer fails at once."""
        last = "not attempted"
        text = scrub(text)  # nothing exception-derived leaves through a chat sink unscrubbed
        for attempt in range(self.attempts):
            wait = min(2 ** attempt, 8)
            try:
                with self._opener(self._request(text), timeout=self.timeout) as r:
                    status = getattr(r, "status", 200)
                    body = r.read(65536) if hasattr(r, "read") else b""
                ok, why = self._judge(status, body)
                if ok:
                    return True, f"{self.name} -> HTTP {status}"
                return False, self._scrub(f"{self.name} -> HTTP {status}: {why}")
            except urllib.error.HTTPError as e:
                try:
                    body = e.read(65536)
                except Exception:
                    body = b""
                last = self._scrub(f"{self.name} -> HTTP {e.code}{self._hint(e.code, body)}")
                if e.code not in RETRYABLE:
                    return False, last
                ra = self._retry_after(e, body)
                if ra is not None:
                    wait = min(ra, MAX_RETRY_AFTER)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = f"{self.name} failed: {type(getattr(e, 'reason', e)).__name__}"
            if attempt < self.attempts - 1:
                self._sleep(wait)
        return False, f"{last} (after {self.attempts} attempts)"

    def _judge(self, status, body):
        return 200 <= status < 300, ""

    def _hint(self, code, body):
        return ""

    @staticmethod
    def _retry_after(err, body):
        try:
            v = json.loads(body or b"{}")
            ra = v.get("retry_after", (v.get("parameters") or {}).get("retry_after"))
            if ra is not None:
                return float(ra)
        except (ValueError, AttributeError, TypeError):
            pass
        try:
            h = err.headers.get("Retry-After") if err.headers else None
            return float(h) if h else None
        except (TypeError, ValueError):
            return None

    def deliver(self, alerts, stamp=None):
        """Send `alerts`. Returns (ok, message, delivered_alerts). Undelivered ones are the caller's to queue.

        `max_messages` caps real HTTP sends (send_text calls) per call, counting every piece of a hard-split
        line. Alerts are only ever held whole: a group whose pieces would cross the cap waits for the next
        cycle. The one exception is a single group that alone needs more than the cap: it is sent whole
        when it comes first, because otherwise it could never be delivered.
        """
        if not alerts:
            return True, "nothing to send", []
        lines = [_line(a, stamp) for a in alerts]
        header = f"nonce-watchtower {__version__}: {len(alerts)} alert(s)"
        budget = self.limit - TAIL_RESERVE
        # Map each message back to the alerts it carries so a mid-batch failure re-queues only the rest.
        groups, cur, cur_len = [], [], len(header)
        for a, ln in zip(alerts, lines):
            add = 1 + len(ln)
            if cur and cur_len + add > budget:
                groups.append(cur)
                cur, cur_len = [], len(header)
            cur.append((a, ln))
            cur_len += add
        if cur:
            groups.append(cur)
        delivered, sends = [], 0
        for i, g in enumerate(groups):
            texts = chunk_lines([ln for _, ln in g], budget, header)
            if sends and sends + len(texts) > self.max_messages:
                left = sum(len(x) for x in groups[i:])
                return True, f"{self.name}: {left} alert(s) held for the next cycle (message cap)", delivered
            more = sum(len(x) for x in groups[i + 1:])
            for j, t in enumerate(texts):
                tail = f"\n(+{more} more alert(s) in following messages or the next cycle)" if more and j == len(texts) - 1 else ""
                ok, msg = self.send_text(t + tail)
                sends += 1
                if not ok:
                    return False, msg, delivered
            delivered.extend(a for a, _ in g)
        return True, f"{self.name}: {len(delivered)} alert(s) in {sends} message(s)", delivered


class TelegramSink(_HttpSink):
    name = "telegram"
    limit = 4096
    API = "https://api.telegram.org"

    def __init__(self, token, chat_id, thread_id=None, **kw):
        super().__init__(**kw)
        if not isinstance(token, str) or not TELEGRAM_TOKEN_RE.match(token):
            raise SinkConfigError("Telegram bot token is malformed (expected <digits>:<secret> from @BotFather)")
        if not TELEGRAM_CHAT_RE.match(str(chat_id)):
            raise SinkConfigError("Telegram chat id is malformed (expected a numeric id or @channelname)")
        register(token)
        self._token = token
        self.chat_id = str(chat_id)
        self.thread_id = None
        if thread_id is not None and str(thread_id).strip() != "":
            t = str(thread_id).strip()
            if not (t.isdigit() and t.isascii() and int(t) > 0 and len(t) <= 19):
                raise SinkConfigError("Telegram thread id must be a positive integer (the forum topic's message_thread_id)")
            self.thread_id = int(t)

    def _secrets(self):
        return (self._token,)

    def _request(self, text):
        msg = {"chat_id": self.chat_id, "text": text, "disable_web_page_preview": True}
        if self.thread_id is not None:
            msg["message_thread_id"] = self.thread_id  # forum topic; on every message, direct or queued
        body = json.dumps(msg).encode()
        return urllib.request.Request(
            f"{self.API}/bot{self._token}/sendMessage", data=body, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": f"nonce-watchtower/{__version__}"},
        )

    def _judge(self, status, body):
        try:
            v = json.loads(body or b"{}")
        except ValueError:
            return False, "non-JSON answer"
        if v.get("ok") is True:
            return True, ""
        return False, str(v.get("description", "Telegram answered ok=false"))[:200]

    def _hint(self, code, body):
        return {401: " (bot token rejected)", 400: " (bad chat id, or bot not in that chat)",
                403: " (bot was blocked or removed from the chat)", 404: " (bot token rejected)"}.get(code, "")


class DiscordSink(_HttpSink):
    name = "discord"
    limit = 2000

    def __init__(self, webhook_url, **kw):
        super().__init__(**kw)
        try:
            validate_http_url(webhook_url, "Discord webhook URL")
        except ValueError:
            raise SinkConfigError("Discord webhook URL must be https") from None
        p = urllib.parse.urlsplit(webhook_url)
        if p.hostname not in DISCORD_HOSTS or not p.path.startswith("/api/webhooks/"):
            raise SinkConfigError("Discord webhook URL must look like https://discord.com/api/webhooks/<id>/<token>")
        register_url(webhook_url)
        self._url = webhook_url

    def _secrets(self):
        return (self._url, urllib.parse.urlsplit(self._url).path)

    def _request(self, text):
        # allowed_mentions: on-chain data must never be able to ping @everyone.
        body = json.dumps({"content": text, "allowed_mentions": {"parse": []}}).encode()
        return urllib.request.Request(
            self._url, data=body, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": f"nonce-watchtower/{__version__}"},
        )

    def _hint(self, code, body):
        return {401: " (webhook token rejected)", 404: " (webhook deleted or URL wrong)"}.get(code, "")


class WebhookSink:
    """The original generic JSON webhook (Slack-compatible `text`, Discord `content`, `alerts` array)."""

    name = "webhook"

    def __init__(self, url, post=None):
        register_url(url)
        self._url = url
        self._post = post or post_webhook

    def __repr__(self):
        return "<WebhookSink webhook>"

    def deliver(self, alerts, stamp=None):
        if not alerts:
            return True, "nothing to send", []
        ok, msg = self._post(self._url, alerts)
        return ok, msg, (list(alerts) if ok else [])


def build_sinks(cfg, environ, webhook=None, webhook_post=None, opener=None, sleep=time.sleep):
    """Sinks configured through env vars named in `cfg`. A half-configured sink is an error, not 'off'."""
    sinks = []
    if webhook:
        sinks.append(WebhookSink(webhook, post=webhook_post))
    tok = environ.get(cfg["telegram_bot_token_env"])
    chat = cfg.get("telegram_chat_id") or environ.get(cfg["telegram_chat_id_env"])
    thread = environ.get(cfg["telegram_thread_id_env"])
    if thread and not (tok or chat):
        raise SinkConfigError(f"{cfg['telegram_thread_id_env']} is set but Telegram is not configured (bot token + chat id)")
    if tok or chat:
        if not (tok and chat):
            missing = cfg["telegram_bot_token_env"] if not tok else f"{cfg['telegram_chat_id_env']} (or telegram_chat_id)"
            raise SinkConfigError(f"Telegram is half-configured: {missing} is not set, so Telegram alerts would never arrive")
        sinks.append(TelegramSink(tok, chat, thread_id=thread, opener=opener, sleep=sleep))
    dis = environ.get(cfg["discord_webhook_url_env"])
    if dis:
        sinks.append(DiscordSink(dis, opener=opener, sleep=sleep))
    return sinks


def _parse_iso(s):
    import datetime as _dt
    try:
        return _dt.datetime.fromisoformat(s).timestamp()
    except (TypeError, ValueError):
        return None


OVERFLOW_KIND = "alert_queue_overflow"


def trim_queue(queue, sink_name, stamp, limit=None):
    """Bound a sink's queue WITHOUT silent loss. Returns (queue, dropped_now).

    Over `limit`, the oldest non-critical alerts go first, critical ones only if nothing else is left.
    Everything dropped is replaced by ONE overflow alert (critical if any critical alert was dropped),
    which merges with an earlier one, sits at the front of the queue and is never itself trimmed.
    """
    limit = MAX_PENDING if limit is None else limit
    prior = [a for a in queue if a.get("kind") == OVERFLOW_KIND]
    rest = [a for a in queue if a.get("kind") != OVERFLOW_KIND]
    excess = len(rest) - limit
    if excess <= 0:
        return prior + rest, 0
    drop = set()
    for want_critical in (False, True):  # rest is oldest-first: walk from the front
        for i, a in enumerate(rest):
            if len(drop) >= excess:
                break
            if (a.get("severity") == "critical") == want_critical:
                drop.add(i)
    dropped = [rest[i] for i in sorted(drop)]
    kept = [a for i, a in enumerate(rest) if i not in drop]
    count = len(dropped) + sum(int(p.get("dropped", 0)) for p in prior)
    times = [a.get("at") for a in dropped if a.get("at")] + [p.get("oldest_dropped") for p in prior if p.get("oldest_dropped")]
    oldest = min(times) if times else None
    any_critical = any(a.get("severity") == "critical" for a in dropped) or any(p.get("severity") == "critical" for p in prior)
    kinds = sorted({a.get("kind") for a in dropped} | {k for p in prior for k in p.get("dropped_kinds", [])})
    overflow = {
        "severity": "critical" if any_critical else "high", "kind": OVERFLOW_KIND, "subject": sink_name, "at": stamp,
        "detail": f"{count} alert(s) for {sink_name} were DROPPED (queue overflow while it could not deliver), oldest "
                  f"raised at {oldest}. They are still in stdout/the journal; review them there. Kinds: {', '.join(kinds)}",
        "dropped": count, "oldest_dropped": oldest, "dropped_kinds": kinds,
    }
    return [overflow] + kept, len(dropped)


def deliver_direct(sinks, alerts, stamp):
    """Best-effort send that bypasses queues and state (used when the cycle itself failed).

    Returns {sink name: (ok, message)}. Never raises.
    """
    out = {}
    for s in sinks:
        try:
            ok, msg, _ = s.deliver(list(alerts), stamp)
        except Exception as e:  # a sink bug must not hide the failure we are reporting
            ok, msg = False, f"{s.name} failed: {type(e).__name__}"
        msg = scrub(msg)
        out[s.name] = (ok, msg)
    return out


def subject_key(alert):
    return json.dumps([alert.get("subject"), alert.get("wallet")])


def _admit(ledger, alert, stamp, now, window):
    """Dedup decision for one NEW alert on one sink; records it as the subject's latest alert either way.

    Suppressed only if ALL hold: it is not critical; it is byte-identical (apart from its timestamp) to the
    LATEST alert this sink saw for the same subject (so A -> B -> A re-fires: B is in between); and that
    latest alert is younger than `window` seconds. Everything else is sent.
    """
    k, sk = dedup_key(alert), subject_key(alert)
    last = ledger.get(sk)
    fresh = isinstance(last, list) and len(last) == 2 and (_parse_iso(last[1]) or 0) > now - max(window, 0)
    ledger[sk] = [k, stamp]
    if alert.get("severity") == "critical":
        return True
    return not (fresh and last[0] == k)


def deliver_all(sinks, alerts, state, stamp, dedup_seconds=DEFAULT_DEDUP_SECONDS, now=None):
    """Deliver new `alerts` plus each sink's queue. Mutates `state` (`pending_<sink>`, `delivered`).

    Returns (failures, notes, held): failure strings for sinks that did not accept what they were sent,
    informational notes (duplicates suppressed, backlog held by the message cap), and {sink: count} of
    alerts still queued for a sink that did not fail (message cap backlog).
    Queued alerts were already admitted in an earlier cycle and are not deduplicated again.
    """
    now = time.time() if now is None else now
    ledger_all = state.setdefault("delivered", {})
    failures, working, notes, held = [], [], [], {}
    for sink in sinks:
        pkey = f"pending_{sink.name}"
        raw = ledger_all.get(sink.name)
        ledger = {k: v for k, v in (raw or {}).items() if isinstance(v, list)}  # drops the pre-0.3.0 format
        to_send, suppressed = list(state.get(pkey) or []), 0
        for a in alerts:
            if _admit(ledger, a, stamp, now, dedup_seconds):
                to_send.append(a)
            else:
                suppressed += 1
        ok, msg, sent = sink.deliver(to_send, stamp)
        sent_ids = {id(a) for a in sent}
        ledger_all[sink.name] = ledger
        state[pkey], dropped = trim_queue([a for a in to_send if id(a) not in sent_ids], sink.name, stamp)
        if dropped:
            failures.append((sink, f"{sink.name}: {dropped} queued alert(s) DROPPED (queue overflow, limit {MAX_PENDING}); "
                                   f"an {OVERFLOW_KIND} alert replaces them"))
        if not ok:
            failures.append((sink, f"{msg}; {len(state[pkey])} alert(s) queued for retry"))
        else:
            working.append(sink)
            if state[pkey]:
                notes.append(msg)
                held[sink.name] = len(state[pkey])
        if suppressed:
            notes.append(f"{sink.name}: {suppressed} unchanged repeat alert(s) suppressed")
    # Surface each failure through the sinks that still work (deduplicated like any alert).
    if failures and working:
        notices = [{"severity": "warn", "kind": "alert_delivery_failed", "subject": s.name, "at": stamp,
                    "detail": f"alerts are NOT reaching {s.name}: {m.split(';')[0]}. They are queued and retried "
                              "each cycle."}
                   for s, m in failures]
        for sink in working:
            ledger = ledger_all.setdefault(sink.name, {})
            fresh = [n for n in notices if _admit(ledger, n, stamp, now, dedup_seconds)]
            sink.deliver(fresh, stamp)
    return [m for _, m in failures], notes, held
