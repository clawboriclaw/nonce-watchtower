"""Alert sinks: stdout (always) and an optional webhook POST.

The webhook URL is a secret (Slack/Discord URLs are bearer credentials): it must
be https, it is never printed, and failures are reported without it.
"""

import json
import sys
import urllib.error
import urllib.request

from . import __version__
from .rpc import redact_url, validate_http_url

SEV_MARK = {"critical": "CRIT", "high": "HIGH", "warn": "WARN", "medium": "MED ", "info": "info"}


def format_alert(a):
    who = f" [{a['wallet']}]" if a.get("wallet") else ""
    change = ""
    if "before" in a or "after" in a:
        change = f" ({a.get('before')} -> {a.get('after')})"
    base = " (baseline)" if a.get("baseline") else ""
    return f"{SEV_MARK.get(a['severity'], a['severity'])} {a['kind']}{base}{who} {a['subject']}: {a['detail']}{change}"


def emit_stdout(alerts, as_json=False, stream=None):
    stream = stream or sys.stdout
    for a in alerts:
        stream.write((json.dumps(a, sort_keys=True) if as_json else format_alert(a)) + "\n")
    stream.flush()


def webhook_payload(alerts, max_lines=25):
    lines = [format_alert(a) for a in alerts[:max_lines]]
    if len(alerts) > max_lines:
        lines.append(f"... and {len(alerts) - max_lines} more")
    text = "nonce-watchtower:\n" + "\n".join(lines)
    # `text` = Slack, `content` = Discord (2000-char cap); `alerts` = machine-readable.
    return {"text": text, "content": text[:1990], "alerts": alerts}


def post_webhook(url, alerts, timeout=10.0, opener=None):
    """Returns (ok: bool, message: str). Never raises, never echoes the URL path/query."""
    if not alerts:
        return True, "nothing to send"
    try:
        validate_http_url(url, "webhook URL")
    except ValueError as e:
        return False, str(e)
    body = json.dumps(webhook_payload(alerts)).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"nonce-watchtower/{__version__}"},
    )
    try:
        with (opener or urllib.request.urlopen)(req, timeout=timeout) as r:
            return True, f"webhook {redact_url(url)} -> HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"webhook {redact_url(url)} -> HTTP {e.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return False, f"webhook {redact_url(url)} failed: {type(getattr(e, 'reason', e)).__name__}"
