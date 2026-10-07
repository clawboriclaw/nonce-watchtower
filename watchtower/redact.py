"""Central secret redaction for every channel output can leave by: stdout, stderr, the state file, alert sinks.

Two layers:
  * Registered secrets. Every component that is handed a credential registers it here when it is
    constructed: the RPC and WebSocket URLs (RpcClient, ws.connect, the stream command), the Telegram bot
    token, the Discord and generic webhook URLs. For a URL, the secret-bearing parts are registered: the
    whole URL, its userinfo, query string and each query value, its path and each long path segment
    (providers put API keys in the path). Exact matches are replaced, longest first.
  * Patterns, for text nobody registered (for example a server error that echoes some other URL): any
    URL keeps only scheme://host, a Telegram-shaped bot token is replaced, and `key=value` pairs whose
    key looks like a credential lose their value.

scrub() never raises and is cheap enough to run on every log line and on the serialized state file.
"""

import re
import threading
import urllib.parse

from .base58 import b58decode

MASK = "<redacted>"
_MIN_LEN = 6
_lock = threading.Lock()
_secrets = {}   # secret -> replacement
_ordered = []

_URL_RE = re.compile(r"\b((?:https?|wss?)://)([^\s/?#'\"<>@]*@)?([^\s/?#'\"<>]+)([^\s'\"<>]*)", re.IGNORECASE)
_TG_TOKEN_RE = re.compile(r"\b\d{5,}:[A-Za-z0-9_-]{30,}\b")
# Explicit credential keys: the value is ALWAYS masked, whatever its shape (some providers issue API keys that
# look exactly like a base58 address).
_CREDENTIAL_KEYS = (r"x[-_]api[-_]key|api[-_]?key|apikey|access[-_]?token|auth[-_]?token|refresh[-_]?token|id[-_]?token|"
                    r"client[-_]?secret|secret[-_]?key|secret|password|passwd|pwd|private[-_]?key|bearer")
_DICT_ONLY_CREDENTIAL_KEYS = r"authorization"  # in text, the header rule above handles it
# Ambiguous keys: `token` / `auth` usually carry a credential, but `token=<mint address>` is ordinary text.
# Only for these two, a value that is a public identifier (32/64-byte base58) is left as is.
_AMBIGUOUS_KEYS = r"token|auth"


def _field_re(keys):
    """`key=value`, `key: value`, `key="value"`, `key='value'`, `"key": "value"` (JSON), any case."""
    return re.compile(
        r"(?i)(?P<k>[\"']?\b(?:" + keys + r")\b[\"']?)(?P<sep>\s*[=:]\s*)(?P<q>[\"']?)"
        r"(?P<v>(?:(?<=\")[^\"\r\n]+|(?<=')[^'\r\n]+|(?<![\"'])[^\s\"'&,;}<>]+))(?P=q)")


_KV_CREDENTIAL_RE = _field_re(_CREDENTIAL_KEYS)
_KV_AMBIGUOUS_RE = _field_re(_AMBIGUOUS_KEYS)
_CREDENTIAL_KEY_FULL = re.compile(r"(?i)(?:" + _CREDENTIAL_KEYS + "|" + _DICT_ONLY_CREDENTIAL_KEYS + r")")
_AMBIGUOUS_KEY_FULL = re.compile(r"(?i)(?:" + _AMBIGUOUS_KEYS + r")")
# HTTP auth: `Authorization: Bearer|Basic|Token <value>` (header name any case) and a bare `Bearer <value>`
# (case-sensitive, so prose such as "token account" is untouched): the credential is always masked.
_AUTH_HEADER_RE = re.compile(r"(?i)(?P<h>\bauthorization\b[\"']?\s*[:=]\s*[\"']?)(?P<s>(?:bearer|basic|token)\s+)?"
                             r"(?P<v>(?!<redacted>)[^\s\"',;}<>]+)")
_BEARER_RE = re.compile(r"\bBearer(\s+)(?!<redacted>)([A-Za-z0-9._~+/=:-]{6,})")
_BASE58_ALPHABET = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


def is_chain_identifier(text):
    """True for a public on-chain identifier: base58 that decodes to 32 bytes (address) or 64 (signature).
    Such a value is never masked on its own, wherever it appears."""
    if not isinstance(text, str) or not (32 <= len(text) <= 88) or not set(text) <= _BASE58_ALPHABET:
        return False
    try:
        return len(b58decode(text)) in (32, 64)
    except ValueError:
        return False
_WEBHOOK_PATH_RE = re.compile(r"/api/webhooks/\d+/[A-Za-z0-9_.-]+")


def register(*values, replacement=MASK):
    """Register literal secrets. Short or empty values are ignored (they would mask ordinary text)."""
    global _ordered
    added = False
    with _lock:
        for v in values:
            # A public identifier is never a bare secret: masking it would hide (or, in the state file, rewrite)
            # an address. Such a fragment is only masked in context (inside its URL or key=value pair).
            if isinstance(v, str) and len(v) >= _MIN_LEN and v not in _secrets and not is_chain_identifier(v):
                # Boundaries: never replace inside a longer alphanumeric run (for example inside an address).
                pre = r"(?<![A-Za-z0-9])" if v[0].isalnum() else ""
                post = r"(?![A-Za-z0-9])" if v[-1].isalnum() else ""
                _secrets[v] = (re.compile(pre + re.escape(v) + post), replacement)
                added = True
        if added:
            _ordered = [rx for _, rx in sorted(_secrets.items(), key=lambda kv: len(kv[0]), reverse=True)]


def register_url(url):
    """Register the secret-bearing parts of a URL. A URL with no path, query or userinfo registers nothing."""
    if not isinstance(url, str) or not url:
        return
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        register(url)
        return
    host = p.hostname or "?"
    contextual, bare = [], []
    if p.username or p.password:
        contextual.append(p.netloc.rsplit("@", 1)[0] + "@")  # user:pass@
        bare += [p.password or ""]
    if p.query:
        contextual.append("?" + p.query)
        for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True):
            if not is_chain_identifier(v):  # `mint=<address>` outside the URL is ordinary text
                contextual.append(f"{k}={v}")
            bare.append(v)
    if p.path not in ("", "/"):
        contextual.append(host + p.path)  # host-anchored: only matches the URL itself
        if not any(is_chain_identifier(seg) for seg in p.path.split("/")):
            contextual.append(p.path + ("?" + p.query if p.query else ""))
        # Key-like segments: long, or mixing letters and digits (so words such as "webhooks" stay readable).
        bare += [seg for seg in p.path.split("/")
                 if len(seg) >= 16 or (len(seg) >= 8 and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg))]
    if contextual or bare:
        # The whole URL collapses to scheme://host, so diagnostics keep the host and lose the credential.
        register(url, replacement=f"{p.scheme}://{host}/{MASK}")
        register(*contextual)
        # Bare fragments only when they are credential-shaped: never digits only (an id, would mask numbers) and
        # never a public on-chain identifier (register() refuses those).
        register(*[x for x in bare if not x.isdigit()])


def _url_sub(m):
    scheme, _userinfo, host, rest = m.group(1), m.group(2), m.group(3), m.group(4)
    return f"{scheme}{host}" + ("/" + MASK if rest not in ("", "/") else rest)


def _mask_field(m):
    if m.group("v") == MASK:
        return m.group(0)
    return f"{m.group('k')}{m.group('sep')}{m.group('q')}{MASK}{m.group('q')}"


def scrub(text, literals=True):
    """Return `text` (any object, stringified) with every known and pattern-matched secret masked."""
    try:
        s = text if isinstance(text, str) else str(text)
    except Exception:
        return MASK
    if literals:
        for rx, rep in _ordered:
            s = rx.sub(lambda _m, r=rep: r, s)
    s = _URL_RE.sub(_url_sub, s)
    s = _WEBHOOK_PATH_RE.sub("/api/webhooks/" + MASK, s)
    s = _TG_TOKEN_RE.sub(MASK, s)
    s = _AUTH_HEADER_RE.sub(lambda m: f"{m.group('h')}{m.group('s') or ''}{MASK}", s)
    s = _BEARER_RE.sub(lambda m: f"Bearer{m.group(1)}{MASK}", s)
    s = _KV_CREDENTIAL_RE.sub(_mask_field, s)
    s = _KV_AMBIGUOUS_RE.sub(lambda m: m.group(0) if is_chain_identifier(m.group("v")) else _mask_field(m), s)
    return s


def scrub_obj(obj):
    """Deep copy of a JSON-like object with every string (keys included) scrubbed. Numbers are left intact,
    so a serialized state file can never be corrupted by masking."""
    if isinstance(obj, str):
        return scrub(obj)
    if isinstance(obj, dict):
        # Keys are identities (addresses, check names): pattern-only scrubbing, which cannot touch a bare address.
        # A VALUE under a credential key is masked whole (token/auth: unless it is an address or signature).
        return {scrub(k, literals=False) if isinstance(k, str) else k: _scrub_value(k, v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub_obj(v) for v in obj]
    return obj


def _scrub_value(key, value):
    if isinstance(key, str) and value is not None:
        k = key.strip()
        if _CREDENTIAL_KEY_FULL.fullmatch(k):
            return MASK
        if _AMBIGUOUS_KEY_FULL.fullmatch(k) and not (isinstance(value, str) and is_chain_identifier(value)):
            return MASK
    return scrub_obj(value)


def exc_text(exc, limit=300):
    """`Type: message` of an exception, scrubbed. Use this wherever exception text is built."""
    return scrub(f"{type(exc).__name__}: {exc}")[:limit]
