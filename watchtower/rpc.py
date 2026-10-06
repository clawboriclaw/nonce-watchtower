"""Read-only Solana JSON-RPC client.

Security properties (enforced here, tested in tests/test_rpc.py):
  * Only methods in READ_ONLY_METHODS can be called. There is no code path that
    can sign or submit a transaction; sendTransaction / simulateTransaction /
    requestAirdrop are rejected before any network I/O.
  * The RPC URL is treated as a secret (provider URLs embed API keys). It is
    never printed; errors show only scheme://host.
  * Responses are size-capped to bound memory.
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
RPC_ENV_VAR = "WATCHTOWER_RPC_URL"

READ_ONLY_METHODS = frozenset(
    {
        "getProgramAccounts",
        "getTokenAccountsByOwner",
        "getAccountInfo",
        "getMultipleAccounts",
        "getSlot",
        # History reads for nonce provenance (who created the account).
        "getSignaturesForAddress",
        "getTransaction",
    }
)

MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class RpcError(Exception):
    """The node answered, but with a JSON-RPC error."""

    def __init__(self, method, code, message):
        super().__init__(f"{method}: RPC error {code}: {message}")
        self.method = method
        self.code = code
        self.message = message


class RpcUnavailable(Exception):
    """Transport-level failure: HTTP error, timeout, refusal, oversize body."""

    def __init__(self, method, reason, http_status=None):
        super().__init__(f"{method}: {reason}")
        self.method = method
        self.reason = reason
        self.http_status = http_status


def redact_url(url: str) -> str:
    """scheme://host only. Paths and query strings often carry API keys."""
    try:
        p = urllib.parse.urlsplit(url)
        host = p.hostname or "?"
        return f"{p.scheme}://{host}" + ("/…" if (p.path not in ("", "/") or p.query) else "")
    except ValueError:
        return "<unparseable url>"


def validate_http_url(url: str, what: str, allow_http: bool = False) -> str:
    p = urllib.parse.urlsplit(url)
    allowed = ("https", "http") if allow_http else ("https",)
    if p.scheme not in allowed or not p.hostname:
        raise ValueError(
            f"{what} must be an {'http(s)' if allow_http else 'https'} URL (got {redact_url(url)})"
        )
    return url


class RpcClient:
    def __init__(self, url=DEFAULT_RPC, timeout=60.0, transport=None, retries=2):
        """`transport(method, params) -> dict` replaces the network (used by tests)."""
        if transport is None:
            # Plain http is allowed only for localhost nodes.
            host = urllib.parse.urlsplit(url).hostname or ""
            validate_http_url(url, "RPC URL", allow_http=host in ("localhost", "127.0.0.1", "::1"))
        self.url = url
        self.timeout = timeout
        self.retries = retries
        self._transport = transport
        self._id = 0

    @property
    def display(self) -> str:
        return redact_url(self.url) if self._transport is None else "<fixture>"

    def call(self, method, params):
        if method not in READ_ONLY_METHODS:
            raise PermissionError(f"refusing non-read-only RPC method {method!r}")
        if self._transport is not None:
            resp = self._transport(method, params)
        else:
            resp = self._http(method, params)
        if not isinstance(resp, dict):
            raise RpcUnavailable(method, "malformed JSON-RPC response")
        if "error" in resp and resp["error"] is not None:
            err = resp["error"]
            raise RpcError(method, err.get("code"), str(err.get("message", ""))[:500])
        if "result" not in resp:
            raise RpcUnavailable(method, "JSON-RPC response has no result")
        return resp["result"]

    def _http(self, method, params):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": f"nonce-watchtower/{__version__}"},
        )
        last = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    raw = r.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise RpcUnavailable(method, "response exceeded size cap")
                return json.loads(raw)
            except urllib.error.HTTPError as e:
                last = RpcUnavailable(method, f"HTTP {e.code} from {self.display}", e.code)
                # Some nodes put a JSON-RPC error inside a non-200 body. Transient codes are retried
                # first; only a non-retryable status surfaces that body as the answer.
                if e.code not in (429, 502, 503, 504):
                    try:
                        payload = json.loads(e.read(65536))
                        if isinstance(payload, dict) and payload.get("error"):
                            return payload
                    except Exception:
                        pass
                if e.code not in (429, 502, 503, 504):
                    raise last from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                reason = getattr(e, "reason", e)
                last = RpcUnavailable(method, f"network error talking to {self.display}: {type(reason).__name__}")
            except json.JSONDecodeError:
                raise RpcUnavailable(method, f"non-JSON response from {self.display}") from None
            if attempt < self.retries:
                time.sleep(2 * (attempt + 1))
        raise last
