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
from .redact import register_url

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
        # Absolute freshness: the wall-clock time of the finalized reference slot.
        "getBlockTime",
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


class RpcStale(RpcUnavailable):
    """The node answered, but the answer cannot be shown to be current (lagging index, no context slot)."""


# Reads whose answer is checked for freshness against the endpoint's own finalized slot.
FRESHNESS_COMMITMENT = "finalized"
DEFAULT_MAX_SLOT_LAG = 64      # ~25 s of slots; configurable (max_slot_lag / --max-slot-lag)
DEFAULT_MAX_BLOCK_AGE = 120    # seconds; configurable (max_block_age / --max-block-age)
_CFG_INDEX = {"getProgramAccounts": 1, "getAccountInfo": 1, "getMultipleAccounts": 1, "getTokenAccountsByOwner": 2}


class FreshnessGuard:
    """Wraps an RpcClient so that no state read is trusted unless it is provably recent.

    Every state read (getProgramAccounts, getAccountInfo, getMultipleAccounts, getTokenAccountsByOwner) is made at
    `finalized` commitment with its context slot. Immediately before EACH read the guard takes a fresh reference:
      1. getSlot (finalized) from the same endpoint. The answer's context slot may lag it by at most
         `max_slot_lag` slots. This catches an index that lags its own node.
      2. Absolute age: getBlockTime(reference slot) from the same endpoint vs this machine's clock. The finalized
         reference may be at most `max_block_age` seconds old. This catches a node that is uniformly behind the
         chain (its slot and its index agree with each other, but both are old). A verified age is reused while
         `verified_age + elapsed` stays inside the limit and the reference slot has not gone backwards, since a
         newer slot can only be younger.
      3. Optional independent `reference` RPC: its finalized getSlot may lead the primary's reference by at most
         `max_slot_lag` slots. This catches a node that lies about time as well as slots, if the two endpoints do
         not share the fault.
    Any failure (no context slot, a failed getSlot/getBlockTime, a limit exceeded) raises RpcStale, which callers
    turn into an `unverified`/`unavailable` check: a coverage gap, never "nothing found".
    What it does not prove: an endpoint that fabricates consistent, current-looking slots and block times AND
    omits accounts passes 1 and 2; only an independent reference (3) narrows that, and only if it is honest.
    getProgramAccounts results are unwrapped back to the plain list callers expect.
    """

    def __init__(self, client, max_slot_lag=DEFAULT_MAX_SLOT_LAG, max_block_age=DEFAULT_MAX_BLOCK_AGE, reference=None,
                 clock=time.time, monotonic=time.monotonic):
        self._client = client
        self.max_slot_lag = max_slot_lag
        self.max_block_age = max_block_age
        self.reference = reference
        self.clock, self.monotonic = clock, monotonic
        self.ref_slot = None
        self._age_ok = None  # (slot, verified age in s, monotonic time of the check)

    def __getattr__(self, name):
        return getattr(self._client, name)

    def _slot_of(self, client, who):
        try:
            slot = client.call("getSlot", [{"commitment": FRESHNESS_COMMITMENT}])
        except (RpcError, RpcUnavailable) as e:
            raise RpcStale("getSlot", f"cannot read the {who} {FRESHNESS_COMMITMENT} slot to verify freshness "
                                      f"({type(e).__name__})") from None
        if not isinstance(slot, int) or isinstance(slot, bool):
            raise RpcStale("getSlot", f"{who} getSlot returned no slot number; freshness cannot be verified")
        return slot

    def _check_age(self, slot):
        if self.max_block_age is None:
            return
        now_m = self.monotonic()
        if self._age_ok is not None:
            vslot, vage, vat = self._age_ok
            if slot >= vslot and vage + (now_m - vat) <= self.max_block_age:
                return
        try:
            bt = self._client.call("getBlockTime", [slot])
        except (RpcError, RpcUnavailable) as e:
            raise RpcStale("getBlockTime", f"cannot read the time of finalized slot {slot} to verify freshness "
                                           f"({type(e).__name__})") from None
        if not isinstance(bt, (int, float)) or isinstance(bt, bool):
            raise RpcStale("getBlockTime", f"no block time for finalized slot {slot}; freshness cannot be verified")
        age = self.clock() - bt
        if age > self.max_block_age:
            raise RpcStale("getBlockTime", f"the endpoint's finalized slot {slot} is {int(age)}s old (limit "
                                           f"{self.max_block_age}s): the node is behind the chain, results not trusted")
        self._age_ok = (slot, max(age, 0.0), now_m)

    def reference_slot(self):
        slot = self._slot_of(self._client, "endpoint's")
        self._check_age(slot)
        if self.reference is not None:
            other = self._slot_of(self.reference, "reference RPC's")
            if other - slot > self.max_slot_lag:
                raise RpcStale("getSlot", f"the endpoint's finalized slot is {other - slot} slots behind the reference "
                                          f"RPC (limit {self.max_slot_lag}): results not trusted")
        self.ref_slot = slot
        return slot

    def call(self, method, params):
        idx = _CFG_INDEX.get(method)
        if idx is None:
            return self._client.call(method, params)
        params = list(params)
        while len(params) <= idx:
            params.append({})
        cfg = dict(params[idx] or {})
        cfg["commitment"] = FRESHNESS_COMMITMENT
        if method == "getProgramAccounts":
            cfg["withContext"] = True
        params[idx] = cfg
        ref = self.reference_slot()  # fresh before EVERY guarded read, never reused
        res = self._client.call(method, params)
        ctx = (res.get("context") or {}).get("slot") if isinstance(res, dict) else None
        if not isinstance(ctx, int) or isinstance(ctx, bool):
            raise RpcStale(method, "answer carries no context slot, so its freshness cannot be verified")
        lag = ref - ctx
        if lag > self.max_slot_lag:
            raise RpcStale(method, f"answer is {lag} slots behind the endpoint's {FRESHNESS_COMMITMENT} slot (limit "
                                   f"{self.max_slot_lag}): stale or lagging index, result not trusted")
        if method == "getProgramAccounts":
            if "value" not in res:
                raise RpcStale(method, "context-wrapped answer has no value")
            return res["value"]
        return res


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
        register_url(url)  # whatever this client does, its URL never reaches output
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
