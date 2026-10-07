"""Minimal read-only WebSocket (RFC 6455) client for Solana PubSub. Stdlib only.

Why not a library: the package has no third-party dependencies, so the supply chain is
CPython alone. This client implements only what Solana's PubSub endpoint needs: the
opening handshake (with Sec-WebSocket-Accept verification), masked client text frames,
ping/pong, close, fragmented messages, and a per-message size cap. No extensions
(permessage-deflate) are requested, so the server must not use them.

Security properties (tested in tests/test_ws.py):
  * Only subscription methods in READ_ONLY_WS_METHODS can be sent; anything else raises
    before any I/O. PubSub cannot submit transactions anyway, but the guard keeps the
    "read-only by construction" rule uniform with the HTTP client.
  * The URL is a secret (provider URLs embed API keys): only scheme://host is ever shown.
  * Plain ws:// is allowed only for localhost nodes.
"""

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import time
import urllib.parse

from . import __version__
from .redact import register_url
from .rpc import redact_url

WS_ENV_VAR = "WATCHTOWER_WS_URL"

READ_ONLY_WS_METHODS = frozenset(
    {
        "accountSubscribe",
        "accountUnsubscribe",
        "programSubscribe",
        "programUnsubscribe",
        "logsSubscribe",
        "logsUnsubscribe",
    }
)

MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_HANDSHAKE_BYTES = 16 * 1024
_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


class WsError(Exception):
    """Connection-level failure (handshake, protocol violation, closed, network). Message has no secrets."""


class WsClosed(WsError):
    pass


def validate_ws_url(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    host = p.hostname or ""
    allowed = ("wss", "ws") if host in LOCAL_HOSTS else ("wss",)
    if p.scheme not in allowed or not host:
        raise ValueError(f"WebSocket URL must be wss:// (ws:// only for localhost) (got {redact_url(url)})")
    return url


def derive_ws_url(rpc_url: str) -> str:
    """https://host/path?q -> wss://host/path?q. A local node's default RPC port 8899 maps to PubSub port 8900."""
    p = urllib.parse.urlsplit(rpc_url)
    scheme = {"https": "wss", "http": "ws"}.get(p.scheme)
    if scheme is None:
        raise ValueError(f"cannot derive a WebSocket URL from {redact_url(rpc_url)}; set it explicitly")
    netloc = p.netloc
    if p.port == 8899 and p.hostname in LOCAL_HOSTS:
        netloc = netloc[: -len("8899")] + "8900"
    return urllib.parse.urlunsplit((scheme, netloc, p.path, p.query, ""))


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1(key.encode() + _GUID).digest()).decode()


def _mask(payload: bytes, key: bytes) -> bytes:
    n = len(payload)
    if not n:
        return b""
    k = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(k, "big")).to_bytes(n, "big")


def encode_frame(opcode: int, payload: bytes, mask_key: bytes = None) -> bytes:
    """A single FIN frame. Client frames are always masked (RFC 6455 5.3)."""
    mask_key = mask_key if mask_key is not None else os.urandom(4)
    n = len(payload)
    head = bytes([0x80 | opcode])
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 1 << 16:
        head += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack("!Q", n)
    return head + mask_key + _mask(payload, mask_key)


class FrameReader:
    """Incremental frame parser: feed bytes, take complete frames. Never blocks, never half-consumes."""

    def __init__(self, max_bytes=MAX_MESSAGE_BYTES):
        self.buf = bytearray()
        self.max_bytes = max_bytes
        self._frag_op = None
        self._frag = bytearray()

    def feed(self, data: bytes):
        self.buf += data

    def _frame(self):
        b = self.buf
        if len(b) < 2:
            return None
        fin, rsv, op = b[0] & 0x80, b[0] & 0x70, b[0] & 0x0F
        masked, n = b[1] & 0x80, b[1] & 0x7F
        if rsv:
            raise WsError("protocol error: reserved bits set (no extension was negotiated)")
        if masked:
            raise WsError("protocol error: server frame is masked")
        pos = 2
        if n == 126:
            if len(b) < 4:
                return None
            n = struct.unpack("!H", b[2:4])[0]
            pos = 4
        elif n == 127:
            if len(b) < 10:
                return None
            n = struct.unpack("!Q", b[2:10])[0]
            pos = 10
        if n > self.max_bytes:
            raise WsError("message exceeded size cap")
        if op >= 0x8 and (n > 125 or not fin):
            raise WsError("protocol error: bad control frame")
        if len(b) < pos + n:
            return None
        payload = bytes(b[pos: pos + n])
        del b[: pos + n]
        return bool(fin), op, payload

    def next_message(self):
        """(opcode, payload) for a complete message or control frame, or None if more bytes are needed."""
        while True:
            fr = self._frame()
            if fr is None:
                return None
            fin, op, payload = fr
            if op >= 0x8:
                return op, payload
            if op == OP_CONT:
                if self._frag_op is None:
                    raise WsError("protocol error: continuation without a start frame")
                self._frag += payload
                if len(self._frag) > self.max_bytes:
                    raise WsError("message exceeded size cap")
                if fin:
                    out = (self._frag_op, bytes(self._frag))
                    self._frag_op, self._frag = None, bytearray()
                    return out
                continue
            if op not in (OP_TEXT, OP_BINARY):
                raise WsError(f"protocol error: unknown opcode {op}")
            if self._frag_op is not None:
                raise WsError("protocol error: new message inside a fragmented one")
            if fin:
                return op, payload
            self._frag_op, self._frag = op, bytearray(payload)


class WsConnection:
    """One PubSub connection. `recv(timeout)` returns a decoded JSON message or None on timeout."""

    def __init__(self, sock, display, leftover=b"", clock=time.monotonic):
        self.sock = sock
        self.display = display
        self.reader = FrameReader()
        self.reader.feed(leftover)
        self.clock = clock
        self.last_frame_at = clock()
        self._id = 0
        self.closed = False

    def __repr__(self):
        return f"<WsConnection {self.display}>"

    def _send(self, opcode, payload):
        if self.closed:
            raise WsClosed(f"connection to {self.display} is closed")
        try:
            self.sock.sendall(encode_frame(opcode, payload))
        except OSError as e:
            self.closed = True
            raise WsError(f"send to {self.display} failed: {type(e).__name__}") from None

    def request(self, method, params):
        """Send a JSON-RPC request; returns its id. The response arrives through recv()."""
        if method not in READ_ONLY_WS_METHODS:
            raise PermissionError(f"refusing non-read-only PubSub method {method!r}")
        self._id += 1
        self._send(OP_TEXT, json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode())
        return self._id

    def ping(self):
        self._send(OP_PING, b"wt")

    def recv(self, timeout):
        deadline = self.clock() + max(0.0, timeout)
        while True:
            msg = self.reader.next_message()
            if msg is not None:
                self.last_frame_at = self.clock()
                op, payload = msg
                if op == OP_PING:
                    self._send(OP_PONG, payload)
                    continue
                if op == OP_PONG:
                    continue
                if op == OP_CLOSE:
                    code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else None
                    try:
                        self._send(OP_CLOSE, payload[:2])
                    except WsError:
                        pass
                    self.closed = True
                    raise WsClosed(f"server {self.display} closed the connection (code {code})")
                if op == OP_BINARY:
                    raise WsError("protocol error: unexpected binary message")
                try:
                    return json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return {"_malformed": True}
            remaining = deadline - self.clock()
            if remaining <= 0:
                return None
            try:
                self.sock.settimeout(remaining)
                data = self.sock.recv(65536)
            except (socket.timeout, TimeoutError):
                return None
            except OSError as e:
                self.closed = True
                raise WsError(f"connection to {self.display} failed: {type(e).__name__}") from None
            if not data:
                self.closed = True
                raise WsClosed(f"connection to {self.display} dropped (EOF)")
            self.reader.feed(data)

    def close(self):
        if not self.closed:
            try:
                self._send(OP_CLOSE, struct.pack("!H", 1000))
            except WsError:
                pass
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass


def connect(url, timeout=15.0, sock_factory=None, ssl_context=None):
    """Open a PubSub connection. Raises WsError with a redacted message on any failure."""
    validate_ws_url(url)
    register_url(url)
    p = urllib.parse.urlsplit(url)
    display = redact_url(url)
    port = p.port or (443 if p.scheme == "wss" else 80)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    try:
        sock = (sock_factory or socket.create_connection)((p.hostname, port), timeout)
        if p.scheme == "wss":
            sock = (ssl_context or ssl.create_default_context()).wrap_socket(sock, server_hostname=p.hostname)
    except (OSError, ssl.SSLError) as e:
        raise WsError(f"cannot connect to {display}: {type(e).__name__}") from None
    key = base64.b64encode(os.urandom(16)).decode()
    host = p.hostname if p.port is None else f"{p.hostname}:{p.port}"
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: nonce-watchtower/{__version__}\r\n\r\n"
    )
    try:
        sock.settimeout(timeout)
        sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise WsError(f"handshake with {display} failed: connection closed")
            buf += chunk
            if len(buf) > MAX_HANDSHAKE_BYTES:
                raise WsError(f"handshake with {display} failed: oversized response")
    except OSError as e:
        sock.close()
        raise WsError(f"handshake with {display} failed: {type(e).__name__}") from None
    except WsError:
        sock.close()
        raise
    head, leftover = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    status = lines[0].split(" ")
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        headers[k.strip().lower()] = v.strip()
    if len(status) < 2 or status[1] != "101":
        sock.close()
        raise WsError(f"handshake with {display} refused: HTTP {status[1] if len(status) > 1 else '?'}")
    if headers.get("sec-websocket-accept") != accept_key(key) or headers.get("upgrade", "").lower() != "websocket":
        sock.close()
        raise WsError(f"handshake with {display} failed: bad Sec-WebSocket-Accept/Upgrade")
    if headers.get("sec-websocket-extensions"):
        sock.close()
        raise WsError(f"handshake with {display} failed: server forced an extension we did not request")
    return WsConnection(sock, display, leftover)
