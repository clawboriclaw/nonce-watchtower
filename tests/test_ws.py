"""The stdlib WebSocket client, against an in-memory fake socket. Offline."""

import json
import re
import struct
import unittest

from watchtower import ws
from watchtower.ws import (OP_CLOSE, OP_PING, OP_PONG, OP_TEXT, FrameReader, WsClosed, WsError, accept_key, connect,
                           derive_ws_url, encode_frame, validate_ws_url)

SECRET_URL = "wss://rpc.example.com/ws?api-key=SECRET123"


def server_frame(op, payload, fin=True, masked=False, rsv=0):
    head = bytes([(0x80 if fin else 0) | rsv | op])
    n = len(payload)
    m = 0x80 if masked else 0
    if n < 126:
        head += bytes([m | n])
    elif n < 1 << 16:
        head += bytes([m | 126]) + struct.pack("!H", n)
    else:
        head += bytes([m | 127]) + struct.pack("!Q", n)
    return head + (b"\0\0\0\0" if masked else b"") + payload


def unmask_client_frames(data):
    """Decode masked client frames -> [(opcode, payload)]."""
    out, i = [], 0
    while i < len(data):
        op = data[i] & 0x0F
        assert data[i + 1] & 0x80, "client frame must be masked"
        n = data[i + 1] & 0x7F
        i += 2
        if n == 126:
            n = struct.unpack("!H", data[i:i + 2])[0]
            i += 2
        elif n == 127:
            n = struct.unpack("!Q", data[i:i + 8])[0]
            i += 8
        key = data[i:i + 4]
        i += 4
        out.append((op, bytes(b ^ key[j % 4] for j, b in enumerate(data[i:i + n]))))
        i += n
    return out


class FakeSock:
    """Answers the handshake (optionally wrongly), then serves scripted bytes."""

    def __init__(self, frames=b"", status="101 Switching Protocols", bad_accept=False, extra_headers="", chunk=None):
        self.frames = frames
        self.status = status
        self.bad_accept = bad_accept
        self.extra_headers = extra_headers
        self.sent = b""
        self.rx = b""
        self.chunk = chunk
        self.closed = False
        self.handshook = False

    def settimeout(self, t):
        pass

    def sendall(self, data):
        if not self.handshook:
            self.handshook = True
            key = re.search(rb"Sec-WebSocket-Key: (\S+)", data).group(1).decode()
            acc = "AAAA" if self.bad_accept else accept_key(key)
            self.request = data
            self.rx = (f"HTTP/1.1 {self.status}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       f"Sec-WebSocket-Accept: {acc}\r\n{self.extra_headers}\r\n").encode() + self.frames
        else:
            self.sent += data

    def recv(self, n):
        if not self.rx:
            raise TimeoutError
        n = min(n, self.chunk or n)
        out, self.rx = self.rx[:n], self.rx[n:]
        return out

    def close(self):
        self.closed = True


def open_with(sock, url="ws://127.0.0.1:8900/"):
    return connect(url, sock_factory=lambda addr, timeout: sock)


class HandshakeTests(unittest.TestCase):
    def test_accept_key_rfc_example(self):
        self.assertEqual(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_good_handshake_and_leftover_bytes(self):
        sock = FakeSock(frames=server_frame(OP_TEXT, b'{"jsonrpc":"2.0","result":7,"id":1}'))
        c = open_with(sock)
        self.assertIn(b"GET / HTTP/1.1", sock.request)
        self.assertIn(b"Sec-WebSocket-Version: 13", sock.request)
        self.assertNotIn(b"Sec-WebSocket-Extensions", sock.request)
        self.assertEqual(c.recv(1.0), {"jsonrpc": "2.0", "result": 7, "id": 1})

    def test_bad_accept_rejected(self):
        with self.assertRaises(WsError):
            open_with(FakeSock(bad_accept=True))

    def test_non_101_rejected_without_leaking_url(self):
        with self.assertRaises(WsError) as cm:
            connect("wss://rpc.example.com/ws?api-key=SECRET123",
                    sock_factory=lambda a, t: FakeSock(status="403 Forbidden"),
                    ssl_context=type("Ctx", (), {"wrap_socket": lambda self, s, server_hostname: s})())
        self.assertIn("403", str(cm.exception))
        self.assertNotIn("SECRET", str(cm.exception))

    def test_forced_extension_rejected(self):
        with self.assertRaises(WsError):
            open_with(FakeSock(extra_headers="Sec-WebSocket-Extensions: permessage-deflate\r\n"))

    def test_connect_failure_is_redacted(self):
        def boom(addr, timeout):
            raise ConnectionRefusedError(f"refused {SECRET_URL}")
        with self.assertRaises(WsError) as cm:
            connect(SECRET_URL, sock_factory=boom)
        self.assertNotIn("SECRET", str(cm.exception))


class FrameTests(unittest.TestCase):
    def test_client_frames_are_masked_and_roundtrip(self):
        for n in (0, 5, 125, 126, 300, 70000):
            data = encode_frame(OP_TEXT, b"a" * n)
            self.assertEqual(unmask_client_frames(data), [(OP_TEXT, b"a" * n)])

    def test_fragmented_message_reassembled_with_interleaved_ping(self):
        sock = FakeSock(frames=server_frame(OP_TEXT, b'{"a":', fin=False) + server_frame(OP_PING, b"p")
                        + server_frame(0x0, b"1}", fin=True), chunk=3)
        c = open_with(sock)
        self.assertEqual(c.recv(1.0), {"a": 1})
        self.assertIn((OP_PONG, b"p"), unmask_client_frames(sock.sent))

    def test_server_ping_answered_pong_ignored(self):
        sock = FakeSock(frames=server_frame(OP_PONG, b"") + server_frame(OP_PING, b"xy"))
        c = open_with(sock)
        self.assertIsNone(c.recv(0.01))
        self.assertEqual(unmask_client_frames(sock.sent), [(OP_PONG, b"xy")])

    def test_close_frame_raises_closed_and_echoes(self):
        sock = FakeSock(frames=server_frame(OP_CLOSE, struct.pack("!H", 1001)))
        c = open_with(sock)
        with self.assertRaises(WsClosed):
            c.recv(1.0)
        self.assertEqual(unmask_client_frames(sock.sent)[0][0], OP_CLOSE)

    def test_eof_raises_closed(self):
        sock = FakeSock()
        c = open_with(sock)
        sock.recv = lambda n: b""
        with self.assertRaises(WsClosed):
            c.recv(1.0)

    def test_protocol_violations(self):
        for bad in (server_frame(OP_TEXT, b"x", masked=True), server_frame(OP_TEXT, b"x", rsv=0x40),
                    server_frame(OP_PING, b"x", fin=False), server_frame(0x0, b"x"), server_frame(0x2, b"x")):
            c = open_with(FakeSock(frames=bad))
            with self.assertRaises(WsError):
                c.recv(1.0)

    def test_size_cap(self):
        r = FrameReader(max_bytes=10)
        r.feed(server_frame(OP_TEXT, b"x" * 11))
        with self.assertRaises(WsError):
            r.next_message()

    def test_partial_frame_waits_for_more_bytes(self):
        r = FrameReader()
        f = server_frame(OP_TEXT, b"hello world")
        r.feed(f[:4])
        self.assertIsNone(r.next_message())
        r.feed(f[4:])
        self.assertEqual(r.next_message(), (OP_TEXT, b"hello world"))

    def test_malformed_json_is_flagged_not_dropped(self):
        c = open_with(FakeSock(frames=server_frame(OP_TEXT, b"not json")))
        self.assertEqual(c.recv(1.0), {"_malformed": True})


class GuardTests(unittest.TestCase):
    def test_only_read_only_subscriptions_before_io(self):
        sock = FakeSock()
        c = open_with(sock)
        for m in ("sendTransaction", "signatureSubscribe", "requestAirdrop", "simulateTransaction"):
            with self.assertRaises(PermissionError):
                c.request(m, [])
        self.assertEqual(sock.sent, b"")
        rid = c.request("programSubscribe", ["11111111111111111111111111111111", {}])
        self.assertEqual(json.loads(unmask_client_frames(sock.sent)[0][1])["id"], rid)
        self.assertFalse(any(m.startswith(("send", "request", "simulate")) for m in ws.READ_ONLY_WS_METHODS))

    def test_url_rules(self):
        validate_ws_url("wss://x.example.com/")
        validate_ws_url("ws://127.0.0.1:8900")
        for bad in ("ws://example.com/", "https://example.com/", "wss://"):
            with self.assertRaises(ValueError):
                validate_ws_url(bad)
        with self.assertRaises(ValueError) as cm:
            validate_ws_url("ws://evil.example.com/?api-key=SECRET123")
        self.assertNotIn("SECRET", str(cm.exception))

    def test_derive(self):
        self.assertEqual(derive_ws_url("https://mainnet.example.com/?api-key=k"), "wss://mainnet.example.com/?api-key=k")
        self.assertEqual(derive_ws_url("http://127.0.0.1:8899"), "ws://127.0.0.1:8900")
        self.assertEqual(derive_ws_url("https://api.mainnet-beta.solana.com"), "wss://api.mainnet-beta.solana.com")
        self.assertNotIn("SECRET", repr(open_with(FakeSock(), url="ws://127.0.0.1:8900/?k=SECRET")))


if __name__ == "__main__":
    unittest.main()
