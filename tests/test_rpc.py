import unittest

from watchtower.rpc import READ_ONLY_METHODS, RpcClient, RpcError, redact_url, validate_http_url

from .helpers import load


class ReadOnlyGuardTests(unittest.TestCase):
    def test_write_methods_are_refused_before_io(self):
        calls = []
        c = RpcClient(transport=lambda m, p: calls.append(m) or {"result": None})
        for m in ("sendTransaction", "simulateTransaction", "requestAirdrop", "sendRawTransaction"):
            with self.assertRaises(PermissionError):
                c.call(m, [])
        self.assertEqual(calls, [])

    def test_allowlist_is_read_only(self):
        self.assertFalse(any(m.startswith(("send", "request", "simulate")) for m in READ_ONLY_METHODS))

    def test_no_signing_code_in_package(self):
        import pathlib

        src = "".join(p.read_text() for p in pathlib.Path(__file__).parents[1].joinpath("watchtower").glob("*.py"))
        for needle in ("Keypair", "sign_message", "secret_key", "private_key", "sendTransaction\"", "nacl"):
            self.assertNotIn(needle, src)

    def test_jsonrpc_error_raises(self):
        c = RpcClient(transport=lambda m, p: load("rpc_error_excluded.json"))
        with self.assertRaises(RpcError) as cm:
            c.call("getProgramAccounts", [])
        self.assertEqual(cm.exception.code, -32010)


class UrlHygieneTests(unittest.TestCase):
    def test_redaction_hides_keys(self):
        r = redact_url("https://mainnet.helius-rpc.com/?api-key=SECRET123")
        self.assertNotIn("SECRET", r)
        self.assertTrue(r.startswith("https://mainnet.helius-rpc.com"))
        self.assertNotIn("abc", redact_url("https://x.quiknode.pro/abc/"))

    def test_http_rejected_except_localhost(self):
        with self.assertRaises(ValueError):
            RpcClient("http://example.com")
        RpcClient("http://127.0.0.1:8899")
        with self.assertRaises(ValueError):
            validate_http_url("file:///etc/passwd", "webhook URL")
