"""Regression tests for the transport-level review fixes (independent review, 2026-10-06): these drive the real
_http path with a patched urlopen, which the transport-injection tests elsewhere bypass."""
import io
import json
import unittest
import urllib.error
from unittest import mock

from watchtower.rpc import RpcClient, RpcError, RpcUnavailable
from watchtower.scan import scan_permanent_delegates

URL = "https://rpc.example.com/secret-key"


def http_error(code, body):
    return urllib.error.HTTPError(URL, code, "err", {}, io.BytesIO(json.dumps(body).encode()))


class _Ok:
    def __init__(self, body):
        self._raw = json.dumps(body).encode()

    def read(self, n=-1):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class RetryBeforeErrorBodyTests(unittest.TestCase):
    @mock.patch("watchtower.rpc.time.sleep")
    def test_429_with_json_body_is_retried(self, _sleep):
        busy = http_error(429, {"jsonrpc": "2.0", "id": 1, "error": {"code": 429, "message": "Too many requests"}})
        ok = _Ok({"jsonrpc": "2.0", "id": 1, "result": 42})
        with mock.patch("watchtower.rpc.urllib.request.urlopen", side_effect=[busy, ok]) as uo:
            self.assertEqual(RpcClient(URL, retries=2).call("getSlot", []), 42)
        self.assertEqual(uo.call_count, 2)

    @mock.patch("watchtower.rpc.time.sleep")
    def test_persistent_429_is_unavailable_not_an_answer(self, _sleep):
        body = {"jsonrpc": "2.0", "id": 1, "error": {"code": 429, "message": "Too many requests"}}
        with mock.patch("watchtower.rpc.urllib.request.urlopen", side_effect=[http_error(429, body) for _ in range(3)]):
            with self.assertRaises(RpcUnavailable):
                RpcClient(URL, retries=2).call("getSlot", [])

    def test_non_retryable_status_surfaces_json_error(self):
        body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32010, "message": "excluded from account secondary indexes"}}
        with mock.patch("watchtower.rpc.urllib.request.urlopen", side_effect=[http_error(410, body)]):
            with self.assertRaises(RpcError):
                RpcClient(URL, retries=2).call("getSlot", [])


class MultipleAccountsLengthGuardTests(unittest.TestCase):
    def test_short_value_list_is_an_error_not_silently_clean(self):
        mints = ["So11111111111111111111111111111111111111112", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"]
        c = RpcClient(transport=lambda m, p: {"result": {"context": {"slot": 1}, "value": [None]}})
        found, errors = scan_permanent_delegates(c, mints)
        self.assertEqual(found, {})
        self.assertTrue(errors and "returned 1 values for 2 mints" in errors[0])


if __name__ == "__main__":
    unittest.main()
