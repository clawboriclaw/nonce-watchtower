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


class NftLockClassificationTests(unittest.TestCase):
    """Outreach scan of a real signer showed 132 'high' delegates that were frozen 1-of-1 NFT staking locks."""

    def _report(self, **tok):
        from watchtower.scan import findings
        item = {"account": "Acct111", "mint": "Mint111", "owner": "W", "state": "frozen", "delegate": "D111",
                "delegated_amount": "1", "delegated_ui": "1", "close_authority": None, "amount": "1", "decimals": 0,
                "mint_checked": True, "mint_supply": "1", "mint_freeze_authority": None}
        item.update(tok)
        rep = {"wallets": [{"pubkey": "W", "label": "", "nonces": {"status": "ok", "items": []},
                            "token_accounts": {"status": "ok", "items": [item], "permanent_delegates": []}}],
               "mints": [], "programs": []}
        return findings(rep)

    def test_thawable_lock_is_medium_not_info(self):
        kinds = {(f["kind"], f["severity"]) for f in self._report(mint_freeze_authority="EditionPda111")}
        self.assertIn(("nft_lock_delegate", "medium"), kinds)

    def test_fungible_decimals0_supply_gt1_stays_high(self):
        kinds = {(f["kind"], f["severity"]) for f in self._report(mint_supply="1000000")}
        self.assertIn(("token_delegate", "high"), kinds)

    def test_unverified_mint_stays_high(self):
        kinds = {(f["kind"], f["severity"]) for f in self._report(mint_checked=False)}
        self.assertIn(("token_delegate", "high"), kinds)

    def test_permanent_delegate_unaffected_by_lock_carveout(self):
        from watchtower.scan import findings
        item = {"account": "A", "mint": "M", "owner": "W", "state": "frozen", "delegate": "D", "delegated_amount": "1",
                "delegated_ui": "1", "close_authority": None, "amount": "1", "decimals": 0, "mint_checked": True,
                "mint_supply": "1", "mint_freeze_authority": None}
        rep = {"wallets": [{"pubkey": "W", "label": "", "nonces": {"status": "ok", "items": []},
                            "token_accounts": {"status": "ok", "items": [item],
                                               "permanent_delegates": [{"mint": "M", "delegate": "P"}]}}],
               "mints": [], "programs": []}
        self.assertIn(("mint_permanent_delegate", "medium"), {(f["kind"], f["severity"]) for f in findings(rep)})

    def test_frozen_one_of_one_is_info_lock(self):
        kinds = {(f["kind"], f["severity"]) for f in self._report()}
        self.assertIn(("nft_lock_delegate", "info"), kinds)
        self.assertNotIn(("token_delegate", "high"), kinds)

    def test_fungible_delegate_stays_high(self):
        kinds = {(f["kind"], f["severity"]) for f in self._report(state="initialized", amount="5000000", decimals=6,
                                                                  delegated_amount="5000000")}
        self.assertIn(("token_delegate", "high"), kinds)

    def test_unfrozen_nft_delegate_stays_high(self):
        # An NFT delegate that is NOT locked can be transferred right now: keep it loud.
        kinds = {(f["kind"], f["severity"]) for f in self._report(state="initialized")}
        self.assertIn(("token_delegate", "high"), kinds)

    def test_lock_close_authority_is_info(self):
        kinds = {(f["kind"], f["severity"]) for f in self._report(close_authority="PdaLock111")}
        self.assertIn(("nft_lock_close_authority", "info"), kinds)
        self.assertNotIn(("foreign_close_authority", "medium"), kinds)

    def test_close_authority_on_fungible_stays_medium(self):
        kinds = {(f["kind"], f["severity"]) for f in self._report(close_authority="Other111", state="initialized",
                                                                  amount="5", decimals=6, delegated_amount="5")}
        self.assertIn(("foreign_close_authority", "medium"), kinds)
