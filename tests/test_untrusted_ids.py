"""Security scan 2026-11-08 (Hermes Security plugin, scan_2257e9861eaf2e461fd6e3b9), findings 2 and 3:
identifiers returned by the RPC endpoint are validated before they reach alerts, snapshot keys or file names."""
import base64
import re
import struct
import unittest

from watchtower.base58 import b58decode
from watchtower.scan import scan_nonces, scan_token_accounts

from .helpers import NONCE_AUTH

SYSTEM = "11111111111111111111111111111111"
TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
GOOD_ACCT = "So11111111111111111111111111111111111111112"
EVIL = "\x1b[2J\x1b[31mFAKE ALERT\x1b[0m"


def nonce_account():
    raw = struct.pack("<II", 1, 1) + b58decode(NONCE_AUTH) + b"\x07" * 32 + struct.pack("<Q", 5000)
    return {"owner": SYSTEM, "lamports": 1447680, "data": [base64.b64encode(raw).decode(), "base64"]}


class FakeClient:
    def __init__(self, answers):
        self.answers = answers

    def call(self, method, params):
        a = self.answers[method]
        return a(params) if callable(a) else a


class NonceIds(unittest.TestCase):
    def test_valid_id_is_kept(self):
        out = scan_nonces(FakeClient({"getProgramAccounts": [{"pubkey": GOOD_ACCT, "account": nonce_account()}]}), NONCE_AUTH)
        self.assertEqual(out["status"], "ok")
        self.assertEqual([i["account"] for i in out["items"]], [GOOD_ACCT])

    def test_escape_sequence_id_is_rejected_and_result_untrusted(self):
        out = scan_nonces(FakeClient({"getProgramAccounts": [{"pubkey": EVIL, "account": nonce_account()}]}), NONCE_AUTH)
        self.assertEqual(out["items"], [])
        self.assertEqual(out["status"], "unverified")      # never "ok": the endpoint lied about something
        self.assertNotIn("\x1b", repr(out["items"]))

    def test_missing_id_is_rejected(self):
        out = scan_nonces(FakeClient({"getProgramAccounts": [{"account": nonce_account()}]}), NONCE_AUTH)
        self.assertEqual(out["status"], "unverified")


class TokenIds(unittest.TestCase):
    def _entry(self, pubkey):
        info = {"mint": GOOD_ACCT, "owner": NONCE_AUTH, "state": "initialized", "delegate": NONCE_AUTH,
                "delegatedAmount": {"amount": "1"}, "tokenAmount": {"amount": "5", "decimals": 0}}
        return {"pubkey": pubkey, "account": {"data": {"parsed": {"info": info}}}}

    def test_invalid_token_account_id_makes_the_program_unavailable(self):
        def answer(params):
            return {"value": [self._entry(EVIL)]} if params[1]["programId"] == TOKEN else {"value": []}
        out, _ = scan_token_accounts(FakeClient({"getTokenAccountsByOwner": answer}), NONCE_AUTH)
        self.assertNotEqual(out["status"], "ok")
        self.assertEqual(out["program_status"][TOKEN], "unavailable")
        self.assertFalse(any("\x1b" in i["account"] for i in out["items"]))

    def test_valid_token_account_id_is_kept(self):
        out, _ = scan_token_accounts(FakeClient({"getTokenAccountsByOwner": {"value": [self._entry(GOOD_ACCT)]}}), NONCE_AUTH)
        self.assertEqual(out["status"], "ok")
        self.assertIn(GOOD_ACCT, [i["account"] for i in out["items"]])


class DriftRecorderNames(unittest.TestCase):
    PAT = re.compile(r"[1-9A-HJ-NP-Za-km-z]{64,88}")

    def test_recorder_guards_signature_characters(self):
        with open("tools/record_drift.py", encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("not base58; refusing to use them as file names", src)
        self.assertIsNone(self.PAT.fullmatch("../../../etc/passwd" + "1" * 60))
        self.assertIsNotNone(self.PAT.fullmatch("5" * 87))


if __name__ == "__main__":
    unittest.main()
