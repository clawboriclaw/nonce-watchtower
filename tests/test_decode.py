import base64
import unittest

from watchtower.base58 import b58decode, b58encode, is_pubkey
from watchtower.decode import (
    account_bytes,
    decode_nonce,
    decode_program,
    decode_programdata_header,
)

from .helpers import JUP_PD, NONCE_AUTH, load


class Base58Tests(unittest.TestCase):
    def test_roundtrip_and_leading_zeros(self):
        for raw in (b"\0" * 32, b"\0\0\x01" + b"\xff" * 29, bytes(range(32))):
            self.assertEqual(b58decode(b58encode(raw)), raw)
        self.assertEqual(b58encode(b"\0" * 32), "1" * 32)

    def test_is_pubkey(self):
        self.assertTrue(is_pubkey("11111111111111111111111111111111"))
        self.assertTrue(is_pubkey("1nc1nerator11111111111111111111111111111111"))
        self.assertFalse(is_pubkey("1nc1nerator11111111111111111111111111111110"))  # '0' not in alphabet
        self.assertFalse(is_pubkey("abc"))
        self.assertFalse(is_pubkey("1" * 44))  # 44 zero bytes, not 32
        self.assertFalse(is_pubkey(None))


class NonceLayoutTests(unittest.TestCase):
    def test_real_nonce_accounts_decode(self):
        res = load("gpa_nonce_real.json")["result"]
        self.assertEqual(len(res), 5)
        for e in res:
            raw = account_bytes(e["account"])
            self.assertEqual(len(raw), 80)
            d = decode_nonce(raw)
            self.assertEqual(d["authority"], NONCE_AUTH)
            self.assertEqual(d["version"], "current")
            self.assertEqual(d["lamports_per_signature"], 5000)
            self.assertTrue(is_pubkey(d["nonce"]))

    def test_rejects_uninitialized_and_wrong_size(self):
        self.assertIsNone(decode_nonce(b"\x01\0\0\0" + b"\0" * 76))  # Current/Uninitialized
        self.assertIsNone(decode_nonce(b"\x01\0\0\0\x01\0\0\0" + b"\0" * 71))
        self.assertIsNone(decode_nonce(b"\x07\0\0\0\x01\0\0\0" + b"\0" * 72))  # bogus version tag

    def test_legacy_version(self):
        raw = b"\0\0\0\0\x01\0\0\0" + bytes(range(32)) + b"\x02" * 32 + (5000).to_bytes(8, "little")
        self.assertEqual(decode_nonce(raw)["version"], "legacy")


class LoaderLayoutTests(unittest.TestCase):
    def test_program_and_programdata(self):
        prog = load("program_jup.json")["result"]["value"]
        self.assertEqual(decode_program(account_bytes(prog)), JUP_PD)
        pd = load("programdata_jup.json")["result"]["value"]
        hdr = decode_programdata_header(account_bytes(pd))
        self.assertEqual(hdr["upgrade_authority"], "CvQZZ23qYDWF2RUpxYJ8y9K4skmuvYEEjH7fK58jtipQ")
        self.assertEqual(hdr["slot"], 451957263)

    def test_frozen_program_has_no_authority(self):
        raw = (3).to_bytes(4, "little") + (99).to_bytes(8, "little") + b"\0" + b"\0" * 32
        self.assertEqual(decode_programdata_header(raw), {"slot": 99, "upgrade_authority": None})

    def test_wrong_tags(self):
        self.assertIsNone(decode_program((3).to_bytes(4, "little") + b"\0" * 32))
        self.assertIsNone(decode_programdata_header((2).to_bytes(4, "little") + b"\0" * 41))

    def test_account_bytes_requires_base64(self):
        with self.assertRaises(ValueError):
            account_bytes({"data": {"parsed": {}}})
        self.assertEqual(account_bytes({"data": [base64.b64encode(b"ab").decode(), "base64"]}), b"ab")
