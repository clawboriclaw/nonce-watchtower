"""Security scan 2026-11-08 (Hermes Security plugin, scan_2257e9861eaf2e461fd6e3b9), finding 1: token accounts, mints and
the NFT-lock enrichment are decoded from the account BYTES, so an endpoint's jsonParsed view cannot hide or downgrade a
delegate, close authority, freeze or permanent delegate."""
import base64
import unittest

from watchtower.rpc import RpcClient
from watchtower.scan import enrich_lock_candidates, findings, run_scan, scan_mint, scan_token_accounts
from watchtower.spl import NotAMint, decode_mint, decode_token_account, ui_amount_string

from .helpers import (DELEGATOR, EMPTY, LAYOUT_MINTS, NONCE_AUTH, PYUSD, SPL, T22, USDC, FixtureRpc, encode_mint,
                      encode_token_account, load)

OWNER = NONCE_AUTH
DELEGATE = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
NFT_MINT = "So11111111111111111111111111111111111111112"
ACCT = "FvfLBAWRX28qr7B6ZkeV1baQuqgHj5FJ4TPpstystD1U"
FREEZER = "7dGbd2QZcCKcTndnHcTL8q7SMVXAkp688NTQYwrRCrar"


def b64(raw):
    return [base64.b64encode(raw).decode(), "base64"]


def values(name):
    return load(name)["result"]["value"]


class FakeClient:
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def call(self, method, params):
        self.calls.append((method, params))
        a = self.answers[method]
        return a(params) if callable(a) else a


class LayoutAgainstMainnet(unittest.TestCase):
    """layout_*.json: the same accounts recorded from mainnet in base64 and jsonParsed (fixtures/README.md)."""

    def test_token_accounts_decode_to_the_rpcs_own_parse(self):
        n = 0
        for tag in ("spl", "t22"):
            parsed = {e["pubkey"]: e for e in values(f"layout_tabo_{tag}_jsonParsed.json")}
            for e in values(f"layout_tabo_{tag}_base64.json"):
                info = parsed[e["pubkey"]]["account"]["data"]["parsed"]["info"]
                raw = base64.b64decode(e["account"]["data"][0])
                d = decode_token_account(raw, e["account"]["owner"])
                self.assertEqual((d["mint"], d["owner"], d["state"], d["amount"], d["delegate"], d["close_authority"]),
                                 (info["mint"], info["owner"], info["state"], info["tokenAmount"]["amount"],
                                  info.get("delegate"), info.get("closeAuthority")))
                self.assertEqual(d["delegated_amount"], (info.get("delegatedAmount") or {}).get("amount", "0"))
                dec = info["tokenAmount"]["decimals"]
                self.assertEqual(ui_amount_string(int(d["amount"]), dec), info["tokenAmount"]["uiAmountString"])
                if info.get("delegatedAmount"):
                    self.assertEqual(ui_amount_string(int(d["delegated_amount"]), dec), info["delegatedAmount"]["uiAmountString"])
                # The test-side encoder (used to replay the jsonParsed fixtures) reproduces the real bytes exactly.
                self.assertEqual(encode_token_account(info, len(raw)), raw)
                n += 1
        self.assertEqual(n, 6)

    def test_mints_decode_to_the_rpcs_own_parse(self):
        for mint, vb, vp in zip(LAYOUT_MINTS, values("layout_mints_base64.json"), values("layout_mints_jsonParsed.json")):
            info = vp["data"]["parsed"]["info"]
            raw = base64.b64decode(vb["data"][0])
            d = decode_mint(raw, vb["owner"])
            exts = {e["extension"]: e.get("state") or {} for e in info.get("extensions", [])}
            self.assertEqual(
                (d["mint_authority"], d["freeze_authority"], d["supply"], d["decimals"], d["permanent_delegate"],
                 d["close_authority"], d["transfer_hook_authority"], d["transfer_hook_program"]),
                (info["mintAuthority"], info["freezeAuthority"], info["supply"], info["decimals"],
                 exts.get("permanentDelegate", {}).get("delegate"), exts.get("mintCloseAuthority", {}).get("closeAuthority"),
                 exts.get("transferHook", {}).get("authority"), exts.get("transferHook", {}).get("programId")), mint)
            # The test-side encoder agrees with the real bytes on every decoded field (a None COption may keep stale
            # key bytes on chain, e.g. JUP's renounced mint authority, so byte equality is not expected for mints).
            self.assertEqual(decode_mint(encode_mint(info, len(raw)), vb["owner"]), d, mint)
        pyusd = decode_mint(base64.b64decode(values("layout_mints_base64.json")[1]["data"][0]), T22)
        self.assertIsNotNone(pyusd["permanent_delegate"])  # the extension path really ran
        self.assertIsNotNone(pyusd["close_authority"])


class MalformedBytes(unittest.TestCase):
    def _acct(self, **kw):
        info = {"mint": NFT_MINT, "owner": OWNER, "state": "initialized", "tokenAmount": {"amount": "5"}}
        info.update(kw)
        return bytearray(encode_token_account(info))

    def test_rejects_short_bad_tags_uninitialized_and_wrong_program(self):
        raw = self._acct()
        with self.assertRaises(ValueError):
            decode_token_account(bytes(raw[:164]), SPL)
        with self.assertRaises(ValueError):
            decode_token_account(bytes(raw) + b"\x02", SPL)  # SPL Token accounts are exactly 165 bytes
        bad = bytearray(raw)
        bad[72] = 7  # delegate COption tag
        with self.assertRaises(ValueError):
            decode_token_account(bytes(bad), SPL)
        bad = bytearray(raw)
        bad[108] = 0
        with self.assertRaises(ValueError):
            decode_token_account(bytes(bad), SPL)
        with self.assertRaises(ValueError):
            decode_token_account(bytes(raw), "11111111111111111111111111111111")
        with self.assertRaises(ValueError):
            decode_token_account(bytes(raw) + b"\x01" + bytes(9), T22)  # Token-2022 account-type byte says mint

    def test_mint_rejects_truncated_extensions_and_flags_other_layouts(self):
        info = {"mintAuthority": None, "supply": "1", "decimals": 0, "freezeAuthority": None,
                "extensions": [{"extension": "permanentDelegate", "state": {"delegate": DELEGATE}}]}
        raw = encode_mint(info, 165 + 1 + 4 + 32)
        self.assertEqual(decode_mint(raw, T22)["permanent_delegate"], DELEGATE)
        with self.assertRaises(ValueError):
            decode_mint(raw[:-1], T22)  # truncated TLV value: never "no permanent delegate"
        with self.assertRaises(ValueError):
            decode_mint(raw, SPL)  # extensions only exist under Token-2022
        with self.assertRaises(NotAMint):
            decode_mint(bytes(self._acct()), SPL)
        self.assertIsNone(decode_mint(encode_mint(dict(info, extensions=[{"extension": "permanentDelegate",
                                                                          "state": {"delegate": None}}]), 202), T22)["permanent_delegate"])

    def test_ui_amount_string(self):
        self.assertEqual([ui_amount_string(a, d) for a, d in ((0, 6), (1, 6), (1500000, 6), (7, 0), (10**9, 9))],
                         ["0", "0.000001", "1.5", "7", "1"])

    def test_undecodable_watched_mint_is_unavailable_not_ok(self):
        c = FakeClient({"getAccountInfo": {"value": {"owner": SPL, "data": b64(bytes(81))}}})
        self.assertEqual(scan_mint(c, USDC)["status"], "unavailable")
        c = FakeClient({"getAccountInfo": {"value": {"owner": SPL, "data": b64(bytes(self._acct()))}}})
        self.assertEqual(scan_mint(c, USDC)["status"], "not_a_mint")


class RegressionFinding1(unittest.TestCase):
    def _tabo(self, entry):
        return lambda params: {"value": [entry]} if params[1]["programId"] == SPL else {"value": []}

    def test_parsed_view_cannot_hide_a_delegate_that_is_in_the_bytes(self):
        info = {"mint": NFT_MINT, "owner": OWNER, "state": "initialized", "delegate": DELEGATE,
                "tokenAmount": {"amount": "5"}, "delegatedAmount": {"amount": "5"}}
        raw = encode_token_account(info)
        lying_parsed = {k: v for k, v in info.items() if k not in ("delegate", "delegatedAmount")}

        # 1. The endpoint answers base64 (as asked) but also carries a parsed-looking body without the delegate:
        #    only the bytes count, the delegate is found.
        entry = {"pubkey": ACCT, "account": {"owner": SPL, "data": b64(raw), "parsed": {"info": lying_parsed}}}
        c = FakeClient({"getTokenAccountsByOwner": self._tabo(entry)})
        out, _ = scan_token_accounts(c, OWNER)
        self.assertTrue(all(p[2] == {"encoding": "base64"} for _, p in c.calls))
        self.assertEqual(out["status"], "ok")
        self.assertEqual([(i["account"], i["delegate"]) for i in out["items"]], [(ACCT, DELEGATE)])

        # 2. The endpoint ignores the encoding and answers jsonParsed without the delegate: nothing to decode, so the
        #    program is reported unavailable, never ok-with-fewer-findings.
        entry = {"pubkey": ACCT, "account": {"owner": SPL, "data": {"parsed": {"info": lying_parsed, "type": "account"}}}}
        out, _ = scan_token_accounts(FakeClient({"getTokenAccountsByOwner": self._tabo(entry)}), OWNER)
        self.assertEqual(out["items"], [])
        self.assertNotEqual(out["status"], "ok")
        self.assertEqual(out["program_status"][SPL], "unavailable")
        rep = {"wallets": [{"pubkey": OWNER, "label": "", "nonces": {"status": "ok", "items": []}, "token_accounts": out}],
               "mints": [], "programs": []}
        self.assertIn(("warn", "coverage_gap"), {(f["severity"], f["kind"]) for f in findings(rep)})

        # 3. Bytes that belong to another owner are not silently dropped either.
        foreign = encode_token_account(dict(info, owner=EMPTY))
        entry = {"pubkey": ACCT, "account": {"owner": SPL, "data": b64(foreign)}}
        out, _ = scan_token_accounts(FakeClient({"getTokenAccountsByOwner": self._tabo(entry)}), OWNER)
        self.assertEqual(out["program_status"][SPL], "unavailable")

    def _lock_item(self):
        info = {"mint": NFT_MINT, "owner": OWNER, "state": "frozen", "delegate": DELEGATE,
                "tokenAmount": {"amount": "1"}, "delegatedAmount": {"amount": "1"}}
        entry = {"pubkey": ACCT, "account": {"owner": SPL, "data": b64(encode_token_account(info))}}
        out, _ = scan_token_accounts(FakeClient({"getTokenAccountsByOwner": self._tabo(entry)}), OWNER)
        return out

    def _graded(self, mint_value):
        out = self._lock_item()
        c = FakeClient({"getMultipleAccounts": {"value": [mint_value]}})
        out["lock_check_errors"] = enrich_lock_candidates(c, out["items"])
        self.assertEqual(c.calls[0][1][1], {"encoding": "base64"})
        rep = {"wallets": [{"pubkey": OWNER, "label": "", "nonces": {"status": "ok", "items": []}, "token_accounts": out}],
               "mints": [], "programs": []}
        return out, {(f["kind"], f["severity"]) for f in findings(rep)}

    def test_bogus_freeze_authority_cannot_downgrade_a_lock_from_medium_to_info(self):
        mint_raw = encode_mint({"mintAuthority": None, "supply": "1", "decimals": 0, "freezeAuthority": FREEZER})
        # Honest bytes: thawable lock -> medium.
        _, kinds = self._graded({"owner": SPL, "data": b64(mint_raw)})
        self.assertIn(("nft_lock_delegate", "medium"), kinds)
        # The endpoint's parsed view claims the freeze authority is renounced; it is not decoded, so the lock is
        # unverified and stays a loud plain delegate (high), never info.
        lying = {"owner": SPL, "data": {"parsed": {"type": "mint", "info": {"mintAuthority": None, "supply": "1",
                                                                            "decimals": 0, "freezeAuthority": None}}}}
        out, kinds = self._graded(lying)
        self.assertNotIn(("nft_lock_delegate", "info"), kinds)
        self.assertIn(("token_delegate", "high"), kinds)
        self.assertTrue(out["lock_check_errors"])
        # A mint owned by the wrong program is not trusted either.
        _, kinds = self._graded({"owner": T22, "data": b64(mint_raw)})
        self.assertIn(("token_delegate", "high"), kinds)

    def test_honest_endpoint_gives_the_same_findings_as_before(self):
        """Pinned from the jsonParsed scanner (f670898) on the same replayed fixtures."""
        rep = run_scan(RpcClient(transport=FixtureRpc()), [{"pubkey": NONCE_AUTH, "label": "n"}, {"pubkey": DELEGATOR, "label": "d"}],
                       [USDC, PYUSD], [])
        self.assertTrue(rep["complete"])
        got = sorted((f["severity"], f["kind"], f["subject"], f["detail"]) for f in rep["findings"]
                     if f["kind"] in ("token_delegate", "mint_authorities", "mint_permanent_delegate", "foreign_close_authority",
                                      "frozen_account", "nft_lock_delegate"))
        move = "delegate JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 may move {} of mint {}"
        self.assertEqual(got, sorted([
            ("high", "token_delegate", "32DmrRcfbieV136Uq3PKc25eXsJfJHnoDW5tR6grwpfV", move.format("0.426096", "DriFtupJYLTosbwoN8koMbEYSx54aFAVLddWsbksjwg7")),
            ("high", "token_delegate", "Cy6hH6AcTT6FqjtApTZcZPdH4fghhZx5wQuxnbA3kg8U", move.format("2.089716", "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R")),
            ("high", "token_delegate", "FvfLBAWRX28qr7B6ZkeV1baQuqgHj5FJ4TPpstystD1U", move.format("2.907638", "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN")),
            ("high", "token_delegate", "Got6G3sa8qMztcQrV7bCjL3jaE754Ee9mVr1M6ZTHtf2", move.format("1189.944224", "pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn")),
            ("high", "token_delegate", "kuzWpKQ7D1DXaA7b1G2oKvdb9RHgBLzh7GmfH6jKqru", move.format("0.235960813", "jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL")),
            ("info", "mint_authorities", USDC, "mint=BJE5MMbqXjVwjAF7oxwPYXnTXDyspzZyt4vwenNw5ruG freeze=7dGbd2QZcCKcTndnHcTL8q7SMVXAkp688NTQYwrRCrar permanent_delegate=None"),
            ("info", "mint_authorities", PYUSD, "mint=8Jornc27vtAYPkwDzsZVgLQchAYyC8nD7aCNPCDV8Qk2 freeze=2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk permanent_delegate=2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk"),
        ]))
        self.assertEqual(rep["wallets"][1]["token_accounts"]["permanent_delegates_status"], "ok")

    def test_held_mint_the_endpoint_omits_makes_permanent_delegates_unavailable(self):
        from watchtower.scan import scan_permanent_delegates
        found, errors = scan_permanent_delegates(FakeClient({"getMultipleAccounts": {"value": [None]}}), [PYUSD])
        self.assertEqual(found, {})
        self.assertTrue(errors)




if __name__ == "__main__":
    unittest.main()
