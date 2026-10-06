"""Milestone 1: Squads v4 member discovery. Real fixtures: Exponent Finance's 3-of-5 upgrade multisig (v4) and
Phoenix's upgrade multisig (v3), both recorded read-only from mainnet on 2026-10-06."""
import base64
import io
import os
import tempfile
import unittest
from unittest import mock

from watchtower.base58 import b58decode
from watchtower.cli import main, watch_cycle
from watchtower.config import load_config
from watchtower.decode import account_bytes
from watchtower.diff import diff, snapshot
from watchtower.pda import find_program_address, is_on_curve
from watchtower.rpc import RpcClient, RpcUnavailable
from watchtower.scan import run_scan
from watchtower.squads import MULTISIG_DISCRIMINATOR, MultisigDecodeError, decode_multisig, vault_pda

from .helpers import EMPTY, SQUADS_V3_MS, SQUADS_V4_MS, SQUADS_V4_VAULT0, FixtureRpc, load

EXPONENT_MEMBERS = [
    ("ZsGaxkUnULynp4jX5AkYfQGtvacoKf9Axcdowc7s3cA", 7),
    ("2cVAT3oviEWgaTJkBipmN5KiYpmguzSqJG6hBa4Jfqgj", 7),
    ("AnWCbbRmFSmb4kW5w8oeBqW3bQ1pip9vncxTzDPgW2er", 7),
    ("HN8obiLBzfKUz87S7bmkWgcu8ysV7otcPUnws5gQU78E", 6),
    ("Hg8U22DzhvGHJ34yjkMi8WS82F3VH2EGuV3wiN6byNm3", 7),
]
MEMBERS_OFFSET = 8 + 32 + 32 + 2 + 4 + 8 + 8  # = 94: rent_collector Option tag


def ms_fixture(mutate=None, owner=None):
    f = load("squads_v4_exponent.json")
    v = f["result"]["value"]
    if mutate:
        raw = bytearray(base64.b64decode(v["data"][0]))
        raw = mutate(raw)
        v["data"][0] = base64.b64encode(bytes(raw)).decode()
    if owner:
        v["owner"] = owner
    return f


def scan_squads(squads, overrides=None, wallets=()):
    rpc = FixtureRpc(overrides=overrides)
    rep = run_scan(RpcClient(transport=rpc), [{"pubkey": w, "label": ""} for w in wallets], squads=list(squads))
    return rep, rpc


class PdaTests(unittest.TestCase):
    def test_vault_matches_on_chain_upgrade_authority(self):
        # Exponent's program upgrade authority (read from its ProgramData on-chain) is this multisig's vault 0.
        self.assertEqual(vault_pda(SQUADS_V4_MS, 0), (SQUADS_V4_VAULT0, 255))

    def test_vault_needs_off_curve_bump_search(self):
        # Published in github.com/Bonasa-Tech/manifest README; bump 253 means 255 and 254 landed on the curve.
        self.assertEqual(vault_pda("6o29zFofTxn8nM5o83JTY12G3cGgFy7mrtM2Cp3GQJXg", 0),
                         ("CDFU8tEWsVU2ZMiek57Sgk3Huha2yBNcSHLAts3V3Cbf", 253))

    def test_associated_token_accounts_from_real_fixture(self):
        ata_prog = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        spl = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        for e in load("tabo_spl_delegates.json")["result"]["value"]:
            info = e["account"]["data"]["parsed"]["info"]
            addr, _ = find_program_address([b58decode(info["owner"]), b58decode(spl), b58decode(info["mint"])], ata_prog)
            self.assertEqual(addr, e["pubkey"])

    def test_wallet_keys_are_on_curve(self):
        for k, _ in EXPONENT_MEMBERS:
            self.assertTrue(is_on_curve(b58decode(k)))
        self.assertFalse(is_on_curve(b58decode(SQUADS_V4_VAULT0)))


class DecodeTests(unittest.TestCase):
    def test_real_v4_multisig(self):
        ms = decode_multisig(account_bytes(load("squads_v4_exponent.json")["result"]["value"]))
        self.assertEqual([(m["key"], m["permissions"]) for m in ms["members"]], EXPONENT_MEMBERS)
        self.assertEqual(ms["members"][3]["permission_names"], ["vote", "execute"])
        self.assertEqual((ms["threshold"], ms["time_lock"]), (3, 36000))
        self.assertEqual((ms["transaction_index"], ms["stale_transaction_index"]), (208, 208))
        self.assertIsNone(ms["config_authority"])
        self.assertIsNone(ms["rent_collector"])
        self.assertEqual(ms["create_key"], "JCvBShe3qJeSMDjx33awH438yKe99tb8i7FdTUGBqt9D")
        self.assertEqual(ms["bump"], 252)

    def test_rent_collector_some_shifts_members(self):
        rc = b58decode(EMPTY)
        ms = decode_multisig(account_bytes(ms_fixture(
            lambda r: r[:MEMBERS_OFFSET] + b"\x01" + rc + r[MEMBERS_OFFSET + 1:])["result"]["value"]))
        self.assertEqual(ms["rent_collector"], EMPTY)
        self.assertEqual([(m["key"], m["permissions"]) for m in ms["members"]], EXPONENT_MEMBERS)

    def test_rejects_wrong_discriminator_bad_mask_truncation(self):
        raw = account_bytes(load("squads_v4_exponent.json")["result"]["value"])
        self.assertEqual(raw[:8], MULTISIG_DISCRIMINATOR)
        with self.assertRaises(MultisigDecodeError):
            decode_multisig(b"\0" * 8 + raw[8:])
        bad = bytearray(raw)
        bad[MEMBERS_OFFSET + 2 + 4 + 32] = 8  # first member's mask
        with self.assertRaises(MultisigDecodeError):
            decode_multisig(bytes(bad))
        with self.assertRaises(MultisigDecodeError):
            decode_multisig(raw[: MEMBERS_OFFSET + 2 + 4 + 33 * 2])


class ResolveTests(unittest.TestCase):
    def test_scan_watches_every_member_and_vault(self):
        rep, rpc = scan_squads([SQUADS_V4_MS])
        ms = rep["multisigs"][0]
        self.assertEqual(ms["status"], "ok")
        watched = [w["pubkey"] for w in rep["wallets"]]
        self.assertEqual(watched, [k for k, _ in EXPONENT_MEMBERS] + [SQUADS_V4_VAULT0])
        self.assertTrue(rep["wallets"][-1]["label"].endswith("vault 0"))
        nonce_queries = {p[1]["filters"][1]["memcmp"]["bytes"] for m, p in rpc.calls if m == "getProgramAccounts"}
        self.assertTrue(set(watched) <= nonce_queries)
        self.assertTrue(rep["complete"])
        self.assertIn("squads_multisig", [f["kind"] for f in rep["findings"]])

    def test_member_also_listed_by_hand_is_not_duplicated(self):
        rep, _ = scan_squads([SQUADS_V4_MS], wallets=[EXPONENT_MEMBERS[0][0]])
        self.assertEqual(len(rep["wallets"]), 6)

    def test_config_authority_is_watched_and_flagged(self):
        auth = b58decode(EMPTY)
        rep, _ = scan_squads([SQUADS_V4_MS], overrides={
            ("getAccountInfo", SQUADS_V4_MS): ms_fixture(lambda r: r[:40] + auth + r[72:])})
        self.assertIn(EMPTY, [w["pubkey"] for w in rep["wallets"]])
        self.assertIn(("medium", "squads_config_authority"), [(f["severity"], f["kind"]) for f in rep["findings"]])

    def _assert_loud(self, rep, status):
        ms = rep["multisigs"][0]
        self.assertEqual(ms["status"], status)
        self.assertEqual(rep["wallets"], [])  # nothing guessed
        self.assertFalse(rep["complete"])
        self.assertIn(("warn", "squads_" + status), [(f["severity"], f["kind"]) for f in rep["findings"]])

    def test_wrong_owner_fails_loud(self):
        rep, _ = scan_squads([SQUADS_V4_MS], overrides={
            ("getAccountInfo", SQUADS_V4_MS): ms_fixture(owner="11111111111111111111111111111111")})
        self._assert_loud(rep, "wrong_owner")

    def test_real_v3_multisig_is_unsupported(self):
        rep, _ = scan_squads([SQUADS_V3_MS])
        self._assert_loud(rep, "unsupported_v3")
        self.assertIn("NOT being watched", rep["findings"][0]["detail"])

    def test_missing_unavailable_and_forged_layout(self):
        rep, _ = scan_squads([EMPTY])
        self._assert_loud(rep, "missing")
        rep, _ = scan_squads([SQUADS_V4_MS], overrides={("getAccountInfo", SQUADS_V4_MS): RpcUnavailable("getAccountInfo", "HTTP 503")})
        self._assert_loud(rep, "unavailable")
        # Right owner and discriminator, but create_key changed: it no longer derives this address.
        rep, _ = scan_squads([SQUADS_V4_MS], overrides={
            ("getAccountInfo", SQUADS_V4_MS): ms_fixture(lambda r: r[:8] + b"\x05" * 32 + r[40:])})
        self._assert_loud(rep, "undecodable")

    def test_cli_exit_code_and_stderr(self):
        err = io.StringIO()
        with mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc())), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", err):
            self.assertEqual(main(["scan", "--squads", SQUADS_V4_MS]), 0)
            self.assertEqual(main(["scan", "--squads", SQUADS_V3_MS]), 2)
        self.assertIn("UNSUPPORTED_V3", err.getvalue())


def drop_last_member(raw):
    n = int.from_bytes(raw[96:100], "little")
    raw[96:100] = (n - 1).to_bytes(4, "little")
    end = 100 + 33 * n
    return raw[: end - 33] + b"\0" * 33 + raw[end:]


class WatchSquadsTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "w.toml")
        with open(p, "w") as f:
            f.write(f'squads = ["{SQUADS_V4_MS}"]\n')
        self.cfg = load_config(p)

    def test_member_removed_is_critical(self):
        before = snapshot(scan_squads([SQUADS_V4_MS])[0])
        after = snapshot(scan_squads([SQUADS_V4_MS], overrides={
            ("getAccountInfo", SQUADS_V4_MS): ms_fixture(drop_last_member)})[0], before)
        a = [x for x in diff(before, after) if x["kind"].startswith("multisig_")]
        self.assertEqual([(x["severity"], x["kind"], x["before"]) for x in a],
                         [("critical", "multisig_member_removed", EXPONENT_MEMBERS[-1][0])])

    def test_resolution_outage_keeps_last_known_members_watched(self):
        st = self.cfg["state_file"]
        watch_cycle(self.cfg, RpcClient(transport=FixtureRpc()), st, None, out=io.StringIO())
        rpc = FixtureRpc(overrides={("getAccountInfo", SQUADS_V4_MS): RpcUnavailable("getAccountInfo", "HTTP 503")})
        with mock.patch("sys.stderr", io.StringIO()):
            a = watch_cycle(self.cfg, RpcClient(transport=rpc), st, None, out=io.StringIO())
        queried = {p[1]["filters"][1]["memcmp"]["bytes"] for m, p in rpc.calls if m == "getProgramAccounts"}
        self.assertTrue({k for k, _ in EXPONENT_MEMBERS} | {SQUADS_V4_VAULT0} <= queried)
        self.assertEqual([(x["kind"], x["subject"]) for x in a], [("coverage_lost", f"squads:{SQUADS_V4_MS}")])


if __name__ == "__main__":
    unittest.main()
