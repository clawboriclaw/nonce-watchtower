"""Regression tests for the Milestone 1 review (Ava FIX-FIRST + K3 GO-with-fixes, 2026-10-06).
Each test fails on 00c767b."""
import unittest

from watchtower.base58 import b58decode, b58encode
from watchtower.diff import diff, snapshot
from watchtower.pda import is_on_curve
from watchtower.rpc import RpcClient
from watchtower.scan import run_scan

from .helpers import NONCE_ACCOUNTS, NONCE_AUTH, NONCE_CREATE_SIG, SPL, SYS, FixtureRpc, load

OUTSIDE = "8fyiEk9KAb25rbuW9PxBtUWBkWFFHNgEbSYkQGP6dV4a"
A82 = "82FQGbm5h1DC89F3h8LLzgtLRG4xw2TiMFmUA37G7jZs"


def tx_with(mutate):
    t = load("tx_nonce_create_3BxRHV8L.json")
    mutate(t["result"])
    return t


def scan(tx=None, overrides=None):
    ov = dict(overrides or {})
    if tx is not None:
        ov[("getTransaction", NONCE_CREATE_SIG)] = tx
    return run_scan(RpcClient(transport=FixtureRpc(overrides=ov)), [{"pubkey": NONCE_AUTH, "label": "c1"}])


def prov(rep):
    return {it["account"]: it["provenance"] for it in rep["wallets"][0]["nonces"]["items"]}


def sev_kinds(rep, kind):
    return [f["severity"] for f in rep["findings"] if f["kind"] == kind]


def _sys_tag(ix):
    return int.from_bytes(b58decode(ix["data"])[:4], "little")


class FunderUnknownTests(unittest.TestCase):
    """Ava #1 (blocking): only InitializeNonceAccount visible -> funder unknown -> unverified, never ok/watched."""

    def test_init_only_is_unverified(self):
        def drop_creates(tx):
            m = tx["transaction"]["message"]
            m["instructions"] = [ix for ix in m["instructions"]
                                 if not (m["accountKeys"][ix["programIdIndex"]] == SYS and _sys_tag(ix) == 0)]
        rep = scan(tx_with(drop_creates))
        for pv in prov(rep).values():
            self.assertEqual(pv["status"], "unverified")
            self.assertIn("funder unknown", pv["error"])
        self.assertFalse(rep["complete"])
        self.assertEqual(sev_kinds(rep, "nonce_created_by_watched"), [])
        self.assertEqual(len(sev_kinds(rep, "provenance_unavailable")), 5)

    def test_create_only_is_unverified(self):
        """CreateAccount visible, InitializeNonceAccount (system tag 6) dropped: initial authority unknown, not clean."""
        def drop_inits(tx):
            m = tx["transaction"]["message"]
            m["instructions"] = [ix for ix in m["instructions"]
                                 if not (m["accountKeys"][ix["programIdIndex"]] == SYS and _sys_tag(ix) == 6)]
        rep = scan(tx_with(drop_inits))
        for pv in prov(rep).values():
            self.assertEqual(pv["status"], "unverified")
            self.assertIn("initial authority unknown", pv["error"])
        self.assertFalse(rep["complete"])
        self.assertEqual(sev_kinds(rep, "nonce_created_by_watched"), [])


def watched_funder_outside_fee_payer(tx):
    """Fee payer (index 0) becomes OUTSIDE; NONCE_AUTH moves to the v0 writable lookup slot and funds every create."""
    m = tx["transaction"]["message"]
    n = len(m["accountKeys"])
    m["accountKeys"][0] = OUTSIDE
    tx["meta"]["loadedAddresses"]["writable"] = [NONCE_AUTH]
    for ix in m["instructions"]:
        ix["accounts"] = [i + 1 if i >= n else i for i in ix["accounts"]]
        if ix["accounts"] and m["accountKeys"][ix["programIdIndex"]] == SYS and _sys_tag(ix) == 0:
            ix["accounts"][0] = n


class CreatorClassificationTests(unittest.TestCase):
    """Ava #2 / K3 #3: funder or initial authority decides; an outside fee payer alone is a separate MEDIUM."""

    def test_outside_fee_payer_only_is_medium_not_high(self):
        rep = scan(tx_with(watched_funder_outside_fee_payer))
        for pv in prov(rep).values():
            self.assertEqual((pv["status"], pv["creator"], pv["funder"]), ("ok", "watched", NONCE_AUTH))
            self.assertTrue(pv["fee_payer_outside"])
        self.assertEqual(sev_kinds(rep, "nonce_outside_creator"), [])
        self.assertEqual(sev_kinds(rep, "nonce_outside_fee_payer"), ["medium"] * 5)
        d = next(f["detail"] for f in rep["findings"] if f["kind"] == "nonce_outside_fee_payer")
        self.assertIn(f"funded by watched key c1 ({NONCE_AUTH})", d)
        self.assertIn(f"fee paid by outside key {OUTSIDE} (relayer?)", d)

    def test_outside_initial_authority_is_high(self):
        def outside_init_authority(tx):
            m = tx["transaction"]["message"]
            for ix in m["instructions"]:
                if m["accountKeys"][ix["programIdIndex"]] == SYS and _sys_tag(ix) == 6 and m["accountKeys"][ix["accounts"][0]] == A82:
                    raw = b58decode(ix["data"])
                    ix["data"] = b58encode(raw[:4] + b58decode(OUTSIDE) + raw[36:])
        rep = scan(tx_with(outside_init_authority))
        pv = prov(rep)[A82]
        self.assertEqual((pv["creator"], pv["initial_authority"], pv["outside_keys"]), ("outside", OUTSIDE, [OUTSIDE]))
        self.assertEqual(sev_kinds(rep, "nonce_outside_creator"), ["high"])
        d = next(f["detail"] for f in rep["findings"] if f["kind"] == "nonce_outside_creator")
        self.assertIn(f"funded by watched key c1 ({NONCE_AUTH})", d)
        self.assertIn(f"initial nonce authority was OUTSIDE key {OUTSIDE}", d)

    def test_outside_funder_text_does_not_contradict(self):
        def outside_payer(tx):
            tx["transaction"]["message"]["accountKeys"][0] = OUTSIDE
        rep = scan(tx_with(outside_payer))
        details = [f["detail"] for f in rep["findings"] if f["kind"] == "nonce_outside_creator"]
        self.assertEqual(len(details), 5)
        for d in details:
            self.assertIn(f"funded by OUTSIDE key {OUTSIDE}", d)
            self.assertIn(f"fee paid by outside key {OUTSIDE}", d)
            self.assertNotIn("watched key", d)
        self.assertEqual(sev_kinds(rep, "nonce_outside_fee_payer"), [])  # covered by the high finding

    def test_watch_diff_uses_the_same_rule(self):
        snap = snapshot(scan(tx_with(watched_funder_outside_fee_payer)))
        a = diff(None, snap)
        self.assertEqual([x["severity"] for x in a if x["kind"] == "nonce_outside_fee_payer"], ["medium"] * 5)
        self.assertFalse([x for x in a if x["kind"] == "nonce_outside_creator"])


def lock_report(**tok):
    item = {"account": "LockAcct1111111111111111111111111111111111", "program": SPL, "mint": "Mint111", "owner": "W",
            "state": "frozen", "delegate": "D111", "delegated_amount": "1", "delegated_ui": "1", "close_authority": None,
            "amount": "1", "decimals": 0, "mint_checked": True, "mint_supply": "1", "mint_freeze_authority": None}
    item.update(tok)
    tokens = {"status": "ok", "program_status": {SPL: "ok", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "ok"},
              "items": [item], "permanent_delegates_status": "ok", "permanent_delegates": []}
    return {"wallets": [{"pubkey": "W", "label": "", "nonces": {"status": "ok", "items": []}, "token_accounts": tokens}],
            "mints": [], "programs": []}


class WatchNftLockTests(unittest.TestCase):
    """K3 #1: watch must grade a verified frozen 1-of-1 lock like scan (info/medium), and an unverified one HIGH."""

    def _delegate_alerts(self, old, new):
        return [(a["severity"], a["kind"]) for a in diff(old, new) if "delegate" in a["kind"] or "lock" in a["kind"]]

    def test_verified_lock_is_not_high(self):
        self.assertEqual(self._delegate_alerts(None, snapshot(lock_report())), [("info", "existing_nft_lock_delegate")])
        thawable = snapshot(lock_report(mint_freeze_authority="FreezeAuth1"))
        self.assertEqual(self._delegate_alerts(None, thawable), [("medium", "existing_nft_lock_delegate")])
        empty = snapshot(lock_report(delegate=None))
        self.assertEqual(self._delegate_alerts(empty, snapshot(lock_report())), [("info", "new_nft_lock_delegate")])

    def test_unverified_mint_stays_high(self):
        unverified = snapshot(lock_report(mint_checked=None, mint_supply=None))
        self.assertEqual(self._delegate_alerts(None, unverified), [("high", "existing_delegate")])

    def test_thawed_lock_re_arms_delegate_high(self):
        before = snapshot(lock_report())
        after = snapshot(lock_report(state="initialized"), before)
        self.assertIn(("high", "nft_lock_released"), self._delegate_alerts(before, after))


class ProvenanceCarryForwardTests(unittest.TestCase):
    """K3 #2: an outage must not erase a settled provenance, so nonce_outside_creator does not re-fire."""

    def test_outside_creator_fires_once_across_an_outage(self):
        def outside_payer(tx):
            tx["transaction"]["message"]["accountKeys"][0] = OUTSIDE
        outside = tx_with(outside_payer)
        no_history = {("getSignaturesForAddress", a): {"jsonrpc": "2.0", "id": 1, "result": []} for a in NONCE_ACCOUNTS}
        s1 = snapshot(scan(outside))
        s2 = snapshot(scan(overrides=no_history), s1)
        self.assertTrue(all(v["provenance"]["status"] == "ok" for v in s2["nonces"].values()))
        a2 = diff(s1, s2)
        self.assertEqual({x["kind"] for x in a2}, {"coverage_lost"})
        s3 = snapshot(scan(outside), s2)
        a3 = diff(s2, s3)
        self.assertEqual({x["kind"] for x in a3}, {"coverage_restored"})


class PdaCanonicalityTests(unittest.TestCase):
    """K3 #4 (comment fix): y >= p is reduced, as curve25519-dalek's FieldElement::from_bytes does."""

    def test_non_canonical_y_is_reduced(self):
        y = (2**255 - 18).to_bytes(32, "little")  # = p + 1, which dalek decodes to 1 -> the point (0, 1)
        self.assertTrue(is_on_curve(y))


if __name__ == "__main__":
    unittest.main()
