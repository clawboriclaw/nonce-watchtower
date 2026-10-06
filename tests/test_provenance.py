"""Milestone 1: nonce provenance. Real fixtures: the signature history of the 5 real nonce accounts held by
NONCE_AUTH and the transaction that created all of them, recorded read-only from mainnet on 2026-10-06."""
import io
import os
import tempfile
import unittest
from unittest import mock

from watchtower.cli import main, watch_cycle
from watchtower.config import load_config
from watchtower.provenance import MAX_PAGES, PAGE_LIMIT, nonce_provenance
from watchtower.rpc import READ_ONLY_METHODS, RpcClient, RpcUnavailable
from watchtower.scan import run_scan

from .helpers import EMPTY, NONCE_ACCOUNTS, NONCE_AUTH, NONCE_CREATE_SIG, NONCE_USE_SIG, FixtureRpc, load

OUTSIDE = "8fyiEk9KAb25rbuW9PxBtUWBkWFFHNgEbSYkQGP6dV4a"


def scan(overrides=None, provenance=True):
    rpc = FixtureRpc(overrides=overrides)
    rep = run_scan(RpcClient(transport=rpc), [{"pubkey": NONCE_AUTH, "label": "council-1"}], provenance=provenance)
    return rep, rpc


def items(rep):
    return rep["wallets"][0]["nonces"]["items"]


def kinds(rep):
    return [(f["severity"], f["kind"]) for f in rep["findings"]]


def tx_with(mutate):
    t = load("tx_nonce_create_3BxRHV8L.json")
    mutate(t["result"])
    return t


def outside_payer(tx):
    tx["transaction"]["message"]["accountKeys"][0] = OUTSIDE


class RealProvenanceTests(unittest.TestCase):
    def test_created_by_watched_key(self):
        rep, rpc = scan()
        self.assertEqual(len(items(rep)), 5)
        for it in items(rep):
            pv = it["provenance"]
            self.assertEqual(pv["status"], "ok")
            self.assertEqual(pv["signature"], NONCE_CREATE_SIG)
            self.assertEqual(pv["created_at"], "2025-07-08T18:10:18+00:00")
            self.assertEqual(pv["slot"], 351986500)
            self.assertEqual((pv["fee_payer"], pv["funder"], pv["initial_authority"]), (NONCE_AUTH,) * 3)
            self.assertEqual((pv["creator"], pv["fee_payer_watched"]), ("watched", "council-1"))
        self.assertEqual(kinds(rep).count(("info", "nonce_created_by_watched")), 5)
        self.assertNotIn(("high", "nonce_outside_creator"), kinds(rep))
        self.assertTrue(rep["complete"])
        # 2HYc... has 2 signatures; the OLDEST (the creation) must be the one fetched, never the newer advance.
        txs = [p for m, p in rpc.calls if m == "getTransaction"]
        self.assertEqual({p[0] for p in txs}, {NONCE_CREATE_SIG})
        self.assertEqual(txs[0][1]["maxSupportedTransactionVersion"], 0)

    def test_pruned_history_showing_only_a_later_use_is_unverified(self):
        # Real data: 2HYc...'s newer transaction is a durable-nonce USE (AdvanceNonceAccount), not its creation.
        # An RPC that has pruned the creation would show only that one; it must not be read as the creator.
        acct = "2HYcWwR6ZzVeHfoSB2Z1MtytZwXMbMRpTqC36wJHfJHn"
        sigs = load(f"sigs_{acct}.json")
        sigs["result"] = [s for s in sigs["result"] if s["signature"] == NONCE_USE_SIG]
        rep, rpc = scan({("getSignaturesForAddress", acct): sigs})
        pv = {it["account"]: it["provenance"] for it in items(rep)}[acct]
        self.assertEqual(pv["status"], "unverified")
        self.assertIn(NONCE_USE_SIG, [p[0] for m, p in rpc.calls if m == "getTransaction"])
        self.assertFalse(rep["complete"])

    def test_history_methods_are_read_only_allowlisted(self):
        self.assertTrue({"getSignaturesForAddress", "getTransaction"} <= READ_ONLY_METHODS)


class SyntheticProvenanceTests(unittest.TestCase):
    def test_outside_creator_is_high(self):
        rep, _ = scan({("getTransaction", NONCE_CREATE_SIG): tx_with(outside_payer)})
        pv = items(rep)[0]["provenance"]
        self.assertEqual((pv["creator"], pv["fee_payer"], pv["outside_keys"]), ("outside", OUTSIDE, [OUTSIDE]))
        hi = [f for f in rep["findings"] if f["kind"] == "nonce_outside_creator"]
        self.assertEqual(len(hi), 5)
        self.assertTrue(all(f["severity"] == "high" and OUTSIDE in f["detail"] for f in hi))

    def test_outside_creator_exit_code_and_watch_alert(self):
        ov = {("getTransaction", NONCE_CREATE_SIG): tx_with(outside_payer)}
        with mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc(overrides=ov))), \
                mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(main(["scan", NONCE_AUTH]) & 1, 1)
        d = tempfile.mkdtemp()
        p = os.path.join(d, "w.toml")
        with open(p, "w") as f:
            f.write(f'[[wallets]]\nlabel = "c1"\npubkey = "{NONCE_AUTH}"\n')
        cfg = load_config(p)
        with mock.patch("sys.stderr", io.StringIO()):
            a = watch_cycle(cfg, RpcClient(transport=FixtureRpc(overrides=ov)), cfg["state_file"], None, out=io.StringIO())
        self.assertEqual([x["severity"] for x in a if x["kind"] == "nonce_outside_creator"], ["high"] * 5)

    def test_outside_funder_with_watched_fee_payer_is_still_outside(self):
        # Put OUTSIDE in the v0 lookup-table writable slot (index 8, ahead of the readonly sysvars) and make it
        # the funding account of the CreateAccount for 82FQ...: resolves loaded addresses, then flags the funder.
        def outside_funder(tx):
            n = len(tx["transaction"]["message"]["accountKeys"])
            tx["meta"]["loadedAddresses"]["writable"] = [OUTSIDE]
            for ix in tx["transaction"]["message"]["instructions"]:
                ix["accounts"] = [i + 1 if i >= n else i for i in ix["accounts"]]
            tx["transaction"]["message"]["instructions"][2]["accounts"][0] = n
        rep, _ = scan({("getTransaction", NONCE_CREATE_SIG): tx_with(outside_funder)})
        pv = {it["account"]: it["provenance"] for it in items(rep)}
        self.assertEqual((pv["82FQGbm5h1DC89F3h8LLzgtLRG4xw2TiMFmUA37G7jZs"]["funder"],
                          pv["82FQGbm5h1DC89F3h8LLzgtLRG4xw2TiMFmUA37G7jZs"]["creator"]), (OUTSIDE, "outside"))
        self.assertEqual(pv["82FQGbm5h1DC89F3h8LLzgtLRG4xw2TiMFmUA37G7jZs"]["fee_payer"], NONCE_AUTH)
        self.assertEqual(pv["2HYcWwR6ZzVeHfoSB2Z1MtytZwXMbMRpTqC36wJHfJHn"]["creator"], "watched")

    def _assert_not_clean(self, rep, status):
        for it in items(rep):
            self.assertEqual(it["provenance"]["status"], status)
        self.assertFalse(rep["complete"])
        self.assertEqual(kinds(rep).count(("warn", "provenance_unavailable")), 5)
        self.assertNotIn(("info", "nonce_created_by_watched"), kinds(rep))

    def test_no_history_is_unavailable_not_clean(self):
        empty = {"jsonrpc": "2.0", "id": 1, "result": []}
        rep, _ = scan({("getSignaturesForAddress", a): empty for a in NONCE_ACCOUNTS})
        self._assert_not_clean(rep, "unavailable")
        with mock.patch("watchtower.cli._client", return_value=RpcClient(transport=FixtureRpc(
                overrides={("getSignaturesForAddress", a): empty for a in NONCE_ACCOUNTS}))), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(main(["scan", NONCE_AUTH]), 3)

    def test_rpc_failures_are_unavailable(self):
        rep, _ = scan({("getSignaturesForAddress", a): RpcUnavailable("getSignaturesForAddress", "HTTP 429") for a in NONCE_ACCOUNTS})
        self._assert_not_clean(rep, "unavailable")
        rep, _ = scan({("getTransaction", NONCE_CREATE_SIG): {"jsonrpc": "2.0", "id": 1, "result": None}})
        self._assert_not_clean(rep, "unavailable")

    def test_oldest_visible_tx_that_does_not_create_is_unverified(self):
        def strip_system(tx):
            m = tx["transaction"]["message"]
            m["instructions"] = [ix for ix in m["instructions"] if m["accountKeys"][ix["programIdIndex"]] != "11111111111111111111111111111111"]
        rep, _ = scan({("getTransaction", NONCE_CREATE_SIG): tx_with(strip_system)})
        self._assert_not_clean(rep, "unverified")

    def test_substituted_transaction_is_unverified(self):
        rep, _ = scan({("getTransaction", NONCE_CREATE_SIG): tx_with(lambda t: t["transaction"]["signatures"].__setitem__(0, "1" * 64))})
        self._assert_not_clean(rep, "unverified")

    def test_pagination_walks_to_the_oldest(self):
        acct = NONCE_ACCOUNTS[0]
        real = load(f"sigs_{acct}.json")["result"]
        filler = [{"signature": f"S{i}", "err": None, "slot": 10**9 - i} for i in range(PAGE_LIMIT)]
        pages = []

        def route(m, p):
            if m == "getSignaturesForAddress":
                pages.append(p[1].get("before"))
                return {"result": filler if p[1].get("before") is None else real}
            if m == "getTransaction":
                return load("tx_nonce_create_3BxRHV8L.json") if p[0] == NONCE_CREATE_SIG else {"result": None}
            raise AssertionError(m)

        pv = nonce_provenance(RpcClient(transport=route), acct, {NONCE_AUTH: "c1"})
        self.assertEqual(pages, [None, f"S{PAGE_LIMIT - 1}"])
        self.assertEqual((pv["status"], pv["signature"], pv["history_signatures"]), ("ok", NONCE_CREATE_SIG, PAGE_LIMIT + 2))

    def test_history_too_long_is_unavailable(self):
        filler = [{"signature": f"S{i}", "err": None} for i in range(PAGE_LIMIT)]
        calls = []
        route = lambda m, p: calls.append(m) or {"result": filler}
        pv = nonce_provenance(RpcClient(transport=route), NONCE_ACCOUNTS[0], {})
        self.assertEqual(pv["status"], "unavailable")
        self.assertEqual(len(calls), MAX_PAGES)

    def test_no_provenance_flag_skips_history(self):
        rep, rpc = scan(provenance=False)
        self.assertFalse([m for m, _ in rpc.calls if m in ("getSignaturesForAddress", "getTransaction")])
        self.assertEqual(rep["provenance"], "skipped")

    def test_watch_caches_settled_provenance(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "w.toml")
        with open(p, "w") as f:
            f.write(f'[[wallets]]\npubkey = "{NONCE_AUTH}"\n')
        cfg = load_config(p)
        with mock.patch("sys.stderr", io.StringIO()):
            watch_cycle(cfg, RpcClient(transport=FixtureRpc()), cfg["state_file"], None, out=io.StringIO())
            rpc = FixtureRpc()
            self.assertEqual(watch_cycle(cfg, RpcClient(transport=rpc), cfg["state_file"], None, out=io.StringIO()), [])
        self.assertFalse([m for m, _ in rpc.calls if m in ("getSignaturesForAddress", "getTransaction")])

    def test_empty_wallet_needs_no_history(self):
        rpc = FixtureRpc()
        rep = run_scan(RpcClient(transport=rpc), [{"pubkey": EMPTY, "label": ""}])
        self.assertTrue(rep["complete"])
        self.assertFalse([m for m, _ in rpc.calls if m == "getSignaturesForAddress"])


if __name__ == "__main__":
    unittest.main()
