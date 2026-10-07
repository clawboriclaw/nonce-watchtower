"""Replay of the Drift Protocol exploit (1 April 2026) through the real watch cycle, offline.

The attacker staged two durable-nonce accounts whose authorities were two member keys of the Squads multisig
that held Drift's admin (its Security Council, per public reports), paid for by a key outside that multisig,
days before using them to take over the protocol's admin. This test watches those two member keys and steps the
chain through four points in time, running the same scan -> snapshot -> diff cycle that `watchtower watch`
runs. It shows, on recorded data, that the alerts fire at staging time, more than eight days before the exploit
(assuming the watcher was running then: the real lead time is this minus one scan interval).

Data: tests/fixtures/drift/ (public mainnet RPC responses, recorded by tools/record_drift.py). What is recorded
verbatim and what is rebuilt from it is spelled out in tests/fixtures/drift/README.md.
"""

import base64
import datetime as dt
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr

from watchtower.base58 import b58decode, b58encode as _b58encode
from watchtower.cli import watch_cycle
from watchtower.rpc import RpcClient

from .helpers import FIX, FixtureRpc, SYS

DRIFT = os.path.join(FIX, "drift")

MEMBER_A = "39JyWrdbVdRqjzw9yyEjxNtTbTKcTPLdtdCgbz7C7Aq8"  # member of COUNCIL_MS (signed attack tx 1)
MEMBER_B = "6UJbu9ut5VAsFYQFgPEa5xPfoyF5bB5oi4EknFPvu924"  # member of COUNCIL_MS (signed attack tx 2)
COUNCIL_MS = "2LW6PSEjp81xSEttWwXDB6Etb1eKdhYPbFEojYbyhx88"  # Squads v4 multisig whose vault held Drift's admin
DRIFT_STATE = "5zpq7DvB6UdFFvpmBPspGPNfUGoBRRCE2HHg5u3gxcsN"  # Drift program state account (admin field)
SQUADS_V4 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
DRIFT_PROGRAM = "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH"
SYSTEM_ADVANCE_NONCE = 4  # System instruction tag
NONCE_A = "7s7s6saC5LHZoLyBXLM3pCjpWaA7meyQdP8NiH9ktAeC"   # authority MEMBER_A
NONCE_B = "EmYEryTDXtuVCxrjNqJXbiwr4hfiJajd4g5P58vvhQnc"   # authority MEMBER_B
FUNDER = "FMJnBkVpHj5JzN7w4XFysCwY931CYSYk1DsXzqNi7YPF"    # paid for both nonce accounts; not a council key
ATTACK_1 = "2HvMSgDEfKhNryYZKhjowrBY55rUx5MWtcWkG9hqxZCFBaTiahPwfynP1dxBSRk9s5UTVc8LFeS4Btvkm9pc2C4H"
ATTACK_2 = "4BKBmAJn6TdsENij7CsVbyMVLJU1tX27nfrMM1zgKv1bs2KJy6Am2NqdA3nJm4g9C6eC64UAf5sNs974ygB9RsN1"
NONCE_FIELD = slice(40, 72)  # stored durable-nonce value inside the 80-byte nonce account


def _load(name):
    with open(os.path.join(DRIFT, name)) as f:
        return json.load(f)


def _tx(sig):
    return _load(f"tx_{sig[:8]}.json")["result"]


def anchor_disc(name):
    """Anchor instruction discriminator: first 8 bytes of sha256("global:<name>")."""
    return hashlib.sha256(f"global:{name}".encode()).digest()[:8]


NAMES = ("vault_transaction_create", "proposal_create", "proposal_approve", "vault_transaction_execute", "update_admin")


def _name(data):
    return {anchor_disc(n): n for n in NAMES}.get(b58decode(data)[:8])


def _keys(tx):
    meta = tx["meta"]
    return tx["transaction"]["message"]["accountKeys"] + meta["loadedAddresses"]["writable"] + meta["loadedAddresses"]["readonly"]


def decoded(tx, program):
    """(instruction name or None, account keys) for each top-level instruction of `program`, from its data bytes."""
    keys = _keys(tx)
    return [(_name(i["data"]), [keys[a] for a in i["accounts"]])
            for i in tx["transaction"]["message"]["instructions"] if keys[i["programIdIndex"]] == program]


def decoded_inner(tx, program):
    """(parent top-level instruction name, inner instruction name, account keys) for each inner (CPI) instruction
    of `program`, bound to its parent through the innerInstructions group index."""
    keys, top = _keys(tx), tx["transaction"]["message"]["instructions"]
    return [(_name(top[g["index"]]["data"]), _name(i["data"]), [keys[a] for a in i["accounts"]])
            for g in tx["meta"].get("innerInstructions") or [] for i in g["instructions"]
            if keys[i["programIdIndex"]] == program]


class Chain:
    """The recorded history of one nonce account, queryable "as of" a slot."""

    def __init__(self, account, member):
        self.account, self.member = account, member
        self.sigs = _load(f"sigs_{account}.json")["result"]  # newest first, as the RPC returns them
        self.now = _load(f"account_{account}.json")["result"]["value"]  # state after the attack (unchanged since)
        if len(self.sigs) != 2:
            raise ValueError(f"{account}: expected exactly the creation and the attack's advance in the recorded history")
        create, advance = self.sigs[-1], self.sigs[0]
        self.created_slot, self.created_time = create["slot"], create["blockTime"]
        self.advanced_slot = advance["slot"]
        # The nonce value before the advance is the `recentBlockhash` the advancing transaction was signed
        # against: a durable-nonce transaction carries the stored nonce there (recorded, not invented).
        self.before = _tx(advance["signature"])["transaction"]["message"]["recentBlockhash"]

    def account_as_of(self, slot):
        if slot < self.created_slot:
            return None
        raw = bytearray(base64.b64decode(self.now["data"][0]))
        if slot < self.advanced_slot:
            raw[NONCE_FIELD] = b58decode(self.before)
        value = dict(self.now, data=[base64.b64encode(bytes(raw)).decode(), "base64"])
        return {"pubkey": self.account, "account": value}

    def sigs_as_of(self, slot):
        return [s for s in self.sigs if s["slot"] <= slot]


class TimeTravelRpc(FixtureRpc):
    """FixtureRpc that answers for the Drift accounts as the chain stood at `slot`."""

    def __init__(self, slot, chains, hide_history=False):
        super().__init__(slot=slot, gpa_slot=slot)
        self.at, self.chains, self.hide_history = slot, chains, hide_history
        self.txs = {s["signature"]: s["slot"] for c in chains for s in c.sigs}

    def _route(self, method, params):
        key = self._key(method, params)
        if method == "getProgramAccounts" and key != SYS:
            hits = [c.account_as_of(self.at) for c in self.chains if c.member == key]
            return {"jsonrpc": "2.0", "id": 1, "result": [h for h in hits if h]}
        if method == "getSignaturesForAddress":
            chain = next((c for c in self.chains if c.account == key), None)
            res = [] if (chain is None or self.hide_history) else chain.sigs_as_of(self.at)
            return {"jsonrpc": "2.0", "id": 1, "result": res}
        if method == "getTransaction":
            ok = key in self.txs and self.txs[key] <= self.at
            return {"jsonrpc": "2.0", "id": 1, "result": _tx(key) if ok else None}
        if method == "getAccountInfo" and any(c.account == key for c in self.chains):
            c = next(c for c in self.chains if c.account == key)
            hit = c.account_as_of(self.at)
            return {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": self.at}, "value": hit and hit["account"]}}
        return super()._route(method, params)


CHAINS = [Chain(NONCE_A, MEMBER_A), Chain(NONCE_B, MEMBER_B)]
A, B = CHAINS
EXPLOIT_TIME = _tx(ATTACK_1)["blockTime"]
CHECKPOINTS = [
    ("before staging", A.created_slot - 1),
    ("nonce A staged", A.created_slot),
    ("nonce B staged", B.created_slot),
    ("exploit executed", B.advanced_slot),
]


def replay(wallets, hide_history=False):
    """Run one watch cycle per checkpoint against a fresh state file. Returns {checkpoint name: alerts}."""
    cfg = {"wallets": wallets, "mints": [], "programs": [], "squads": []}
    out = {}
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state.json")
        for name, slot in CHECKPOINTS:
            client = RpcClient(transport=TimeTravelRpc(slot, CHAINS, hide_history))
            with redirect_stderr(io.StringIO()):
                out[name] = watch_cycle(cfg, client, state, webhook=None, out=io.StringIO())
    return out


COUNCIL = [{"pubkey": MEMBER_A, "label": "council signer A"}, {"pubkey": MEMBER_B, "label": "council signer B"}]


def by_kind(alerts, kind, subject=None):
    return [a for a in alerts if a["kind"] == kind and (subject is None or a["subject"] == subject)]


class DriftReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cycles = replay(COUNCIL)

    def test_recorded_timeline_is_what_the_test_claims(self):
        # Guards the fixtures themselves: slots and times as recorded from mainnet.
        self.assertEqual((A.created_slot, A.advanced_slot, B.created_slot, B.advanced_slot),
                         (408444056, 410344005, 409999217, 410344009))
        self.assertEqual(dt.datetime.fromtimestamp(A.created_time, dt.timezone.utc).isoformat(), "2026-03-24T01:22:06+00:00")
        self.assertEqual(dt.datetime.fromtimestamp(EXPLOIT_TIME, dt.timezone.utc).isoformat(), "2026-04-01T16:05:18+00:00")
        self.assertEqual({A.sigs[0]["signature"], B.sigs[0]["signature"]}, {ATTACK_1, ATTACK_2})

    def test_each_attack_tx_advances_its_own_nonce_first(self):
        # Runtime rule: a durable-nonce transaction's FIRST instruction is AdvanceNonceAccount on the nonce whose
        # stored value is the transaction's recentBlockhash. That is what makes Chain.before a recorded value.
        for c in CHAINS:
            tx = _tx(c.sigs[0]["signature"])
            keys, first = tx["transaction"]["message"]["accountKeys"], tx["transaction"]["message"]["instructions"][0]
            self.assertEqual(keys[first["programIdIndex"]], SYS)
            self.assertEqual(int.from_bytes(b58decode(first["data"])[:4], "little"), SYSTEM_ADVANCE_NONCE)
            self.assertEqual(keys[first["accounts"][0]], c.account)

    def test_watched_keys_are_members_of_the_multisig_that_moved_drift_admin(self):
        # What the fixtures prove about the two keys (no outside attribution needed): each signed a successful
        # transaction that approved a proposal on COUNCIL_MS (Squads only accepts approvals from members), and the
        # second executed that multisig's vault transaction, which ran Drift's UpdateAdmin on DRIFT_STATE.
        for sig, member in ((ATTACK_1, MEMBER_A), (ATTACK_2, MEMBER_B)):
            tx = _tx(sig)
            msg, meta = tx["transaction"]["message"], tx["meta"]
            keys = msg["accountKeys"] + meta["loadedAddresses"]["writable"] + meta["loadedAddresses"]["readonly"]
            self.assertIsNone(meta["err"])
            self.assertEqual((msg["header"]["numRequiredSignatures"], keys[0]), (1, member))
            squads = [ix for ix in msg["instructions"] if keys[ix["programIdIndex"]] == SQUADS_V4]
            self.assertTrue(squads and all(keys[ix["accounts"][0]] == COUNCIL_MS for ix in squads))
            # Decoded from the instruction bytes, not the logs: a proposal_approve on COUNCIL_MS whose member
            # account (index 1: multisig, member, proposal) is the signer.
            approvals = [accts for name, accts in decoded(tx, SQUADS_V4) if name == "proposal_approve"]
            self.assertEqual([(a[0], a[1]) for a in approvals], [(COUNCIL_MS, member)])
            self.assertIn("Program log: Instruction: ProposalApprove", meta["logMessages"])  # secondary
        self.assertEqual([n for n, _ in decoded(_tx(ATTACK_1), SQUADS_V4)],
                         ["vault_transaction_create", "proposal_create", "proposal_approve"])
        executed = _tx(ATTACK_2)
        self.assertEqual([n for n, _ in decoded(executed, SQUADS_V4)], ["proposal_approve", "vault_transaction_execute"])
        # Drift's admin change ran as an inner (CPI) instruction whose parent is that vault_transaction_execute,
        # on the Drift state account.
        admin = [(parent, accts) for parent, name, accts in decoded_inner(executed, DRIFT_PROGRAM) if name == "update_admin"]
        self.assertEqual(len(admin), 1)
        self.assertEqual(admin[0][0], "vault_transaction_execute")
        self.assertIn(DRIFT_STATE, admin[0][1])
        self.assertIn("Program log: Instruction: UpdateAdmin", executed["meta"]["logMessages"])  # secondary
        loaded = executed["meta"]["loadedAddresses"]
        self.assertIn(DRIFT_STATE, executed["transaction"]["message"]["accountKeys"] + loaded["writable"] + loaded["readonly"])

    def test_mutant_wrong_discriminator_is_not_decoded_as_an_approval(self):
        # The decode check must be able to fail: corrupt the proposal_approve data and it no longer matches.
        tx = json.loads(json.dumps(_tx(ATTACK_1)))
        keys = tx["transaction"]["message"]["accountKeys"]
        ix = [i for i in tx["transaction"]["message"]["instructions"] if keys[i["programIdIndex"]] == SQUADS_V4][-1]
        self.assertEqual(b58decode(ix["data"])[:8], anchor_disc("proposal_approve"))
        bad = bytearray(b58decode(ix["data"]))
        bad[0] ^= 0xFF
        ix["data"] = _b58encode(bytes(bad))
        self.assertNotIn("proposal_approve", [n for n, _ in decoded(tx, SQUADS_V4)])

    def test_quiet_before_staging(self):
        nonce_kinds = [a["kind"] for a in self.cycles["before staging"] if "nonce" in a["kind"]]
        self.assertEqual(nonce_kinds, [])

    def test_unrecorded_token_state_is_a_loud_gap_not_clean(self):
        # March token-account state was not recorded, so the replay serves none that passes the freshness check.
        # The tool must say those checks are not running rather than report the signers' tokens as clean.
        gaps = {a["subject"] for a in self.cycles["before staging"] if a["kind"] == "coverage_lost"}
        self.assertEqual(gaps, {f"tokens:{MEMBER_A}", f"tokens:{MEMBER_B}"})

    def test_first_nonce_alerts_at_staging(self):
        alerts = self.cycles["nonce A staged"]
        new = by_kind(alerts, "new_nonce_account", NONCE_A)
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]["severity"], "critical")
        self.assertEqual(new[0]["wallet"], "council signer A")
        self.assertIn(f"Funded by an OUTSIDE key {FUNDER}", new[0]["detail"])
        outside = by_kind(alerts, "nonce_outside_creator", NONCE_A)
        self.assertEqual(len(outside), 1)
        self.assertEqual(outside[0]["severity"], "high")
        self.assertIn(f"funded by OUTSIDE key {FUNDER}", outside[0]["detail"])
        self.assertEqual(by_kind(alerts, "new_nonce_account", NONCE_B), [])

    def test_second_nonce_alerts_and_first_is_not_repeated(self):
        alerts = self.cycles["nonce B staged"]
        self.assertEqual([a["severity"] for a in by_kind(alerts, "new_nonce_account", NONCE_B)], ["critical"])
        outside = by_kind(alerts, "nonce_outside_creator", NONCE_B)
        self.assertEqual(len(outside), 1)
        self.assertIn(FUNDER, outside[0]["detail"])
        self.assertEqual(outside[0]["wallet"], "council signer B")
        self.assertEqual([a for a in alerts if a["subject"] == NONCE_A], [])

    def test_exploit_shows_as_both_nonces_advancing(self):
        alerts = self.cycles["exploit executed"]
        for c in CHAINS:
            adv = by_kind(alerts, "nonce_advanced", c.account)
            self.assertEqual(len(adv), 1, c.account)
            self.assertEqual(adv[0]["before"], c.before)
            self.assertNotEqual(adv[0]["after"], c.before)

    def test_lead_time_over_eight_days(self):
        first_critical = min(c.created_time for c in CHAINS)
        lead = dt.timedelta(seconds=EXPLOIT_TIME - first_critical)
        self.assertGreaterEqual(lead, dt.timedelta(days=8))
        self.assertEqual(lead, dt.timedelta(days=8, hours=14, minutes=43, seconds=12))
        # ...and the alert really was raised at that checkpoint, not later.
        self.assertTrue(by_kind(self.cycles["nonce A staged"], "new_nonce_account", NONCE_A))


class DriftReplayMutants(unittest.TestCase):
    """The assertions above are not vacuous: change one input and the specific alert goes away."""

    def test_funder_inside_watched_set_is_not_outside(self):
        run = replay(COUNCIL + [{"pubkey": FUNDER, "label": "funder"}])
        self.assertEqual(by_kind(run["nonce A staged"], "nonce_outside_creator"), [])
        self.assertEqual(len(by_kind(run["nonce A staged"], "new_nonce_account", NONCE_A)), 1)

    def test_no_history_means_creator_unknown_not_cleared(self):
        run = replay(COUNCIL, hide_history=True)
        alerts = run["nonce A staged"]
        self.assertEqual(by_kind(alerts, "nonce_outside_creator"), [])
        new = by_kind(alerts, "new_nonce_account", NONCE_A)
        self.assertEqual(len(new), 1)
        self.assertIn("Creator UNKNOWN", new[0]["detail"])
        self.assertEqual(new[0]["severity"], "critical")  # unknown is not downgraded

    def test_unwatched_keys_see_nothing(self):
        run = replay([{"pubkey": FUNDER, "label": "funder"}])
        self.assertEqual([a for al in run.values() for a in al if "nonce" in a["kind"]], [])


if __name__ == "__main__":
    unittest.main()
