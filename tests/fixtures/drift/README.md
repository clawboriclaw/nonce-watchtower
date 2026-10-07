Drift exploit replay fixtures (used by `tests/test_drift_replay.py`).

Source: `https://api.mainnet-beta.solana.com`, recorded 2026-10-07 by `tools/record_drift.py` (read-only methods
only, through the project's allowlisted RPC client). Each file is the JSON-RPC `result`, verbatim, wrapped as
`{"jsonrpc", "id", "result"}`.

Recorded (verbatim):
- `sigs_<nonce account>.json`: `getSignaturesForAddress` for the two nonce accounts the attack advanced,
  `7s7s6saC5LHZoLyBXLM3pCjpWaA7meyQdP8NiH9ktAeC` and `EmYEryTDXtuVCxrjNqJXbiwr4hfiJajd4g5P58vvhQnc`. Each has exactly
  two transactions: its creation and the attack's advance.
- `tx_<first 8 chars of signature>.json`: `getTransaction` (raw `json` encoding) of those four transactions:
  `LJuBqSWp…` (creates + initializes `7s7s…`, authority `39JyWrdb…`, rent paid by `FMJnBkVp…`, slot 408444056),
  `59yWWZjn…` (same for `EmYE…`, authority `6UJbu9ut…`, slot 409999217), and the two attack transactions
  `2HvMSgDE…` (slot 410344005) and `4BKBmAJn…` (slot 410344009).
- `account_<nonce account>.json`: `getAccountInfo` (base64) of each nonce account at recording time. Neither has
  any transaction after the attack, so this is the state right after the advance.

Verification (2026-10-07, `tools/verify_drift.py`):
- `https://api.mainnet-beta.solana.com` (the recording source), re-queried: every file matches, and a
  `getSignaturesForAddress` page `before` the oldest recorded signature is empty for both accounts, so each
  history is complete, not just short. The recorder now makes the same check itself.
- `https://api.tatum.io/v3/blockchain/node/solana-mainnet` (an independent provider): both accounts (owner and
  data) and all four transactions (signatures, slot, block time, account keys, recent blockhash, instructions,
  error status, loaded addresses) match byte for byte. It does not serve `getSignaturesForAddress` anonymously,
  so the two-signature histories rest on the first provider. The creation transactions are also self-evident
  starts: `CreateAccount` only succeeds on an address holding no lamports.
- `https://solana-rpc.publicnode.com` has pruned this history (empty answers), so it neither confirms nor
  contradicts.

How the test serves it: `TimeTravelRpc` (a subclass of the suite's `FixtureRpc`) answers the queries the real
scan sends: `getProgramAccounts` on the System program with a `dataSize` 80 filter and a `memcmp` at offset 8
(the nonce authority), `getSignaturesForAddress` and `getTransaction` for provenance, and `getAccountInfo`. Its
`getSlot` and `getProgramAccounts` context slot equal the checkpoint slot, so the freshness guard sees a current
node at every checkpoint (freshness itself is tested elsewhere).

The test also checks the recorded transactions themselves: each attack transaction's first instruction is
`AdvanceNonceAccount` on its own nonce account, and the two watched keys signed successful approvals on the
multisig `2LW6PSEjp81xSEttWwXDB6Etb1eKdhYPbFEojYbyhx88`, whose second transaction ran Drift's `UpdateAdmin` on
state account `5zpq7DvB6UdFFvpmBPspGPNfUGoBRRCE2HHg5u3gxcsN`.

Rebuilt by the test from the recorded data (nothing invented):
- The account state BEFORE the advance: the recorded account bytes with the 32-byte stored-nonce field replaced
  by the `recentBlockhash` of the advancing transaction. A durable-nonce transaction carries the stored nonce in
  that field, so this is the value the account held from its creation until the attack.
- "As of slot S" answers: an account exists only from its creation slot; signature lists and transactions are
  served only up to S.

Not recorded, on purpose:
- Token-account state of the two signers in March. The replay serves none that passes the freshness check, so
  those checks show up as coverage gaps (the test asserts this), never as clean.
- The Squads multisig account as it was in March (only its current state is readable). The replay watches the
  two signer keys directly, as a council would after listing its members.
