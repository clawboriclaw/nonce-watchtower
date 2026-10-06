Recorded verbatim from https://api.mainnet-beta.solana.com on 2026-10-06 (public on-chain data),
except `rpc_error_excluded.json`, which is a hand-written JSON-RPC error in the shape nodes return
for an excluded secondary index, used to exercise the refusal path.

Milestone 1 fixtures (same source, 2026-10-06, read-only methods only):
- `squads_v4_exponent.json`: `getAccountInfo` of Exponent Finance's Squads v4 multisig
  `51smH7pBDKJDgmVnVks3gMWaPQFfmQ5s4Fc223yHcjuH` (3-of-5, 10 h time lock).
- `squads_v3_phoenix.json`: `getAccountInfo` of Phoenix's Squads v3 multisig `6x3BDkL2n7VjBWxRD95EsbQi2R2E4zxrvcz1VA6pihnK`.
- `sigs_<nonce account>.json`: `getSignaturesForAddress` for the 5 real nonce accounts in `gpa_nonce_real.json`.
- `tx_nonce_create_3BxRHV8L.json`: `getTransaction` of the transaction that created all 5.
- `tx_nonce_use_2qnC1mFf.json`: `getTransaction` of a later durable-nonce use of `2HYcWwR6…`.
Synthetic variants (wrong owner, forged create_key, outside fee payer/funder, stripped instructions)
are derived from these in the tests, never stored.
