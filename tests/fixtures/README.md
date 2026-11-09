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

Token and mint fixtures (security review 2026-11-08, finding 1): the scanner now requests base64 for
token accounts and mints and decodes the bytes itself. `tabo_*.json`, `t22_mints.json`,
`mint_usdc.json` and `mint_pyusd_t22.json` are still the 2026-10-06 jsonParsed recordings; they were
NOT re-recorded. `tests/helpers.py` (`as_base64`, `encode_token_account`, `encode_mint`) re-encodes
their recorded parsed fields into the SPL Token / Token-2022 byte layout when a test asks for base64.
Only the fields the scanner reads are encoded (Token-2022 mint extensions other than
MintCloseAuthority, PermanentDelegate and TransferHook are dropped; the account is zero-padded to its
recorded size).

To pin the layout itself, `layout_mints_{base64,jsonParsed}.json` (getMultipleAccounts of USDC, PYUSD,
PUMP and the five SPL mints held by the delegator fixture wallet) and
`layout_tabo_{spl,t22}_{base64,jsonParsed}.json` (getTokenAccountsByOwner of that wallet under each
token program) were recorded verbatim from https://api.mainnet-beta.solana.com on 2026-11-09, read-only,
once in each encoding. `tests/test_spl.py` decodes the base64 bytes and checks every field against the
node's own jsonParsed answer, and checks the test-side encoder against the same bytes.
`layout_mints_base64.json` also supplies the five SPL mints (decimals) to the fake RPC.
