# nonce-watchtower

A read-only monitor for the **standing powers** attached to a set of Solana keys: the
things that let someone move funds or seize control later, without asking the key holder
again.

Given wallets, multisig-member keys, or a **Squads v4 multisig address** (it reads the
members itself), it lists:

1. **Durable-nonce accounts whose authority is one of those keys.** Pre-signed
   transactions that use them never expire until the nonce is advanced. For each one it
   looks up **who created it** (first transaction, funder, initial nonce authority, fee
   payer), and flags a nonce funded or first authorized by a key outside the watched set.
2. **SPL Token and Token-2022 delegate approvals** on their token accounts (plus foreign
   close authorities, frozen accounts, and Token-2022 *permanent delegates* on mints they
   hold).
3. **Mint/freeze authorities** of the mints you name, and **upgrade authorities**
   (plus last-deploy slot) of the programs you name.

`watch` mode keeps a local state file and alerts (stdout + optional webhook) when any of
these change.

It **never signs or sends transactions and holds no private keys**. It only needs public keys.

## Threat model

### The attack this is built around

On 1 April 2026 Drift Protocol lost roughly $270-285M. The attacker never broke Drift's
contracts. Instead they:

- created **durable-nonce accounts tied to Security Council members** (23-30 March),
- got two of the five signers of the 2-of-5 Squads multisig to approve transactions whose
  real effect was misrepresented, and those signatures were bound to the nonces so they
  **never expired**, and
- about nine days later, submitted the pre-signed transactions, took admin control, and
  drained the protocol in minutes.

Sources: [CoinDesk, "How a Solana feature designed for convenience let an attacker drain $270 million from Drift"](https://www.coindesk.com/tech/2026/04/02/how-a-solana-feature-designed-for-convenience-let-an-attacker-drain-usd270-million-from-drift),
[Halborn, "Explained: The Drift Hack (April 2026)"](https://www.halborn.com/blog/post/explained-the-drift-hack-april-2026),
[BlockSec incident analysis](https://blocksec.com/blog/drift-protocol-incident-multisig-governance-compromise-via-durable-nonce-exploitation).

The nonce accounts sat on-chain, in public, for about nine days before they were used.
Any signer could have seen them with one query. This tool runs that query on a schedule,
along with the related standing-approval checks.

### What it detects

| Signal | Why it matters | Alert |
|---|---|---|
| New nonce account with a watched key as authority | Staging step for deferred pre-signed transactions | `new_nonce_account` (critical) |
| Nonce account funded (rent paid) by, or first initialized with an authority of, a key outside the watched set | Someone else staged a nonce on your key: the Drift pattern | `nonce_outside_creator` (high) |
| Nonce funded by a watched key, but the transaction fee was paid by an outside key | Sponsored/relayed fee: often benign, worth confirming | `nonce_outside_fee_payer` (medium) |
| Nonce creator could not be established (no history, or only the initialize step visible so the funder is unknown) | Unknown is not cleared | `provenance_unavailable` (warn) |
| Squads member added/removed, threshold or config authority changed | Who can approve changed | `multisig_member_added` / `_removed` / `_threshold_changed` / `_config_authority_changed` (critical) |
| Squads member permissions or time lock changed | Approval rules changed | `multisig_permissions_changed`, `multisig_time_lock_changed` (high) |
| Squads multisig has a config authority | That key can change members and threshold without a vote | `squads_config_authority` (medium) |
| Squads address is not a v4 multisig (wrong owner, v3, missing, undecodable) | Members are NOT being watched | `squads_<status>` (warn) |
| Nonce value changed | A durable-nonce transaction executed, or someone advanced the nonce | `nonce_advanced` (high) |
| New or changed token delegate, allowance increase | The delegate can move the tokens with no further signature | `new_delegate`, `delegate_changed`, `delegate_allowance_increased` (high) |
| Allowance decreased | The delegate may have spent the tokens | `delegate_allowance_decreased` (medium) |
| Foreign close authority, frozen account, permanent delegate | Third-party control over the account or its balance | medium |
| Mint/freeze/permanent-delegate/transfer-hook authority changed on a watched mint | Supply or freeze control moved | critical |
| Upgrade authority changed / program redeployed | Code-control takeover, or new bytecode | critical / high |
| A check stopped working | Changes in that area are no longer detected | `coverage_lost` (warn) |

On the first run, every standing nonce and delegate is reported as `existing_*`, so a
nonce staged *before* you installed the tool does not get quietly accepted as baseline.

### Security design

- **Read-only by construction.** The RPC client only accepts an allow-list of methods
  (`getProgramAccounts`, `getTokenAccountsByOwner`, `getAccountInfo`,
  `getMultipleAccounts`, `getSlot`, and for nonce provenance `getSignaturesForAddress`,
  `getTransaction`). Any other method raises before any network I/O. The
  package has no signing code, and a test checks that.
- **Unknown is never reported as clean.** If a check cannot run, it is reported as
  `unavailable`, `unverified` or `partial`, `scan` exits non-zero (bit 2), and `watch`
  keeps the last known values and emits `coverage_lost`. An outage never looks like "the
  nonce account disappeared".
- **Silent-filter canary.** An RPC that quietly returns `[]` for System-program
  `getProgramAccounts` would make every wallet look clean. Each scan first queries the
  bricked (currently 26) nonce accounts whose authority is the System program itself (no one can ever
  sign as it, so they cannot be withdrawn). If that returns nothing, nonce coverage is
  marked `unavailable`.
- **The server-side filter is not trusted.** Every returned nonce account is decoded
  locally, and it is dropped unless its owner is the System program and its authority
  bytes equal the queried key.
- **Secrets stay out of output.** RPC and webhook URLs often embed API keys. They are read
  from environment variables. The config file refuses inline `rpc_url`/`webhook_url`. Every
  message shows only `scheme://host`. Webhooks must be https.
- **Squads members are read, not trusted blindly.** The multisig account must be owned by the
  Squads v4 program, carry the v4 `Multisig` discriminator, decode cleanly (permission masks < 8,
  no duplicate members), and its decoded `create_key` + `bump` must derive its own address. Any
  failure is reported (`wrong_owner`, `unsupported_v3`, `missing`, `undecodable`, `unavailable`),
  the scan is incomplete (exit bit 2), and no member list is guessed. In `watch` mode, the last
  verified member list stays watched while resolution is failing.
- **Provenance is decoded locally.** The creating System-program instruction (`CreateAccount`,
  `CreateAccountWithSeed` or `InitializeNonceAccount`, top level or CPI, including v0 lookup-table
  addresses) is decoded from raw instruction data, not from the RPC's parsed view.
- **State file** is written atomically with mode 0600.
- **Strict config.** Unknown keys are rejected. This includes the TOML trap of writing
  `mints = [...]` after a `[[wallets]]` header, which would otherwise silently drop the list.
- **No third-party dependencies.** Python 3.11+ stdlib only, so there is no supply chain
  beyond CPython.

### Not in scope / limits

- It sees **state, not intent**. Every nonce is still flagged for a human to confirm, even one
  your own key created. Provenance answers only "which key funded the account, which authority it
  was first initialized with, and who paid the fee". The funder and initial authority decide
  "outside"; an outside fee payer alone is reported separately at medium.
  "Created by watched key X" does not prove X's holder meant to: a stolen or tricked member key
  looks the same. "Created by an outside key" is a strong signal, not proof of an attack (a
  wallet app or relayer can legitimately pay fees).
- **Provenance limits.** It needs an RPC that serves full transaction history for the nonce
  account. Many providers and self-hosted nodes prune old ledger data; then the oldest visible
  transaction is not the creation, and the answer is `unverified`/`unavailable`, never a guess.
  If only the `InitializeNonceAccount` step is visible (the `CreateAccount` was in an earlier
  transaction that is not visible), the funder is unknown and the answer is `unverified`.
  Histories longer than 10,000 signatures (a busy nonce) are not walked and are reported
  `unavailable`. Only the 3 oldest successful transactions are inspected. If an account was closed
  and re-created at the same address (this needs the address keypair), the first creation is
  reported. A settled provenance is cached in the `watch` state file and not re-fetched, and a
  later failed lookup never overwrites it.
- **It does not stop signing.** It complements pre-sign decoders such as
  [sign-safe](https://github.com/lrafasouza/sign-safe-skill) and wallet-side nonce warnings.
  It is the after-the-fact, always-on layer.
- **Polling, not streaming.** Default interval is 300 s. An attacker who stages a nonce and
  uses it within one interval is caught only after the fact (`nonce_advanced` /
  `nonce_account_gone`). Use a shorter interval for council keys.
- **RPC availability.** Finding nonces by authority needs `getProgramAccounts` on the
  System program with a `memcmp` filter. On 2026-10-06 the public
  `api.mainnet-beta.solana.com` served it. Some providers block it (see "RPC" below), and
  the canary will catch that.
- Mints and programs are checked only when you list them. The tool does not yet discover
  every mint or program a key controls (M2).
- Programs under loader-v4 are reported as `unsupported_loader`.
- **Squads:** only v4 (`SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`) is decoded. A v3
  (`SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu`) multisig is reported `unsupported_v3`: list its
  members yourself. Only vault index 0 is derived and watched; vaults 1..255 are not. Members are
  re-read every cycle, so a member change is seen within one polling interval, not instantly.
  Spending limits, proposals and pending transactions are not inspected. SPL Governance (Realms)
  and other multisig programs are not supported.
- A local attacker who can edit the state file can suppress alerts.

## Related work

- [solana-nonce-guard](https://github.com/AaronTan11/solana-nonce-guard) (Rust, MIT): audits a
  Squads/SPL multisig for durable-nonce staging, and has a WebSocket monitor. It covers nonces
  only.
- [solgov](https://github.com/EdgeVault/solgov) (TypeScript, MIT): governance monitoring for a
  fixed list of about 50 protocols, including nonce detection on their signers.
- [sign-safe](https://github.com/lrafasouza/sign-safe-skill) (MIT): decodes a transaction before
  you sign it.

nonce-watchtower works on any set of keys, combines nonces, delegates and authorities in one
diffing watcher, and is designed to fail loudly instead of reporting clean.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Usage

```bash
# one-off scan (exit: 0 clean, 1 findings, 2 incomplete coverage, 3 both, 64 usage)
watchtower scan <pubkey> [<pubkey> ...] [--mint MINT]... [--program PROGRAM_ID]... [--json]

# watch every member, vault 0 and (if set) the config authority of a Squads v4 multisig
watchtower scan --squads <MULTISIG_ADDRESS> [--squads ...] [<pubkey> ...] [--no-provenance]

# continuous watch
export WATCHTOWER_RPC_URL='https://your-provider.example/?api-key=...'   # optional, recommended
export WATCHTOWER_WEBHOOK_URL='https://hooks.slack.com/services/...'      # optional
watchtower watch --config wallets.toml --interval 300
watchtower watch --config wallets.toml --once    # one cycle, for cron/systemd timers
```

See `examples/wallets.example.toml`. Top-level `squads`/`mints`/`programs` must come before the
first `[[wallets]]` block. `squads = ["<multisig address>"]` adds every member key, vault 0 and
any config authority to the watched set. The multisig account address is the one Squads shows in
its app URL, not the vault address.

`--squads` takes the **multisig account**, not the vault. Members found this way are labelled
`squads <addr>… member N (permissions)`, `vault 0` or `config authority`.

Nonce provenance runs by default. Each nonce account costs at least two extra RPC calls on the
first scan (`--no-provenance` skips it in `scan`; the report then says `provenance: skipped`).

Webhook payloads carry `text` (Slack), `content` (Discord) and a machine-readable `alerts`
array. If a delivery fails, the alerts are queued in the state file and retried next cycle.

### RPC

The default is `https://api.mainnet-beta.solana.com`. If an endpoint refuses or filters
System-program `getProgramAccounts`, the scan says so. It prints advice to set
`WATCHTOWER_RPC_URL` to a provider or your own node that serves it, and it marks nonce
coverage UNKNOWN. Passing `--rpc` with a key in it works, but it leaves the key in your
shell history.

## Development

```bash
.venv/bin/python -m unittest discover -s tests -t .
```

Tests use JSON fixtures recorded from mainnet (see `tests/fixtures/README.md`) and never
touch the network.

## Verified layouts

- Squads v4 `Multisig` (Anchor/Borsh, decoded sequentially): 8-byte discriminator
  `sha256("account:Multisig")[:8]`, `create_key`, `config_authority` (all-zero = autonomous),
  `threshold` u16, `time_lock` u32, `transaction_index` u64, `stale_transaction_index` u64,
  `rent_collector` `Option<Pubkey>` (1 tag byte, payload only when Some), `bump` u8,
  `members` `Vec<(Pubkey, permissions u8)>` (Initiate 1, Vote 2, Execute 4). Multisig PDA seeds
  `[b"multisig", b"multisig", create_key]`; vault PDA seeds `[b"multisig", multisig, b"vault", u8 index]`.
  Source: [Squads-Protocol/v4](https://github.com/Squads-Protocol/v4) at commit `af94153f`,
  [`state/multisig.rs`](https://github.com/Squads-Protocol/v4/blob/af94153ff77a28b6effe46b9c94baaa93742b48c/programs/squads_multisig_program/src/state/multisig.rs),
  [`state/seeds.rs`](https://github.com/Squads-Protocol/v4/blob/af94153ff77a28b6effe46b9c94baaa93742b48c/programs/squads_multisig_program/src/state/seeds.rs),
  [`instructions/multisig_create.rs`](https://github.com/Squads-Protocol/v4/blob/af94153ff77a28b6effe46b9c94baaa93742b48c/programs/squads_multisig_program/src/instructions/multisig_create.rs),
  [`sdk/multisig/src/pda.ts`](https://github.com/Squads-Protocol/v4/blob/af94153ff77a28b6effe46b9c94baaa93742b48c/sdk/multisig/src/pda.ts).
  Checked against mainnet: the decoded Exponent Finance multisig derives its own address, and its
  vault 0 equals the on-chain upgrade authority of the Exponent program; the Manifest vault
  published in its README (bump 253) is reproduced.
- PDA derivation: `sha256(seeds || bump || program_id || "ProgramDerivedAddress")`, rejected
  when the result decompresses to an ed25519 point (same rule as curve25519-dalek). Checked
  against real associated-token-account addresses.
- System instructions used for provenance (bincode u32 tag): `CreateAccount` = 0
  (accounts: funder, new), `CreateAccountWithSeed` = 3, `InitializeNonceAccount` = 6
  (accounts: nonce, …; data: authority).

- Nonce account (80 bytes, bincode): `Versions` u32 tag @0, `State` u32 tag @4,
  **authority @8**, durable nonce @40, lamports_per_signature @72. See
  `anza-xyz/solana-sdk` `nonce/src/state.rs` (`State::size() == 80`) and `versions.rs`.
- Upgradeable loader: `Program{tag=2, programdata@4}`,
  `ProgramData{tag=3, slot@4, Option<authority> tag@12, authority@13}`.

## License

MIT
