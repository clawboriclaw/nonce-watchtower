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

`watch` mode polls on an interval; `stream` mode subscribes to Solana PubSub (WebSocket) and
re-scans within seconds of a change, with a full re-sync after every reconnect. Both keep a
local state file and alert when any of these change: stdout always, plus **Telegram**,
**Discord** and/or a generic JSON webhook.

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

### Replay: the Drift timeline

`tests/test_drift_replay.py` runs the real `watch` cycle (scan, snapshot, diff, provenance)
against the recorded mainnet history of the two nonce accounts the attack used, watching the
two keys that signed the attack transactions. The fixtures show both were members of the Squads
multisig `2LW6PSEj…` whose vault held Drift's admin (its Security Council, per public reports):
each approved a proposal on it, and the second executed it, running Drift's `UpdateAdmin`. The
test steps the chain through four points in time:

| When (UTC) | Slot | On-chain event | What the tool reports |
|---|---|---|---|
| before 2026-03-24 01:22 | 408444055 | nothing staged on either signer | no nonce alerts |
| 2026-03-24 01:22:06 | 408444056 | nonce `7s7s6saC…` created with authority signer `39JyWrdb…`, rent paid by `FMJnBkVp…` (not a council key) | `new_nonce_account` (critical) + `nonce_outside_creator` (high) naming `FMJnBkVp…` |
| 2026-03-31 02:35:49 | 409999217 | same funder creates nonce `EmYEryTD…` with authority signer `6UJbu9ut…` | the same two alerts for that nonce and signer |
| 2026-04-01 16:05:18–19 | 410344005 / 410344009 | both nonces advanced by the attack transactions `2HvMSgDE…` and `4BKBmAJn…`, which approve and execute the admin transfer | `nonce_advanced` (high) for both |

The first critical alert comes **8 days 14 h 43 min before the exploit**, measured from the
nonce's creation to the first attack transaction; a watcher running then would raise it within
one scan interval of creation. The replay presents the RPC as current at each checkpoint, so it
shows the alert logic on fresh data, not behaviour against a slow or lying node (other tests
cover that). The test also checks
the opposite cases: with the funder in the watched set there is no outside-creator alert, with
no transaction history the creator is reported UNKNOWN (not cleared), and keys that are not
signers see nothing.

Note: some public write-ups list `39JyWrdb…` and `6UJbu9ut…` as nonce accounts. On-chain they
are the signer keys (the nonce authorities); the nonce accounts are `7s7s6saC…` and `EmYEryTD…`.

Run it offline with `python -m unittest tests.test_drift_replay -v`. The fixtures are public RPC
responses recorded by `tools/record_drift.py` and cross-checked against a second provider with
`tools/verify_drift.py`; `tests/fixtures/drift/README.md` lists what is recorded verbatim, what
the test rebuilds from it, and how it was verified.

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
| `stream`: live connection down, or a subscription rejected | Only periodic polling is running; changes are seen late | `coverage_lost` on `stream` / `stream:<subscription>` (warn) |
| `stream`: reconnected, full re-sync scan complete | States the outage window; net changes inside it are alerted normally | `stream_gap` (warn) |
| `stream`: reconnected but the re-sync scan was incomplete | The outage window is NOT verified yet | `stream_gap_unresolved` (warn) |
| `stream`: a nonce account with a watched authority appeared live but is gone by the follow-up scan | Created and closed (or re-authorized away) quickly, or the RPC lags | `nonce_seen_live` (critical) |
| An alert could not be delivered to Telegram/Discord/webhook | Alerts are queued and retried; other sinks are told | `alert_delivery_failed` (warn) |
| A sink's retry queue overflowed (more than 500 undelivered alerts) | Alerts were dropped: oldest non-critical first; the record of it is never dropped | `alert_queue_overflow` (high, critical if a critical alert was dropped) |
| The scan/alert/state cycle itself failed (bug, disk full, unwritable state) | Nothing is being detected or recorded until a cycle succeeds | `scan_failed` (high), sent straight to every sink; `stream` coverage `scan_failed` |
| `stream`: a nonce notification could not be decoded and the next scan does not explain it | A nonce created and closed in between would be invisible | `nonce_notification_undecodable` (high) |
| A known nonce account is missing from a scan, but a direct read shows it still exists | The RPC's answer was stale or partial | that wallet's nonce check becomes `unverified` (`coverage_lost`), the account is kept |

On the first run, every standing nonce and delegate is reported as `existing_*`, so a
nonce staged *before* you installed the tool does not get quietly accepted as baseline.

### Security design

- **Read-only by construction.** The RPC client only accepts an allow-list of methods
  (`getProgramAccounts`, `getTokenAccountsByOwner`, `getAccountInfo`,
  `getMultipleAccounts`, `getSlot`, and for nonce provenance `getSignaturesForAddress`,
  `getTransaction`). Any other method raises before any network I/O. The PubSub client has
  its own allow-list (`accountSubscribe`, `programSubscribe`, `logsSubscribe` and their
  unsubscribes). The package has no signing code, and a test checks that.
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
- **Secrets stay out of output.** RPC/WebSocket/webhook URLs and the Telegram bot token are
  credentials. They are read from environment variables. The config file refuses inline
  `rpc_url`, `ws_url`, `webhook_url`, `telegram_bot_token` and `discord_webhook_url`. Every
  message shows only `scheme://host` or the sink name and HTTP status. Exception text (which can
  echo a URL or token) goes through one central redactor (`watchtower/redact.py`) before it can
  reach stdout, stderr, the state file or any sink: every configured secret (bot token, webhook
  URLs and their path tokens, keyed RPC/WebSocket URLs: query strings, path API keys, userinfo)
  is masked, and any other URL is cut to `scheme://host`. Tests inject exceptions carrying each
  kind of secret through both `watch` and `stream` and check every output channel. Residual: under
  the ambiguous keys `token=` and `auth=` (outside a URL), a value shaped like an address or
  signature (32/64-byte base58) is left visible, because it is usually one; explicit credential
  keys (`api_key`, `secret`, `password`, ...) are always masked. Recognised forms: `key=value`,
  `key: value`, quoted values, JSON fields, `Authorization: Bearer|Basic|Token <value>` (header in
  any case), a bare `Bearer <value>` (capital B only, so prose like "the bearer of" is untouched),
  and dict values under a credential key in the state file. Key names must match exactly: out of
  scope are unregistered secrets under other or compound key names (for example `key=`, `sig=`,
  `password_hash`, `my_secret`), a bare lowercase `bearer <value>`, unquoted values
  containing spaces, and multi-line forms (YAML blocks, XML); registered secrets (your configured
  URLs and tokens) are masked wherever they appear. Webhooks must
  be https; PubSub must be `wss://` (plain `ws://` only for localhost).
- **Answer age is bounded and checked.** Every state read (`getProgramAccounts`, `getAccountInfo`,
  `getMultipleAccounts`, `getTokenAccountsByOwner`) asks for `finalized` commitment with its
  context slot, and immediately before EACH read the tool takes a fresh reference from the same
  endpoint. What that proves:
  1. **Internal consistency:** the answer's context slot is at most `max_slot_lag` slots behind
     the endpoint's own finalized slot (default 64, about 25 s; `max_slot_lag` / `--max-slot-lag`).
     This catches an index lagging its node; the canary alone cannot, because old canary accounts
     are still listed by an index that has not caught up with a nonce created seconds ago.
  2. **Absolute age:** `getBlockTime` of that finalized slot is at most `max_block_age` seconds
     before this machine's clock (default 120; `max_block_age` / `--max-block-age`). This catches
     a node that is uniformly behind the chain, whose slot and index agree with each other but are
     both old. It relies on this machine's clock being right (run NTP).
  3. **Optional independent reference:** with `WATCHTOWER_REFERENCE_RPC_URL` set (name configurable
     via `reference_rpc_url_env`; a credential, never printed), the primary's finalized slot may
     trail that second RPC's by at most `max_slot_lag`.

  Failing any of these, or an answer without a context slot, or a failed `getSlot`/`getBlockTime`,
  makes that check `unverified` (nonces) or `unavailable`: a coverage gap, never clean. **What it
  does not prove:** an endpoint that fabricates consistent, current-looking slots and block times
  while omitting accounts passes 1 and 2; only an honest, independent reference (3) narrows that.
  Inside the bounds an answer can still trail the chain by up to `max_slot_lag` slots. Raise the
  limits if your provider load-balances across nodes that drift. Provenance history reads
  (`getSignaturesForAddress`, `getTransaction`) are not age-checked.
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
  beyond CPython. That includes the WebSocket client (`watchtower/ws.py`, a minimal RFC 6455
  client: handshake with `Sec-WebSocket-Accept` check, masked frames, ping/pong, close,
  fragmentation, size cap, no extensions).

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
- **Polling latency (`watch`).** Default interval is 300 s. An attacker who stages a nonce and
  uses it within one interval is caught only after the fact (`nonce_advanced` /
  `nonce_account_gone`). Use `stream` (or a shorter interval) for council keys.
- **Streaming limits (`stream`).** Subscriptions use `finalized` commitment (the same view the
  scan reads), so an alert lands roughly 15-30 s after the transaction, plus the scan time.
  Notifications are triggers, not evidence: each one (debounced, at most one scan per
  `--min-gap` seconds) runs the same full scan as `watch`. A WebSocket can drop notifications
  without disconnecting, so a full re-sync scan also runs every `--resync-interval` seconds.
  While the stream is down, `stream` keeps polling at that interval. A change that happens
  and reverts inside an outage or between two scans is not visible; the outage itself is
  always reported (`coverage_lost` on `stream`, then `stream_gap`). Some providers refuse
  `programSubscribe` on the System or Token programs; that subscription is reported
  `subscribe_failed` and its changes are seen only by polling. A watched mint's supply
  changes do not trigger scans (only its other bytes do).
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
  In `stream` mode the multisig account is subscribed, so a member change triggers a scan
  within seconds. Spending limits, proposals and pending transactions are not inspected. SPL Governance (Realms)
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
.venv/bin/pip install nonce-watchtower      # or, from a checkout: .venv/bin/pip install -e .
.venv/bin/watchtower --help
```

Python 3.11+, no dependencies. The console script is `watchtower` (`python -m watchtower` works too).

## Usage

```bash
# one-off scan (exit: 0 clean, 1 findings, 2 incomplete coverage, 3 both, 64 usage)
watchtower scan <pubkey> [<pubkey> ...] [--mint MINT]... [--program PROGRAM_ID]... [--json]

# watch every member, vault 0 and (if set) the config authority of a Squads v4 multisig
watchtower scan --squads <MULTISIG_ADDRESS> [--squads ...] [<pubkey> ...] [--no-provenance]

# polling watch (rescans every --interval seconds)
export WATCHTOWER_RPC_URL='https://your-provider.example/?api-key=...'   # optional, recommended
export WATCHTOWER_WEBHOOK_URL='https://hooks.slack.com/services/...'      # optional
watchtower watch --config wallets.toml --interval 300
watchtower watch --config wallets.toml --once    # one cycle, for cron/systemd timers

# live: WebSocket subscriptions, full re-sync every 300 s and after every reconnect
export WATCHTOWER_WS_URL='wss://your-provider.example/?api-key=...'      # optional: derived from the RPC URL
watchtower stream --config wallets.toml [--resync-interval 300] [--min-gap 10] [--json]

# check that alerts actually arrive (sends one test message to every configured sink)
watchtower alert-test --config wallets.toml
```

`watch --once` exits 0 when the cycle ran and every alert was delivered, and 2 when the cycle
failed, a configured alert sink did not accept its alerts, or alerts are still queued behind the
per-cycle message cap (stderr says `ALERTS NOT YET DELIVERED`; the next run sends them). Either
way a timer unit shows as failed.

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

### Alerts: Telegram and Discord

Set the secrets as environment variables (names can be changed in `wallets.toml`, see
`examples/watchtower.env.example`):

| Sink | Variables |
|---|---|
| Telegram | `WATCHTOWER_TELEGRAM_BOT_TOKEN` (from @BotFather) and `WATCHTOWER_TELEGRAM_CHAT_ID` (or `telegram_chat_id = ...` in the config; a chat id is not a secret). Optional `WATCHTOWER_TELEGRAM_THREAD_ID`: a forum topic id (positive integer), sent as `message_thread_id` with every message, including `scan_failed` and `alert-test` |
| Discord | `WATCHTOWER_DISCORD_WEBHOOK_URL` (`https://discord.com/api/webhooks/<id>/<token>`) |
| Generic webhook | `WATCHTOWER_WEBHOOK_URL` or `--webhook` |

Then run `watchtower alert-test --config wallets.toml`. Delivery rules:

- **Fail loud at startup.** A malformed token, a non-Discord or non-https webhook URL, or
  Telegram with only one of token/chat id set is a startup error (exit 64), never a silently
  disabled sink.
- **Retry, then queue.** Network errors, HTTP 429 (honouring `retry_after`) and 5xx are retried
  3 times per message with backoff. A 4xx (bad token, bot not in the chat, deleted webhook) is
  not retried. Undelivered alerts are kept per sink in the state file (up to 500) and retried
  every cycle; a sink that fails never blocks the others.
- **Surface failures.** A failed delivery is printed to stderr (`ALERT DELIVERY FAILED`), sent as
  `alert_delivery_failed` through the sinks that still work, and makes `watch --once` exit 2.
- **Overflow is never silent.** A queue holds at most 500 alerts. Beyond that the oldest
  non-critical alerts are dropped first (critical ones only if nothing else is left), and one
  `alert_queue_overflow` alert (count, oldest time, kinds) takes their place at the front of the
  queue. It is never trimmed itself, is reported on stderr as `DROPPED`, and makes `watch --once`
  exit 2. The dropped alerts are still in stdout/the journal.
- **A failed cycle is an alert, not a log line.** If the scan, diff, delivery or state write
  raises, a `scan_failed` alert goes to stdout and straight to every sink (bypassing the queue and
  state file, which may be what failed). A sink that misses it is retried on every later attempt.
  In `stream` mode, retries back off after consecutive failures (`--min-gap`, doubling, capped
  at `--resync-interval`, reset by the first fully successful cycle), and a fresh `scan_failed`
  ("STILL FAILING", with the gap's start time) is sent so that delivered ones are never more
  than one `--resync-interval` apart; `watch` raises one on every failed cycle. In `stream` mode the `stream` check reads `scan_failed` and a gap is
  open until a cycle fully succeeds; that cycle then delivers `coverage_lost` and `stream_gap`
  through the normal, persisted path.
- **Deduplicate only unchanged repeats.** A non-critical alert is not sent again to a sink when
  it is identical (apart from its timestamp) to the **latest** alert that sink saw for the same
  subject, within `alert_dedup_seconds` (default 1800). This absorbs exact repeats such as a
  recurring `alert_delivery_failed` notice. It never absorbs a change: if anything else was
  alerted on that subject in between (A -> B -> A, for example a member added, removed and
  re-added, or a check lost, restored and lost again), the repeat is sent, at every severity.
  **Critical alerts are never deduplicated.** stdout always gets every alert. Delivery is at-least-once: a crash between
  sending and saving the state can repeat a message.
- **Nothing is cut.** Long batches are split across messages (Telegram 4096, Discord 2000
  characters). At most 10 HTTP sends per sink per cycle, counting every piece of a split line;
  alerts are held whole for the next cycle rather than half-sent. The one exception: a single
  alert so long that it alone needs more than 10 messages is sent whole when it is first in line,
  since it could otherwise never be delivered.
  Messages are plain text, and Discord mentions are disabled so on-chain strings cannot ping
  `@everyone`.

### Streaming mode

`watchtower stream` opens one PubSub connection and subscribes, at `finalized` commitment, to:

| Subscription | Catches |
|---|---|
| `programSubscribe` System program, `dataSize 80` + authority `memcmp`, per watched key | A nonce account created for, or re-authorized to, a watched key. The authority is instruction data, not an account key, so a `logsSubscribe` mention filter would miss a nonce staged by an outside key. |
| `programSubscribe` SPL Token (`dataSize 165`) and Token-2022, owner `memcmp`, per watched key | Delegate approvals, allowance changes, close authorities, freezes |
| `accountSubscribe` each known nonce account | Nonce advanced, closed, or authority moved away |
| `accountSubscribe` each Squads multisig, watched mint, program and its ProgramData | Member/threshold changes, authority changes, upgrades |

Watched keys include every Squads member, vault 0 and config authority. New nonce accounts and
new members are subscribed after the scan that finds them.

Order of operations on every (re)connect: subscribe, wait for every subscription to be
confirmed or rejected, **then** run a full re-sync scan, so a change between the scan and the
subscription cannot fall through. Reconnects use exponential backoff with jitter (1 s doubling
to 60 s, reset after a connection stayed up 60 s). A connection that delivers no frame, not
even a pong to our 30 s ping, for 90 s is treated as dead.

After each scan the subscription set is brought in line with what was found: new nonce
accounts and members are subscribed, and targets that left (a closed nonce account, a removed
member) are unsubscribed. A nonce account only "leaves" once a direct `getAccountInfo` confirms it
is closed or no longer has a watched authority. If the scan omitted it but it still exists (a
stale or partial RPC index), it stays watched and subscribed and the wallet's nonce check is
`unverified`, so the gap stays open. Every nonce notification is decoded locally. One that cannot
be decoded is reported (`nonce_notification_undecodable`) unless the next scan read that account
itself.

A coverage gap is never reported as clean. The `stream` check is `ok`, `partial` (some
subscriptions rejected) or `disconnected`. **`stream: ok` means the connection is alive and
the subscriptions were accepted; it does not prove notifications are flowing.** A connection
that stays up (answers pings) but silently stops forwarding notifications looks healthy, and
such a change is caught only by the next full re-sync scan. Freshness is therefore bounded by
`--resync-interval` (default 300 s), not by the stream.

**Structural limit: coverage is continuous only to the extent the provider delivers
notifications.** A change AND its revert that both land between two full scans, with both
notifications dropped by the provider while the socket stays alive, cannot be detected: each
scan sees the same state, and no notification arrived to say otherwise. nonce-watchtower never
claims complete continuous coverage. It claims: every full scan is checked for completeness and
freshness, every outage it can observe is reported, and nothing unverified is reported as clean. After reconnecting, `stream_gap` gives the window
(`before` = last frame received, `after` = re-sync time). It is raised only when the re-sync
scan ran every check. Otherwise `stream_gap_unresolved` is raised and the window stays open until
a complete scan. A restart of the process is reported the same way, from the state file's last
update.

### Running as a service

`examples/nonce-watchtower-stream.service` runs `stream` under systemd with a throwaway
`DynamicUser`, state in `/var/lib/nonce-watchtower`, secrets in a 0600 `EnvironmentFile`
(`examples/watchtower.env.example`), `Restart=always`, and a strict sandbox (read-only
filesystem, no new privileges, IP sockets only). Install steps are in the file's header. Logs go
to the journal (`journalctl -u nonce-watchtower-stream -f`).

### RPC

The default is `https://api.mainnet-beta.solana.com`. If an endpoint refuses or filters
System-program `getProgramAccounts`, the scan says so. It prints advice to set
`WATCHTOWER_RPC_URL` to a provider or your own node that serves it, and it marks nonce
coverage UNKNOWN. Passing `--rpc` with a key in it works, but it leaves the key in your
shell history.

## Development

```bash
.venv/bin/pip install 'setuptools>=77'     # only for the clean-install test
.venv/bin/python -m unittest discover -s tests -t .
```

Tests use JSON fixtures recorded from mainnet (see `tests/fixtures/README.md`) and never
touch the network. The WebSocket, Telegram and Discord endpoints are replaced by in-memory
fakes, and streaming tests run on a fake clock. `tests/test_packaging.py` builds the sdist,
builds the wheel from the unpacked sdist, installs it into a fresh venv with `--no-index`, and
runs `watchtower --help` plus an offline smoke test from outside the source tree. It is skipped
(and says so) if `setuptools>=77` is not installed.

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
