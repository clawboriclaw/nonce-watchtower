# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Drift exploit timeline replay: the real `watch` cycle runs against recorded public data and
  decodes Squads and Drift instructions instead of searching logs.
- Release workflow builds, tests and publishes to PyPI through Trusted Publishing (no stored token).
- `SECURITY.md`, `CONTRIBUTING.md`, this changelog and issue templates.

## [0.3.0] - 2026-10-06

### Added
- `stream` mode: Solana PubSub (WebSocket) subscriptions with a full re-sync after every reconnect.
- Native Telegram and Discord alerts, plus a generic JSON webhook.
- PyPI packaging and a systemd unit.

## [0.2.0] - 2026-10-06

### Added
- Squads v4 member auto-discovery from a multisig address.
- Nonce provenance: who created each durable-nonce account, the funder, the initial nonce
  authority and fee payer; nonces funded or first authorized outside the watched set are flagged.

## [0.1.0] - 2026-10-06

### Added
- Read-only watch on durable-nonce accounts, SPL Token / Token-2022 delegates and authorities
  held by a set of keys.

[Unreleased]: https://github.com/clawboriclaw/nonce-watchtower/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/clawboriclaw/nonce-watchtower/releases/tag/v0.3.0
[0.2.0]: https://github.com/clawboriclaw/nonce-watchtower/commit/42472ab
[0.1.0]: https://github.com/clawboriclaw/nonce-watchtower/commit/8cf2559
