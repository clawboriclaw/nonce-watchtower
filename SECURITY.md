# Security policy

nonce-watchtower is a read-only monitor: it never signs or sends transactions and holds no
private keys. Its security value is that it **reports standing powers correctly**, so the most
important bugs are the quiet ones.

## What counts as a security issue

- A **missed or wrong finding**: a durable-nonce account, token delegate, close/permanent
  delegate, mint/freeze authority or upgrade authority that the tool fails to report, reports
  for the wrong key, or reports as "clean" when it could not verify it.
- **Alert suppression or spoofing**: a way to make `watch`/`stream` skip an alert, or to make a
  crafted on-chain account produce a misleading one.
- **Leaks**: webhook URLs, Telegram/Discord tokens or RPC credentials ending up in logs, state
  files, alerts or crash output.
- Anything that would make the tool sign, send or hold keys (it must never do so).

Ordinary bugs and feature requests go in public issues.

## How to report

Please report privately through GitHub: **Security → Report a vulnerability** on this
repository (GitHub private vulnerability reporting). Include the version (`watchtower
--version`), the command you ran, and public addresses or a transaction
signature that reproduce it. Never send private keys or seed phrases — the tool never needs them.

We usually acknowledge reports within 7 days. Fixed issues are listed in CHANGELOG.md, crediting the
reporter unless they prefer otherwise.

## Supported versions

Fixes go into the latest release on PyPI. Older versions are not patched; upgrade with
`pip install -U nonce-watchtower`.
