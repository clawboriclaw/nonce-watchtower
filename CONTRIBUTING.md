# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Ground rules

- **Read-only forever.** The tool never signs or sends transactions and never holds keys.
  Changes that would need a key are out of scope.
- **Fail loud.** An answer the tool could not verify is a coverage gap, never "clean". A new
  check needs a regression test that fails on the broken version.
- **No new runtime dependencies** without discussion; the package runs on the Python standard
  library.

## Development

```bash
git clone https://github.com/clawboriclaw/nonce-watchtower
cd nonce-watchtower
python -m unittest discover -t . -s tests -v
```

Tests run offline against recorded public RPC fixtures.

## Pull requests

- Keep each pull request to one change, with a test.
- Describe what you checked and how.
- Sign off your commits (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/).

## Security issues

Do not open public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).
