# Contributing

This is a personal learning project, but issues and pull requests are welcome.

## Setup

| Tool | Needs |
|------|-------|
| logpipe | Go 1.22+ |
| sigma-lite, auth-anom, eventgen | Python 3.10+; `pip install -r tools/sigma-lite/requirements-dev.txt` |
| ioc-feed, caseboard | Node.js 22+; `npm ci` in the tool directory |
| ir-triage | Rust (stable) |
| ebpf-telemetry | Linux 5.8+ with BTF, clang, libbpf headers, Go 1.21+ |

```bash
make build   # build everything except ebpf-telemetry
make test    # run every test suite
make lint    # run every linter
```

## Rules

- **Contracts first.** If a change touches the shape of an event or alert, update `docs/standards/` in the same pull request and check every consumer.
- **Every detection has tests.** A new sigma-lite rule needs at least one matching and one non-matching case in `tools/sigma-lite/tests/test_rules.py`. The test suite fails if either is missing.
- **Synthetic data only.** No real logs, hostnames, addresses or indicators in samples and tests. Use the RFC 5737 ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example.net`.
- **stdout is data.** Diagnostics go to stderr. See `docs/standards/logging_style.md`.
- **Keep ir-triage read-only.** Collectors must not write to the host or run external commands.

## Pull requests

- One topic per pull request, with a short description of what changed and why.
- CI must pass.
- Add a line to `CHANGELOG.md` for anything a user would notice.

## Licence

By contributing you agree that your contribution is licensed under the terms in
[LICENSE](LICENSE) and [NOTICE](NOTICE).
