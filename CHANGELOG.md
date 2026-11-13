# Changelog

## 1.0.0

First release as a single repository. The eight separate repositories
(`logpipe`, `sigma-lite`, `auth-anom`, `detections-ci`, `ebpf-telemetry`,
`ioc-feed`, `caseboard`, `ir-triage`) and the `blue-team-portfolio` docs hub
were merged into `soc-in-a-box`.

### Added

- One-command demo: Docker Compose and a local script run a simulated intrusion through the whole pipeline into caseboard.
- CI for every tool, the full pipeline, the eBPF programs (loaded into the runner kernel) and the demo.
- sigma-lite: `all` / `any` conditions; `equals`, `contains`, `startswith`, `endswith`, `regex` and `in` operators; rule validation (`--validate`); `--rules`; seven new rules with MITRE ATT&CK tags.
- auth-anom: `--geo-map` for CIDR to country mapping; evidence and ATT&CK tags on alerts.
- eventgen: `root_login`, `sudo_shell`, `ioc_scan`, `malware` and `attack_chain` scenarios; `--seed`.
- ebpf-telemetry: IPv6 connections, user names, parent PID read in the kernel, user-space unit tests.
- caseboard: health endpoint, severity-ordered inbox, alert details and entity column in the UI.
- logpipe: `--version`; process id from the syslog tag.
- Event and alert schemas documented field by field.

### Fixed

- sigma-lite only found its rules when started from its own directory.
- sigma-lite gave every alert raised in the same second the same id.
- auth-anom measured time windows by arrival time, so replayed logs gave wrong results.
- auth-anom treated any two unknown addresses as two different countries.
- logpipe recorded the account as `invalid` for `Failed password for invalid user <name>` lines.
- logpipe classified any message containing the word "sudo" as privilege escalation, and missed real sudo lines.
- logpipe put December log lines read in January into the future.
- ebpf-telemetry did not compile with current libbpf headers, and read socket addresses from fixed struct offsets before the kernel had filled them in. It now uses tracepoints.
- caseboard UI inserted alert titles, case titles and notes into the page as HTML (stored cross-site scripting).
- caseboard `npm start` served no UI because the build did not copy the static files.
- The integration tests contained a path that only existed on one machine.

### Changed

- Licence is now PolyForm Noncommercial 1.0.0 (was MIT without a copyright holder).
- caseboard listens on `127.0.0.1` unless `HOST` is set, validates all input, and sends a Content-Security-Policy.
- caseboard and ioc-feed: dependencies updated, `npm audit` reports no known vulnerabilities; tests moved from Jest to Vitest; Node.js 22 or newer is required.
- Password spray and IOC alerts always carry `host.name`, as the alert schema requires.
