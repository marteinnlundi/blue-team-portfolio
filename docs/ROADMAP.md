# Roadmap

## Done

### Phase 0: Foundation

- [x] Event and alert contracts, logging and naming conventions
- [x] Issue and pull request templates, markdown lint in CI

### Phase 1: First end-to-end detection path

- [x] **logpipe**: syslog and JSON input, normalised JSONL output
- [x] **sigma-lite**: YAML rule engine and first rule
- [x] Synthetic event generator and full-pipeline tests in CI

### Phase 2: Endpoint telemetry and identity detections

- [x] **ebpf-telemetry**: process start and TCP connect events from eBPF
- [x] **auth-anom**: brute force, password spray, impossible travel

### Phase 3: Threat intel and case workflow

- [x] **ioc-feed**: STIX 2.1 ingestion, SQLite store with dedup and expiry, IP and domain matching
- [x] **caseboard**: alert inbox, case lifecycle, timeline, notes, evidence, JSON export, web UI

### Phase 4: Incident response

- [x] **ir-triage**: process, network, session, persistence and log collectors with a SHA-256 manifest

### Phase 5: Hardening and polish

- [x] One repository, one licence, CI for every tool
- [x] One-command demo of the whole pipeline (Docker Compose and local)
- [x] sigma-lite: `all` / `any` conditions, six operators, rule validation, eight rules with ATT&CK tags
- [x] auth-anom: windows measured in event time, CIDR-based location map
- [x] ebpf-telemetry: moved from kprobes with fixed offsets to tracepoints and CO-RE; IPv6; user-space unit tests
- [x] caseboard: input validation, Content-Security-Policy, UI no longer renders API data as HTML
- [x] logpipe: `invalid user`, public key logins, IPv6 sources, sudo, year rollover

## Next

Ordered roughly by value.

- **caseboard authentication.** At least a shared API token for ingest and a login for the UI. Until then it must stay on loopback.
- **Alert deduplication and grouping.** `auth-001` fires once per failed login; group repeats by rule and entity.
- **ir-triage upload.** A flag to attach the report to a caseboard case directly, and a `verify` subcommand that re-checks the manifest.
- **Real GeoIP.** Read a MaxMind GeoLite2 database in auth-anom and compare distance over time instead of country only.
- **More log sources in logpipe.** auditd, journald JSON, web server access logs.
- **File hashes.** ebpf-telemetry reports the SHA-256 of executed binaries so ioc-feed can match its hash indicators.
- **Streaming transport.** Replace pipes with a queue so stages can restart independently.
- **Multi-host demo.** Several containers each running ebpf-telemetry into one pipeline.
