# Roadmap

## Phase 0 — Portfolio foundation ✅

- [x] Standards: `event_schema.md`, `alert_schema.md`, `logging_style.md`, `naming_conventions.md`
- [x] Markdown lint + link check CI
- [x] `REPOS.md`, `ARCHITECTURE.md`, issue/PR templates

## Phase 1 — First end-to-end detections path ✅

Goal: normalized events → rule detections → tested in CI.

- [x] **logpipe** — parses Linux auth logs (Syslog) and JSON; extracts `user.name`, `network.src_ip`; outputs JSONL events
- [x] **sigma-lite** — YAML rule engine; `auth-001` rule detects auth failures; rule tests
- [x] **detections-ci** — synthetic event generator (`normal`, `brute_force`, `password_spray`, `impossible_travel`); 6 full-pipeline integration tests; GitHub Actions CI

Exit criteria met:

```bash
python3 generate.py --scenario brute_force --count 10 \
  | ../logpipe/logpipe \
  | python3 ../sigma-lite/main.py
```

## Phase 2 — Telemetry + identity detections ✅

- [x] **ebpf-telemetry** — eBPF probes for `execve` and `tcp_v4_connect`; outputs JSONL events
- [x] **auth-anom** — stateful detections: brute force, password spray, impossible travel (mock GeoIP)

## Phase 3 — Intel + workflow ✅

- [x] **ioc-feed** — STIX 2.1 feed ingestion; SQLite store with dedup + expiry; IP and domain matching; alerts per `alert_schema.md`; CLI (`ingest`, `match`, `purge`); 23 tests
- [x] **caseboard** — Express REST API; case lifecycle (open → investigating → resolved → closed); timeline with alerts, notes, and evidence; JSON export; HTML/CSS browser UI; 12 tests

## Phase 4 — Incident response ✅

- [x] **ir-triage** — Linux collectors: processes, network connections, active sessions, auth events, systemd services, cron entries, log slices; SHA-256 integrity manifest; `report.json` bundle; 22 tests

## Next (Phase 5 ideas)

- Connect ir-triage report upload directly to caseboard via CLI flag
- Add more sigma-lite rules (privilege escalation, process injection patterns)
- Real GeoIP lookup in auth-anom (MaxMind GeoLite2)
- Grafana/OpenSearch dashboard consuming logpipe output
- Multi-host Docker Compose demo
