# Roadmap

This roadmap builds one working end-to-end path early, then expands coverage.

## Phase 0 — Portfolio foundation (this repo)

- [ ] Add docs, schemas, templates
- [ ] Enable markdown lint + link check CI
- [ ] Keep REPOS.md updated as repos are created

## Phase 1 — First end-to-end detections path

Goal: normalized events -> rule detections -> tested in CI.

- [ ] Create logpipe (MVP)
  - [ ] Parse at least 2 sources (example: Linux auth log + JSON input)
  - [ ] Output JSONL events using standards/event_schema.md
- [ ] Create sigma-lite (MVP)
  - [ ] YAML rule format
  - [ ] Rule tests (expected alert / no alert)
- [ ] Create detections-ci (MVP)
  - [ ] Synthetic events generator
  - [ ] GitHub Action template that runs rule tests

Exit criteria:

- One command can run:
  generate sample events -> normalize -> run detections -> produce alerts.

## Phase 2 — Telemetry + identity detections

- [ ] Create ebpf-telemetry (MVP)
  - [ ] exec events
  - [ ] connect events
- [ ] Create auth-anom (MVP)
  - [ ] password spray detection
  - [ ] brute force detection
  - [ ] impossible travel (optional if you have geo data)

## Phase 3 — Intel + workflow

- [ ] Create ioc-feed (MVP)
  - [ ] ingest one feed format
  - [ ] dedupe and expiry
  - [ ] match against events
- [ ] Create caseboard (MVP)
  - [ ] ingest alerts
  - [ ] case timeline and evidence attachments
  - [ ] audit trail for edits

## Phase 4 — Incident response

- [ ] Create ir-triage (MVP)
  - [ ] collect artifacts on Linux
  - [ ] produce evidence bundle
  - [ ] attach to a caseboard case (manual upload is fine for MVP)
