# Repositories

## Core tools

| Repo | Purpose | Language(s) | Status |
|------|---------|-------------|--------|
| [logpipe](https://github.com/marteinnlundi/logpipe) | Ingest + normalize raw logs to the event schema | Go | MVP |
| [sigma-lite](https://github.com/marteinnlundi/sigma-lite) | YAML rule engine over normalized events | Python | MVP |
| [detections-ci](https://github.com/marteinnlundi/detections-ci) | Full-pipeline integration tests + GitHub Actions CI | Python | MVP |
| [auth-anom](https://github.com/marteinnlundi/auth-anom) | Auth anomaly detections (brute force, spray, impossible travel) | Python | MVP |
| [ebpf-telemetry](https://github.com/marteinnlundi/ebpf-telemetry) | Linux endpoint telemetry via eBPF (exec, TCP connect) | C (eBPF), Go | MVP |
| [ioc-feed](https://github.com/marteinnlundi/ioc-feed) | STIX 2.1 IOC ingestion, dedup, expiry, and event matching | TypeScript | MVP |
| [caseboard](https://github.com/marteinnlundi/caseboard) | Case management API + browser UI for alert triage | TypeScript | MVP |
| [ir-triage](https://github.com/marteinnlundi/ir-triage) | Host triage CLI — collect artifacts, produce evidence bundle | Rust | MVP |

## Status meanings

| Status | Meaning |
|--------|---------|
| MVP | Basic working version with tests |
| Stable | Ready for repeated use, polished docs and error handling |
