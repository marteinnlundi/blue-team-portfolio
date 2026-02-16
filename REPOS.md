# Repositories

## Core tools

| Repo | Purpose | Main languages | Status |
| --- | --- | --- | --- |
| logpipe | Ingest + normalize logs to the event schema | Go | MVP |
| sigma-lite | YAML rules over normalized events | Python, YAML | MVP |
| detections-ci | Rule test harness + GitHub Action | Python, YAML | MVP |
| auth-anom | Auth anomaly detections (brute force, spray, impossible travel) | Python | MVP |
| ebpf-telemetry | Linux endpoint telemetry (exec, connect) | C (eBPF), Go | MVP |
| ioc-feed | IOC ingest, store, and match | TypeScript, SQL | Planned |
| caseboard | Case UI for alerts and evidence | TypeScript | Planned |
| ir-triage | Host triage CLI, outputs an evidence bundle | Rust | Planned |

## Links

- logpipe: [repo](https://github.com/marteinnlundi/logpipe)
- sigma-lite: [repo](https://github.com/marteinnlundi/sigma-lite)
- auth-anom: [repo](https://github.com/marteinnlundi/auth-anom)
- ir-triage: [repo](https://github.com/marteinnlundi/ir-triage)
- ebpf-telemetry: [repo](https://github.com/marteinnlundi/ebpf-telemetry)
- ioc-feed: [repo](https://github.com/marteinnlundi/ioc-feed)
- caseboard: [repo](https://github.com/marteinnlundi/caseboard)
- detections-ci: [repo](https://github.com/marteinnlundi/detections-ci)

## Status meanings

- Planned: not started
- MVP: basic working version
- Stable: ready for repeated use
- Polishing: docs, tests, performance, UX improvements
