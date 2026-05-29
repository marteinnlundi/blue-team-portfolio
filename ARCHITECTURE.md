# Architecture

## Data types

| Type | Description |
|------|-------------|
| **Event** | Normalized security observation from a host or network source |
| **Alert** | Decision produced by a detection rule or analytic |
| **Case** | Investigation container holding alerts, timeline, notes, and evidence |

## Data flow

```
TELEMETRY SOURCES
  ebpf-telemetry  ─── kernel exec / TCP connect events
  raw log files   ─── syslog, auth.log, Sysmon JSON
         │
         ▼
    [ logpipe ]
    Normalize to event_schema.md JSONL
         │
         ├──► [ sigma-lite ]       YAML rule matching → alerts
         ├──► [ auth-anom ]        Stateful auth anomalies → alerts
         └──► [ ioc-feed ]         STIX 2.1 IOC matching → alerts
                   │
                   ▼
             [ caseboard ]
             Ingest alerts → cases → timeline → export
                   │
                   ▼
             [ ir-triage ]
             Host artifact collection → report.json → attach to case
```

## Contracts

All tools communicate via two JSON schemas:

- **Events** must conform to [`standards/event_schema.md`](standards/event_schema.md)
- **Alerts** must conform to [`standards/alert_schema.md`](standards/alert_schema.md)

This means any tool can be swapped or extended independently as long as it honours the schemas.

## Pipe examples

```bash
# Normalize + rule detect
echo 'May 29 10:00:00 prod sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2' \
  | logpipe | python3 sigma-lite/main.py

# Normalize + stateful auth anomaly detect
python3 detections-ci/generate.py --scenario brute_force --count 10 \
  | logpipe | python3 auth-anom/main.py

# Normalize + IOC match
logpipe | node --import tsx/esm ioc-feed/src/cli.ts match --feed ioc-feed/samples/feed.stix.json

# Ingest alerts into caseboard
python3 auth-anom/main.py < events.jsonl \
  | while read line; do
      curl -s -X POST http://localhost:3000/api/alerts/ingest \
        -H 'Content-Type: application/json' -d "$line"
    done

# Collect host artifacts
sudo ir-triage/target/release/ir-triage --output ./case-001 --pretty
```

## Repo responsibilities

| Repo | Produces | Consumes |
|------|---------|---------|
| ebpf-telemetry | Events (JSONL) | — |
| logpipe | Events (JSONL) | Raw logs (syslog, JSON) |
| sigma-lite | Alerts (JSONL) | Events (JSONL) |
| auth-anom | Alerts (JSONL) | Events (JSONL) |
| ioc-feed | Alerts (JSONL) | Events (JSONL), STIX 2.1 feeds |
| caseboard | Cases (SQLite + JSON export) | Alerts (JSONL via API) |
| ir-triage | Evidence bundle (report.json) | Local host (`/proc`, `/etc`, `/var/log`) |
| detections-ci | Test results | All of the above |
