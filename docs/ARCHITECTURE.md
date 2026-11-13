# Architecture

## Data types

| Type | Meaning | Contract |
|------|---------|----------|
| **Event** | One normalised observation from a host: a login attempt, a process start, a connection. | [event_schema.md](standards/event_schema.md) |
| **Alert** | A decision by a detection that some event or group of events needs attention. | [alert_schema.md](standards/alert_schema.md) |
| **Case** | An investigation: linked alerts, a timeline, notes and evidence references. | caseboard API |
| **Evidence bundle** | A point-in-time snapshot of a host with integrity hashes. | ir-triage `report.json` |

## Data flow

```text
COLLECT     ebpf-telemetry ── process starts, TCP connects (JSON events)
            log files      ── syslog, auth.log (raw lines)
                 │
NORMALISE   [ logpipe ]  one event schema, JSONL
                 │
                 ├──► [ sigma-lite ]  stateless YAML rules ───┐
DETECT           ├──► [ auth-anom ]   stateful, time windows ─┼─► alerts (JSONL)
                 └──► [ ioc-feed ]    threat intel lookups ───┘
                                                                    │
TRIAGE                                                     [ caseboard ]
                                                           inbox → case → timeline → export
                                                                    ▲
RESPOND     [ ir-triage ]  host snapshot + SHA-256 manifest ────────┘ attached as evidence
```

## Design decisions

**JSON Lines over pipes.** Every tool reads stdin and writes stdout. There is no
broker, no shared database and no service discovery, which keeps each tool small
enough to read in one sitting and easy to test with a text file. The cost is
that there is no buffering or replay: a real deployment would put a queue
between the stages.

**Two contracts instead of shared code.** The tools are written in different
languages on purpose and share no library. They agree only on the event and
alert schemas. The integration tests in `tests/integration/` are what enforce
that agreement.

**Three kinds of detection.** They need different machinery, so they are
separate tools:

| Tool | Looks at | State | Example |
|------|----------|-------|---------|
| sigma-lite | one event at a time | none | a command line that matches a reverse shell pattern |
| auth-anom | a sliding time window | in memory | more than five failed logins for one account in a minute |
| ioc-feed | one event plus external knowledge | SQLite | a connection to an address in a threat feed |

**Event time, not arrival time.** auth-anom measures its windows using
`event.time`, so replaying yesterday's log gives the same alerts as watching it
live.

**Tracepoints, not kprobes.** ebpf-telemetry attaches to `sched:sched_process_exec`
and `sock:inet_sock_set_state`. Tracepoints are a stable kernel interface, so the
program does not depend on function names, register layouts or struct offsets of
one kernel build. The one kernel struct it reads (`task_struct`, for the parent
PID) is accessed through CO-RE relocations.

**Read-only response tooling.** ir-triage only reads from `/proc`, `/etc` and
`/var/log`. It runs no external commands and changes nothing on the host, so it
is safe to run on a machine that may be evidence.

**Caseboard keeps the original alert.** Each alert is stored exactly as received
(`raw`), next to the few fields the UI needs. A detector can add fields without
a caseboard change, and an exported case contains everything the detector said.

## Responsibilities

| Tool | Consumes | Produces |
|------|----------|----------|
| ebpf-telemetry | Linux kernel tracepoints | Events (JSONL) |
| logpipe | Raw syslog lines, JSON events | Events (JSONL) |
| sigma-lite | Events, YAML rules | Alerts (JSONL) |
| auth-anom | Events | Alerts (JSONL) |
| ioc-feed | Events, STIX 2.1 bundles | Alerts (JSONL) |
| caseboard | Alerts over HTTP | Cases (SQLite, JSON export) |
| ir-triage | `/proc`, `/etc`, `/var/log` | `report.json` evidence bundle |
| eventgen | nothing | Raw synthetic logs |

## Pipe examples

Build first with `make build`.

```bash
# Normalise and run rules
echo 'May 29 10:00:00 prod sshd[1]: Failed password for root from 203.0.113.99 port 22 ssh2' \
  | tools/logpipe/logpipe | python3 tools/sigma-lite/main.py

# Live endpoint telemetry through the rules (Linux, root)
sudo tools/ebpf-telemetry/ebpf-telemetry | tools/logpipe/logpipe | python3 tools/sigma-lite/main.py

# Threat intel matching
python3 tools/eventgen/generate.py --scenario malware | tools/logpipe/logpipe \
  | IOC_DB=:memory: node tools/ioc-feed/dist/cli.js match --feed tools/ioc-feed/samples/feed.stix.json

# Send alerts to caseboard
python3 tools/auth-anom/main.py < events.jsonl | while read -r alert; do
  curl -s -X POST http://127.0.0.1:3000/api/alerts/ingest -H 'Content-Type: application/json' -d "$alert"
done

# Collect host evidence
sudo tools/ir-triage/target/release/ir-triage --output ./case-001 --pretty
```
