# logpipe

Normalises raw log lines into [events](../../docs/standards/event_schema.md).
Reads stdin, writes JSON Lines to stdout. Written in Go with no dependencies
outside the standard library.

## Build and run

```bash
go build -o logpipe ./cmd/logpipe

echo 'Jan 13 17:45:00 prod-server sshd[4821]: Failed password for invalid user oracle from 203.0.113.99 port 22 ssh2' | ./logpipe
```

```json
{"event":{"time":"2026-01-13T17:45:00Z","source":"syslog","kind":"authentication_failure"},"host":{"name":"prod-server"},"severity":"medium","user":{"name":"oracle"},"process":{"name":"sshd","pid":4821,"command_line":"Failed password for invalid user oracle from 203.0.113.99 port 22 ssh2"},"network":{"src_ip":"203.0.113.99"}}
```

## Input

Each line is handled on its own:

| Line starts with | Treated as | Result |
|------------------|------------|--------|
| `{` | JSON event (for example from ebpf-telemetry) | Passed through; missing required fields get defaults |
| anything else | RFC 3164 syslog: `Mon D HH:MM:SS host proc[pid]: message` | Parsed and classified |

Syslog classification:

| Message | `event.kind` | Extracted |
|---------|--------------|-----------|
| sshd `Failed password` / `Failed publickey` (with or without `invalid user`) | `authentication_failure` | `user.name`, `network.src_ip` |
| sshd `Accepted password` / `Accepted publickey` | `authentication_success` | `user.name`, `network.src_ip` |
| sudo `... COMMAND=...` | `privilege_escalation` | `user.name` |
| anything else | `unknown` | |

Lines that match neither format are skipped with a note on stderr. Lines longer
than 1 MiB are rejected.

## Timestamps

Classic syslog has no year and no time zone. logpipe assumes the current year
and UTC. A timestamp that would land more than a day in the future (a December
line read in January) is moved back one year.

## Tests

```bash
go test ./...
```

## Layout

```text
cmd/logpipe/          entry point: read lines, pick a parser, write events
internal/processor/   syslog and JSON parsers, with tests
internal/schema/      the event struct
internal/output/      JSONL writer
```
