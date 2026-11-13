# Event Schema v0.1

An event is one normalised observation. logpipe and ebpf-telemetry produce
events; sigma-lite, auth-anom and ioc-feed consume them. Events travel as JSON
Lines: one JSON object per line, UTF-8.

## Fields

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `event.time` | string | yes | RFC 3339 timestamp in UTC, when the activity happened |
| `event.source` | string | yes | Where it came from: `syslog`, `ebpf`, ... |
| `event.kind` | string | yes | One of the kinds below |
| `host.name` | string | yes | Host the activity happened on |
| `severity` | string | yes | `low`, `medium`, `high` or `critical` |
| `user.name` | string | no | Account involved |
| `process.name` | string | no | Short process name |
| `process.pid` | integer | no | |
| `process.parent_pid` | integer | no | |
| `process.command_line` | string | no | Full command line, or the log message for syslog events |
| `network.src_ip` | string | no | IPv4 or IPv6 |
| `network.dst_ip` | string | no | IPv4 or IPv6 |
| `network.dst_port` | integer | no | |
| `network.protocol` | string | no | `tcp`, `udp` |
| `tags` | list of strings | no | Free-form labels |

Consumers must ignore fields they do not know.

## Event kinds

| Kind | Meaning | Usual fields |
|------|---------|--------------|
| `authentication_failure` | A login attempt was rejected | `user.name`, `network.src_ip` |
| `authentication_success` | A login was accepted | `user.name`, `network.src_ip` |
| `privilege_escalation` | A user ran a command as another user (sudo) | `user.name`, `process.command_line` |
| `process_start` | A program was executed | `process.*`, `user.name` |
| `network_connection` | An outbound connection was opened | `process.name`, `network.*` |
| `unknown` | Parsed, but not classified | |

## Examples

### SSH login failure

```json
{
  "event": {"time": "2026-01-13T15:30:00Z", "source": "syslog", "kind": "authentication_failure"},
  "host": {"name": "prod-server"},
  "severity": "medium",
  "user": {"name": "root"},
  "process": {"name": "sshd", "pid": 4821, "command_line": "Failed password for root from 192.168.1.50 port 22 ssh2"},
  "network": {"src_ip": "192.168.1.50"}
}
```

### Process start

```json
{
  "event": {"time": "2026-01-13T15:31:05Z", "source": "ebpf", "kind": "process_start"},
  "host": {"name": "workstation-05"},
  "severity": "low",
  "user": {"name": "alice"},
  "process": {"name": "curl", "pid": 4056, "parent_pid": 4001, "command_line": "curl -s https://example.com"}
}
```

### Network connection

```json
{
  "event": {"time": "2026-01-13T15:31:06Z", "source": "ebpf", "kind": "network_connection"},
  "host": {"name": "workstation-05"},
  "severity": "low",
  "user": {"name": "alice"},
  "process": {"name": "curl", "pid": 4056},
  "network": {"src_ip": "192.168.1.10", "dst_ip": "93.184.216.34", "dst_port": 443, "protocol": "tcp"}
}
```
