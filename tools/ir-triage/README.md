# ir-triage

Host triage for the first minutes of an incident. One command collects the
volatile and persistence-related state of a Linux host into a single
`report.json` with a SHA-256 hash of every section. Written in Rust.

It is **read-only**: it reads from `/proc`, `/etc`, `/var/log` and `/var/run`,
runs no external commands, and writes only to the output directory you name.

## Build and run

```bash
cargo build --release

sudo ./target/release/ir-triage --output ./case-001 --pretty
```

It also runs without root, but then it cannot see other users' processes in
full or read protected logs.

| Option | Default | Meaning |
|--------|---------|---------|
| `-o`, `--output <DIR>` | `triage-output` | Directory for `report.json` |
| `--pretty` | off | Indent the JSON |

## What is collected

| Section | Source | Content |
|---------|--------|---------|
| `host` | `/etc/hostname`, `/etc/os-release`, `/proc/version`, `/proc/uptime` | Name, OS, kernel, uptime |
| `processes` | `/proc/<pid>/`, `/etc/passwd` | PID, parent PID, name, command line, owner |
| `network` | `/proc/net/tcp`, `tcp6`, `udp`, `udp6` | Connections with state, and listening ports |
| `users` | `/var/run/utmp`, `/var/log/auth.log` or `/var/log/secure` | Active sessions; recent logins, failures, sudo use |
| `persistence` | systemd unit directories, `/etc/crontab`, `/etc/cron.d`, `/var/spool/cron/crontabs` | Services and scheduled jobs |
| `log_slices` | `auth.log`, `secure`, `syslog`, `messages` | Last 500 lines of each |

A source that does not exist or cannot be read is skipped; the rest is still
collected.

## Report

```json
{
  "schema_version": "1.0",
  "collected_at": "2026-01-13T15:40:00Z",
  "host": {"hostname": "prod-server", "os": "Ubuntu 24.04 LTS", "kernel": "Linux version 6.8.0", "uptime_seconds": 86400},
  "processes": [{"pid": 1, "ppid": 0, "name": "systemd", "command_line": "/sbin/init", "user": "root"}],
  "network": {"connections": [], "listening_ports": []},
  "users": {"active_sessions": [], "recent_auth_events": []},
  "persistence": {"systemd_services": [], "cron_entries": []},
  "log_slices": [],
  "manifest": {"host": "<sha256>", "processes": "<sha256>", "network": "<sha256>", "users": "<sha256>", "persistence": "<sha256>", "logs": "<sha256>"}
}
```

`manifest` holds the SHA-256 of each section's compact JSON, taken at collection
time. Record the hash of `report.json` itself when you attach it to a case
(the demo does this) so later changes to the file can be detected.

## Handling the output

The report contains command lines, account names and log lines. Treat it as
confidential evidence: store it off the host, restrict access, and do not
commit it to a repository.

## Tests

```bash
cargo test
```

## Limits

- Linux only. Sockets are not yet matched to the process that owns them.
- No memory capture, file system timeline or file hashing.
- A snapshot, not a trace: short-lived processes between runs are not seen. That is what [ebpf-telemetry](../ebpf-telemetry) is for.
