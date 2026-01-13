## Examples

### 1. SSH Login Failure
```json
{
  "event": {
    "time": "2025-01-13T15:30:00Z",
    "source": "auth.log",
    "kind": "authentication_failure"
  },
  "host": {
    "name": "prod-server-01"
  },
  "severity": "medium",
  "user": {
    "name": "root"
  },
  "network": {
    "src_ip": "192.168.1.50"
  },
  "tags": ["linux", "ssh"]
}
```
### 2. Process Execution
```json
{
  "event": {
    "time": "2025-01-13T15:31:05Z",
    "source": "sysmon",
    "kind": "process_start"
  },
  "host": {
    "name": "workstation-05"
  },
  "severity": "low",
  "process": {
    "name": "curl",
    "pid": 4056,
    "command_line": "curl google.com"
  }
}
```
