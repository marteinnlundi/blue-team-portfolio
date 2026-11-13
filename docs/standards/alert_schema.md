# Alert Schema v0.1

An alert is a detection's decision that something needs attention. sigma-lite,
auth-anom and ioc-feed produce alerts; caseboard consumes them. Alerts travel as
JSON Lines, or as the JSON body of `POST /api/alerts/ingest`.

## Fields

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `alert.id` | string | yes | Unique per alert (`alert-<uuid>`) |
| `alert.time` | string | yes | RFC 3339 timestamp in UTC, when the alert was raised |
| `alert.title` | string | yes | Short, human readable |
| `alert.severity` | string | yes | `low`, `medium`, `high` or `critical` |
| `rule.id` | string | yes | Stable id of the rule or analytic that fired |
| `host.name` | string | yes | Affected host, or `unknown` |
| `user.name` | string | no | Affected account |
| `process.*` | object | no | Copied from the triggering event |
| `network.*` | object | no | Copied from the triggering event |
| `summary` | string | no | One or two sentences on why this fired |
| `tags` | list of strings | no | For example MITRE ATT&CK ids such as `attack.t1110` |
| `evidence` | object | no | Detector-specific supporting data (counts, time range, matched values) |
| `ioc` | object | no | ioc-feed only: the matched indicator (`type`, `value`, `source`, `confidence`) |

Consumers must ignore fields they do not know. caseboard stores the whole
document, so extra fields are kept and exported.

## Severity

| Level | Use for |
|-------|---------|
| `low` | Worth recording, rarely worth acting on alone |
| `medium` | Suspicious; look at it in context |
| `high` | Likely malicious, or a control has failed |
| `critical` | Active compromise; act now |

## Example

```json
{
  "alert": {
    "id": "alert-6a0f4a3e-2f0c-4c53-9b8e-0c6c5f3a7b11",
    "time": "2026-01-13T15:32:10Z",
    "title": "Brute Force",
    "severity": "high"
  },
  "rule": {"id": "auth-anom-brute-force"},
  "host": {"name": "prod-server"},
  "user": {"name": "root"},
  "network": {"src_ip": "192.168.1.66"},
  "tags": ["attack.credential_access", "attack.t1110.001"],
  "evidence": {
    "failure_count": 6,
    "source_ips": ["192.168.1.66"],
    "first_seen": "2026-01-13T15:32:00Z",
    "last_seen": "2026-01-13T15:32:09Z"
  },
  "summary": "6 authentication failures for user 'root' on host 'prod-server' within 60s (threshold 5)."
}
```
