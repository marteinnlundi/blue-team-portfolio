# auth-anom

Stateful authentication anomaly detection. It reads
[events](../../docs/standards/event_schema.md) from stdin, keeps sliding time
windows in memory, and writes [alerts](../../docs/standards/alert_schema.md) to
stdout. Python standard library only.

## Detections

| Rule id | Fires when | Default | Severity |
|---------|-----------|---------|----------|
| `auth-anom-brute-force` | more than N `authentication_failure` events for one (user, host) | N = 5 in 60 s | high |
| `auth-anom-password-spray` | more than M distinct users fail from one source IP | M = 5 in 600 s | high |
| `auth-anom-impossible-travel` | one user has `authentication_success` from two countries | within 3600 s | medium |

After an alert the counter for that key starts again, so a continuing attack
raises a new alert each time the threshold is crossed.

## Run

```bash
python3 main.py < samples/events_brute_force.jsonl

python3 main.py --brute-force-threshold 10 --brute-force-window-sec 120 < events.jsonl
python3 main.py --geo-map samples/geo_map.example.json < events.jsonl
python3 main.py --help
```

Each alert carries the evidence behind it:

```json
{"alert":{"id":"alert-...","time":"...","title":"Brute Force","severity":"high"},
 "rule":{"id":"auth-anom-brute-force"},"host":{"name":"prod-server"},
 "user":{"name":"root"},"network":{"src_ip":"192.168.1.66"},
 "evidence":{"failure_count":6,"source_ips":["192.168.1.66"],"first_seen":"2026-02-16T12:00:00Z","last_seen":"2026-02-16T12:00:05Z"},
 "tags":["attack.credential_access","attack.t1110.001"],
 "summary":"6 authentication failures for user 'root' on host 'prod-server' within 60s (threshold 5)."}
```

## Time

Windows use `event.time`, not the clock, so a replayed log gives the same
alerts as a live one. Events without a valid time use the current time.

## Locations

Impossible travel needs to know where an address is. `--geo-map FILE` takes a
JSON object of CIDR range to country code; the most specific range wins:

```json
{"198.51.100.0/24": "US", "203.0.113.0/24": "SG", "2001:db8::/32": "DE"}
```

Without `--geo-map`, a two-entry demo map is used (`1.1.1.1` is US, `2.2.2.2`
is CN). Addresses with no known location are ignored: two unknown addresses are
not treated as two countries.

## Tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest
```

## Limits

- State is in memory and is lost on restart.
- Country comparison only: no distance or travel-speed calculation, and VPN exits will raise false positives.
- Events are expected roughly in time order.
