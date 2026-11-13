# ioc-feed

Threat intelligence matching. It loads indicators from STIX 2.1 bundles into
SQLite and checks [events](../../docs/standards/event_schema.md) against them,
writing an [alert](../../docs/standards/alert_schema.md) for every hit.
TypeScript on Node.js 22+.

## Build

```bash
npm ci
npm run build
```

## Use

```bash
# Load a feed into the database
node dist/cli.js ingest samples/feed.stix.json

# Match events from stdin against the database
node dist/cli.js match < events.jsonl

# Load a feed and match in one step, without keeping a database file
IOC_DB=:memory: node dist/cli.js match --feed samples/feed.stix.json < events.jsonl

# Delete indicators whose valid_until has passed
node dist/cli.js purge
```

`IOC_DB` sets the database path (default `ioc-feed.db`).

## What is matched

| Indicator | STIX pattern | Compared with |
|-----------|--------------|---------------|
| IP address | `[ipv4-addr:value = '...']` | `network.src_ip`, `network.dst_ip` |
| Domain | `[domain-name:value = '...']` | domain names found in `process.command_line` |
| SHA-256 | `[file:hashes.SHA-256 = '...']` | stored, but not matched yet: events carry no file hashes |

Only single-value equality patterns are understood. Other STIX objects and more
complex patterns are skipped.

## Indicator lifecycle

- **Dedup**: the key is (type, value). Loading the same indicator again updates it.
- **Validity**: an indicator matches only between `valid_from` and `valid_until`.
- **Expiry**: `purge` removes indicators that are past `valid_until`.

## Alerts

Severity follows the indicator's `confidence`: 80 and above is high, 50 to 79
is medium, below 50 is low. The matched indicator is included under `ioc`, and
its STIX labels become the alert's `tags`.

```json
{"alert":{"id":"alert-...","time":"...","title":"IOC Match: ip 198.51.100.42","severity":"high"},
 "rule":{"id":"ioc-feed-match"},"host":{"name":"prod-server"},
 "ioc":{"type":"ip","value":"198.51.100.42","source":"feed.stix.json","confidence":90},
 "summary":"Event matched IOC ip:198.51.100.42 from feed \"feed.stix.json\". Confirmed C2 server used in APT campaign",
 "tags":["malicious-activity","c2"],"network":{"dst_ip":"198.51.100.42","dst_port":4444}}
```

## Tests

```bash
npm test
```

## Layout

```text
src/stix.ts    STIX bundle parsing
src/db.ts      SQLite store: upsert, lookup, expiry
src/match.ts   pull candidates out of an event and look them up
src/alert.ts   build the alert
src/cli.ts     ingest, match, purge
```
