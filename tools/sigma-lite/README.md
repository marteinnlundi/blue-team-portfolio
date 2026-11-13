# sigma-lite

A small detection rule engine. It reads [events](../../docs/standards/event_schema.md)
from stdin, checks each one against YAML rules, and writes an
[alert](../../docs/standards/alert_schema.md) to stdout for every match.

The rule format is inspired by [Sigma](https://github.com/SigmaHQ/sigma) but is
much smaller and not compatible with it.

## Run

```bash
pip install -r requirements.txt

python3 main.py < samples/events.jsonl
python3 main.py --rules /path/to/rules < events.jsonl
python3 main.py --validate          # check the rules, exit 2 if any is invalid
```

## Rule format

```yaml
id: "exec-002"                      # stable, unique
title: "Reverse Shell Command Line"
severity: "critical"                # low | medium | high | critical
description: "Shown as the alert summary."
tags: ["attack.execution", "attack.t1059.004"]
detection:
  all:                              # every matcher must match
    - field: "event.kind"
      equals: "process_start"
  any:                              # and at least one of these, if present
    - field: "process.command_line"
      regex: '/dev/(tcp|udp)/\d'
    - field: "process.command_line"
      regex: '\b(nc|ncat|netcat)\b.*\s-(e|c)\s'
```

A matcher names a `field` (dotted path into the event) and exactly one operator:

| Operator | Matches when the field |
|----------|------------------------|
| `equals` | is exactly this value |
| `in` | is one of the listed values |
| `contains` | contains this text |
| `startswith` / `endswith` | starts or ends with this text |
| `regex` | matches this Python regular expression (search, not full match) |

A matcher never matches when the field is missing. Text comparison is case
sensitive; use `(?i)` in a regex when case should not matter. The older
single-matcher form `detection.condition: {field, value}` is still accepted.

An invalid rule file is reported on stderr and skipped; the other rules still run.

## Rules

| Id | Title | Severity |
|----|-------|----------|
| `auth-001` | SSH Authentication Failure | medium |
| `auth-002` | Direct Root Login over SSH | high |
| `privesc-001` | Interactive Root Shell via sudo | medium |
| `exec-001` | Download Piped to Shell | high |
| `exec-002` | Reverse Shell Command Line | critical |
| `exec-003` | Execution from World-Writable Directory | medium |
| `persist-001` | Local Account Created | medium |
| `net-001` | Outbound Connection to Suspicious Port | medium |

## Tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest
```

`tests/test_rules.py` holds a matching and a non-matching event for every rule
and fails if a rule has neither. `tests/test_engine.py` covers the operators,
rule validation, the alert shape and the command line.

## Limits

- Stateless: one event at a time. Counting and correlation live in [auth-anom](../auth-anom).
- Regexes in rules are trusted input. Do not load rules from an untrusted source.
