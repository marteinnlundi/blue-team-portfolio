#!/usr/bin/env python3
"""sigma-lite: a small YAML rule engine for normalised security events.

Reads events (JSONL, see docs/standards/event_schema.md) from stdin, evaluates
every rule in the rules directory against each event, and writes one alert
(JSONL, see docs/standards/alert_schema.md) to stdout per match.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"
SEVERITIES = {"low", "medium", "high", "critical"}
OPERATORS = ("equals", "contains", "startswith", "endswith", "regex", "in")
_MISSING = object()


class RuleError(ValueError):
    """Raised when a rule file is not valid."""


def get_field(event: Any, path: str) -> Any:
    """Return the value at a dotted path such as "event.kind", or _MISSING."""
    current = event
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _compile_matcher(raw: Any, where: str) -> dict:
    """Validate one matcher and return it in a normalised form."""
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: matcher must be a mapping")
    field = raw.get("field")
    if not isinstance(field, str) or not field:
        raise RuleError(f"{where}: matcher needs a 'field'")

    # "value" is the original v0.1 spelling of "equals".
    ops = {("equals" if k == "value" else k): v for k, v in raw.items() if k != "field"}
    if len(ops) != 1:
        raise RuleError(f"{where}: matcher on '{field}' needs exactly one operator ({', '.join(OPERATORS)})")
    op, expected = next(iter(ops.items()))
    if op not in OPERATORS:
        raise RuleError(f"{where}: unknown operator '{op}' on '{field}'")

    if op == "regex":
        try:
            expected = re.compile(str(expected))
        except re.error as exc:
            raise RuleError(f"{where}: bad regex on '{field}': {exc}") from exc
    elif op == "in" and not isinstance(expected, list):
        raise RuleError(f"{where}: 'in' on '{field}' needs a list")

    return {"field": field, "op": op, "expected": expected}


def compile_rule(doc: Any, where: str = "rule") -> dict:
    """Validate a parsed YAML rule and return a compiled rule."""
    if not isinstance(doc, dict):
        raise RuleError(f"{where}: rule must be a mapping")
    for key in ("id", "title"):
        if not isinstance(doc.get(key), str) or not doc[key]:
            raise RuleError(f"{where}: missing '{key}'")

    severity = doc.get("severity", "low")
    if severity not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {sorted(SEVERITIES)}")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise RuleError(f"{where}: missing 'detection'")

    all_of = [_compile_matcher(m, where) for m in detection.get("all", [])]
    any_of = [_compile_matcher(m, where) for m in detection.get("any", [])]
    if "condition" in detection:  # v0.1 single-matcher form
        all_of.append(_compile_matcher(detection["condition"], where))
    if not all_of and not any_of:
        raise RuleError(f"{where}: detection needs 'all', 'any' or 'condition'")

    return {
        "id": doc["id"],
        "title": doc["title"],
        "severity": severity,
        "description": doc.get("description", ""),
        "tags": [str(t) for t in doc.get("tags", [])],
        "all": all_of,
        "any": any_of,
    }


def load_rules(rules_dir: Path) -> list[dict]:
    """Load every *.yaml / *.yml rule in rules_dir. Invalid rules are skipped."""
    rules: list[dict] = []
    seen: set[str] = set()
    files = sorted(list(rules_dir.glob("*.yaml")) + list(rules_dir.glob("*.yml")))
    for path in files:
        try:
            rule = compile_rule(yaml.safe_load(path.read_text(encoding="utf-8")), path.name)
            if rule["id"] in seen:
                raise RuleError(f"{path.name}: duplicate rule id '{rule['id']}'")
        except (RuleError, yaml.YAMLError, OSError) as exc:
            print(f"sigma-lite: skipping rule: {exc}", file=sys.stderr)
            continue
        seen.add(rule["id"])
        rules.append(rule)
    return rules


def _matches(event: dict, matcher: dict) -> bool:
    actual = get_field(event, matcher["field"])
    if actual is _MISSING or actual is None:
        return False
    op, expected = matcher["op"], matcher["expected"]
    if op == "equals":
        return actual == expected
    if op == "in":
        return actual in expected
    if op == "regex":
        return expected.search(str(actual)) is not None
    text, needle = str(actual), str(expected)
    if op == "contains":
        return needle in text
    if op == "startswith":
        return text.startswith(needle)
    return text.endswith(needle)  # endswith


def check_rule(event: dict, rule: dict) -> bool:
    """True when every 'all' matcher and at least one 'any' matcher (if given) match."""
    if not all(_matches(event, m) for m in rule["all"]):
        return False
    if rule["any"] and not any(_matches(event, m) for m in rule["any"]):
        return False
    return True


def create_alert(rule: dict, event: dict) -> dict:
    """Build an alert that follows docs/standards/alert_schema.md."""
    host = get_field(event, "host.name")
    alert: dict[str, Any] = {
        "alert": {
            "id": f"alert-{uuid.uuid4()}",
            "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "title": rule["title"],
            "severity": rule["severity"],
        },
        "rule": {"id": rule["id"]},
        "host": {"name": host if isinstance(host, str) and host else "unknown"},
        "summary": rule["description"],
    }

    for key in ("user", "process", "network"):
        if isinstance(event.get(key), dict):
            alert[key] = event[key]
    if rule["tags"]:
        alert["tags"] = rule["tags"]

    evidence = {
        key: value
        for key, value in (
            ("event_time", get_field(event, "event.time")),
            ("event_kind", get_field(event, "event.kind")),
            ("event_source", get_field(event, "event.source")),
        )
        if isinstance(value, str)
    }
    if evidence:
        alert["evidence"] = evidence
    return alert


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run YAML detection rules over JSONL events from stdin.")
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES_DIR,
        help="directory with rule files (default: the rules/ folder next to this script)",
    )
    parser.add_argument("--validate", action="store_true", help="check the rules and exit (exit code 2 if any is invalid)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.rules.is_dir():
        print(f"sigma-lite: rules directory not found: {args.rules}", file=sys.stderr)
        return 2

    files = list(args.rules.glob("*.yaml")) + list(args.rules.glob("*.yml"))
    rules = load_rules(args.rules)
    print(f"sigma-lite: loaded {len(rules)} of {len(files)} rule file(s) from {args.rules}", file=sys.stderr)

    if args.validate:
        return 0 if len(rules) == len(files) else 2

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue

        for rule in rules:
            if check_rule(event, rule):
                print(json.dumps(create_alert(rule, event)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
