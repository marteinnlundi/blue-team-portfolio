"""Engine behaviour: rule validation, operators, alert shape, CLI."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

import main as sigma

ROOT = Path(__file__).resolve().parent.parent

EVENT = {
    "event": {"time": "2026-01-28T12:00:00Z", "source": "syslog", "kind": "authentication_failure"},
    "host": {"name": "prod-server"},
    "user": {"name": "root"},
    "network": {"src_ip": "192.168.1.100", "dst_port": 22},
}


def rule(detection, **extra):
    return sigma.compile_rule({"id": "t-001", "title": "Test", "detection": detection, **extra})


@pytest.mark.parametrize(
    "matcher,expected",
    [
        ({"field": "event.kind", "equals": "authentication_failure"}, True),
        ({"field": "event.kind", "value": "authentication_failure"}, True),
        ({"field": "event.kind", "equals": "process_start"}, False),
        ({"field": "event.kind", "contains": "_fail"}, True),
        ({"field": "event.kind", "startswith": "authentication"}, True),
        ({"field": "event.kind", "endswith": "success"}, False),
        ({"field": "network.src_ip", "regex": r"^192\.168\."}, True),
        ({"field": "network.dst_port", "in": [22, 2222]}, True),
        ({"field": "network.dst_port", "in": [80, 443]}, False),
        ({"field": "process.name", "equals": "sshd"}, False),  # field missing
    ],
)
def test_operators(matcher, expected):
    assert sigma.check_rule(EVENT, rule({"all": [matcher]})) is expected


def test_all_and_any_are_combined():
    r = rule(
        {
            "all": [{"field": "event.kind", "equals": "authentication_failure"}],
            "any": [{"field": "user.name", "equals": "admin"}, {"field": "user.name", "equals": "root"}],
        }
    )
    assert sigma.check_rule(EVENT, r)
    assert not sigma.check_rule({**EVENT, "user": {"name": "alice"}}, r)


@pytest.mark.parametrize(
    "doc",
    [
        "not a mapping",
        {"title": "no id", "detection": {"all": [{"field": "a", "equals": 1}]}},
        {"id": "x", "title": "no detection"},
        {"id": "x", "title": "empty detection", "detection": {}},
        {"id": "x", "title": "bad severity", "severity": "urgent", "detection": {"all": [{"field": "a", "equals": 1}]}},
        {"id": "x", "title": "no operator", "detection": {"all": [{"field": "a"}]}},
        {"id": "x", "title": "two operators", "detection": {"all": [{"field": "a", "equals": 1, "contains": "b"}]}},
        {"id": "x", "title": "unknown operator", "detection": {"all": [{"field": "a", "gt": 1}]}},
        {"id": "x", "title": "bad regex", "detection": {"all": [{"field": "a", "regex": "("}]}},
        {"id": "x", "title": "in needs list", "detection": {"all": [{"field": "a", "in": "abc"}]}},
    ],
)
def test_invalid_rules_are_rejected(doc):
    with pytest.raises(sigma.RuleError):
        sigma.compile_rule(doc)


def test_invalid_rule_file_is_skipped_not_fatal(tmp_path):
    (tmp_path / "good.yaml").write_text('id: "g-1"\ntitle: "Good"\ndetection:\n  condition: {field: "event.kind", value: "x"}\n')
    (tmp_path / "bad.yaml").write_text('id: "b-1"\ntitle: "Bad"\n')
    (tmp_path / "dup.yaml").write_text('id: "g-1"\ntitle: "Duplicate id"\ndetection:\n  condition: {field: "event.kind", value: "y"}\n')
    rules = sigma.load_rules(tmp_path)
    assert [r["id"] for r in rules] == ["g-1"]


def test_alert_follows_alert_schema():
    r = rule({"all": [{"field": "event.kind", "equals": "authentication_failure"}]}, severity="high", description="d", tags=["attack.t1110"])
    alert = sigma.create_alert(r, EVENT)
    assert alert["alert"]["id"].startswith("alert-")
    assert alert["alert"]["time"].endswith("Z")
    assert alert["alert"]["title"] == "Test"
    assert alert["alert"]["severity"] == "high"
    assert alert["rule"]["id"] == "t-001"
    assert alert["host"]["name"] == "prod-server"
    assert alert["user"]["name"] == "root"
    assert alert["tags"] == ["attack.t1110"]
    assert alert["evidence"]["event_time"] == "2026-01-28T12:00:00Z"
    json.dumps(alert)  # must be serialisable


def test_alert_ids_are_unique():
    r = rule({"all": [{"field": "event.kind", "equals": "authentication_failure"}]})
    ids = {sigma.create_alert(r, EVENT)["alert"]["id"] for _ in range(50)}
    assert len(ids) == 50


def test_alert_without_host_uses_unknown():
    r = rule({"all": [{"field": "event.kind", "equals": "x"}]})
    assert sigma.create_alert(r, {"event": {"kind": "x"}})["host"]["name"] == "unknown"


def run_cli(stdin, *args, cwd=None):
    return subprocess.run([sys.executable, str(ROOT / "main.py"), *args], input=stdin, capture_output=True, text=True, cwd=cwd)


def test_cli_finds_rules_from_any_working_directory(tmp_path):
    """Regression: rules used to be looked up relative to the current directory."""
    proc = run_cli(json.dumps(EVENT) + "\n", cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    alerts = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [a["rule"]["id"] for a in alerts] == ["auth-001"]


def test_cli_ignores_garbage_lines():
    proc = run_cli("not json\n[1,2]\n\n" + json.dumps(EVENT) + "\n")
    assert proc.returncode == 0
    assert len(proc.stdout.splitlines()) == 1


def test_cli_validate_reports_bad_rules(tmp_path):
    (tmp_path / "bad.yaml").write_text("id: 1\n")
    assert run_cli("", "--rules", str(tmp_path), "--validate").returncode == 2
    assert run_cli("", "--validate").returncode == 0


def test_cli_missing_rules_dir(tmp_path):
    assert run_cli("", "--rules", str(tmp_path / "nope")).returncode == 2
