"""End-to-end tests of the command line: JSONL in, JSONL out."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_cli(stdin, *args):
    return subprocess.run([sys.executable, str(ROOT / "main.py"), *args], input=stdin, capture_output=True, text=True)


def test_sample_file_produces_brute_force_alert():
    events = (ROOT / "samples" / "events_brute_force.jsonl").read_text()
    proc = run_cli(events)
    assert proc.returncode == 0, proc.stderr
    alerts = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [a["rule"]["id"] for a in alerts] == ["auth-anom-brute-force"]


def test_garbage_input_is_skipped():
    proc = run_cli("not json\n[1, 2]\n\n")
    assert proc.returncode == 0
    assert proc.stdout == ""


def test_thresholds_are_configurable():
    events = (ROOT / "samples" / "events_brute_force.jsonl").read_text()
    proc = run_cli(events, "--brute-force-threshold", "50")
    assert proc.stdout == ""


def test_bad_geo_map_exits_2(tmp_path):
    bad = tmp_path / "geo.json"
    bad.write_text("[]")
    assert run_cli("", "--geo-map", str(bad)).returncode == 2
    assert run_cli("", "--geo-map", str(tmp_path / "missing.json")).returncode == 2
