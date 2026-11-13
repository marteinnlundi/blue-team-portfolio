#!/usr/bin/env python3
"""Run the whole soc-in-a-box pipeline once and load the result into caseboard.

    eventgen -> logpipe -> sigma-lite + auth-anom + ioc-feed -> caseboard

Used by both demo entry points (Docker Compose and run-local.sh). Only the
Python standard library is needed here; the tools themselves are started as
subprocesses, the same way you would pipe them together by hand.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def env_path(name: str, default: Path) -> Path:
    return Path(os.environ.get(name) or default)


LOGPIPE_BIN = env_path("LOGPIPE_BIN", TOOLS / "logpipe" / "logpipe")
IOC_FEED_CLI = env_path("IOC_FEED_CLI", TOOLS / "ioc-feed" / "dist" / "cli.js")
IOC_FEED_SAMPLE = TOOLS / "ioc-feed" / "samples" / "feed.stix.json"


def step(message: str) -> None:
    print(f"\n==> {message}", flush=True)


def run(cmd: list[str], stdin: bytes = b"", env: dict | None = None) -> bytes:
    result = subprocess.run(cmd, input=stdin, capture_output=True, env={**os.environ, **(env or {})})
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode(errors="replace"))
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(cmd)}")
    return result.stdout


def jsonl(data: bytes) -> list[dict]:
    return [json.loads(line) for line in data.decode().splitlines() if line.strip()]


class Caseboard:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, path: str, body: dict | None = None) -> dict | list:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base_url + "/api" + path, data=data, method=method, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def wait_until_ready(self, timeout_sec: float = 60.0) -> None:
        deadline = time.monotonic() + timeout_sec
        while True:
            try:
                self.request("GET", "/health")
                return
            except (urllib.error.URLError, OSError):
                if time.monotonic() > deadline:
                    raise SystemExit(f"caseboard did not answer at {self.base_url} within {timeout_sec:.0f}s") from None
                time.sleep(0.5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--caseboard-url", default=os.environ.get("CASEBOARD_URL", "http://127.0.0.1:3000"))
    parser.add_argument("--scenario", default="attack_chain", help="eventgen scenario (default: attack_chain)")
    parser.add_argument("--workdir", type=Path, help="keep raw logs, events and alerts in this directory")
    parser.add_argument("--evidence-report", type=Path, help="ir-triage report.json to attach to the case as evidence")
    parser.add_argument("--no-case", action="store_true", help="only load alerts; do not open an example case")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    python = sys.executable
    node = shutil.which("node")
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="soc-in-a-box-"))
    workdir.mkdir(parents=True, exist_ok=True)

    if not LOGPIPE_BIN.is_file():
        raise SystemExit(f"logpipe binary not found at {LOGPIPE_BIN} (build it or set LOGPIPE_BIN)")

    board = Caseboard(args.caseboard_url)
    step(f"Waiting for caseboard at {args.caseboard_url}")
    board.wait_until_ready()

    step(f"eventgen: generating the '{args.scenario}' scenario")
    raw = run([python, str(TOOLS / "eventgen" / "generate.py"), "--scenario", args.scenario])
    (workdir / "raw.log").write_bytes(raw)
    print(f"    {len(raw.splitlines())} raw log lines")

    step("logpipe: normalising raw logs into events")
    events = run([str(LOGPIPE_BIN)], raw)
    (workdir / "events.jsonl").write_bytes(events)
    kinds = Counter(e["event"]["kind"] for e in jsonl(events))
    print(f"    {sum(kinds.values())} events: " + ", ".join(f"{n} {k}" for k, n in kinds.most_common()))

    detectors: dict[str, tuple[list[str], dict]] = {
        "sigma-lite": ([python, str(TOOLS / "sigma-lite" / "main.py")], {}),
        "auth-anom": ([python, str(TOOLS / "auth-anom" / "main.py")], {}),
    }
    if node and IOC_FEED_CLI.is_file():
        detectors["ioc-feed"] = ([node, str(IOC_FEED_CLI), "match", "--feed", str(IOC_FEED_SAMPLE)], {"IOC_DB": ":memory:"})
    else:
        print("    (ioc-feed is not built, skipping threat intel matching)")

    alerts: list[dict] = []
    for name, (cmd, env) in detectors.items():
        step(f"{name}: detecting")
        found = jsonl(run(cmd, events, env))
        alerts += found
        by_rule = Counter(a["rule"]["id"] for a in found)
        print(f"    {len(found)} alerts: " + (", ".join(f"{n}x {r}" for r, n in sorted(by_rule.items())) or "none"))
    (workdir / "alerts.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts))

    step("caseboard: ingesting alerts")
    ingested = [board.request("POST", "/alerts/ingest", alert) for alert in alerts]
    by_severity = Counter(a["severity"] for a in ingested)
    print(f"    {len(ingested)} alerts: " + ", ".join(f"{by_severity[s]} {s}" for s in SEVERITY_ORDER if by_severity[s]))

    if not args.no_case:
        # Open one example case the way an analyst would: everything serious on the compromised host.
        serious = [
            stored["id"]
            for alert, stored in zip(alerts, ingested, strict=True)
            if alert.get("host", {}).get("name") == "prod-server" and stored["severity"] in ("high", "critical")
        ]
        if serious:
            step("caseboard: opening an example case for prod-server")
            case = board.request(
                "POST",
                "/cases",
                {"title": "Suspected compromise of prod-server", "severity": "critical", "tags": ["demo", "prod-server"], "alertIds": serious},
            )
            board.request("PATCH", f"/cases/{case['id']}", {"status": "investigating"})
            board.request(
                "POST",
                f"/cases/{case['id']}/notes",
                {
                    "author": "demo",
                    "content": "Brute force against root succeeded, followed by a root shell, a download piped to bash, "
                    "a reverse shell to a known C2 address and a new local account. Host triage requested.",
                },
            )
            if args.evidence_report and args.evidence_report.is_file():
                content = args.evidence_report.read_bytes()
                report = json.loads(content)
                try:
                    ref = str(args.evidence_report.resolve().relative_to(REPO))
                except ValueError:
                    ref = str(args.evidence_report)
                board.request(
                    "POST",
                    f"/cases/{case['id']}/evidence",
                    {
                        "ref": ref,
                        "description": f"ir-triage bundle from host '{report['host']['hostname']}' "
                        f"({len(report['processes'])} processes, {len(report['network']['listening_ports'])} listening ports), "
                        f"sha256 {hashlib.sha256(content).hexdigest()}",
                    },
                )
                print("    attached the ir-triage report as evidence")
            print(f"    case {case['id']} with {len(serious)} linked alerts")

    step("Done")
    print(f"    Open {args.caseboard_url} to triage the alerts.")
    print(f"    Raw logs, events and alerts are in {workdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
