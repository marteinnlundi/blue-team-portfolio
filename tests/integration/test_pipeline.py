"""Integration tests: eventgen | logpipe | <detection tool>.

Every test runs the real pipeline as subprocesses and checks the alerts
against docs/standards/alert_schema.md.
"""

import json
import os
import subprocess

import pytest

from conftest import AUTH_ANOM, GENERATE, IOC_FEED_SAMPLE, SIGMA_LITE

pytestmark = pytest.mark.integration

SEVERITIES = {"low", "medium", "high", "critical"}


def run_pipeline(python, logpipe_bin, scenario, count, detector_cmd, env=None):
    """Return (events, alerts) for one scenario pushed through one detector."""
    raw = subprocess.run(
        [python, str(GENERATE), "--scenario", scenario, "--count", str(count), "--seed", "7"],
        capture_output=True, check=True,
    ).stdout
    normalised = subprocess.run([logpipe_bin], input=raw, capture_output=True, check=True).stdout
    detected = subprocess.run(
        detector_cmd, input=normalised, capture_output=True, check=True,
        env={**os.environ, **(env or {})},
    ).stdout
    events = [json.loads(line) for line in normalised.decode().splitlines() if line.strip()]
    alerts = [json.loads(line) for line in detected.decode().splitlines() if line.strip()]
    for alert in alerts:
        assert_alert_schema(alert)
    return events, alerts


def assert_alert_schema(alert):
    assert alert["alert"]["id"]
    assert alert["alert"]["time"]
    assert alert["alert"]["title"]
    assert alert["alert"]["severity"] in SEVERITIES
    assert alert["rule"]["id"]
    assert alert["host"]["name"]


def rule_ids(alerts):
    return [a["rule"]["id"] for a in alerts]


@pytest.fixture
def sigma(python, logpipe_bin):
    return lambda scenario, count: run_pipeline(python, logpipe_bin, scenario, count, [python, str(SIGMA_LITE)])


@pytest.fixture
def auth(python, logpipe_bin):
    return lambda scenario, count, *args: run_pipeline(python, logpipe_bin, scenario, count, [python, str(AUTH_ANOM), *args])


@pytest.fixture
def ioc(python, logpipe_bin, ioc_feed_cmd):
    return lambda scenario, count: run_pipeline(
        python, logpipe_bin, scenario, count,
        [*ioc_feed_cmd, "match", "--feed", str(IOC_FEED_SAMPLE)],
        env={"IOC_DB": ":memory:"},
    )


class TestLogpipe:
    def test_every_generated_line_is_normalised(self, sigma):
        events, _ = sigma("attack_chain", 1)
        assert len(events) == 37
        for event in events:
            assert event["event"]["time"] and event["event"]["source"] and event["event"]["kind"]
            assert event["host"]["name"]
            assert event["severity"] in SEVERITIES

    def test_invalid_user_is_parsed_as_the_real_account(self, sigma):
        events, _ = sigma("ioc_scan", 3)
        assert [e["user"]["name"] for e in events] == ["admin", "root", "ubuntu"]


class TestSigmaLite:
    def test_brute_force_triggers_auth001(self, sigma):
        _, alerts = sigma("brute_force", 1)
        assert rule_ids(alerts) == ["auth-001"]
        assert alerts[0]["alert"]["title"] == "SSH Authentication Failure"
        assert alerts[0]["alert"]["severity"] == "medium"
        assert alerts[0]["user"]["name"] == "root"

    def test_normal_events_no_alert(self, sigma):
        _, alerts = sigma("normal", 20)
        assert alerts == []

    def test_root_login(self, sigma):
        _, alerts = sigma("root_login", 1)
        assert rule_ids(alerts) == ["auth-002"]

    def test_sudo_shell(self, sigma):
        _, alerts = sigma("sudo_shell", 1)
        assert rule_ids(alerts) == ["privesc-001"]
        assert alerts[0]["user"]["name"] == "alice"

    def test_malware_activity(self, sigma):
        _, alerts = sigma("malware", 1)
        assert sorted(rule_ids(alerts)) == ["exec-001", "exec-002", "exec-003", "net-001", "persist-001"]
        reverse_shell = next(a for a in alerts if a["rule"]["id"] == "exec-002")
        assert reverse_shell["alert"]["severity"] == "critical"


class TestAuthAnom:
    def test_brute_force_detected(self, auth):
        _, alerts = auth("brute_force", 10, "--brute-force-threshold", "5", "--brute-force-window-sec", "60")
        assert "auth-anom-brute-force" in rule_ids(alerts)
        bf = next(a for a in alerts if a["rule"]["id"] == "auth-anom-brute-force")
        assert bf["alert"]["severity"] == "high"
        assert bf["user"]["name"] == "root"
        assert bf["network"]["src_ip"] == "192.168.1.66"

    def test_password_spray_detected(self, auth):
        _, alerts = auth("password_spray", 10, "--password-spray-threshold", "5", "--password-spray-window-sec", "600")
        assert "auth-anom-password-spray" in rule_ids(alerts)
        spray = next(a for a in alerts if a["rule"]["id"] == "auth-anom-password-spray")
        assert spray["alert"]["severity"] == "high"
        assert spray["network"]["src_ip"] == "10.0.0.99"

    def test_impossible_travel_detected(self, auth):
        _, alerts = auth("impossible_travel", 4, "--impossible-travel-window-sec", "3600")
        assert "auth-anom-impossible-travel" in rule_ids(alerts)
        travel = next(a for a in alerts if a["rule"]["id"] == "auth-anom-impossible-travel")
        assert travel["alert"]["severity"] == "medium"
        assert travel["user"]["name"] == "alice"

    def test_normal_events_no_alert(self, auth):
        _, alerts = auth("normal", 30)
        assert alerts == []


class TestIocFeed:
    def test_scanner_ip_matches_feed(self, ioc):
        _, alerts = ioc("ioc_scan", 3)
        assert rule_ids(alerts) == ["ioc-feed-match"] * 3
        assert {a["ioc"]["value"] for a in alerts} == {"203.0.113.99"}

    def test_c2_ip_and_phishing_domain_match(self, ioc):
        _, alerts = ioc("malware", 1)
        assert {(a["ioc"]["type"], a["ioc"]["value"]) for a in alerts} == {
            ("ip", "198.51.100.42"),
            ("domain", "evil-login.example.net"),
        }

    def test_normal_events_no_alert(self, ioc):
        _, alerts = ioc("normal", 20)
        assert alerts == []


class TestAttackChain:
    """The demo scenario must light up every detection at least once."""

    def test_sigma_lite_covers_all_rules(self, sigma):
        _, alerts = sigma("attack_chain", 1)
        assert set(rule_ids(alerts)) == {
            "auth-001", "auth-002", "privesc-001", "exec-001", "exec-002", "exec-003", "persist-001", "net-001",
        }

    def test_auth_anom_covers_all_detections(self, auth):
        _, alerts = auth("attack_chain", 1)
        assert set(rule_ids(alerts)) == {
            "auth-anom-brute-force", "auth-anom-password-spray", "auth-anom-impossible-travel",
        }
