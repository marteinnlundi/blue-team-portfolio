"""Unit tests for the three detections. Time is driven by event.time, not the clock."""

from datetime import datetime, timedelta, timezone

import main as auth_anom

T0 = datetime(2026, 2, 16, 12, 0, 0, tzinfo=timezone.utc)


def ev(kind, user, src_ip, offset_sec=0, host="prod-server"):
    time = (T0 + timedelta(seconds=offset_sec)).isoformat().replace("+00:00", "Z")
    event = {"event": {"time": time, "source": "syslog", "kind": kind}, "host": {"name": host}, "user": {"name": user}}
    if src_ip:
        event["network"] = {"src_ip": src_ip}
    return event


def fail(user, src_ip="192.168.1.66", offset_sec=0, host="prod-server"):
    return ev("authentication_failure", user, src_ip, offset_sec, host)


def ok(user, src_ip, offset_sec=0, host="prod-server"):
    return ev("authentication_success", user, src_ip, offset_sec, host)


def run(events, **kwargs):
    detector = auth_anom.Detector(**kwargs)
    return [alert for event in events for alert in detector.process(event)]


def ids(alerts):
    return [a["rule"]["id"] for a in alerts]


# --- brute force -----------------------------------------------------------


def test_brute_force_triggers_above_threshold():
    alerts = run([fail("root", offset_sec=i) for i in range(6)])
    assert ids(alerts) == ["auth-anom-brute-force"]
    alert = alerts[0]
    assert alert["alert"]["title"] == "Brute Force"
    assert alert["alert"]["severity"] == "high"
    assert alert["user"]["name"] == "root"
    assert alert["host"]["name"] == "prod-server"
    assert alert["network"]["src_ip"] == "192.168.1.66"
    assert alert["evidence"]["failure_count"] == 6


def test_brute_force_not_triggered_at_threshold():
    assert run([fail("root", offset_sec=i) for i in range(5)]) == []


def test_brute_force_respects_window_in_event_time():
    # Six failures, but 30 s apart: never more than three inside a 60 s window.
    assert run([fail("root", offset_sec=i * 30) for i in range(6)]) == []


def test_brute_force_is_per_user_and_host():
    events = [fail("root", offset_sec=i, host="a") for i in range(3)] + [fail("root", offset_sec=i, host="b") for i in range(3)]
    assert run(events) == []


def test_brute_force_resets_after_alert():
    alerts = run([fail("root", offset_sec=i) for i in range(12)])
    assert ids(alerts) == ["auth-anom-brute-force", "auth-anom-brute-force"]


# --- password spray --------------------------------------------------------

USERS = ["alice", "bob", "charlie", "dave", "eve", "frank"]


def test_password_spray_triggers():
    alerts = run([fail(u, "10.0.0.5", offset_sec=i) for i, u in enumerate(USERS)])
    assert ids(alerts) == ["auth-anom-password-spray"]
    alert = alerts[0]
    assert alert["alert"]["title"] == "Password Spray Detected"
    assert alert["network"]["src_ip"] == "10.0.0.5"
    assert alert["host"]["name"] == "prod-server"  # required by the alert schema
    assert alert["evidence"]["users"] == sorted(USERS)


def test_password_spray_needs_distinct_users():
    assert ids(run([fail("alice", "10.0.0.5", offset_sec=i) for i in range(5)])) == []


def test_password_spray_respects_window():
    events = [fail(u, "10.0.0.5", offset_sec=i * 300) for i, u in enumerate(USERS)]
    assert run(events) == []


def test_password_spray_needs_source_ip():
    assert run([fail(u, "", offset_sec=i) for i, u in enumerate(USERS)]) == []


# --- impossible travel -----------------------------------------------------


def test_impossible_travel_triggers():
    alerts = run([ok("admin", "1.1.1.1"), ok("admin", "2.2.2.2", offset_sec=600)])
    assert ids(alerts) == ["auth-anom-impossible-travel"]
    alert = alerts[0]
    assert alert["alert"]["title"] == "Impossible Travel"
    assert alert["user"]["name"] == "admin"
    assert [login["country"] for login in alert["evidence"]["logins"]] == ["US", "CN"]


def test_impossible_travel_same_country_is_fine():
    assert run([ok("admin", "1.1.1.1"), ok("admin", "1.1.1.1", offset_sec=60)]) == []


def test_impossible_travel_outside_window_is_fine():
    assert run([ok("admin", "1.1.1.1"), ok("admin", "2.2.2.2", offset_sec=7200)]) == []


def test_impossible_travel_ignores_unknown_locations():
    # Two different IPs with no known location must not count as two countries.
    assert run([ok("admin", "10.0.0.1"), ok("admin", "10.0.0.2", offset_sec=60)]) == []


def test_impossible_travel_is_per_user():
    assert run([ok("alice", "1.1.1.1"), ok("bob", "2.2.2.2", offset_sec=60)]) == []


# --- geo map ---------------------------------------------------------------


def test_geo_map_from_file_with_cidr_ranges(tmp_path):
    path = tmp_path / "geo.json"
    path.write_text('{"198.51.100.0/24": "US", "203.0.113.0/24": "SG", "198.51.100.7/32": "IS", "2001:db8::/32": "DE"}')
    lookup = auth_anom.load_geo_map(str(path))
    assert lookup("198.51.100.20") == "US"
    assert lookup("198.51.100.7") == "IS"  # most specific range wins
    assert lookup("203.0.113.9") == "SG"
    assert lookup("2001:db8::1") == "DE"
    assert lookup("192.0.2.1") is None
    assert lookup("not-an-ip") is None

    alerts = run([ok("admin", "198.51.100.20"), ok("admin", "203.0.113.9", offset_sec=60)], geo_lookup=lookup)
    assert ids(alerts) == ["auth-anom-impossible-travel"]


# --- misc ------------------------------------------------------------------


def test_other_event_kinds_are_ignored():
    assert run([ev("process_start", "root", "1.1.1.1")] * 20) == []


def test_alert_ids_are_unique():
    alerts = run([fail("root", offset_sec=i) for i in range(60)])
    assert len({a["alert"]["id"] for a in alerts}) == len(alerts) == 10


def test_missing_time_falls_back_to_wall_clock():
    events = [{"event": {"kind": "authentication_failure"}, "host": {"name": "h"}, "user": {"name": "root"}} for _ in range(6)]
    assert ids(run(events)) == ["auth-anom-brute-force"]
