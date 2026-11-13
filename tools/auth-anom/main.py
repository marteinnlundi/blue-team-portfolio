#!/usr/bin/env python3
"""auth-anom: stateful authentication anomaly detection.

Reads normalised events (JSONL, see docs/standards/event_schema.md) from stdin
and writes alerts (JSONL, see docs/standards/alert_schema.md) to stdout.

Detections
- Brute force:       more than N failures for the same (user, host) in a window.
- Password spray:    more than M distinct users failing from one source IP in a window.
- Impossible travel: one user logging in from two different countries in a window.

Windows are measured in event time (event.time), so replaying an old log gives
the same result as watching it live. Only the standard library is used.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from collections.abc import Callable, Iterable, Iterator

# Built-in demo locations, used when no --geo-map is given.
DEFAULT_GEO_MAP = {"1.1.1.1/32": "US", "2.2.2.2/32": "CN"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Auth anomaly detection (stdin JSONL events -> stdout JSONL alerts)")
    p.add_argument("--brute-force-threshold", type=int, default=5, help="alert when failures for one (user, host) exceed this (default: 5)")
    p.add_argument("--brute-force-window-sec", type=float, default=60.0, help="brute force window in seconds (default: 60)")
    p.add_argument("--password-spray-threshold", type=int, default=5, help="alert when distinct users failing from one IP exceed this (default: 5)")
    p.add_argument("--password-spray-window-sec", type=float, default=600.0, help="password spray window in seconds (default: 600)")
    p.add_argument("--impossible-travel-window-sec", type=float, default=3600.0, help="impossible travel window in seconds (default: 3600)")
    p.add_argument("--geo-map", metavar="FILE", help='JSON file mapping CIDR ranges to country codes, e.g. {"198.51.100.0/24": "US"}')
    return p.parse_args(argv)


def load_geo_map(path: str | None) -> Callable[[str], str | None]:
    """Return a lookup function: IP string -> country code, or None if unknown."""
    raw = DEFAULT_GEO_MAP
    if path:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            raise ValueError("geo map must be a JSON object of CIDR -> country code")

    networks = [(ipaddress.ip_network(cidr, strict=False), str(country)) for cidr, country in raw.items()]
    # Most specific range first, so a /32 wins over the /8 that contains it.
    networks.sort(key=lambda item: item[0].prefixlen, reverse=True)

    def lookup(ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for network, country in networks:
            if addr.version == network.version and addr in network:
                return country
        return None

    return lookup


def get_str(obj: object, *keys: str) -> str:
    for key in keys:
        if not isinstance(obj, dict):
            return ""
        obj = obj.get(key)
    return obj.strip() if isinstance(obj, str) else ""


def event_timestamp(event: dict) -> float:
    """Event time as a Unix timestamp. Falls back to the wall clock if missing or invalid."""
    raw = get_str(event, "event", "time")
    if raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            pass
    return time.time()


def make_alert(title: str, severity: str, rule_id: str, host: str, summary: str, **extra: object) -> dict:
    return {
        "alert": {
            "id": f"alert-{uuid.uuid4()}",
            "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "title": title,
            "severity": severity,
        },
        "rule": {"id": rule_id},
        "host": {"name": host},
        **extra,
        "summary": summary,
    }


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


class Detector:
    """Keeps sliding-window state and turns events into alerts."""

    def __init__(
        self,
        brute_force_threshold: int = 5,
        brute_force_window_sec: float = 60.0,
        password_spray_threshold: int = 5,
        password_spray_window_sec: float = 600.0,
        impossible_travel_window_sec: float = 3600.0,
        geo_lookup: Callable[[str], str | None] | None = None,
    ) -> None:
        self.bf_threshold = brute_force_threshold
        self.bf_window = brute_force_window_sec
        self.spray_threshold = password_spray_threshold
        self.spray_window = password_spray_window_sec
        self.travel_window = impossible_travel_window_sec
        self.geo_lookup = geo_lookup or load_geo_map(None)

        # (user, host) -> deque of (timestamp, src_ip)
        self._failures: dict[tuple[str, str], deque] = defaultdict(deque)
        # src_ip -> deque of (timestamp, user, host)
        self._spray: dict[str, deque] = defaultdict(deque)
        # user -> deque of (timestamp, country, src_ip, host)
        self._logins: dict[str, deque] = defaultdict(deque)

    @staticmethod
    def _prune(entries: deque, cutoff: float) -> None:
        while entries and entries[0][0] < cutoff:
            entries.popleft()

    def process(self, event: dict) -> list[dict]:
        """Feed one event; return the alerts it triggers (usually none)."""
        kind = get_str(event, "event", "kind")
        if kind not in ("authentication_failure", "authentication_success"):
            return []

        ts = event_timestamp(event)
        host = get_str(event, "host", "name") or "unknown"
        user = get_str(event, "user", "name") or "unknown"
        src_ip = get_str(event, "network", "src_ip")

        if kind == "authentication_failure":
            alerts = self._brute_force(ts, user, host, src_ip)
            if src_ip:
                alerts += self._password_spray(ts, user, host, src_ip)
            return alerts
        if src_ip:
            return self._impossible_travel(ts, user, host, src_ip)
        return []

    def _brute_force(self, ts: float, user: str, host: str, src_ip: str) -> list[dict]:
        key = (user, host)
        entries = self._failures[key]
        entries.append((ts, src_ip))
        self._prune(entries, ts - self.bf_window)
        if len(entries) <= self.bf_threshold:
            return []

        sources = sorted({ip for _, ip in entries if ip})
        extra: dict[str, object] = {"user": {"name": user}}
        if len(sources) == 1:
            extra["network"] = {"src_ip": sources[0]}
        alert = make_alert(
            "Brute Force",
            "high",
            "auth-anom-brute-force",
            host,
            f"{len(entries)} authentication failures for user '{user}' on host '{host}' within {self.bf_window:g}s (threshold {self.bf_threshold}).",
            evidence={"failure_count": len(entries), "source_ips": sources, "first_seen": _iso(entries[0][0]), "last_seen": _iso(ts)},
            tags=["attack.credential_access", "attack.t1110.001"],
            **extra,
        )
        del self._failures[key]
        return [alert]

    def _password_spray(self, ts: float, user: str, host: str, src_ip: str) -> list[dict]:
        entries = self._spray[src_ip]
        entries.append((ts, user, host))
        self._prune(entries, ts - self.spray_window)
        users = sorted({u for _, u, _ in entries})
        if len(users) <= self.spray_threshold:
            return []

        hosts = sorted({h for _, _, h in entries})
        alert = make_alert(
            "Password Spray Detected",
            "high",
            "auth-anom-password-spray",
            host,
            f"{len(users)} distinct users failed authentication from {src_ip} within {self.spray_window:g}s (threshold {self.spray_threshold}).",
            network={"src_ip": src_ip},
            evidence={"users": users, "hosts": hosts, "first_seen": _iso(entries[0][0]), "last_seen": _iso(ts)},
            tags=["attack.credential_access", "attack.t1110.003"],
        )
        del self._spray[src_ip]
        return [alert]

    def _impossible_travel(self, ts: float, user: str, host: str, src_ip: str) -> list[dict]:
        country = self.geo_lookup(src_ip)
        if country is None:
            return []  # unknown location: nothing to compare

        entries = self._logins[user]
        entries.append((ts, country, src_ip, host))
        self._prune(entries, ts - self.travel_window)
        countries = sorted({c for _, c, _, _ in entries})
        if len(countries) < 2:
            return []

        alert = make_alert(
            "Impossible Travel",
            "medium",
            "auth-anom-impossible-travel",
            host,
            f"User '{user}' logged in from {' and '.join(countries)} within {self.travel_window:g}s.",
            user={"name": user},
            network={"src_ip": src_ip},
            evidence={"logins": [{"time": _iso(t), "country": c, "src_ip": ip, "host": h} for t, c, ip, h in entries]},
            tags=["attack.initial_access", "attack.t1078"],
        )
        del self._logins[user]
        return [alert]


def read_events(lines: Iterable[str]) -> Iterator[dict]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            yield event


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        geo_lookup = load_geo_map(args.geo_map)
    except (OSError, ValueError) as exc:
        print(f"auth-anom: cannot load geo map: {exc}", file=sys.stderr)
        return 2

    detector = Detector(
        brute_force_threshold=args.brute_force_threshold,
        brute_force_window_sec=args.brute_force_window_sec,
        password_spray_threshold=args.password_spray_threshold,
        password_spray_window_sec=args.password_spray_window_sec,
        impossible_travel_window_sec=args.impossible_travel_window_sec,
        geo_lookup=geo_lookup,
    )

    for event in read_events(sys.stdin):
        for alert in detector.process(event):
            print(json.dumps(alert), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
