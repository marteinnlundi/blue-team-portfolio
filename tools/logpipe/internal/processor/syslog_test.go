package processor

import (
	"testing"
	"time"
)

func TestParseSyslog_AuthFailure(t *testing.T) {
	raw := []byte("Jan 13 17:45:00 prod-server sshd[100]: Failed password for root from 192.168.1.66 port 22 ssh2")

	event, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Host.Name != "prod-server" {
		t.Errorf("host: want prod-server, got %s", event.Host.Name)
	}
	if event.Event.Source != "syslog" {
		t.Errorf("source: want syslog, got %s", event.Event.Source)
	}
	if event.Event.Kind != "authentication_failure" {
		t.Errorf("kind: want authentication_failure, got %s", event.Event.Kind)
	}
	if event.Severity != "medium" {
		t.Errorf("severity: want medium, got %s", event.Severity)
	}
	if event.Process == nil || event.Process.Name != "sshd" {
		t.Errorf("process.name: want sshd, got %v", event.Process)
	}
	if event.User == nil || event.User.Name != "root" {
		t.Errorf("user.name: want root, got %v", event.User)
	}
	if event.Network == nil || event.Network.SrcIP != "192.168.1.66" {
		t.Errorf("network.src_ip: want 192.168.1.66, got %v", event.Network)
	}
	_, month, day := event.Event.Time.Date()
	if month != time.January || day != 13 {
		t.Errorf("time: want Jan 13, got %s %d", month, day)
	}
}

func TestParseSyslog_AuthSuccess(t *testing.T) {
	raw := []byte("May 29 10:00:00 bastion-host sshd[200]: Accepted password for alice from 1.1.1.1 port 22 ssh2")

	event, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Event.Kind != "authentication_success" {
		t.Errorf("kind: want authentication_success, got %s", event.Event.Kind)
	}
	if event.User == nil || event.User.Name != "alice" {
		t.Errorf("user.name: want alice, got %v", event.User)
	}
	if event.Network == nil || event.Network.SrcIP != "1.1.1.1" {
		t.Errorf("network.src_ip: want 1.1.1.1, got %v", event.Network)
	}
}

func TestParseSyslog_InvalidFormat(t *testing.T) {
	_, err := ParseSyslog([]byte("not a syslog line at all"))
	if err == nil {
		t.Error("expected error for invalid syslog line")
	}
}

func TestParseSyslog_InvalidUser(t *testing.T) {
	raw := []byte("Jan 13 17:45:00 prod-server sshd[100]: Failed password for invalid user oracle from 203.0.113.99 port 4022 ssh2")

	event, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Event.Kind != "authentication_failure" {
		t.Errorf("kind: want authentication_failure, got %s", event.Event.Kind)
	}
	if event.User == nil || event.User.Name != "oracle" {
		t.Errorf("user.name: want oracle, got %v", event.User)
	}
	if event.Network == nil || event.Network.SrcIP != "203.0.113.99" {
		t.Errorf("network.src_ip: want 203.0.113.99, got %v", event.Network)
	}
}

func TestParseSyslog_PublicKeyAndIPv6(t *testing.T) {
	raw := []byte("Jan 13 17:45:00 bastion-host sshd[100]: Accepted publickey for deploy from 2001:db8::1 port 22 ssh2")

	event, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Event.Kind != "authentication_success" {
		t.Errorf("kind: want authentication_success, got %s", event.Event.Kind)
	}
	if event.Network == nil || event.Network.SrcIP != "2001:db8::1" {
		t.Errorf("network.src_ip: want 2001:db8::1, got %v", event.Network)
	}
}

func TestParseSyslog_Sudo(t *testing.T) {
	raw := []byte("Jan 13 17:45:00 db-01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash")

	event, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Event.Kind != "privilege_escalation" {
		t.Errorf("kind: want privilege_escalation, got %s", event.Event.Kind)
	}
	if event.User == nil || event.User.Name != "alice" {
		t.Errorf("user.name: want alice, got %v", event.User)
	}
}

func TestParseSyslog_UnrelatedLineIsUnknown(t *testing.T) {
	raw := []byte("Jan 13 17:45:00 db-01 systemd[1]: Started Daily Cleanup of sudo logs.")

	event, err := ParseSyslog(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Event.Kind != "unknown" {
		t.Errorf("kind: want unknown, got %s", event.Event.Kind)
	}
}

func TestParseTimestamp_YearRollover(t *testing.T) {
	orig := now
	defer func() { now = orig }()
	now = func() time.Time { return time.Date(2026, time.January, 2, 8, 0, 0, 0, time.UTC) }

	got := parseTimestamp("Dec 31 23:59:00")
	if got.Year() != 2025 {
		t.Errorf("year: want 2025 for a December line read in January, got %d", got.Year())
	}

	got = parseTimestamp("Jan  2 07:00:00")
	if got.Year() != 2026 {
		t.Errorf("year: want 2026, got %d", got.Year())
	}
}
