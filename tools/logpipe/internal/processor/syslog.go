package processor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marteinnlundi/soc-in-a-box/tools/logpipe/internal/schema"
)

// RFC 3164 style line: "Jan 13 17:45:00 host proc[pid]: message".
var syslogRegex = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+)\s([^\s]+)\s([^\[:]+)(?:\[(\d+)\])?:\s+(.*)$`)

// sshd authentication results. "invalid user" is optional so that the real
// account name is captured instead of the literal word "invalid".
var (
	failedAuthRegex   = regexp.MustCompile(`Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)`)
	acceptedAuthRegex = regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from ([0-9a-fA-F:.]+)`)
	sudoUserRegex     = regexp.MustCompile(`^\s*(\S+)\s*:`)
)

// now is replaced in tests so year inference is deterministic.
var now = time.Now

// ParseSyslog converts one syslog line into a normalised event.
func ParseSyslog(line []byte) (*schema.Event, error) {
	matches := syslogRegex.FindStringSubmatch(string(line))
	if matches == nil {
		return nil, fmt.Errorf("does not match syslog format")
	}

	host := matches[2]
	procName := strings.TrimSpace(matches[3])
	msg := matches[5]

	kind := "unknown"
	severity := "low"

	var userName string
	var srcIP string

	if m := failedAuthRegex.FindStringSubmatch(msg); m != nil {
		kind = "authentication_failure"
		severity = "medium"
		userName = m[1]
		srcIP = m[2]
	} else if m := acceptedAuthRegex.FindStringSubmatch(msg); m != nil {
		kind = "authentication_success"
		userName = m[1]
		srcIP = m[2]
	} else if procName == "sudo" && strings.Contains(msg, "COMMAND=") {
		kind = "privilege_escalation"
		if m := sudoUserRegex.FindStringSubmatch(msg); m != nil {
			userName = m[1]
		}
	}

	event := &schema.Event{
		Event: schema.EventMeta{
			Time:   parseTimestamp(matches[1]),
			Source: "syslog",
			Kind:   kind,
		},
		Host:     schema.Host{Name: host},
		Severity: severity,
		Process: &schema.Process{
			Name:        procName,
			CommandLine: msg,
		},
	}

	if pid, err := strconv.Atoi(matches[4]); err == nil {
		event.Process.PID = pid
	}

	if userName != "" {
		event.User = &schema.User{Name: userName}
	}
	if srcIP != "" {
		event.Network = &schema.Network{SrcIP: srcIP}
	}

	return event, nil
}

// parseTimestamp turns a year-less syslog timestamp into a UTC time.
// Classic syslog omits the year, so the current year is assumed. A result more
// than a day in the future (a December line read in January) is moved back one
// year. Unparseable timestamps fall back to the current time.
func parseTimestamp(raw string) time.Time {
	current := now().UTC()
	t, err := time.Parse(time.Stamp, raw)
	if err != nil {
		return current
	}
	t = t.AddDate(current.Year(), 0, 0)
	if t.After(current.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t.UTC()
}
