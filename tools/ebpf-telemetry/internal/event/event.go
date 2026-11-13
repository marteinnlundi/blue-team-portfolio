// Package event turns raw records from the eBPF ring buffers into events that
// follow docs/standards/event_schema.md. It has no kernel dependencies, so it
// can be tested on any platform.
package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	afINET  = 2
	afINET6 = 10
)

// ExecRecord mirrors struct exec_event in bpf/telemetry.bpf.c.
type ExecRecord struct {
	Pid      uint32
	Ppid     uint32
	UID      uint32
	Comm     [16]byte
	Filename [256]byte
}

// ConnectRecord mirrors struct connect_event in bpf/telemetry.bpf.c.
type ConnectRecord struct {
	Pid    uint32
	UID    uint32
	Family uint16
	Dport  uint16
	Saddr  [16]byte
	Daddr  [16]byte
	Comm   [16]byte
}

// Event is the normalised output document.
type Event struct {
	Event    Meta     `json:"event"`
	Host     Host     `json:"host"`
	Severity string   `json:"severity"`
	User     *User    `json:"user,omitempty"`
	Process  *Process `json:"process,omitempty"`
	Network  *Network `json:"network,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

type Meta struct {
	Time   string `json:"time"`
	Source string `json:"source"`
	Kind   string `json:"kind"`
}

type Host struct {
	Name string `json:"name"`
}

type User struct {
	Name string `json:"name"`
}

type Process struct {
	Name        string `json:"name,omitempty"`
	PID         uint32 `json:"pid,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	ParentPID   uint32 `json:"parent_pid,omitempty"`
}

type Network struct {
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// Resolver supplies the facts that only user space knows. Any field may be nil.
type Resolver struct {
	// Cmdline returns the full command line of a PID, or "" if it is gone.
	Cmdline func(pid uint32) string
	// Username returns the account name for a UID, or "" if unknown.
	Username func(uid uint32) string
}

// DecodeExec parses a raw sample from the exec ring buffer.
func DecodeExec(raw []byte) (ExecRecord, error) {
	var rec ExecRecord
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &rec); err != nil {
		return rec, fmt.Errorf("decode exec record (%d bytes): %w", len(raw), err)
	}
	return rec, nil
}

// DecodeConnect parses a raw sample from the connect ring buffer.
func DecodeConnect(raw []byte) (ConnectRecord, error) {
	var rec ConnectRecord
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &rec); err != nil {
		return rec, fmt.Errorf("decode connect record (%d bytes): %w", len(raw), err)
	}
	return rec, nil
}

// FromExec builds a process_start event.
func FromExec(rec ExecRecord, host string, now time.Time, r Resolver) Event {
	filename := cString(rec.Filename[:])
	cmdline := ""
	if r.Cmdline != nil {
		cmdline = r.Cmdline(rec.Pid)
	}
	if cmdline == "" {
		// Short-lived process already exited: fall back to the executed path.
		cmdline = filename
	}

	return Event{
		Event:    Meta{Time: now.UTC().Format(time.RFC3339Nano), Source: "ebpf", Kind: "process_start"},
		Host:     Host{Name: host},
		Severity: "low",
		User:     user(rec.UID, r),
		Process: &Process{
			Name:        cString(rec.Comm[:]),
			PID:         rec.Pid,
			CommandLine: cmdline,
			ParentPID:   rec.Ppid,
		},
	}
}

// FromConnect builds a network_connection event for an outbound TCP connect.
func FromConnect(rec ConnectRecord, host string, now time.Time, r Resolver) (Event, error) {
	src, dst, err := addresses(rec)
	if err != nil {
		return Event{}, err
	}

	network := &Network{DstIP: dst.String(), DstPort: rec.Dport, Protocol: "tcp"}
	if !src.IsUnspecified() {
		network.SrcIP = src.String()
	}

	return Event{
		Event:    Meta{Time: now.UTC().Format(time.RFC3339Nano), Source: "ebpf", Kind: "network_connection"},
		Host:     Host{Name: host},
		Severity: "low",
		User:     user(rec.UID, r),
		Process:  &Process{Name: cString(rec.Comm[:]), PID: rec.Pid},
		Network:  network,
	}, nil
}

func addresses(rec ConnectRecord) (src, dst netip.Addr, err error) {
	switch rec.Family {
	case afINET:
		return netip.AddrFrom4([4]byte(rec.Saddr[:4])), netip.AddrFrom4([4]byte(rec.Daddr[:4])), nil
	case afINET6:
		// Unmap turns ::ffff:a.b.c.d (IPv4 over an IPv6 socket) back into a.b.c.d.
		return netip.AddrFrom16(rec.Saddr).Unmap(), netip.AddrFrom16(rec.Daddr).Unmap(), nil
	default:
		return src, dst, fmt.Errorf("unsupported address family %d", rec.Family)
	}
}

func user(uid uint32, r Resolver) *User {
	if r.Username == nil {
		return nil
	}
	if name := r.Username(uid); name != "" {
		return &User{Name: name}
	}
	return nil
}

// cString returns the bytes before the first NUL as a string.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.ToValidUTF8(string(b), "?")
}

// CmdlineFromProc converts the NUL-separated /proc/<pid>/cmdline format.
func CmdlineFromProc(data []byte) string {
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
}
