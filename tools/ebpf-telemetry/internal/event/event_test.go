package event

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 1, 13, 15, 31, 5, 0, time.UTC)

func fill(dst []byte, s string) { copy(dst, s) }

func encode(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRecordSizesMatchKernelStructs(t *testing.T) {
	// sizeof(struct exec_event) and sizeof(struct connect_event) in telemetry.bpf.c.
	if got := binary.Size(ExecRecord{}); got != 284 {
		t.Errorf("ExecRecord size: want 284, got %d", got)
	}
	if got := binary.Size(ConnectRecord{}); got != 60 {
		t.Errorf("ConnectRecord size: want 60, got %d", got)
	}
}

func TestExecRoundTrip(t *testing.T) {
	in := ExecRecord{Pid: 4056, Ppid: 4001, UID: 1000}
	fill(in.Comm[:], "curl")
	fill(in.Filename[:], "/usr/bin/curl")

	rec, err := DecodeExec(encode(t, in))
	if err != nil {
		t.Fatal(err)
	}

	r := Resolver{
		Cmdline:  func(pid uint32) string { return "curl -s https://example.com" },
		Username: func(uid uint32) string { return "alice" },
	}
	ev := FromExec(rec, "workstation-05", fixedTime, r)

	if ev.Event.Kind != "process_start" || ev.Event.Source != "ebpf" {
		t.Errorf("meta: %+v", ev.Event)
	}
	if ev.Event.Time != "2026-01-13T15:31:05Z" {
		t.Errorf("time: %s", ev.Event.Time)
	}
	if ev.Host.Name != "workstation-05" || ev.Severity != "low" {
		t.Errorf("host/severity: %+v %s", ev.Host, ev.Severity)
	}
	if ev.User == nil || ev.User.Name != "alice" {
		t.Errorf("user: %+v", ev.User)
	}
	p := ev.Process
	if p.Name != "curl" || p.PID != 4056 || p.ParentPID != 4001 || p.CommandLine != "curl -s https://example.com" {
		t.Errorf("process: %+v", p)
	}
}

func TestExecFallsBackToFilename(t *testing.T) {
	in := ExecRecord{Pid: 1}
	fill(in.Comm[:], "true")
	fill(in.Filename[:], "/usr/bin/true")

	ev := FromExec(in, "h", fixedTime, Resolver{Cmdline: func(uint32) string { return "" }})
	if ev.Process.CommandLine != "/usr/bin/true" {
		t.Errorf("command_line: want /usr/bin/true, got %q", ev.Process.CommandLine)
	}
	if ev.User != nil {
		t.Errorf("user should be omitted without a resolver, got %+v", ev.User)
	}
}

func TestConnectIPv4(t *testing.T) {
	in := ConnectRecord{Pid: 77, UID: 0, Family: afINET, Dport: 4444}
	copy(in.Saddr[:], []byte{10, 0, 0, 5})
	copy(in.Daddr[:], []byte{198, 51, 100, 42})
	fill(in.Comm[:], "bash")

	rec, err := DecodeConnect(encode(t, in))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := FromConnect(rec, "h", fixedTime, Resolver{})
	if err != nil {
		t.Fatal(err)
	}
	n := ev.Network
	if n.SrcIP != "10.0.0.5" || n.DstIP != "198.51.100.42" || n.DstPort != 4444 || n.Protocol != "tcp" {
		t.Errorf("network: %+v", n)
	}
	if ev.Event.Kind != "network_connection" || ev.Process.Name != "bash" || ev.Process.PID != 77 {
		t.Errorf("event: %+v process: %+v", ev.Event, ev.Process)
	}
}

func TestConnectIPv6AndMappedIPv4(t *testing.T) {
	in := ConnectRecord{Family: afINET6, Dport: 443}
	copy(in.Daddr[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	ev, err := FromConnect(in, "h", fixedTime, Resolver{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Network.DstIP != "2001:db8::1" {
		t.Errorf("dst_ip: %s", ev.Network.DstIP)
	}
	if ev.Network.SrcIP != "" {
		t.Errorf("unspecified source should be omitted, got %q", ev.Network.SrcIP)
	}

	mapped := ConnectRecord{Family: afINET6, Dport: 80}
	copy(mapped.Daddr[:], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 93, 184, 216, 34})
	ev, err = FromConnect(mapped, "h", fixedTime, Resolver{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Network.DstIP != "93.184.216.34" {
		t.Errorf("mapped dst_ip: %s", ev.Network.DstIP)
	}
}

func TestConnectUnknownFamily(t *testing.T) {
	if _, err := FromConnect(ConnectRecord{Family: 1}, "h", fixedTime, Resolver{}); err == nil {
		t.Error("expected error for unsupported family")
	}
}

func TestDecodeShortRecord(t *testing.T) {
	if _, err := DecodeExec([]byte{1, 2, 3}); err == nil {
		t.Error("expected error for short exec record")
	}
	if _, err := DecodeConnect(nil); err == nil {
		t.Error("expected error for empty connect record")
	}
}

func TestCmdlineFromProc(t *testing.T) {
	if got := CmdlineFromProc([]byte("curl\x00-s\x00https://example.com\x00")); got != "curl -s https://example.com" {
		t.Errorf("got %q", got)
	}
}

func TestJSONMatchesEventSchema(t *testing.T) {
	in := ExecRecord{Pid: 9, Ppid: 1}
	fill(in.Comm[:], "ls")
	out, err := json.Marshal(FromExec(in, "h", fixedTime, Resolver{}))
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(out, &generic); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"event", "host", "severity", "process"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("missing %q in %s", key, out)
		}
	}
	proc := generic["process"].(map[string]any)
	for _, key := range []string{"name", "pid", "parent_pid"} {
		if _, ok := proc[key]; !ok {
			t.Errorf("missing process.%s in %s", key, out)
		}
	}
}
