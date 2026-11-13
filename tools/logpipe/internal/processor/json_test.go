package processor

import "testing"

func TestParseJSON_PassesThroughFields(t *testing.T) {
	raw := []byte(`{"event":{"time":"2026-01-13T15:31:05Z","source":"ebpf","kind":"process_start"},"host":{"name":"workstation-05"},"process":{"name":"curl","pid":4056,"command_line":"curl example.com"}}`)

	event, err := ParseJSON(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Event.Kind != "process_start" || event.Event.Source != "ebpf" {
		t.Errorf("event meta not preserved: %+v", event.Event)
	}
	if event.Process == nil || event.Process.PID != 4056 {
		t.Errorf("process not preserved: %+v", event.Process)
	}
	if event.Severity != "low" {
		t.Errorf("severity default: want low, got %s", event.Severity)
	}
}

func TestParseJSON_FillsDefaults(t *testing.T) {
	event, err := ParseJSON([]byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Event.Time.IsZero() {
		t.Error("time should default to now")
	}
	if event.Event.Source != "unknown" || event.Event.Kind != "unknown" || event.Host.Name != "unknown" {
		t.Errorf("defaults not applied: %+v host=%+v", event.Event, event.Host)
	}
}

func TestParseJSON_Invalid(t *testing.T) {
	if _, err := ParseJSON([]byte(`{not json`)); err == nil {
		t.Error("expected error for invalid JSON")
	}
}
