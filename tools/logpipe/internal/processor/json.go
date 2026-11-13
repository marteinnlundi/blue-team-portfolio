package processor

import (
	"encoding/json"
	"fmt"

	"github.com/marteinnlundi/soc-in-a-box/tools/logpipe/internal/schema"
)

// ParseJSON accepts an event that is already JSON (for example from
// ebpf-telemetry) and fills in the required fields that are missing.
func ParseJSON(raw []byte) (*schema.Event, error) {
	var event schema.Event

	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("failed to parse json: %w", err)
	}

	if event.Event.Time.IsZero() {
		event.Event.Time = now().UTC()
	}
	if event.Event.Source == "" {
		event.Event.Source = "unknown"
	}
	if event.Event.Kind == "" {
		event.Event.Kind = "unknown"
	}
	if event.Host.Name == "" {
		event.Host.Name = "unknown"
	}
	if event.Severity == "" {
		event.Severity = "low"
	}

	return &event, nil
}
