# Architecture

## Data types
- Event: raw security-relevant observation from a host or network source
- Alert: decision produced by a detection rule or analytic over events
- Case: an investigation container holding alerts, evidence, notes, and actions

## Flow
1) Telemetry sources produce events
   - ebpf-telemetry (endpoint)
   - file logs (Sysmon exports, auth logs, Zeek logs)

2) logpipe normalizes events
   - outputs JSONL in the event schema

3) Detection tools consume normalized events
   - sigma-lite: rule-based detections
   - auth-anom: auth-focused detections
   - ioc-feed: IOC matches

4) Alerts go to caseboard
   - triage, notes, evidence references, timeline

5) ir-triage supports response
   - collects host artifacts into a bundle
   - bundle is attached to a case

## Contracts
- events must follow: standards/event_schema.md
- alerts must follow: standards/alert_schema.md
