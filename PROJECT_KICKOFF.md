# Blue Team Portfolio: Project Kickoff

## 1. Executive Summary

The **Blue Team Portfolio** is a modular, end-to-end security operations platform designed to simulate a modern Defense (Blue Team) environment. It demonstrates the complete lifecycle of a security incident: from raw telemetry ingestion to detection, alert management, and final incident response.

Instead of a monolithic tool, it is composed of loosely coupled micro-services that communicate via standardized JSON schemas.

**Core Workflow:**

1. **Observe:** Agents (`ebpf-telemetry`) and logs flow into the normalizer (`logpipe`).
2. **Detect:** Normalized events are analyzed by rule engines (`sigma-lite`, `auth-anom`, `ioc-feed`).
3. **Triage:** Alerts are aggregated in a Case Management system (`caseboard`).
4. **Respond:** Analysts deploy forensic tools (`ir-triage`) to capture evidence for the case.

---

## 2. Definition of Done (DoD)

This checklist tracks the completion of the MVP. A phase is considered "Done" only when all checks are complete and the Integration Test passes.

### 🟢 Phase 1: End-to-End MVP

**Goal:** Establish the "Golden Path" (Logs  Normalized Events  Detection  Alert).

* **Ingestion (logpipe)**
* [x] MVP Implemented: JSON & Syslog parsing working.
* [x] Unit tests passing.


* **Detection (sigma-lite)**
* [ ] **Issue 1:** Python rule engine implemented (Events  Alerts).
* [ ] **Issue 2:** YAML rule schema defined with sample rules (SSH failure, Sudo).


* **Validation (detections-ci)**
* [ ] **Issue 3:** Synthetic event generator created (Normal vs. Attack traffic).
* [ ] **Issue 4:** GitHub Action pipeline runs `generator | logpipe | sigma-lite`.


* **Milestone**
* [ ] **Issue 5:** Local "One Command" demo works successfully.



### 🟣 Phase 2: Telemetry & Identity

**Goal:** Expand visibility into the Linux Kernel and stateful identity attacks.

* **Endpoint Telemetry (ebpf-telemetry)**
* [ ] **Issue 1:** Capture `execve` (Process Start) events via eBPF.
* [ ] **Issue 2:** Capture `tcp_connect` (Network Outbound) events.


* **Identity Detections (auth-anom)**
* [ ] **Issue 3:** Stateful Brute Force detection (> N failures / time).
* [ ] **Issue 4:** Password Spray detection (Unique users / single IP).
* [ ] **Issue 5:** Impossible Travel stub (GeoIP distance check).


* **Milestone**
* [ ] **Issue 6:** Integration verified (eBPF events trigger detections).



### 🔵 Phase 3: Cases & IR

**Goal:** Operationalize the data with Threat Intel, Case Management, and Forensic Triage.

* **Threat Intelligence (ioc-feed)**
* [ ] **Issue 1:** Service ingests and deduplicates a threat feed (IPs/Hashes).
* [ ] **Issue 2:** Real-time matching engine triggers alerts on bad IPs.


* **Case Management (caseboard)**
* [ ] **Issue 3:** API accepts alerts from all detection tools.
* [ ] **Issue 4:** UI allows promoting Alerts to Cases.
* [ ] **Issue 5:** Immutable Audit Trail tracks all user actions.


* **Incident Response (ir-triage)**
* [ ] **Issue 1 (Ph4):** Rust CLI collects running process list.
* [ ] **Issue 2 (Ph4):** Tool collects active network connections and file hashes.
* [ ] **Issue 3 (Ph4):** Tool outputs a single "Evidence Bundle" JSON.


* **Milestone**
* [ ] **Issue 5 (Ph4):** Full Portfolio Demo (Detect  Triage  Response) documented.



---

## 3. Architecture Standards

All contributions must adhere to the following contracts to ensure modularity:

* **Events:** Must strictly follow `standards/event_schema.md`.
* **Alerts:** Must strictly follow `standards/alert_schema.md`.
* 
**Logging:** All tools must output structured JSON logs to Stdout.


* 
**Exit Codes:** 0 (Success), 1 (Failure), 2 (Invalid Input).



---

