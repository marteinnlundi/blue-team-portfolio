# Security

## Scope

soc-in-a-box is a lab and learning project. It is not hardened for production
use. Known limits that are not vulnerabilities:

- caseboard has no authentication or authorisation. It binds to `127.0.0.1` by default; exposing it is at your own risk.
- ebpf-telemetry and ir-triage need root and read sensitive host data by design. Their output contains command lines, account names and log lines. Treat it as confidential.
- The detections can be evaded and are not a substitute for a real monitoring stack.

## Reporting a vulnerability

Please report privately through GitHub:
<https://github.com/marteinnlundi/soc-in-a-box/security/advisories/new>

Include what you found, how to reproduce it, and the impact. Please do not open
a public issue for security problems. I will reply as soon as I can; this is a
personal project, so there is no guaranteed response time.

Things I would especially like to hear about:

- script injection or request forgery in the caseboard UI or API
- input that crashes a tool or makes a detector miss an attack it documents
- ir-triage or ebpf-telemetry writing to, or changing, the host
