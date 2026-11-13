# eventgen

Generates synthetic raw logs for tests and the demo. Output goes to stdout and
is meant to be piped into [logpipe](../logpipe): syslog lines for authentication
activity, and JSON lines shaped like [ebpf-telemetry](../ebpf-telemetry) output
for process and network activity.

```bash
python3 generate.py --scenario brute_force --count 10
python3 generate.py --scenario attack_chain --seed 7
```

| Scenario | Produces | Meant to trigger |
|----------|----------|------------------|
| `normal` | harmless sshd, sudo and systemd lines | nothing |
| `brute_force` | failed root logins from one address | `auth-001`, brute force |
| `password_spray` | failed logins for many accounts from one address | `auth-001`, password spray |
| `impossible_travel` | logins for one account from two countries | impossible travel |
| `root_login` | accepted root login | `auth-002` |
| `sudo_shell` | sudo to `/bin/bash` | `privesc-001` |
| `ioc_scan` | failed logins from an address in the sample threat feed | `auth-001`, IOC match |
| `malware` | download piped to shell, run from `/tmp`, C2 connection, reverse shell, new account | `exec-001` to `exec-003`, `net-001`, `persist-001`, IOC matches |
| `attack_chain` | all of the above as one timeline with background noise | everything |

`--count` is the number of lines, or the number of repetitions for `malware`
and `attack_chain`. `--seed` makes the random parts repeatable.

Nothing here touches a real system. The scanner, C2 and phishing indicators are
from the RFC 5737 documentation ranges and `example.net`, and match
`tools/ioc-feed/samples/feed.stix.json`.
