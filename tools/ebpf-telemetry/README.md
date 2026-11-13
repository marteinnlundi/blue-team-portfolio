# ebpf-telemetry

Endpoint telemetry from the Linux kernel. Two small eBPF programs report every
process start and every outbound TCP connection; a Go program loads them and
prints one [event](../../docs/standards/event_schema.md) per line.

## Requirements

- Linux 5.8 or newer with BTF (`/sys/kernel/btf/vmlinux` exists; true for current Ubuntu, Debian, Fedora and Arch kernels)
- root, to load eBPF programs
- To build: Go 1.21+, clang, libbpf headers

```bash
sudo apt install clang llvm libbpf-dev     # Debian, Ubuntu
sudo dnf install clang llvm libbpf-devel   # Fedora
```

## Build and run

```bash
make build
sudo ./ebpf-telemetry
```

In another terminal run `ls` or `curl https://example.com`:

```json
{"event":{"time":"2026-01-13T15:31:05.048466111Z","source":"ebpf","kind":"process_start"},"host":{"name":"workstation-05"},"severity":"low","user":{"name":"alice"},"process":{"name":"curl","pid":4056,"command_line":"curl https://example.com","parent_pid":4001}}
{"event":{"time":"2026-01-13T15:31:05.071869392Z","source":"ebpf","kind":"network_connection"},"host":{"name":"workstation-05"},"severity":"low","user":{"name":"alice"},"process":{"name":"curl","pid":4056},"network":{"src_ip":"192.168.1.10","dst_ip":"93.184.216.34","dst_port":443,"protocol":"tcp"}}
```

The compiled eBPF object is embedded in the binary, so the binary is all you
need to copy to another host of the same architecture.

Feed it into the rest of the pipeline:

```bash
sudo ./ebpf-telemetry | ../logpipe/logpipe | python3 ../sigma-lite/main.py
```

## How it works

| Event | Kernel hook | Why this hook |
|-------|-------------|---------------|
| `process_start` | tracepoint `sched:sched_process_exec` | Fires after a successful exec, so the process name is already the new program |
| `network_connection` | tracepoint `sock:inet_sock_set_state`, filtered to TCP entering `SYN_SENT` | Fires when a process calls `connect()`, with addresses and port already filled in, for IPv4 and IPv6 |

Tracepoints are a stable kernel interface, unlike kprobes on internal
functions. The only kernel struct the program reads is `task_struct` (for the
parent PID), through CO-RE, so the same object runs on different kernel
versions without recompiling.

Events travel from the kernel to user space through two ring buffers. User
space adds what the kernel side does not have: the full command line from
`/proc/<pid>/cmdline`, the account name for the UID, and the host name.

## Tests

```bash
make test
```

The unit tests cover decoding of ring buffer records and conversion to events,
and need neither root nor a kernel. CI additionally loads the programs into the
runner's kernel and checks that a process start is reported.

## Layout

```text
bpf/telemetry.bpf.c    kernel side: two tracepoint programs, two ring buffers
bpf/embed.go           embeds the compiled object into the Go binary
internal/event/        record decoding and event building, with tests
cmd/ebpf-telemetry/    loader: attach, read ring buffers, print JSONL
```

## Limits

- A process that exits within microseconds may be gone before its command line is read; the event then carries the executable path only.
- The source port is not reported (the kernel has not chosen it yet at this point), and UDP is not covered.
- Events are dropped if user space cannot keep up and a ring buffer (1 MiB each) fills.
- Reads only; it does not block or kill anything.

## Licence note

`bpf/telemetry.bpf.c` is dual licensed MIT or GPL-2.0, unlike the rest of the
repository. The kernel only allows GPL-compatible eBPF programs to use the
tracing helpers it calls. See [NOTICE](../../NOTICE).
