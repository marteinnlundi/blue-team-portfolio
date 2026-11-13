//go:build ignore

// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// Kernel side of ebpf-telemetry. Two stable tracepoints are used instead of
// kprobes, so the program does not depend on function names, CPU registers or
// struct offsets of one particular kernel build:
//
//   sched:sched_process_exec  -> process_start events
//   sock:inet_sock_set_state  -> network_connection events (outbound TCP)
//
// This file is the one exception to the repository licence: the kernel only
// lets GPL-compatible programs call the helpers used here. See LICENSE notes
// in the repository README.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define TCP_SYN_SENT 2

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Only the fields that are read. CO-RE relocates them against the running
 * kernel's BTF at load time, so no vmlinux.h is needed. */
struct task_struct {
	int tgid;
	struct task_struct *real_parent;
} __attribute__((preserve_access_index));

/* Layouts from /sys/kernel/tracing/events/<group>/<name>/format. */
struct tp_sched_process_exec {
	__u64 common;
	__u32 data_loc_filename;
	__s32 pid;
	__s32 old_pid;
};

struct tp_inet_sock_set_state {
	__u64 common;
	const void *skaddr;
	__s32 oldstate;
	__s32 newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

/* Records sent to user space. Keep in sync with internal/event/event.go. */
struct exec_event {
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[FILENAME_LEN];
};

struct connect_event {
	__u32 pid;
	__u32 uid;
	__u16 family;
	__u16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
	__u8 comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} exec_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} connect_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct tp_sched_process_exec *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct exec_event *ev;
	__u32 filename_off;

	ev = bpf_ringbuf_reserve(&exec_events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->pid = bpf_get_current_pid_tgid() >> 32;
	ev->ppid = BPF_CORE_READ(task, real_parent, tgid);
	ev->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	/* __data_loc: low 16 bits are the offset of the string inside the record. */
	filename_off = ctx->data_loc_filename & 0xFFFF;
	if (bpf_probe_read_kernel_str(&ev->filename, sizeof(ev->filename), (void *)ctx + filename_off) < 0)
		ev->filename[0] = 0;

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_connect(struct tp_inet_sock_set_state *ctx)
{
	struct connect_event *ev;
	__u16 family = ctx->family;

	/* A socket enters SYN_SENT when a process calls connect(), and it does so
	 * in that process's context, so the current task is the caller. */
	if (ctx->protocol != IPPROTO_TCP || ctx->newstate != TCP_SYN_SENT)
		return 0;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	ev = bpf_ringbuf_reserve(&connect_events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->pid = bpf_get_current_pid_tgid() >> 32;
	ev->uid = (__u32)bpf_get_current_uid_gid();
	ev->family = family;
	ev->dport = ctx->dport; /* already host byte order in this tracepoint */
	__builtin_memset(ev->saddr, 0, sizeof(ev->saddr));
	__builtin_memset(ev->daddr, 0, sizeof(ev->daddr));
	if (family == AF_INET) {
		__builtin_memcpy(ev->saddr, ctx->saddr, 4);
		__builtin_memcpy(ev->daddr, ctx->daddr, 4);
	} else {
		__builtin_memcpy(ev->saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(ev->daddr, ctx->daddr_v6, 16);
	}
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
