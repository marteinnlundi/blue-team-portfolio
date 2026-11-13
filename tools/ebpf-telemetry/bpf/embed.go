// Package bpf embeds the compiled eBPF object so the binary is self-contained.
// Build the object first with "make bpf".
package bpf

import _ "embed"

// Object is the compiled bpf/telemetry.bpf.c (little-endian BPF ELF).
//
//go:embed telemetry.bpf.o
var Object []byte
