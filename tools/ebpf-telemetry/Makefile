# ebpf-telemetry build. Needs clang, libbpf headers and Go on Linux:
#   Debian/Ubuntu: apt install clang llvm libbpf-dev
#   Fedora:        dnf install clang llvm libbpf-devel

CLANG   ?= clang
GO      ?= go
BPF_SRC := bpf/telemetry.bpf.c
BPF_OBJ := bpf/telemetry.bpf.o
BIN     := ebpf-telemetry

# Debian/Ubuntu keep <asm/*.h> in a per-architecture directory.
ARCH_INC := /usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS ?= -g -O2 -Wall -target bpf -I$(ARCH_INC)

.PHONY: all bpf build test run clean

all: build

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build: $(BPF_OBJ)
	$(GO) build -o $(BIN) ./cmd/ebpf-telemetry

# Unit tests cover the user-space event decoding and need no kernel access.
test:
	$(GO) test ./internal/...

run: build
	sudo ./$(BIN)

clean:
	rm -f $(BPF_OBJ) $(BIN)
