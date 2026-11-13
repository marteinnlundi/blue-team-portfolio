# soc-in-a-box: common tasks for the whole repository.
#   make demo        one-command demo in Docker (http://localhost:3000)
#   make demo-local  the same demo without Docker
#   make test        every test suite
#   make lint        every linter

COMPOSE := docker compose -f demo/docker-compose.yml
NODE_TOOLS := ioc-feed caseboard

.PHONY: help build test lint demo demo-local demo-down test-logpipe test-python test-node test-rust test-ebpf test-integration clean

help:
	@sed -n 's/^#   //p' Makefile

build:
	cd tools/logpipe && go build -o logpipe ./cmd/logpipe
	@for t in $(NODE_TOOLS); do (cd tools/$$t && npm ci --no-audit --no-fund && npm run build) || exit 1; done
	cd tools/ir-triage && cargo build --release

test: test-logpipe test-python test-node test-rust test-ebpf test-integration

test-logpipe:
	cd tools/logpipe && go vet ./... && go test ./...

test-python:
	cd tools/sigma-lite && python3 -m pytest -q
	cd tools/auth-anom && python3 -m pytest -q

test-node:
	@for t in $(NODE_TOOLS); do (cd tools/$$t && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run typecheck && npm test) || exit 1; done

test-rust:
	cd tools/ir-triage && cargo test

# User-space unit tests only; loading the eBPF programs needs root (see tools/ebpf-telemetry).
test-ebpf:
	cd tools/ebpf-telemetry && go test ./internal/...

test-integration:
	@[ -f tools/ioc-feed/dist/cli.js ] || (cd tools/ioc-feed && npm ci --no-audit --no-fund && npm run build)
	python3 -m pytest tests/integration -q

lint:
	@test -z "$$(gofmt -l tools/logpipe tools/ebpf-telemetry)" || { echo "gofmt needed:"; gofmt -l tools/logpipe tools/ebpf-telemetry; exit 1; }
	ruff check .
	python3 tools/sigma-lite/main.py --validate
	cd tools/ir-triage && cargo fmt --check && cargo clippy --all-targets -- -D warnings

demo:
	$(COMPOSE) up --build

demo-down:
	$(COMPOSE) down -v

demo-local:
	./demo/run-local.sh

clean:
	rm -rf demo/output tools/logpipe/logpipe tools/*/dist tools/ir-triage/target
	$(MAKE) -C tools/ebpf-telemetry clean
