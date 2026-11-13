#!/usr/bin/env bash
# Run the demo without Docker: build the tools, start caseboard, push one
# simulated intrusion through the pipeline, and leave the UI running.
#
# Needs: Go 1.22+, Python 3.10+ with PyYAML, Node.js 22+. Rust is optional
# (used to attach a real ir-triage report to the example case).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/demo/output"
PORT="${PORT:-3000}"
URL="http://127.0.0.1:$PORT"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not installed" >&2; exit 1; }; }
need go; need python3; need node; need npm
python3 -c "import yaml" 2>/dev/null || { echo "error: PyYAML is required (pip install -r tools/sigma-lite/requirements.txt)" >&2; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT"

echo "==> Building logpipe"
(cd "$REPO/tools/logpipe" && go build -o logpipe ./cmd/logpipe)

for tool in ioc-feed caseboard; do
  echo "==> Building $tool"
  (cd "$REPO/tools/$tool" && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run --silent build)
done

EVIDENCE=()
if command -v cargo >/dev/null 2>&1; then
  echo "==> Building ir-triage and collecting a triage bundle from this machine"
  (cd "$REPO/tools/ir-triage" && cargo build --release --quiet)
  "$REPO/tools/ir-triage/target/release/ir-triage" --output "$OUT/triage" --pretty 2>/dev/null
  EVIDENCE=(--evidence-report "$OUT/triage/report.json")
else
  echo "==> cargo not found, skipping ir-triage"
fi

echo "==> Starting caseboard on $URL"
(cd "$REPO/tools/caseboard" && PORT="$PORT" CASEBOARD_DB="$OUT/caseboard.db" exec node dist/server.js) &
CASEBOARD_PID=$!
trap 'kill "$CASEBOARD_PID" 2>/dev/null || true' EXIT

python3 "$REPO/demo/run_pipeline.py" --caseboard-url "$URL" --workdir "$OUT" "${EVIDENCE[@]}"

if [ "${DEMO_EXIT_AFTER_RUN:-0}" = "1" ]; then exit 0; fi
echo
echo "Caseboard is running at $URL. Press Ctrl-C to stop."
wait "$CASEBOARD_PID"
