#!/bin/bash
# Record the same workload through traffic and DB logs; compare executions, timing, and final state (--mysql for MySQL).
# without-copy (default) requires matching state; full checks missing COPY data.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
D=target/release/dbtap
MODE=${MODE:-without-copy}
engine=pg
if [ "${1:-}" = --mysql ]; then engine=mysql; shift; fi
if [ "${1:-}" = --full ]; then MODE=full; shift; fi
W=${WORK:-/tmp/dbtap/$engine-logs-$(date -u +%Y%m%d-%H%M%S)}
mkdir -p "$W"
app="dbtap-logs-$(date -u +%s)-"
capture_pid=
cleanup() {
  if [ -n "$capture_pid" ]; then sudo kill -INT "$capture_pid" 2>/dev/null || true; wait "$capture_pid" || true; fi
  e2e/logging.sh off >/dev/null 2>&1 || true
}
trap cleanup EXIT
e2e/seed.sh >"$W/seed.txt"
e2e/logging.sh on
port_args=(--pg-port 15432)
workload_args=(--pg 15432)
if [ "$engine" = mysql ]; then port_args=(--mysql-port 13306); workload_args=(--my 13306); fi
sudo "$D" capture --iface lo "${port_args[@]}" -o "$W/wire.dbtap" >"$W/capture.out" 2>"$W/capture.err" &
capture_pid=$!
sleep 1
args=()
if [ "$MODE" = without-copy ]; then args+=(--no-copy); fi
uv run -q e2e/workload.py "${workload_args[@]}" --application-prefix "$app" "${args[@]}" "$@"
sudo kill -INT "$capture_pid"
wait "$capture_pid"
capture_pid=
sudo chown "$(id -u)" "$W/wire.dbtap"
e2e/logging.sh off
e2e/logging.sh fetch "$W"
"$D" inspect "$W/wire.dbtap" --jsonl >"$W/wire.jsonl"
if [ "$engine" = pg ]; then
  "$D" import-logs --pg-csv "$W/postgresql.csv" --server 127.0.0.1:15432 \
    --database shop --application-prefix "$app" -o "$W/logs.dbtap" >"$W/import.json"
else
  mapfile -t ids < <(uv run --no-project python - "$W/wire.jsonl" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e["type"] == "open":
        print(e["info"]["server_session"])
PY
)
  filters=()
  for id in "${ids[@]}"; do filters+=(--mysql-thread "$id"); done
  "$D" import-logs --mysql-slow "$W/mysql-slow.log" --server 127.0.0.1:13306 \
    --database shop "${filters[@]}" -o "$W/logs.dbtap" >"$W/import.json"
fi
"$D" inspect "$W/logs.dbtap" --jsonl >"$W/logs.jsonl"
if [ "$engine" = pg ]; then
  uv run --no-project python e2e/compare_logs.py "$W/wire.jsonl" "$W/logs.jsonl" --application-prefix "$app" >"$W/comparison.json"
else
  uv run --no-project python e2e/compare_mysql_logs.py "$W/wire.jsonl" "$W/logs.jsonl" >"$W/comparison.json"
fi
"$D" replay "$W/logs.dbtap" --pg 127.0.0.1:15433 --mysql 127.0.0.1:13307 --password secret --tls disable --report "$W/report.json" >"$W/replay.txt" 2>"$W/replay.err"
state_rc=0
e2e/state.sh >"$W/state.txt" || state_rc=$?
uv run --no-project python - "$W" "$MODE" "$state_rc" <<'PY'
import json, pathlib, sys
w, mode, rc = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
r = json.loads((w / "report.json").read_text())
assert r["failed"] == 0, r["failures"]
assert all(v == "Match" for v, _ in r["verdicts"]), r["verdicts"]
state = (w / "state.txt").read_text()
if mode == "without-copy":
    assert rc == 0 and r["skipped"] == 0, state
else:
    assert rc == 1 and r["skipped"] > 0, state
    differences = [s for s in state.splitlines() if s.startswith("  DIFFER")]
    assert len(differences) == 1 and "bulk(COPY)" in differences[0], state
print((w / "comparison.json").read_text())
print(state)
print("artifacts:", w)
PY
