#!/bin/bash
# Test multiple journals, per-server routing, and multi-process replay.
#  Capture PostgreSQL/MySQL separately, simulating captures from two client hosts.
#  Merge the journals and route recorded servers with --map.
#          Two processes (--shard 0/2 and 1/2) share one start time.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
D=$PWD/target/release/dbtap
mkdir -p /tmp/dbtap
W=${WORK:-$(mktemp -d /tmp/dbtap/multi-XXXXXX)}
mkdir -p "$W"
[ ! -e "$W/a.dbtap" ] && [ ! -e "$W/b.dbtap" ] || { echo "Choose a new WORK directory" >&2; exit 1; }
capture_pids=()
cleanup() {
  for p in "${capture_pids[@]}"; do sudo kill -INT "$p" 2>/dev/null || true; wait "$p" || true; done
}
trap cleanup EXIT
e2e/seed.sh >/dev/null
sudo "$D" capture --iface lo --pg-port 15432 -o "$W/a.dbtap" 2>/dev/null &
capture_pids+=("$!")
sudo "$D" capture --iface lo --mysql-port 13306 -o "$W/b.dbtap" 2>/dev/null &
capture_pids+=("$!")
sleep 1
uv run -q e2e/workload.py --pg 15432 --my 13306 "$@" >/dev/null
for p in "${capture_pids[@]}"; do sudo kill -INT "$p"; wait "$p"; done
capture_pids=()
sudo chown "$(id -u)" "$W/a.dbtap" "$W/b.dbtap"
"$D" inspect "$W/a.dbtap" "$W/b.dbtap" | sed -n '1,8p'
at=$(( $(date +%s) + 3 ))
for k in 0 1; do
  DBTAP_PASSWORD=secret "$D" replay "$W/a.dbtap" "$W/b.dbtap" --map 127.0.0.1:15432=127.0.0.1:15433 --map 127.0.0.1:13306=127.0.0.1:13307 \
    --tls disable --shard "$k/2" --start-at "$at" --report "$W/shard$k.json" >"$W/shard$k.txt" 2>/dev/null &
done
wait
for k in 0 1; do echo "-- Worker $k --"; sed -n '2,9p' "$W/shard$k.txt"; done
echo "-- Merge both worker reports --"
"$D" report "$W/shard0.json" "$W/shard1.json" | sed -n '2,16p'
echo "-- Final state (source / clone) --"
e2e/state.sh
