#!/bin/bash
# End-to-end: seed, capture source workload, replay to clone, compare final state.
# Usage: e2e/run.sh [workload.py arguments], e.g. --workers 12 --ops 300
#   Set replay options through REPLAY_ARGS, e.g. REPLAY_ARGS="--speed 4".
#   CAPTURE=tcpdump uses tcpdump plus pcap import instead of live capture.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
D=target/release/dbtap
mkdir -p /tmp/dbtap
W=${WORK:-$(mktemp -d /tmp/dbtap/e2e-XXXXXX)}
mkdir -p "$W"
[ ! -e "$W/cap.dbtap" ] && [ ! -e "$W/report.json" ] || { echo "Choose a new WORK directory" >&2; exit 1; }
capture_pid=
cleanup() {
  if [ -n "$capture_pid" ]; then sudo kill -INT "$capture_pid" 2>/dev/null || true; wait "$capture_pid" || true; fi
}
trap cleanup EXIT
e2e/seed.sh >/dev/null
if [ "${CAPTURE:-live}" = live ]; then
  # Native AF_PACKET live capture.
  sudo "$D" capture --iface lo --pg-port 15432 --mysql-port 13306 -o "$W/cap.dbtap" &
  capture_pid=$!
  sleep 1
  uv run -q e2e/workload.py --pg 15432 --my 13306 "$@" >/dev/null
  sudo kill -INT "$capture_pid"
  wait "$capture_pid"
  capture_pid=
  sudo chown "$(id -u)" "$W/cap.dbtap"
else
  # tcpdump capture followed by pcap import.
  sudo tcpdump -i lo -U -w "$W/cap.pcap" 'tcp port 15432 or tcp port 13306' 2>"$W/tcpdump.err" &
  capture_pid=$!
  sleep 1
  uv run -q e2e/workload.py --pg 15432 --my 13306 "$@" >/dev/null
  # tcpdump receives blocks; stopping immediately can omit hundreds of milliseconds at the tail.
  sleep 2
  sudo kill -INT "$capture_pid"
  wait "$capture_pid"
  capture_pid=
  sudo chown "$(id -u)" "$W/cap.pcap"
  "$D" capture --pcap "$W/cap.pcap" --pg-port 15432 --mysql-port 13306 -o "$W/cap.dbtap"
fi
read -r -a replay_args <<< "${REPLAY_ARGS:-}"
DBTAP_PASSWORD=secret "$D" replay "$W/cap.dbtap" --pg 127.0.0.1:15433 --mysql 127.0.0.1:13307 --tls disable \
  --report "$W/report.json" "${replay_args[@]}" 2>"$W/replay.err" | sed -n '1,17p'
# Show immediate diagnostics for any causal timeouts.
rg -A1 "Causal wait timed out" "$W/replay.err" || true
echo "-- Final state (source / clone) --"
e2e/state.sh
echo "artifacts: $W"
