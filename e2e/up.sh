#!/bin/bash
# Start two source/clone pairs for disposable database tests.
# Usage: e2e/up.sh (start)
#                e2e/up.sh down (cleanup)
set -eu
names="dbtap-pg-src dbtap-pg-dst dbtap-my-src dbtap-my-dst"
docker rm -fv $names >/dev/null 2>&1 || true
[ "${1:-}" = down ] && exit 0
# Prepare source PostgreSQL for CSV file logging.
# Toggle statement duration logging at runtime with e2e/logging.sh.
docker run -d --name dbtap-pg-src -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=shop -p 127.0.0.1:15432:5432 postgres:17 \
  -c logging_collector=on -c log_destination=csvlog -c log_filename=postgresql.log -c log_rotation_age=0 -c log_rotation_size=0 >/dev/null
docker run -d --name dbtap-pg-dst -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=shop -p 127.0.0.1:15433:5432 postgres:17 >/dev/null
docker run -d --name dbtap-my-src -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_DATABASE=shop -p 127.0.0.1:13306:3306 mysql:8.4 >/dev/null
docker run -d --name dbtap-my-dst -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_DATABASE=shop -p 127.0.0.1:13307:3306 mysql:8.4 >/dev/null
wait_ready() {
  local name=$1 deadline=$((SECONDS + 180))
  shift
  until docker exec "$name" "$@" >/dev/null 2>&1; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" != true ] || [ "$SECONDS" -ge "$deadline" ]; then
      echo "$name did not become ready; check its logs and available disk space" >&2
      docker logs --tail 25 "$name" >&2 || true
      return 1
    fi
    sleep 1
  done
}
for n in dbtap-pg-src dbtap-pg-dst; do
  wait_ready "$n" pg_isready -q -U postgres -d shop -h 127.0.0.1
done
for n in dbtap-my-src dbtap-my-dst; do
  wait_ready "$n" mysql -uroot -psecret -h127.0.0.1 -e 'select 1'
done
echo ready
