#!/bin/bash
# Toggle source statement logging without restarting either DB.
# Usage: e2e/logging.sh on | off
#                e2e/logging.sh fetch <directory> (retrieve logs)
set -eu
umask 077
pg() { docker exec dbtap-pg-src psql -q -At -U postgres -d shop -c "$1"; }
my() { docker exec dbtap-my-src mysql -N -uroot -psecret -h127.0.0.1 -e "$1" 2>/dev/null; }
case "${1:-}" in
  on)
    # PostgreSQL: log completed statements with duration, plus connections/disconnections.
    # Include failed-statement parameters, which are omitted by default.
    pg "alter system set log_min_duration_statement = 0"
    pg "alter system set log_statement = 'none'"
    pg "alter system set log_duration = off"
    pg "alter system set log_parameter_max_length = -1"
    pg "alter system set log_min_error_statement = 'error'"
    pg "alter system set log_connections = on"
    pg "alter system set log_disconnections = on"
    pg "alter system set log_parameter_max_length_on_error = -1"
    pg "select pg_reload_conf()" >/dev/null
    # MySQL: zero slow threshold; log_slow_extra adds start/end timestamps and other fields.
    # long_query_time is copied at connection setup; existing sessions keep their value.
    my "set global log_output = 'FILE'; set global slow_query_log_file = '/var/lib/mysql/slow.log'; set global log_slow_extra = on; set global long_query_time = 0; set global min_examined_row_limit = 0; set global log_slow_admin_statements = on; set global slow_query_log = on"
    ;;
  off)
    pg "alter system reset log_min_duration_statement"
    pg "alter system reset log_statement"
    pg "alter system reset log_duration"
    pg "alter system reset log_parameter_max_length"
    pg "alter system reset log_min_error_statement"
    pg "alter system reset log_connections"
    pg "alter system reset log_disconnections"
    pg "alter system reset log_parameter_max_length_on_error"
    pg "select pg_reload_conf()" >/dev/null
    my "set global slow_query_log = off; set global long_query_time = 10"
    ;;
  fetch)
    out=$2; mkdir -p "$out"
    docker cp dbtap-pg-src:/var/lib/postgresql/data/log/postgresql.csv "$out/postgresql.csv" >/dev/null
    docker cp dbtap-my-src:/var/lib/mysql/slow.log "$out/mysql-slow.log" >/dev/null
    chmod 600 "$out/postgresql.csv" "$out/mysql-slow.log"
    ;;
  *) echo "Usage: $0 on|off|fetch <dir>" >&2; exit 1;;
esac
