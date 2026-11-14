#!/bin/bash
# Synthetic MySQL workload using the AL2023 mariadb105 client.
# Usage: set MYSQL_PWD/MYSQL_SSL_CA, then mysql-workload.sh <host> <user> <connections> <operations>
# Set DBTAP_PLAINTEXT_TEST=1 only for isolated plaintext capture tests.
set -euo pipefail
umask 077
[ "$#" -eq 4 ] || { echo "usage: $0 host user connections operations" >&2; exit 2; }
host=$1; user=$2; conns=$3; ops=$4
: "${MYSQL_PWD:?MYSQL_PWD must be set}"
[[ "$conns" =~ ^[1-9][0-9]{0,3}$ && "$ops" =~ ^[1-9][0-9]{0,6}$ ]] || {
  echo "connections: 1..9999; operations: 1..9999999" >&2; exit 2;
}
tls=(--ssl --ssl-verify-server-cert)
case "${DBTAP_PLAINTEXT_TEST:-0}" in
  0) : "${MYSQL_SSL_CA:?MYSQL_SSL_CA must be set}"; tls+=(--ssl-ca="$MYSQL_SSL_CA");;
  1) tls=(--skip-ssl);;
  *) echo "DBTAP_PLAINTEXT_TEST must be 0 or 1" >&2; exit 2;;
esac
work=$(mktemp -d "${TMPDIR:-/tmp}/dbtap-mysql.XXXXXXXX")
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait || true
  rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for c in $(seq 1 "$conns"); do
  awk -v seed="$c" -v ops="$ops" 'BEGIN {
    srand(seed)
    for (i = 0; i < ops; i++) {
      k = rand(); x = int(rand() * 50) + 1; y = int(rand() * 50) + 1
      if (x == y) y = (x % 50) + 1
      if (x > y) { t = x; x = y; y = t }
      amt = int(rand() * 20) + 1
      if (k < 0.4)
        printf "begin; update accounts set balance = balance - %d where id = %d; update accounts set balance = balance + %d where id = %d; insert into orders (account_id, amount, ref) values (%d, %d, \x27w%d-%d\x27); commit;\n", amt, x, amt, y, x, amt, seed, i
      else if (k < 0.8)
        printf "select id, balance, note from accounts where id in (%d, %d) order by id;\n", x, y
      else if (k < 0.9)
        printf "select sum(balance), count(*) from accounts;\n"
      else
        printf "select now(6), rand();\n"
    }
  }' > "$work/w$c.sql"
done
for c in $(seq 1 "$conns"); do
  mysql -h "$host" -u "$user" "${tls[@]}" shop < "$work/w$c.sql" > /dev/null &
  pids+=("$!")
done
status=0
for pid in "${pids[@]}"; do wait "$pid" || status=1; done
pids=()
exit "$status"
