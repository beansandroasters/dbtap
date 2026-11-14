#!/bin/bash
# Compare source/clone final business state, excluding time-dependent columns.
set -eu
pg() { docker exec $1 psql -At -U postgres -d shop -c "$2" | md5sum | cut -c1-12; }
my() { docker exec $1 mysql -N -uroot -psecret -h127.0.0.1 shop -e "$2" 2>/dev/null | md5sum | cut -c1-12; }
rc=0
cmp() { if [ "$2" = "$3" ]; then echo "  MATCH  $1"; else echo "  DIFFER  $1 ($2 / $3)"; rc=1; fi; }
note() { if [ "$2" = "$3" ]; then echo "  MATCH  $1"; else echo "  (reference) DIFFER  $1"; fi; }
q1="select id, balance from accounts order by id"
q2="select account_id, amount, ref from orders order by ref"
q3="select k, v from bulk order by k, v"
# Concurrent INSERTs may assign different IDs; show these as reference checks only.
q4="select id, ref from orders order by id"
cmp "PostgreSQL accounts" $(pg dbtap-pg-src "$q1") $(pg dbtap-pg-dst "$q1")
cmp "PostgreSQL orders" $(pg dbtap-pg-src "$q2") $(pg dbtap-pg-dst "$q2")
cmp "PostgreSQL bulk(COPY)" $(pg dbtap-pg-src "$q3") $(pg dbtap-pg-dst "$q3")
note "PostgreSQL orders generated IDs" $(pg dbtap-pg-src "$q4") $(pg dbtap-pg-dst "$q4")
cmp "MySQL accounts" $(my dbtap-my-src "$q1") $(my dbtap-my-dst "$q1")
cmp "MySQL orders" $(my dbtap-my-src "$q2") $(my dbtap-my-dst "$q2")
note "MySQL orders generated IDs" $(my dbtap-my-src "$q4") $(my dbtap-my-dst "$q4")
exit $rc
