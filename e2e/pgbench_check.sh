#!/bin/bash
# Compare pgbench source and clone final state after replay.
# Usage: e2e/pgbench_check.sh
rc=0
for q in "select count(*), sum(abalance) from pgbench_accounts where abalance <> 0" \
         "select sum(tbalance) from pgbench_tellers" "select sum(bbalance) from pgbench_branches" \
         "select count(*), sum(delta) from pgbench_history" \
         "select md5(string_agg(aid || ':' || abalance, ',' order by aid)) from pgbench_accounts where abalance <> 0" \
         "select md5(string_agg(tid||':'||bid||':'||aid||':'||delta, ',' order by tid,bid,aid,delta)) from pgbench_history"; do
  a=$(docker exec dbtap-pg-src psql -At -U postgres -d shop -c "$q")
  b=$(docker exec dbtap-pg-dst psql -At -U postgres -d shop -c "$q")
  if [ "$a" = "$b" ]; then echo "  MATCH  $a"; else echo "  DIFFER  $a / $b"; rc=1; fi
done
exit $rc
