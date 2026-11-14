# /// script
# dependencies = ["pymysql", "cryptography", "psycopg[binary]"]
# ///
"""Probe runtime log settings on existing sessions and absent MySQL syntax errors."""
import json
import pathlib
import subprocess
import sys

import psycopg
import pymysql

w = pathlib.Path(sys.argv[1])
w.mkdir(parents=True, exist_ok=True)
kw = dict(host="127.0.0.1", port=13306, user="root", password="secret",
          database="shop", ssl_disabled=True, autocommit=True)


def my(c, sql):
    with c.cursor() as cur:
        cur.execute(sql)
        return cur.fetchall()


subprocess.run(["e2e/logging.sh", "off"], check=True)
old = pymysql.connect(**kw)
pg = psycopg.connect("host=127.0.0.1 port=15432 dbname=shop user=postgres password=secret sslmode=disable", autocommit=True)
result = {"mysql_before": str(my(old, "select @@session.long_query_time")[0][0]),
          "pg_before": pg.execute("show log_min_duration_statement").fetchone()[0]}
try:
    subprocess.run(["e2e/logging.sh", "on"], check=True)
    new = pymysql.connect(**kw)
    result["mysql_old_after"] = str(my(old, "select @@session.long_query_time")[0][0])
    result["mysql_new_after"] = str(my(new, "select @@session.long_query_time")[0][0])
    result["pg_old_after"] = pg.execute("show log_min_duration_statement").fetchone()[0]
    for name, sql in [
        ("success", "select 1 /*dbtap_probe_success*/"),
        ("syntax", "SELEC 1 /*dbtap_probe_true_syntax*/"),
        ("duplicate", "insert into accounts values (1, 0, 'dbtap_probe_duplicate')"),
    ]:
        try:
            my(new, sql)
            result[f"{name}_errno"] = 0
        except pymysql.MySQLError as e:
            result[f"{name}_errno"] = e.args[0]
    new.close()
finally:
    old.close()
    pg.close()
    subprocess.run(["e2e/logging.sh", "off"], check=True)
subprocess.run(["e2e/logging.sh", "fetch", str(w)], check=True)
text = (w / "mysql-slow.log").read_text()
result["success_logged"] = "dbtap_probe_success" in text
result["syntax_logged"] = "dbtap_probe_true_syntax" in text
result["duplicate_logged"] = "dbtap_probe_duplicate" in text
assert result["syntax_errno"] == 1064 and not result["syntax_logged"], result
assert result["duplicate_errno"] == 1062 and result["duplicate_logged"], result
assert result["mysql_old_after"] == result["mysql_before"] and float(result["mysql_new_after"]) == 0
assert result["pg_old_after"] == "0", result
(w / "probe.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
print(json.dumps(result, ensure_ascii=False, indent=2))
