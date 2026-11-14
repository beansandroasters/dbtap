# /// script
# dependencies = ["psycopg[binary]>=3.2", "pymysql", "mysql-connector-python", "cryptography"]
# ///
"""Synthetic concurrent transfers, reads, errors, and non-deterministic statements.

Balance reads depend on other connections' commits, exposing incorrect replay ordering.
"""
import argparse
import random
import threading
import time

p = argparse.ArgumentParser()
p.add_argument("--pg", type=int)
p.add_argument("--my", type=int)
p.add_argument("--workers", type=int, default=6)
p.add_argument("--ops", type=int, default=120)
p.add_argument("--seed", type=int, default=1)
p.add_argument("--warmup", type=float, default=0, help="Wait this many seconds after connecting (for mid-stream capture tests)")
p.add_argument("--application-prefix", default="worker-")
p.add_argument("--no-copy", action="store_true", help="Replace COPY branches with reads for a fully replayable log test")
a = p.parse_args()


def pause(r):
    time.sleep(r.uniform(0.001, 0.012))


def warmup():
    if a.warmup:
        time.sleep(a.warmup)


def pg_worker(i):
    import psycopg

    r = random.Random(a.seed * 1000 + i)
    # prepare_threshold=3 switches repeated SQL to named server-side prepared statements.
    c = psycopg.connect(f"host=127.0.0.1 port={a.pg} dbname=shop user=postgres password=secret sslmode=disable",
                        prepare_threshold=3, application_name=f"{a.application_prefix}{i}")
    warmup()
    for n in range(a.ops):
        k = r.random()
        x, y = sorted(r.sample(range(1, 51), 2))
        amt = r.randint(1, 20)
        try:
            if k < 0.35:
                with c.transaction():
                    c.execute("update accounts set balance = balance - %s where id = %s", (amt, x))
                    c.execute("update accounts set balance = balance + %s where id = %s", (amt, y))
                    c.execute("insert into orders (account_id, amount, ref) values (%s, %s, %s)", (x, amt, f"w{i}-{n}"))
            elif k < 0.75:
                c.execute("select id, balance, note from accounts where id in (%s, %s) order by id", (x, y)).fetchall()
                c.commit()
            elif k < 0.82:
                c.execute("select sum(balance), count(*) from accounts").fetchall()
                c.commit()
            elif k < 0.88:
                c.execute("select now(), random()").fetchall()
                c.commit()
            elif k < 0.93:
                # Unique constraint violation.
                c.execute("insert into orders (account_id, amount, ref) values (1, 1, 'dup')")
                c.commit()
            elif k < 0.97:
                with c.pipeline():
                    c.execute("select balance from accounts where id = %s", (x,))
                    c.execute("select balance from accounts where id = %s", (y,))
                c.commit()
            elif a.no_copy:
                c.execute("select count(*) from bulk").fetchall()
                c.commit()
            else:
                with c.cursor() as cur, cur.copy("copy bulk (k, v) from stdin") as cp:
                    for j in range(20):
                        cp.write_row((j, f"row {i} {n} {j}"))
                c.commit()
        except psycopg.Error:
            c.rollback()
        pause(r)
    c.close()


def my_worker(i):
    r = random.Random(a.seed * 2000 + i)
    if i % 2 == 0:
        import pymysql

        c = pymysql.connect(host="127.0.0.1", port=a.my, user="root", password="secret", database="shop", ssl_disabled=True)
        cur = c.cursor()
        err = pymysql.Error
    else:
        import mysql.connector

        c = mysql.connector.connect(host="127.0.0.1", port=a.my, user="root", password="secret", database="shop",
                                    ssl_disabled=True, use_pure=True)
        # prepared=True uses binary COM_STMT_PREPARE/EXECUTE.
        cur = c.cursor(prepared=True)
        err = mysql.connector.Error
    warmup()
    for n in range(a.ops):
        k = r.random()
        x, y = sorted(r.sample(range(1, 51), 2))
        amt = r.randint(1, 20)
        try:
            if k < 0.35:
                cur.execute("update accounts set balance = balance - %s where id = %s", (amt, x))
                cur.execute("update accounts set balance = balance + %s where id = %s", (amt, y))
                cur.execute("insert into orders (account_id, amount, ref) values (%s, %s, %s)", (x, amt, f"w{i}-{n}"))
                c.commit()
            elif k < 0.75:
                cur.execute("select id, balance, note from accounts where id in (%s, %s) order by id", (x, y))
                cur.fetchall()
                c.commit()
            elif k < 0.85:
                cur.execute("select sum(balance), count(*) from accounts")
                cur.fetchall()
                c.commit()
            elif k < 0.92:
                cur.execute("select now(6), rand()")
                cur.fetchall()
                c.commit()
            else:
                cur.execute("insert into orders (account_id, amount, ref) values (1, 1, 'dup')")
                c.commit()
        except err:
            c.rollback()
        pause(r)
    c.close()


ts = []
for i in range(a.workers):
    if a.pg:
        ts.append(threading.Thread(target=pg_worker, args=(i,)))
    if a.my:
        ts.append(threading.Thread(target=my_worker, args=(i,)))
for t in ts:
    t.start()
for t in ts:
    t.join()
print("done")
