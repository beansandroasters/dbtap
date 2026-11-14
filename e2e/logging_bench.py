"""Alternate pgbench with logging off/on; retain TPS and added log bytes."""
import argparse
import json
import pathlib
import re
import statistics
import subprocess

p = argparse.ArgumentParser()
p.add_argument("--out", required=True)
p.add_argument("--seconds", type=int, default=10)
p.add_argument("--pairs", type=int, default=3)
p.add_argument("--clients", type=int, default=16)
p.add_argument("--warmup", type=int, default=30)
a = p.parse_args()
w = pathlib.Path(a.out)
w.mkdir(parents=True, exist_ok=True)


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def size():
    return int(run("docker", "exec", "dbtap-pg-src", "stat", "-c", "%s", "/var/lib/postgresql/data/log/postgresql.csv"))


src = run("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "dbtap-pg-src").strip()
print("Initializing", flush=True)
run("e2e/logging.sh", "off")
run("docker", "exec", "-e", "PGPASSWORD=secret", "dbtap-pg-src", "pgbench", "-q", "-i", "-s", "10", "-U", "postgres", "shop")
cmd = ["docker", "exec", "-e", "PGPASSWORD=secret", "dbtap-pg-dst", "pgbench",
       "-h", src, "-U", "postgres", "-c", str(a.clients), "-j", "8", "-M", "prepared"]
print(f"Warmup: {a.warmup} seconds", flush=True)
run(*cmd, "-T", str(a.warmup), "shop")  # Warm up with the same workload.
results = []
try:
    for pair in range(a.pairs):
        for mode in ("off", "on"):
            print(f"Measurement {pair + 1}/{a.pairs}: logging={mode}, {a.seconds} seconds", flush=True)
            run("e2e/logging.sh", mode)
            before = size()
            text = run(*cmd, "-T", str(a.seconds), "shop")
            after = size()
            (w / f"{pair}-{mode}.txt").write_text(text)
            tps = float(re.search(r"tps = ([0-9.]+)", text)[1])
            tx = int(re.search(r"number of transactions actually processed: (\d+)", text)[1])
            record = {"pair": pair, "logging": mode, "tps": tps, "transactions": tx,
                      "log_bytes": after - before, "bytes_per_transaction": (after-before)/tx}
            results.append(record)
            print(json.dumps(record), flush=True)
finally:
    run("e2e/logging.sh", "off")
means = {m: statistics.mean(x["tps"] for x in results if x["logging"] == m) for m in ("off", "on")}
report = {"seconds": a.seconds, "clients": a.clients, "scale": 10, "warmup_seconds": a.warmup, "results": results,
          "mean_tps": means, "change_percent": (means["on"]/means["off"]-1)*100}
(w / "benchmark.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
