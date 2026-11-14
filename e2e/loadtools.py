"""Compare actual Locust runs (local/two workers) with exported result counts.

First capture with e2e/run.sh, then: uv run --project integrations --extra locust e2e/loadtools.py cap.dbtap workdir
"""
import csv
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from dbtap_tools import iter_samples

ROOT = Path(__file__).resolve().parents[1]
journal, work = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
work.mkdir(mode=0o700, parents=True, exist_ok=True)
config = work / "config.json"
config.write_text(json.dumps({
    "argv": [str(ROOT / "target/release/dbtap"), "replay", str(journal),
             "--pg", "127.0.0.1:15433", "--mysql", "127.0.0.1:13307", "--tls", "disable"],
    "output_dir": str(work / "runs"),
}))
env = {**os.environ, "DBTAP_PASSWORD": "secret"}
base = [sys.executable, "-m", "locust", "-f", str(ROOT / "integrations/locustfile.py"),
        "--headless", "--only-summary", "--exit-code-on-error", "0"]
evidence = []
for workers in (1, 2):
    subprocess.run([str(ROOT / "e2e/seed.sh"), "dst"], check=True, stdout=subprocess.DEVNULL)
    before = set((work / "runs").glob("*/samples.jsonl"))
    prefix = work / f"locust-{workers}"
    processes = []
    handles = []
    try:
        if workers == 1:
            commands = [base + ["--dbtap-config", str(config), "-u", "1", "-r", "1",
                                "--run-time", "45s", "--csv", str(prefix)]]
        else:
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = str(s.getsockname()[1])
            commands = [base + ["--master", "--master-bind-host", "127.0.0.1",
                                "--master-bind-port", port, "--expect-workers", "2",
                                "-u", "2", "-r", "2", "--run-time", "45s", "--csv", str(prefix)]]
            commands += [base + ["--worker", "--master-host", "127.0.0.1",
                                 "--master-port", port, "--dbtap-config", str(config)]] * 2
        for i, command in enumerate(commands):
            handle = open(work / f"locust-{workers}-{i}.log", "wb")
            handles.append(handle)
            processes.append(subprocess.Popen(command, env=env, stdout=handle, stderr=handle))
        for p in processes:
            assert p.wait(timeout=65) == 0, f"Locust {workers} failed; see {work}"
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=10)
        for h in handles:
            h.close()
    paths = sorted(set((work / "runs").glob("*/samples.jsonl")) - before)
    assert len(paths) == workers
    samples = list(iter_samples(paths))
    attempted = [r for _, r in samples if r["timing"] is not None]
    counts = {}
    for h, r in samples:
        # Each recorded connection belongs to exactly one worker.
        previous = counts.setdefault(r["conn"], h["worker"])
        assert previous == h["worker"], "connection replayed by multiple workers"
    with open(str(prefix) + "_final_stats.csv") as f:
        total = next(r for r in csv.DictReader(f) if r["Name"] == "Aggregated")
    assert int(total["Request Count"]) == len(attempted)
    assert int(total["Failure Count"]) == sum(not r["request_success"] for r in attempted)
    state = subprocess.run([str(ROOT / "e2e/state.sh")], check=True, text=True, capture_output=True).stdout
    (work / f"state-{workers}.txt").write_text(state)
    evidence.append({"workers": workers, "samples": len(samples), "attempted": len(attempted),
                     "failures": int(total["Failure Count"]), "connections": len(counts), "state": state,
                     "paths": list(map(str, paths))})
# Timeout is not completion; even children waiting to start must be reaped.
before = set((work / "runs").glob("*/samples.jsonl"))
with open(work / "interrupted.log", "wb") as log:
    proc = subprocess.Popen(base + ["--dbtap-config", str(config), "-u", "1", "-r", "1", "--run-time", "2s"],
                            env=env, stdout=log, stderr=log)
    children = set()
    deadline = time.monotonic() + 10
    while proc.poll() is None and time.monotonic() < deadline:
        try:
            children.update(map(int, Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()))
        except FileNotFoundError:
            pass
        time.sleep(0.02)
    assert proc.wait(timeout=5) == 1
    assert children and all(not Path(f"/proc/{pid}").exists() for pid in children)
paths = sorted(set((work / "runs").glob("*/samples.jsonl")) - before)
assert len(paths) == 1
try:
    list(iter_samples(paths))
except ValueError:
    pass
else:
    raise AssertionError("interrupted run published complete samples")
evidence.append({"interrupted_exit": 1, "child_cleanup": True, "partial_output_rejected": True})
# Unreachable targets fail the run without invented zero-latency request samples.
bad_config = work / "unreachable.json"
bad_config.write_text(json.dumps({
    "argv": [str(ROOT / "target/release/dbtap"), "replay", str(journal),
             "--pg", "127.0.0.1:0", "--mysql", "127.0.0.1:0", "--tls", "disable"],
    "output_dir": str(work / "unreachable"),
}))
with open(work / "unreachable.log", "wb") as log:
    r = subprocess.run(base + ["--dbtap-config", str(bad_config), "-u", "1", "-r", "1", "--run-time", "20s"],
                       env=env, stdout=log, stderr=log, timeout=30)
assert r.returncode == 1
rs = list(iter_samples((work / "unreachable").glob("*/samples.jsonl")))
assert rs and all(r["timing"] is None and r["status"] == "failed" for _, r in rs)
evidence.append({"unreachable_exit": 1, "unattempted": len(rs)})
(work / "evidence.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(evidence, ensure_ascii=False, indent=2))
