"""Validate dbtap completion events and export load-tool results using the standard library."""

import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile

MAX_LINE = 65536
ACCEPTED = {"Match", "NonDeterministic", "OrderOnly", "Racy"}
VERDICTS = ACCEPTED | {"ErrorDiff", "RowsDiff", "AffectedDiff", "ContentDiff"}


def integer(value, low=0, high=2**64 - 1):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid integer")
    return value


class Stream:
    """Schema 1 validator shared by live tailing and offline conversion."""

    def __init__(self):
        self.header = None
        self.seq = 0
        self.ended = False

    def feed(self, r):
        if not isinstance(r, dict) or self.ended:
            raise ValueError("record after end / invalid record")
        if self.header is None:
            if r.get("type") != "start" or r.get("schema") != 1:
                raise ValueError("expected schema 1 start")
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(r.get("run_id", ""))):
                raise ValueError("invalid run_id")
            n = integer(r.get("workers"), 1, 65536)
            integer(r.get("worker"), 0, n - 1)
            self.header = r
            return None
        if r.get("type") == "end":
            if integer(r.get("samples")) != self.seq:
                raise ValueError("sample count mismatch")
            self.ended = True
            return None
        if r.get("type") != "sample" or integer(r.get("seq")) != self.seq + 1:
            raise ValueError("missing / duplicate / unordered sample")
        integer(r.get("conn"))
        if not re.fullmatch(r"[a-f0-9]{16}", str(r.get("shape_id", ""))):
            raise ValueError("invalid shape_id")
        if r.get("status") not in {"ran", "failed", "skipped"}:
            raise ValueError("invalid status")
        if r.get("comparison") is not None and r["comparison"] not in VERDICTS:
            raise ValueError("invalid comparison")
        if r.get("error_code") is not None and not re.fullmatch(r"[A-Z0-9]{1,5}", str(r["error_code"])):
            raise ValueError("invalid error code")
        t = r.get("timing")
        if t is not None:
            if not isinstance(t, dict) or r["status"] == "skipped":
                raise ValueError("invalid timing")
            for k in ("started_unix_ns", "latency_ns", "lag_ns", "waited_ns"):
                integer(t.get(k))
            # Bound UNIX timestamps to the range supported by datetime and external tools.
            integer(t["started_unix_ns"] + t["latency_ns"], 0, 2**63 - 1)
            if type(r.get("request_success")) is not bool:
                raise ValueError("attempted sample requires success")
        elif r.get("request_success") is not None or r["status"] == "ran":
            raise ValueError("unattempted sample must not have latency/success")
        self.seq += 1
        return r

    def finish(self):
        if not self.ended:
            raise ValueError("incomplete results: end record missing")


def iter_samples(paths):
    """Read a complete, non-overlapping shard set; consuming to EOF validates completion."""
    seen = set()
    run = None
    workers = None
    for path in paths:
        state = Stream()
        with open(path, "rb") as f:
            while raw := f.readline(MAX_LINE + 1):
                if len(raw) > MAX_LINE or not raw.endswith(b"\n"):
                    raise ValueError("oversized / incomplete JSONL line")
                r = state.feed(json.loads(raw))
                if state.seq == 0 and not state.ended:
                    h = state.header
                    if run is None:
                        run, workers = h["run_id"], h["workers"]
                    if (run, workers) != (h["run_id"], h["workers"]) or h["worker"] in seen:
                        raise ValueError("different run / duplicate shard")
                    seen.add(h["worker"])
                if r is not None:
                    yield state.header, r
        state.finish()
    if workers is None or seen != set(range(workers)):
        raise ValueError("missing shard results")


class Labels:
    def __init__(self):
        self.seen = set()

    def name(self, r):
        label = r["shape_id"]
        if label not in self.seen and len(self.seen) >= 128:
            return "other"
        self.seen.add(label)
        return "sql_" + label


def jmeter(samples, out):
    w = csv.writer(out, lineterminator="\n")
    # Required but unmeasured JMeter HTML columns use zero; documented in README.
    w.writerow(["timeStamp", "elapsed", "label", "responseCode", "responseMessage",
                "threadName", "dataType", "success", "failureMessage", "bytes",
                "sentBytes", "grpThreads", "allThreads", "Latency", "Connect"])
    labels = Labels()
    for h, r in samples:
        if (t := r["timing"]) is None:
            continue
        ok = r["request_success"]
        w.writerow([t["started_unix_ns"] // 1_000_000, round(t["latency_ns"] / 1_000_000),
                    labels.name(r), r["error_code"] or ("OK" if ok else "TRANSPORT"),
                    r["status"], f'w{h["worker"]}-c{r["conn"]}', "text",
                    str(ok).lower(), "" if ok else "DB request failed",
                    0, 0, 0, 0, 0, 0])


def iso(ns):
    sec, nano = divmod(ns, 1_000_000_000)
    return dt.datetime.fromtimestamp(sec, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{nano:09d}Z"


def k6(samples, out):
    metrics = {"iterations": ("counter", "default"), "iteration_duration": ("trend", "time"),
               "dbtap_lag": ("trend", "time"), "dbtap_dependency_wait": ("trend", "time"),
               "dbtap_failed": ("rate", "default"), "checks": ("rate", "default"),
               "dbtap_skipped": ("counter", "default"), "dbtap_unattempted": ("counter", "default")}
    def write(r):
        out.write(json.dumps(r, separators=(",", ":")) + "\n")
    for name, (kind, contains) in metrics.items():
        write({"type": "Metric", "metric": name, "data": {
            "name": name, "type": kind, "contains": contains, "thresholds": [], "submetrics": None,
            "tainted": None}})
    labels = Labels()
    # Concurrent completion notifications can reorder; sort on disk without growing RAM.
    with tempfile.TemporaryDirectory(prefix="dbtap-export-") as temp:
        with sqlite3.connect(Path(temp) / "points.sqlite") as db:
            db.execute("create table points (ns integer, metric text, value real, tags text)")
            last = 0
            pending = {"dbtap_skipped": 0, "dbtap_unattempted": 0}
            for h, r in samples:
                t = r["timing"]
                if t is None:
                    pending["dbtap_skipped" if r["status"] == "skipped" else "dbtap_unattempted"] += 1
                    continue
                ns = t["started_unix_ns"] + t["latency_ns"]
                last = max(last, ns)
                tags = json.dumps({"name": labels.name(r), "worker": str(h["worker"])})
                values = {"iterations": 1, "iteration_duration": t["latency_ns"] / 1e6,
                          "dbtap_lag": t["lag_ns"] / 1e6, "dbtap_dependency_wait": t["waited_ns"] / 1e6,
                          "dbtap_failed": int(not r["request_success"])}
                if r["comparison"] is not None:
                    values["checks"] = int(r["comparison"] in ACCEPTED)
                db.executemany("insert into points values (?,?,?,?)",
                               [(ns, k, v, tags) for k, v in values.items()])
            # Put unsent counters at final completion time, without creating latency samples.
            for name, value in pending.items():
                if value:
                    db.execute("insert into points values (?,?,?,?)", (last, name, value, "{}"))
            for ns, name, value, tags in db.execute("select * from points order by ns, rowid"):
                write({"type": "Point", "metric": name,
                       "data": {"time": iso(ns), "value": value, "tags": json.loads(tags)}})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("format", choices=["jmeter", "k6"])
    p.add_argument("samples", nargs="+")
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()
    dest = Path(args.output)
    # Expose only fully validated outputs and never overwrite an existing file.
    fd, name = tempfile.mkstemp(prefix=".dbtap-", dir=dest.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            {"jmeter": jmeter, "k6": k6}[args.format](iter_samples(args.samples), f)
        os.link(name, dest)
    finally:
        os.unlink(name)


if __name__ == "__main__":
    main()
