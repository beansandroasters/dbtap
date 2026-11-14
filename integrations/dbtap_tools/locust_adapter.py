"""Run dbtap once per Locust process; User count does not set DB connection count."""

import csv
import json
import logging
import math
import os
from pathlib import Path
import time
import uuid

import gevent
from gevent import subprocess
from locust import User, events, task
from locust.runners import MasterRunner, WorkerRunner
from locust.stats import StatsCSV, PERCENTILES_TO_REPORT

from dbtap_tools import ACCEPTED, Labels, MAX_LINE, Stream, integer

log = logging.getLogger(__name__)


class ReplayDriver(User):
    """Replay is process-scoped; a User only keeps the Locust run alive."""
    @task
    def wait_for_replay(self):
        gevent.sleep(1)


@events.init_command_line_parser.add_listener
def options(parser):
    parser.add_argument("--dbtap-config", env_var="DBTAP_CONFIG",
                        help="Local JSON: argv (dbtap replay ...), output_dir")


def load_config(path):
    with open(path, "rb") as f:
        raw = f.read(MAX_LINE + 1)
    if len(raw) > MAX_LINE:
        raise ValueError("config too large")
    cfg = json.loads(raw)
    argv = cfg.get("argv")
    if not isinstance(argv, list) or len(argv) < 3 or argv[1] != "replay":
        raise ValueError("argv must be [absolute dbtap path, replay, journal, ...]")
    if any(not isinstance(x, str) or "\0" in x for x in argv) or not Path(argv[0]).is_absolute():
        raise ValueError("invalid argv")
    managed = {"--samples", "--run-id", "--shard", "--start-at", "--password"}
    if any(x.split("=", 1)[0] in managed for x in argv):
        raise ValueError("samples/run-id/shard/start-at are managed; use DBTAP_PASSWORD")
    if not isinstance(cfg.get("output_dir"), str) or not Path(cfg["output_dir"]).is_absolute():
        raise ValueError("absolute output_dir required")
    return cfg


class Driver:
    def __init__(self, env):
        self.env = env
        self.started = False
        self.finished = False
        self.child = None
        self.stopping = False
        self.expected = set()
        self.done = set()
        self.labels = Labels()
        self.cfg = None
        if not isinstance(env.runner, MasterRunner):
            if not env.parsed_options.dbtap_config:
                raise SystemExit("--dbtap-config is required on each worker/local runner")
            self.cfg = load_config(env.parsed_options.dbtap_config)

    def start(self, assignment):
        if self.started or self.stopping:
            return
        self.started = True
        gevent.spawn(self.run, assignment)

    def run(self, a):
        ok = False
        try:
            # RPC carries assignments only, never commands, paths, or credentials.
            n = integer(a["workers"], 1, 65536)
            k = integer(a["worker"], 0, n - 1)
            start = a["start_at"]
            if type(start) not in (int, float) or not math.isfinite(start) or not time.time() < start < time.time() + 3600:
                raise ValueError("invalid start_at")
            stream = Stream()
            stream.feed({"type": "start", "schema": 1, **{key: a[key] for key in ("run_id", "worker", "workers")}})
            root = Path(self.cfg["output_dir"])
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            dest = root / f'{a["run_id"]}-w{k}'
            dest.mkdir(mode=0o700)
            samples = dest / "samples.jsonl"
            argv = self.cfg["argv"] + ["--samples", str(samples), "--run-id", a["run_id"],
                                       "--shard", f"{k}/{n}", "--start-at", str(start)]
            # Private redirects, no shell, and passwords inherited through the environment.
            with open(dest / "stdout.log", "xb") as out, open(dest / "stderr.log", "xb") as err:
                self.child = subprocess.Popen(argv, stdout=out, stderr=err)
                while not samples.exists() and self.child.poll() is None:
                    gevent.sleep(0.02)
                state = Stream()
                failed = False
                with open(samples, "rb") as f:
                    pending = b""
                    while True:
                        chunk = f.readline(MAX_LINE + 1)
                        if chunk:
                            pending += chunk
                            if len(pending) > MAX_LINE:
                                raise ValueError("oversized sample")
                            if not pending.endswith(b"\n"):
                                continue
                            r = state.feed(json.loads(pending))
                            pending = b""
                            if state.header != stream.header:
                                raise ValueError("worker assignment mismatch")
                            if r is not None and r["status"] == "failed":
                                failed = True
                            if r is not None and r["timing"] is not None:
                                t = r["timing"]
                                self.env.events.request.fire(
                                    request_type="dbtap", name=self.labels.name(r),
                                    start_time=t["started_unix_ns"] / 1e9,
                                    response_time=t["latency_ns"] / 1e6,
                                    response_length=0, response=None,
                                    exception=None if r["request_success"] else RuntimeError(r["error_code"] or "transport"),
                                    context={"comparison": r["comparison"],
                                             "comparison_accepted": r["comparison"] in ACCEPTED,
                                             "observed": r["observed"], "lag_ns": t["lag_ns"]})
                        elif self.child.poll() is not None:
                            if pending:
                                raise ValueError("partial final line")
                            break
                        else:
                            gevent.sleep(0.02)
                if self.child.wait() != 0:
                    raise RuntimeError("dbtap failed; see private stderr.log")
                state.finish()
                if failed:
                    raise RuntimeError("connection/request transport failure in samples")
                ok = True
                self.finished = True
        except Exception as exc:
            log.error("dbtap adapter failed: %s", type(exc).__name__)
            self.env.process_exit_code = 1
        finally:
            self.stop_child()
            if isinstance(self.env.runner, WorkerRunner):
                # Deliver final request events to the master before notifying completion.
                self.env.runner._send_stats()
                self.env.runner.send_message("dbtap_done", {"ok": ok})
            elif not self.stopping:
                gevent.spawn(self.env.runner.quit)

    def stop_child(self):
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait()


@events.init.add_listener
def init(environment, **_):
    driver = Driver(environment)
    environment.dbtap_driver = driver
    runner = environment.runner
    if isinstance(runner, WorkerRunner):
        runner.register_message("dbtap_start", lambda environment, msg, **_: driver.start(msg.data))
    elif isinstance(runner, MasterRunner):
        def completed(environment, msg, **_):
            if msg.node_id not in driver.expected:
                return
            driver.done.add(msg.node_id)
            if msg.data.get("ok") is not True:
                environment.process_exit_code = 1
            if driver.done == driver.expected:
                gevent.spawn(runner.quit)
        runner.register_message("dbtap_done", completed)


@events.test_start.add_listener
def start(environment, **_):
    d = environment.dbtap_driver
    if isinstance(environment.runner, WorkerRunner):
        return  # Master initiates exactly once.
    if d.started:
        environment.process_exit_code = 1
        gevent.spawn(environment.runner.quit)
        return
    run_id = uuid.uuid4().hex
    at = time.time() + 5
    if isinstance(environment.runner, MasterRunner):
        d.started = True
        clients = sorted(environment.runner.clients.keys())
        if not clients:
            environment.process_exit_code = 1
            gevent.spawn(environment.runner.quit)
            return
        d.expected = set(clients)
        for k, client in enumerate(clients):
            environment.runner.send_message("dbtap_start", {
                "run_id": run_id, "worker": k, "workers": len(clients), "start_at": at}, client)
    else:
        d.start({"run_id": run_id, "worker": 0, "workers": 1, "start_at": at})


@events.test_stop.add_listener
def stop(environment, **_):
    d = environment.dbtap_driver
    d.stopping = True
    completed = d.done == d.expected if isinstance(environment.runner, MasterRunner) else d.finished
    if d.started and not completed:
        environment.process_exit_code = 1
    d.stop_child()


@events.quitting.add_listener
def final_stats(environment, **_):
    prefix = environment.parsed_options.csv_prefix
    if prefix and not isinstance(environment.runner, WorkerRunner):
        # Periodic Locust CSV may miss final events; write exact final statistics separately.
        try:
            fd = os.open(prefix + "_final_stats.csv", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", newline="") as f:
                StatsCSV(environment, PERCENTILES_TO_REPORT).requests_csv(csv.writer(f))
        except OSError:
            log.error("cannot write final dbtap stats")
            environment.process_exit_code = 1
