# Local end-to-end tests

English | [日本語](README.ja.md)

Run from the repository root on Linux with Docker, Rust/Cargo, and uv. Live capture uses sudo; the pcap path needs tcpdump; TLS tests need OpenSSL. Use uv for Python scripts.

`up.sh` **deletes and recreates** containers named `dbtap-pg-src`, `dbtap-pg-dst`, `dbtap-my-src`, and `dbtap-my-dst`. It runs PostgreSQL 17 and MySQL 8.4 with host ports bound to 127.0.0.1:15432/15433/13306/13307. The test database is `shop`; the test password is `secret`. Do not reuse these names for data you need to keep.

## First complete run

```bash
cargo build --release --locked
cargo test --workspace --locked
sudo -v
e2e/up.sh
e2e/run.sh
e2e/up.sh down
```

Wait for `ready` after `up.sh`. Startup stops with recent container logs if a DB exits or remains unready for 180 seconds. `run.sh` initializes both pairs with identical data, records source workload traffic, replays against the clones, and directly compares tables. Results go into a fresh `/tmp/dbtap/e2e-XXXXXX`, printed on completion. Set `WORK=/path/to/new-directory` to select another location. Existing journals/reports cannot be overwritten.

The comparison covers accounts balances, orders business columns, and PostgreSQL bulk data. Generated IDs are shown separately because concurrent inserts can assign different IDs. In addition to `state.sh` results, inspect report failures, skips, and verdicts. Restore the target with `e2e/seed.sh dst` before manually replaying the same journal again.

`down` removes the containers and their anonymous data volumes but leaves artifacts for inspection. They contain SQL and values; TLS test output also contains private test keys. Keep them private and remove them after review.

## Input and scheduling variants

With the databases running, execute these sequentially because they reset shared test data:

```bash
CAPTURE=tcpdump e2e/run.sh
REPLAY_ARGS="--speed 4" e2e/run.sh
REPLAY_ARGS="--order table" e2e/run.sh
e2e/multi.sh
e2e/logs.sh
e2e/logs.sh --full
e2e/logs.sh --mysql
```

`logs.sh` compares SQL executions and timing between database logs and traffic, then replays. `--full` expects PostgreSQL COPY to be unreplayable and bulk data to be missing. Traffic unit counts include administrative commands, so they are distinct from SQL execution counts.

```bash
uv run e2e/log_probe.py /tmp/dbtap/probe-new
uv run --no-project e2e/log_regressions.py
uv run --no-project e2e/logging_bench.py --out /tmp/dbtap/log-bench-new --seconds 30
```

To operate logging separately:

```bash
e2e/logging.sh on
uv run -q e2e/workload.py --pg 15432 --my 13306
e2e/logging.sh off
e2e/logging.sh fetch /tmp/dbtap/logs-new
```

## Locust and TLS

```bash
WORK=/tmp/dbtap/tools-capture-new e2e/run.sh --workers 4 --ops 40
uv run --project integrations --extra locust -m unittest discover -s integrations/tests -v
uv run --project integrations --extra locust e2e/loadtools.py \
  /tmp/dbtap/tools-capture-new/cap.dbtap /tmp/dbtap/tools-new

# Run TLS tests last: they replace certificates on both destination databases.
uv run --no-project e2e/tls.py /tmp/dbtap/tools-capture-new/cap.dbtap /tmp/dbtap/tls-new
e2e/up.sh down
```

Locust tests cover local execution, two workers on one host, interruption, and unreachable targets. TLS tests cover a trusted CA/hostname and rejection before SQL is sent for an untrusted CA or wrong hostname. Use new output directories each time.

## pgbench

Run after `up.sh`. Do not run other benchmarks or builds concurrently when measuring CPU/I/O effects.

```bash
src=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' dbtap-pg-src)
dst=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' dbtap-pg-dst)
for name in dbtap-pg-src dbtap-pg-dst; do
  docker exec -e PGPASSWORD=secret "$name" pgbench -q -i -s 10 -U postgres shop
done
sudo ./target/release/dbtap capture --iface docker0 --pg-port 5432 -o bench.dbtap --duration 14 &
capture_pid=$!
sleep 1
docker exec -e PGPASSWORD=secret dbtap-pg-dst pgbench -h "$src" -U postgres -c 32 -j 8 -T 10 -M prepared shop
wait "$capture_pid"
sudo chown "$(id -u)" bench.dbtap
DBTAP_PASSWORD=secret ./target/release/dbtap replay bench.dbtap --pg "$dst:5432" --tls disable
e2e/pgbench_check.sh
e2e/up.sh down
```

## Troubleshooting

- **No space left on device:** check free space on the Docker data filesystem. Remove only disposable resources you own; the test cleanup removes its four containers and attached anonymous volumes.
- **Docker unavailable:** check `docker info` and the daemon/account permissions before running `up.sh`.
- **Capture permission error:** validate sudo first; use the correct interface and ports. The default local test captures `lo` on host-mapped ports.
- **Output already exists:** use a new WORK/output directory. Keep prior results for comparison instead of overwriting.
- **TLS error after TLS tests:** run `up.sh` to recreate the disposable databases before another baseline test.
- **Final data differs:** check capture loss, skips, failures, and dependency diagnostics; do not accept report Match alone.

Actual results and untested scope are in [Measurements](../docs/validation.md).
