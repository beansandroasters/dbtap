# Load-testing integrations

English | [日本語](README.ja.md)

Start on one generator host and measure CPU, memory, file descriptors, network, and `lag` (send delay). Rust/Tokio uses multiple cores and connections. Maximum generator capacity is unmeasured. For multiple hosts, provide **identical journals in the same order**, divide connections with `--shard K/N`, and synchronize clocks.

Replay preserves changes in request frequency, SQL mix, recorded connection timing, and connection-local order. Slow target responses delay subsequent requests on the same connection. `--speed 2` halves scheduled intervals; it does not guarantee twice the TPS. Database CPU, I/O, and lock contention depend on the target's state and configuration.

**Transaction dependencies between workers are not synchronized.** Validate correctness on one host first. Fixed workers can increase sending capacity; elastic resizing and worker restart/resume are unsupported.

| Tool | Support |
|---|---|
| Locust 2.43.3 | Execution, fixed sharding, request completion events and statistics |
| Apache JMeter 5.6.3 | JTL CSV export; HTML with `jmeter -g` |
| k6 | Metric/Point JSON output, not k6 scripts or native k6 execution |
| pgbench / sysbench | Their DB traffic/logs can be recorded through existing inputs; no dedicated plugin. sysbench execution is unvalidated |

## Common measured time series

Build dbtap, add `target/release` to PATH, and run from the repository root. Use Python 3.11+ through uv. Set `DBTAP_PASSWORD` and prepare the clone before replay.

```bash
dbtap replay cap.dbtap --pg clone:5432 --tls require \
  --samples samples.jsonl --run-id trial1 --report report.json
uv run --project integrations dbtap-export jmeter samples.jsonl -o result.jtl
uv run --project integrations dbtap-export k6 samples.jsonl -o result.k6.json
```

Samples are written to a new file only (Unix 0600): schema 1 start, sample records on completion, then end when processing finishes. The queue is bounded at 4,096 entries and flushed every 100 ms. Slow output can delay replay; output failures cause nonzero exit. Measure capacity with samples enabled if you intend to use them.

| Field | Meaning |
|---|---|
| `timing.started_unix_ns` | Actual send start, derived from the initial wall/monotonic clock pair |
| `timing.latency_ns`, `lag_ns`, `waited_ns` | Response time, send delay, dependency-wait component |
| `captured_start_ns`, `captured_end_ns` | Original timestamps; unknown duration is `captured_duration_ns: null` |
| `request_success` | No target DB/transport error; null if never sent |
| `comparison` | Agreement on observed fields; a matching DB error is Match with request_success false |
| `observed`, `shape_id` | Available comparison fields and SQL-shape hash |

Samples omit SQL, bind values, request bytes, endpoints, usernames, and error text. Timing and shape IDs still reveal workload patterns; they are not anonymization. Normal reports and console output can include SQL.

Use one run-id across all workers. The converter rejects mixed runs, duplicate/missing shards, truncation, missing sequence numbers, and missing end records. It validates all input before exposing a finished output and refuses to overwrite existing files.

```bash
uv run --project integrations dbtap-export jmeter w0.jsonl w1.jsonl -o all.jtl
```

## Locust

Create a local JSON configuration on each worker. Paths are local to that host. argv is an array, with no shell expansion; credentials are inherited from `DBTAP_PASSWORD`.

```json
{
  "argv": ["/opt/dbtap", "replay", "/data/cap.dbtap", "--pg", "clone:5432", "--tls", "require"],
  "output_dir": "/data/results"
}
```

Replace the example paths and hostname, add `--tls-ca` if needed, and save as `/data/locust.json` in a protected directory. Single-process run:

```bash
uv run --project integrations --extra locust locust -f integrations/locustfile.py \
  --headless -u 1 -r 1 --run-time 30m --dbtap-config /data/locust.json --csv /data/trial1
```

`-u` does not multiply database connections. dbtap runs once per process, with the journal's connections. The final exact statistics are in `trial1_final_stats.csv`. Locust's periodic `trial1_stats.csv` can omit events arriving just before shutdown. Samples/stdout/stderr are retained in a private per-run directory beneath output_dir.

For two workers, restrict control port 5557 to those workers. The adapter does not add authentication/encryption to Locust control traffic.

```bash
# Master: use its private IP, not a public or wildcard address.
uv run --project integrations --extra locust locust -f integrations/locustfile.py \
  --headless --master --master-bind-host 10.0.1.10 --expect-workers 2 \
  -u 2 -r 2 --run-time 30m --csv /data/trial1

# Once on each worker; use identical recordings/targets and local configuration.
uv run --project integrations --extra locust locust -f integrations/locustfile.py \
  --headless --worker --master-host 10.0.1.10 --dbtap-config /data/locust.json
```

The master sends no DB requests. It assigns the initial worker set to 0/N through N-1/N with a common start five seconds later. Late workers receive no assignment. Start fresh processes for another run. Stopping Locust stops its dbtap child; interrupted samples without end are rejected by the converter.

DB errors count as Locust failures even when they match the recording; check dbtap comparison/report separately. `--exit-code-on-error 0` can disable Locust's request-error exit status, but adapter failures still exit 1. Startup time contributes to overall average RPS. Per-second CSV history reflects notification delay from the 100 ms flush interval and scheduling; use samples for precise send timestamps.

## JMeter

```bash
jmeter -g result.jtl -o html-report
```

The destination directory must be new or empty. JTL timestamps are request-start UNIX milliseconds, and elapsed is measured latency in integer milliseconds. Sub-millisecond latency rounds down to 0. Error rates use request_success. Unsent/skipped units are not request samples; check the original samples/report for them.

The columns bytes/sentBytes/grpThreads/allThreads/Latency/Connect required by standard HTML generation are **unmeasured zero placeholders**. Do not interpret their bandwidth, thread-count, first-response, or connection-time charts. Use the integration for elapsed time, counts, errors, and temporal trends.

## k6 JSON

One unit is one `iterations` event; measured latency is `iteration_duration`. `dbtap_lag` and `dbtap_dependency_wait` use milliseconds; `dbtap_failed` is the DB/transport error rate; `checks` is the accepted-comparison fraction. These are not HTTP requests. Labels are capped at 128, with additional shapes grouped as other. Points are sorted by completion time on disk.

**k6-web-dashboard v0.8.1 `aggregate` drops its pending buffer at EOF.** Testing produced 1,341 events in HTML from 1,450 in JSON; the missing EOF flush was confirmed in its official `dashboard/aggregate.go`. Do not use that version's HTML to validate total counts. All 1,450 events were present in the exported JSON.

## Validation

```bash
uv run --project integrations --extra locust -m unittest discover -s integrations/tests -v
# After e2e/up.sh; use fresh output locations.
WORK=/tmp/dbtap/tools-capture e2e/run.sh --workers 4 --ops 40
uv run --project integrations --extra locust e2e/loadtools.py /tmp/dbtap/tools-capture/cap.dbtap /tmp/dbtap/tools-test
```

On 2026-11-14, local and two-worker runs on one host each produced 1,450 events and 24 DB errors matching the final CSV; final data and generated IDs matched too. Interruption reaped the child and exited 1. An unreachable target left all 1,450 units unsent, without invented 0 ms samples. See [evidence](../docs/loadtools-validation-20261114.json). Multi-instance execution and maximum capacity are unmeasured.

References: [Locust custom protocols](https://docs.locust.io/en/stable/testing-other-systems.html), [JMeter results](https://jmeter.apache.org/usermanual/listeners.html), [k6 JSON](https://grafana.com/docs/k6/latest/results-output/real-time/json/).
