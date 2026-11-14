# Architecture and replay scheduling

English | [日本語](architecture.ja.md)

## Components

| Crate | Responsibility |
|---|---|
| dbtap-core | Journal, units, observed fields |
| dbtap-proto | PostgreSQL/MySQL wire reconstruction and Extractor |
| dbtap-capture | TCP, pcap/pcapng, AF_PACKET |
| dbtap-logs | PostgreSQL CSV / MySQL slow-log import |
| dbtap-replay | Dependencies, clients, replay, comparison, aggregation and samples |
| dbtap-cli | capture / import-logs / inspect / replay / report |

The Python package in `integrations/` supplies load-tool integration.

## Journal and units

A journal begins with `DBTAPJ1\n`, followed by a zstd stream. Records are Header, ConnOpen, Data, ConnClose, Lost, Session, and Unit. Data contains connection, direction, time, and bytes; Session/Unit contain reconstructed log data. See [journal.rs](../crates/dbtap-core/src/journal.rs). The format has no digital signature or authenticity check.

A wire unit groups a PostgreSQL Query or extended-protocol exchange through Sync/ReadyForQuery, or one MySQL command and response. It may contain several SQL statements. Replay sends the request bytes but authenticates using target credentials. MySQL prepared-statement IDs are replaced with IDs returned by the target.

A log unit is one execution, reconstructed as PostgreSQL Parse/Bind/Execute/Sync or Query, or MySQL COM_QUERY. Original type declarations, binary formats, and pipeline boundaries may be unavailable. `Unit.observed` records whether errors, returned rows, affected rows, contents, and duration are known; comparison and timing aggregation follow it.

## Reconstruction and read-ahead

TCP reconstruction uses directional sequence numbers and ACK ordering between directions, including reordered mirror arrivals. Connections without a SYN are held for 20 ms before being treated as mid-stream.

Extractor emits units when responses complete. The reader plans dependencies; one task per connection waits for the schedule and dependencies before sending. Each connection executes serially. Multiple journals are merged by timestamp, with connection IDs separated across inputs.

Read-ahead defaults to 10 seconds and 100,000 queued units. A request longer than the read-ahead window is reconstructed too late for its scheduled start. Metadata, partially reconstructed requests, and large SQL also consume memory: the queue limit is not a total memory limit.

A dedicated timer thread waits for scheduled sends. Actual timestamps are derived from a wall-clock/monotonic-clock pair established at startup. Completed samples use a bounded queue of 4,096 entries and are flushed every 100 ms; slow output can delay sending.

## Dependencies

| `--order` | Waits for | Limitation |
|---|---|---|
| `row` (default) | Operations sharing values on the same server/table; no values means the whole table | Ranges and predicates on different columns are not fully understood |
| `table` | Operations touching the same server/table | More waiting can stretch the timeline |
| `time` | Schedule and connection-local order only | No write ordering across connections |

Non-overlapping recorded operations are ordered when at least one writes. For overlapping writes, lock contention is inferred from shared values and fast durations of the same SQL shape. COMMIT/ROLLBACK affect the transaction's touched tables/values. Failed writes use conservative dependencies.

Tables are extracted lexically from SQL. Views and stored-procedure internals are unknown. Unclassified writes depend on the whole server. This does not reconstruct the database's internal execution order or transaction visibility.

## Lock waits

If replay dependencies and database locks form a cycle, dbtap releases its wait and counts that decision.

- PostgreSQL probes use `pg_blocking_pids`.
- MySQL probes use `performance_schema.data_lock_waits`, requiring performance_schema and SELECT permission.
- If probes are unavailable or `--no-lock-probe` is set, transaction state and elapsed time are used. The fallback grace period is twice the captured duration plus `--lock-grace-ms` (default 100 ms).

Dependency waits are bounded by `--causal-timeout-ms` (default 1,000 ms). Check released waits, timeouts, and send delay in the report.

## Multiple processes and hosts

Give every worker the same journals in the same order and synchronize clocks. `--shard K/N` uses zero-based K. `--shard-by conn` divides connections; `client` groups connections by recorded client host.

```bash
start_at=$(( $(date +%s) + 30 ))
./target/release/dbtap replay capture.dbtap --pg clone:5432 \
  --shard 0/2 --start-at "$start_at" --run-id trial1 --samples w0.jsonl --report r0.json
# Run the other worker with exactly the same start_at/run-id, --shard 1/2, and separate outputs.
```

Workers treat units assigned elsewhere as already complete. **Cross-worker dependencies are not synchronized.** Elastic resizing and restart/resume are unsupported. See [integrations](../integrations/README.md) for coordinated startup and validation of all shard results.
