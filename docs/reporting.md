# Comparison and reports

English | [日本語](reporting.ja.md)

`dbtap replay ... --report report.json` prints a summary and writes aggregate JSON. `dbtap report report.json` displays it again. Normal reports contain SQL shapes and examples, so review them before sharing.

## Verdicts

| JSON verdict | Meaning |
|---|---|
| Match | All observed comparison fields match. Wire input can compare rows, affected rows, contents and errors; logs compare only the fields counted in `compared` |
| NonDeterministic | Contents differ for a statement using values such as time or randomness |
| Racy | A read overlapped a conflicting write in the recording; visibility is not determined by traffic alone |
| OrderOnly | The row multiset matches but order differs, often with no ORDER BY |
| ContentDiff / RowsDiff / AffectedDiff / ErrorDiff | A substantive difference in contents, returned rows, affected rows, or error status/code |

The exact serialized verdict keys are defined in [report.rs](../crates/dbtap-replay/src/report.rs). Check the report itself when writing automation.

A measured 6,401-unit wire run had 6,309 Match, 88 non-deterministic, and four overlapping reads. Those categories explain the comparison; they do not certify complete capture. A log-only Match proves agreement only on available fields.

## Timing

Response-time distributions use buckets about 3% wide, so quantiles have similar rounding. Capture measures at the network observation point; replay measures inside dbtap. Database logs also have different rounding and intervals. Interpret small differences in light of those boundaries.

**Lag** is the delay between scheduled and actual send time. Target responses, dependency waits, generator CPU/network, and output backpressure can all contribute. It does not measure DB CPU or I/O. A write that waited on a lock during recording may be held before sending during replay, shifting that interval into lag.

**Order wait** is time spent waiting for dependencies. A **lock reversal** means the target's lock order changed and dbtap stopped waiting to break a cycle. A **causal timeout** means the dependency remained unfinished at the configured limit (default one second). Nonzero timeouts require reviewing the blocked-unit details in stderr and the report.

For a measured run, captured/replayed p50 latency was 0.150/0.186 ms; lag p50/p95/max was 0.018/0.274/36.821 ms. Maximum order wait was 36.802 ms, explaining most of the maximum lag. These are example measurements, not latency targets.

## Exit codes and automated checks

**Exit code 0 from replay does not guarantee that every unit ran or matched.** Connection and execution failures can be reported in `failed`; skips are counted separately. A samples `end` record means processing completed, not that all requests succeeded.

| Field | Meaning |
|---|---|
| `ran`, `failed`, `skipped`, `elsewhere` | Executed, execution failure, unreplayable, assigned to another shard |
| `verdicts` | Counts by comparison category |
| `compared` | Number of units compared for error, rows, affected rows, content and duration |
| `latency_captured`, `latency_replayed` | Distributions for comparable measured durations |
| `lag`, `order_wait` | Send delay and dependency wait |

For an automated gate, define which verdicts are acceptable for your workload, require the intended units to run, inspect capture/import omissions, and **directly compare final data** using stable business keys. Restore the target before each repeat. The local test scripts demonstrate this pattern.

An expected database error can be Match while `request_success` is false. Locust/JMeter/k6 failure rates count actual DB/transport errors and therefore differ from replay agreement rates.

`dbtap report a.json b.json` adds reports without validating run identity or duplicate shards. For strict merging of a distributed run, use the [samples converter](../integrations/README.md), which requires a common run-id and a complete, non-overlapping shard set. `inspect --jsonl` includes SQL and values; `--samples` is the appropriate input for the load-tool converters.
