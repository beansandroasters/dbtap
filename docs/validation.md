# Measurements and validation

English | [日本語](validation.ja.md)

These are measurements under the stated conditions, not maximum-capacity or complete-reproduction guarantees. SQL units and transactions per second (TPS) are different measures. Final business data is compared directly; concurrent execution can change generated IDs.

## Validated scope

| Check | Environment/result |
|---|---|
| Build/unit tests | Linux x86_64, Rust 1.93.0; 84 Rust, 4 Python export, 8 publication/script tests |
| Wire capture/replay | PG/MySQL on one host, 1,450 units, no execution failures/skips, final data and IDs matched |
| Locust 2.47.0 | Local and two workers on one host, 1,450 each; final CSV counts, data and generated IDs matched |
| JMeter 5.6.3 | HTML generated from 1,450 JTL samples; 24 DB errors |
| k6 JSON | 1,450 exported; k6-web-dashboard v0.8.1 HTML has EOF loss and reports 1,341 |
| TLS | Both engines accept trusted CA/hostname and reject untrusted CA/wrong hostname before SQL |
| Log regression | 72 PG / 56 MySQL executions matched traffic and final data |

[Locust 2.47.0 evidence](locust-validation-20261115.json), [JMeter/k6 and earlier measurements](loadtools-validation-20261114.json), [security review](security.md), [reproduction](../e2e/README.md). Multi-instance Locust, maximum generator capacity, and actual RDS/Aurora log replay are unvalidated.


The publication-candidate round trip replayed 6,401 wire units with zero capture loss, failures, or skips and matching business data. Generated IDs differed in reference checks. PG log 72 / MySQL log 56 executions matched traffic and final state. See `publication_regression` in the [evidence](security-validation-20261114.json).

## Database log recovery and timing

Measured on 2026-11-14 with PostgreSQL **17.12** and MySQL **8.4.13** on the same 8-vCPU host. Each used six connections and 120 operations, including transfers, reads, errors, and prepared execution. All reference wire captures lost zero bytes. [Raw measurements and calculations](log-validation-20261114.json).

| Workload | Wire units | Wire SQL executions | Log executions matched | Replayable | Final state |
|---|---:|---:|---:|---:|---|
| PostgreSQL without COPY | 2,742 | 2,664 | 2,664 (100%) | 2,664 | Matched |
| PostgreSQL with COPY | 2,741 | 2,664 | 2,664 (100%) | 2,643 (99.21%) | Only bulk lacked 420 rows |
| MySQL | 3,660 | 1,942 | 1,942 (100%) | 1,942 | Matched |

Final state covers accounts balances, orders business columns, and PG bulk. Concurrent INSERT IDs are separate reference values. PG without COPY includes 105 units with no execution and 27 with multiple executions; MySQL includes 1,718 non-SQL commands.

Matching follows session order, using SQL/parameters for PG and SQL shape/value keys for MySQL. MySQL value keys do not preserve parameter positions, so this alone cannot prove semantic equivalence for arbitrary input. The 100% figures apply to this workload. PG logged 35 errors without duration; MySQL retained error numbers for 57 executions.

The following differences are **log minus wire**. Negative means the log timestamp is earlier. Same-host measurement excludes inter-host clock skew. PG compares 2,575 single-execution, known-duration units without COPY; MySQL compares 1,942.

| Difference (ms) | p50 | p95 | Min / max |
|---|---:|---:|---:|
| PG start | -0.366 | +0.145 | -0.957 / +2.730 |
| PG end | -0.586 | -0.113 | -5.173 / -0.053 |
| MySQL start | +0.066 | +2.768 | +0.032 / +14.720 |
| MySQL end | -0.022 | +0.032 | -10.003 / +0.853 |

Database execution time differs from network observation time. PG millisecond rounding, separate parse/bind work, internal waits, and response transmission contribute. Do not treat log timestamps as equivalent to wire precision.

| Log size | Selected sessions, uncompressed | Per SQL execution | Imported journal |
|---|---:|---:|---:|
| PG without COPY | 1,237,721 B | 464.6 B | 63,385 B |
| MySQL | 2,113,852 B | 1,088.5 B | 63,880 B |

Sizes include parse/bind and administrative commands and depend on SQL length/prepared usage.

### Source overhead from logging

PostgreSQL 17.12, pgbench TPC-B-like workload, 16 connections, prepared mode, scale 10. After a 30-second warmup, three alternating off/on pairs ran for 30 seconds each. DB and generator shared the 8-vCPU host. No other benchmark/build ran concurrently, but all other host activity was not controlled.

| Pair | Logging off TPS | Logging on TPS | CSV bytes added while on |
|---|---:|---:|---:|
| 1 | 3,414.1 | 3,587.5 | 448,460,654 |
| 2 | 3,242.0 | 3,191.3 | 399,475,757 |
| 3 | 3,625.7 | 3,221.2 | 404,059,695 |
| Mean | 3,427.3 | 3,333.3 | — |

Mean change was **-2.74%**, with substantial variation between pairs; this is not a constant overhead estimate. CSV grew **about 4,167–4,182 B/transaction, 13.3–14.9 MB/s**, including connection/disconnection and parse/bind/execute. Off runs added zero CSV bytes. Slower log storage can cause a larger effect.

`e2e/logging_bench.py` reproduces the procedure. All six completed outputs/settings/calculations are under `logging_benchmark` in the [JSON](log-validation-20261114.json).

## Wire-path performance

One 8-vCPU EC2 host ran Docker DBs, the generator, and dbtap. See [test instructions](../e2e/README.md).

**Mixed workload:** PG17/MySQL8.4, six connections each, transfers, reads, unique violations, non-deterministic SQL, COPY, pipelines, prepared statements; roughly 10 seconds/6,401 units, four runs at defaults.

| Item | Result |
|---|---|
| Capture loss | 0 bytes |
| Comparison | 98.6% Match, 1.4% non-deterministic; 0–3 overlapping reads; 0 substantive differences |
| Lock reversals / timeouts | 0–1 reversals resolved by probes; 0 timeouts |
| Send lag | p50 0.02 ms, p95 0.07–0.15 ms; table mode p95 0.1–0.5 ms |
| Final data | Matched except generated IDs; see [limitations](../README.md#limitations) |

Mid-stream-only capture, 4x replay (MySQL over TLS), and two journals/two replay processes also matched final business data. VXLAN wrapping reproduced the same 6,401 units through both file and live capture.

See [authentication support](../SECURITY.md). MySQL connections using query attributes cannot replay to a target such as MariaDB that lacks that capability; dbtap reports the incompatibility.

**pgbench:** 32 connections, prepared mode, scale 10, heavy contention on ten branch rows.

| Item | Result |
|---|---|
| Wire-capture source overhead | Mean 4,166 TPS without capture / 4,162 with capture; three alternating runs each, within variation |
| Capture CPU | 0.41 CPU seconds for 10 seconds/630,000 packets/27.6 MB, about 4% of one core; zero loss |
| inspect | 30 seconds/727,200 units in 2.7 seconds; peak memory 6.7 MB |
| Replay memory | Same recording: table 164 MB, row 269 MB peak; depends on read-ahead, connections and unit size, not a global limit |
| Replay CPU | 10 seconds/319,352 units: about 14 CPU seconds (user 6.1 / sys 8.3) |

A saturated 10-second recording (4,568 TPS/319,352 units) was replayed twice per policy, alternating policies. Every run had zero substantive differences/reversals and matched final data. pgbench updates are additive, so final state can match even when ordering differs. Other time-mode recordings produced 26–120 overlapping-read verdicts.

| Order | Replay duration | Difference from 10.0-second recording |
|---|---|---|
| table | 12.6 / 12.8 s | +26–28% |
| row | 11.9 / 11.7 s | +16–19% |
| time | 11.0 / 11.0 s | +9% |

## AWS wire validation

Measured 2026-11-13 in a private Tokyo VPC without IGW/NAT: Aurora PostgreSQL 16.15 db.r6g.large, RDS MySQL 8.0.46 db.m6g.large, c6i.xlarge generator/replay host, c6i.large mirror receiver.

| Check | Result |
|---|---|
| DB ENIs as mirror sources | Sessions created for both Aurora and RDS MySQL |
| Mirrored vs direct capture | Identical in all three trials; read load about 29,000 transactions/s: 467,239 packets/233,496 units; write load: 287,341 packets/143,387 units; zero loss |
| Large packets | Truncated unless client MTU reduced to 8951; see [capture](capture.md) |
| TLS replay | Aurora clone and MySQL point-in-time restore accepted `--tls require --tls-ca` with the RDS CA bundle |
| Final data | All eight Aurora checks matched; MySQL balances and order contents matched except generated IDs |

| Workload | Order | Comparison | Reversals | Lag p50 / p95 | Replay duration |
|---|---|---|---:|---|---|
| Saturated: pgbench 16 connections (961 TPS) + MySQL 8; 143,387 units | table | 0 substantive differences | 4 | 5.6 / 7.6 s | 28.2 s (recorded 20.1 s) |
| Rate-limited: pgbench 16 connections at 300/s; 62,642 units | table | All matched | 35 | 5.3 / 298 ms | 31.9 s (recorded 31.6 s) |
| Same recording, another clone | row | All matched | 0 | 0.04 / 2.8 ms | 31.9 s |

For rate-limited row replay, captured p50/p95/p99 was 0.133/3.31/5.57 ms; replay was 0.158/3.24/5.18 ms. Capture at the DB interface and replay at the client have different network measurement boundaries. Saturated row replay was not measured on AWS.

These measurements do not validate deployment of the complete current `aws/verify.yaml`. [AWS reports](../aws/results/) retain the measured aggregates.

References: [PG17 logging/CSV](https://www.postgresql.org/docs/17/runtime-config-logging.html), [MySQL slow log](https://docs.oracle.com/cd/E17952_01/mysql-8.4-en/slow-query-log.html), [variables](https://docs.oracle.com/cd/E17952_01/mysql-8.4-en/using-system-variables.html), [PG portal implementation](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/backend/tcop/postgres.c), [MySQL log implementation](https://github.com/mysql/mysql-server/blob/mysql-8.4.0/sql/log.cc).
