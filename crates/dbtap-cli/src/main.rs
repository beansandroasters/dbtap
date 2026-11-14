use dbtap_capture::{afpacket, pcap, tcp};
use dbtap_core::{journal, unit};
use dbtap_proto::extract;
use dbtap_replay::{net, replay, report};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use journal::Proto;

#[derive(Parser)]
#[command(name = "dbtap", version, about = "Record database workloads, replay their timing, and compare results")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum TlsArg {
    /// Disable TLS (isolated tests only)
    Disable,
    /// Use TLS when available; permit plaintext fallback
    Prefer,
    /// Require TLS and verify certificates
    Require,
}

impl From<TlsArg> for net::TlsMode {
    fn from(t: TlsArg) -> Self {
        match t {
            TlsArg::Disable => net::TlsMode::Disable,
            TlsArg::Prefer => net::TlsMode::Prefer,
            TlsArg::Require => net::TlsMode::Require,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OrderBy {
    Table,
    Row,
    Time,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ShardBy {
    Conn,
    Client,
}

#[derive(Subcommand)]
enum Cmd {
    /// Import database logs as a journal of reconstructed units
    ImportLogs {
        /// PostgreSQL 17 CSV log (UTF-8, log_statement=none)
        #[arg(long, required_unless_present = "mysql_slow", conflicts_with = "mysql_slow")]
        pg_csv: Option<String>,
        /// MySQL 8.4 FILE slow log (log_slow_extra=ON)
        #[arg(long, required_unless_present = "pg_csv")]
        mysql_slow: Option<String>,
        /// Recorded server host:port, used by --map and per-server dependency planning
        #[arg(long)]
        server: String,
        /// PostgreSQL database filter; MySQL initial database if the first use line is absent
        #[arg(long)]
        database: Option<String>,
        /// Only import sessions whose application_name starts with this prefix
        #[arg(long, requires = "pg_csv")]
        application_prefix: Option<String>,
        /// Filter by MySQL Thread_id (repeatable)
        #[arg(long, requires = "mysql_slow")]
        mysql_thread: Vec<u64>,
        /// Window for sorting log records by completion time, in milliseconds
        #[arg(long, default_value_t = 1000)]
        sort_window_ms: u64,
        #[arg(short, long)]
        out: String,
    },
    /// Capture traffic into a journal
    Capture {
        /// Read pcap/pcapng (`-` for stdin); omit for live capture
        #[arg(long)]
        pcap: Option<String>,
        /// Live capture interface; omit to capture all interfaces
        #[arg(long)]
        iface: Option<String>,
        /// Also accept VXLAN traffic on UDP 4789, for VPC Traffic Mirroring receivers
        #[arg(long)]
        vxlan: bool,
        /// Disable promiscuous mode (enabled by default when an interface is specified)
        #[arg(long)]
        no_promisc: bool,
        /// Shared kernel ring size in MiB
        #[arg(long, default_value_t = 64)]
        ring_mb: usize,
        /// Stop live capture after this many seconds
        #[arg(long)]
        duration: Option<u64>,
        /// Port to interpret as PostgreSQL (repeatable)
        #[arg(long = "pg-port")]
        pg_port: Vec<u16>,
        /// Port to interpret as MySQL (repeatable)
        #[arg(long = "mysql-port")]
        mysql_port: Vec<u16>,
        /// New output journal path
        #[arg(short, long)]
        out: String,
    },
    /// Replay journals against a target and compare recorded results
    Replay {
        /// Journals to merge into one recording, such as captures from multiple client hosts
        #[arg(required = true)]
        journal: Vec<String>,
        /// Default PostgreSQL target host:port for servers not routed by --map
        #[arg(long)]
        pg: Option<String>,
        /// Default MySQL target host:port for servers not routed by --map
        #[arg(long)]
        mysql: Option<String>,
        /// Per-server route: `recorded-ip:port=target-host:port` (repeatable).
        /// Use separate writer/reader targets; inspect lists the recorded servers
        #[arg(long = "map")]
        map: Vec<String>,
        /// Replay shard K of N (`K/N`, with zero-based K)
        #[arg(long)]
        shard: Option<String>,
        /// Partition by connection, or group connections by recorded client host
        /// so that one host's connections stay on the same worker
        #[arg(long, value_enum, default_value = "conn")]
        shard_by: ShardBy,
        /// UNIX timestamp in seconds for the first request, shared across workers
        #[arg(long)]
        start_at: Option<f64>,
        /// Read-ahead window in seconds; requests longer than this may be sent late
        #[arg(long, default_value_t = 10.0)]
        lookahead: f64,
        /// Maximum queued units across all connections; memory also depends on unit size
        #[arg(long, default_value_t = 100_000)]
        max_queued: usize,
        /// Target user; defaults to the recorded user
        #[arg(long)]
        user: Option<String>,
        /// Target password; prefer the DBTAP_PASSWORD environment variable
        #[arg(long, env = "DBTAP_PASSWORD", hide_env_values = true, default_value = "")]
        password: String,
        /// Target database; defaults to the recorded database
        #[arg(long)]
        database: Option<String>,
        #[arg(long, value_enum, default_value = "require")]
        tls: TlsArg,
        /// Additional trusted CA certificates in PEM format, such as the RDS CA bundle
        #[arg(long)]
        tls_ca: Option<String>,
        /// Skip certificate verification (isolated tests only)
        #[arg(long)]
        tls_insecure: bool,
        /// SQL to run after connecting (repeatable), for session settings predating capture
        #[arg(long = "init-sql")]
        init_sql: Vec<String>,
        /// Schedule speed multiplier; 2 halves scheduled intervals, not guaranteed TPS
        #[arg(long, default_value_t = 1.0)]
        speed: f64,
        /// Dependency policy.
        /// row: order operations sharing bind/literal values (default). Statements without values
        /// conflict with the whole table; range predicates may not preserve dependencies.
        /// table: order all operations touching the same table. More conservative dependencies
        /// can propagate one connection's delay across the workload.
        /// time: follow the schedule without cross-connection dependencies
        #[arg(long, value_enum, default_value = "row")]
        order: OrderBy,
        /// Alias for --order time
        #[arg(long)]
        no_causal: bool,
        /// Maximum dependency wait in milliseconds
        #[arg(long, default_value_t = 1000)]
        causal_timeout_ms: u64,
        /// Grace period in milliseconds when target lock probes are unavailable.
        /// After the fallback wait, allow progress if a lock-order reversal is inferred
        #[arg(long, default_value_t = 100)]
        lock_grace_ms: u64,
        /// Infer lock reversals from timing without querying target lock state
        #[arg(long)]
        no_lock_probe: bool,
        /// Testing only: disable inferred lock ordering to provoke reversals
        #[arg(long, hide = true)]
        debug_no_lock_order: bool,
        /// Write aggregate JSON to a new file
        #[arg(long)]
        report: Option<String>,
        /// Write measured time-series JSONL without SQL or endpoints to a new file
        #[arg(long)]
        samples: Option<String>,
        /// Identifier shared by one distributed run; generated if omitted
        #[arg(long, requires = "samples")]
        run_id: Option<String>,
        /// Number of SQL shapes to show
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// Merge and display aggregate JSON reports from replay workers
    Report {
        #[arg(required = true)]
        reports: Vec<String>,
        /// Write merged JSON to a new file
        #[arg(long)]
        out: Option<String>,
        /// Number of SQL shapes to show
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// Summarize journal contents
    Inspect {
        #[arg(required = true)]
        journal: Vec<String>,
        /// Display one line per unit
        #[arg(long)]
        units: bool,
        /// Emit connection metadata and units as JSON Lines, without the summary
        #[arg(long, conflicts_with = "units")]
        jsonl: bool,
        /// Number of SQL shapes to show
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
}

fn ports(pg: &[u16], my: &[u16]) -> Result<Vec<(u16, Proto)>> {
    let mut v: Vec<(u16, Proto)> = pg.iter().map(|p| (*p, Proto::Postgres)).collect();
    v.extend(my.iter().map(|p| (*p, Proto::Mysql)));
    if v.is_empty() {
        bail!("Specify at least one --pg-port or --mysql-port");
    }
    Ok(v)
}

fn capture_pcap(path: &str, ports: Vec<(u16, Proto)>, out: &str) -> Result<()> {
    let input: Box<dyn std::io::Read> = if path == "-" {
        Box::new(std::io::stdin().lock())
    } else {
        Box::new(std::fs::File::open(path).with_context(|| format!("open {path}"))?)
    };
    let mut pc = pcap::Pcap::new(input)?;
    let w = journal::Writer::create(out, &format!("pcap:{path}"))?;
    let mut re = tcp::Reassembler::new(ports, w);
    let mut last = 0;
    while let Some((ts, link, frame)) = pc.next()? {
        re.packet(ts, link, frame);
        last = ts;
    }
    re.end(last);
    let st = re.stats.clone();
    re.sink.finish()?;
    eprintln!("{}", st.summary());
    Ok(())
}

fn inspect(paths: &[String], show_units: bool, jsonl: bool, top: usize) -> Result<()> {
    use extract::{Ev, Extractor};
    use std::cmp::Reverse;
    use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap};
    let mut ex = Extractor::open(paths)?;
    let t0 = ex.t_first;
    let proto_name = |p: Proto| match p {
        Proto::Postgres => "PostgreSQL",
        Proto::Mysql => "MySQL",
        Proto::Unknown => "Unknown",
    };
    // Per-server counts distinguish writers/readers and provide the left side of --map.
    let mut servers: BTreeMap<(String, &str), (u64, u64, u64)> = BTreeMap::new();
    let mut conn_server: HashMap<u64, (String, &str)> = HashMap::new();
    let (mut conns, mut mid, mut enc, mut broken) = (0u64, 0u64, 0u64, 0u64);
    let mut why: BTreeMap<String, u64> = BTreeMap::new();
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    let (mut total, mut writes, mut errs) = (0u64, 0u64, 0u64);
    let mut skips: HashMap<unit::Skip, u64> = HashMap::new();
    let mut by: HashMap<String, (u64, u64, u64)> = HashMap::new();
    // Units arrive by completion; buffer briefly to display them by start time.
    let mut lines: BinaryHeap<Reverse<(u64, u64, String)>> = BinaryHeap::new();
    const HOLD_NS: u64 = 10_000_000_000;
    let mut ev = Vec::new();
    loop {
        let more = ex.step(&mut ev)?;
        for e in ev.drain(..) {
            if jsonl {
                let value = match &e {
                    Ev::Open(i) => serde_json::json!({"type": "open", "info": i}),
                    Ev::Info(i) => serde_json::json!({"type": "info", "info": i}),
                    Ev::Unit(u) => serde_json::json!({"type": "unit", "unit": u, "shape": unit::fingerprint(&u.sql)}),
                    Ev::Close { conn, ts } => serde_json::json!({"type": "close", "conn": conn, "ts": ts}),
                };
                println!("{}", serde_json::to_string(&value)?);
                continue;
            }
            match e {
                Ev::Open(i) => {
                    conn_server.insert(i.conn, (i.server.clone(), proto_name(i.proto)));
                }
                Ev::Info(_) => {}
                Ev::Close { conn, .. } => {
                    conn_server.remove(&conn);
                }
                Ev::Unit(u) => {
                    total += 1;
                    writes += u.write as u64;
                    errs += u.out.err.is_some() as u64;
                    if let Some(s) = u.skip {
                        *skips.entry(s).or_default() += 1;
                    }
                    if let Some(k) = conn_server.get(&u.conn) {
                        let e = servers.entry(k.clone()).or_default();
                        e.1 += 1;
                        e.2 += u.write as u64;
                    }
                    if show_units {
                        let sql: String = u.sql.chars().take(100).map(|c| if c == '\n' { ' ' } else { c }).collect();
                        let line = format!(
                            "{:>12.6} c{:<4} {:>9}ms rows={:<5} aff={:<4} {}{}{} {}",
                            u.t_start.saturating_sub(t0) as f64 / 1e9,
                            u.conn,
                            if u.observed.duration { format!("{:.3}", (u.t_end - u.t_start) as f64 / 1e6) } else { "?".into() },
                            if u.observed.rows { u.out.rows.to_string() } else { "?".into() },
                            if u.observed.affected { u.out.affected.to_string() } else { "?".into() },
                            if u.write { "W" } else { "-" },
                            if u.skip.is_some() { "S" } else { "-" },
                            u.out.err.as_deref().map(|e| format!(" err={e}")).unwrap_or_default(),
                            sql
                        );
                        lines.push(Reverse((u.t_start, total, line)));
                    } else {
                        let e = by.entry(unit::fingerprint(&u.sql)).or_default();
                        e.0 += 1;
                        if u.observed.duration {
                            e.1 += u.t_end - u.t_start;
                            e.2 += 1;
                        }
                    }
                }
            }
        }
        for c in ex.take_closed() {
            conns += 1;
            mid += c.mid_stream as u64;
            enc += c.encrypted as u64;
            if let Some(b) = &c.broken {
                broken += 1;
                *why.entry(b.clone()).or_default() += 1;
            }
            hosts.insert(net::host_of(&c.client).to_string());
            servers.entry((c.server.clone(), proto_name(c.proto))).or_default().0 += 1;
        }
        while lines.peek().is_some_and(|l| !more || l.0.0 + HOLD_NS < ex.t_last) {
            println!("{}", lines.pop().unwrap().0.2);
        }
        if !more {
            break;
        }
    }
    if jsonl { return Ok(()); }
    if show_units {
        println!();
    }
    println!("Source       : {}", ex.source);
    println!("Duration     : {:.3} seconds", ex.t_last.saturating_sub(ex.t_first) as f64 / 1e9);
    println!("Traffic      : {} bytes (lost {} bytes)", ex.wire_bytes, ex.lost_bytes);
    println!("Connections  : {conns} (mid-stream {mid} / TLS excluded {enc} / abandoned {broken})");
    for (w, k) in &why {
        println!("  - {w}: {k}");
    }
    println!("Clients      : {} hosts", hosts.len());
    println!("Servers      :");
    for ((addr, proto), (conns, units, writes)) in &servers {
        println!("  {addr:<24} {proto:<10} connections {conns:>5} / units {units:>8} / writes {writes:>8}");
    }
    let skipped: u64 = skips.values().sum();
    let pct = if total > 0 { 100.0 * (total - skipped) as f64 / total as f64 } else { 0.0 };
    println!("Units        : {total} (replayable {} = {pct:.1}%)", total - skipped);
    for (s, k) in &skips {
        let label = match s {
            unit::Skip::UnknownStatement => "References PREPARE before recording",
            unit::Skip::Interactive => "Interactive exchange requires further client input",
            unit::Skip::Incomplete => "Incomplete response",
            unit::Skip::LogDataMissing => "Log lacks request payload or parameters",
            unit::Skip::LogUnsupported => "Request cannot be reconstructed from log",
        };
        println!("  - {label}: {k}");
    }
    println!("  Writes {writes} / error responses {errs}");
    if show_units {
        return Ok(());
    }
    let mut v: Vec<_> = by.into_iter().collect();
    v.sort_by(|a, b| b.1.1.cmp(&a.1.1));
    println!("\nTop {top} by total duration (count / known durations / mean ms / SQL shape)");
    for (fp, (k, ns, known)) in v.into_iter().take(top) {
        let fp: String = fp.chars().take(110).collect();
        let mean = if known > 0 { format!("{:.3}", ns as f64 / known as f64 / 1e6) } else { "?".into() };
        println!("{k:>8} {known:>8} {mean:>10}  {fp}");
    }
    Ok(())
}

fn main() -> Result<()> {
    // Exit quietly when a pipe consumer such as `head` closes stdout.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    match Cli::parse().cmd {
        Cmd::ImportLogs { pg_csv, mysql_slow, server, database, application_prefix, mysql_thread, sort_window_ms, out } => {
            enum LogParser {
                Pg(dbtap_logs::pg::PgCsv<std::fs::File>),
                My(dbtap_logs::mysql::MysqlSlow<std::fs::File>),
            }
            let (path, format) = if let Some(p) = pg_csv { (p, "postgres-csv") } else { (mysql_slow.unwrap(), "mysql-slow") };
            let input = std::fs::File::open(&path).with_context(|| format!("open {path}"))?;
            let mut parser = if format == "postgres-csv" {
                LogParser::Pg(dbtap_logs::pg::PgCsv::new(input, dbtap_logs::pg::Options { server, database, application_prefix }))
            } else {
                LogParser::My(dbtap_logs::mysql::MysqlSlow::new(input, dbtap_logs::mysql::Options { server, database, thread_ids: mysql_thread }))
            };
            // Failed imports must not appear as finished journals; require new output files.
            let partial = format!("{out}.partial");
            anyhow::ensure!(!std::path::Path::new(&out).exists(), "Output already exists: {out}");
            let file = journal::create_private(&partial)?;
            let result = (|| -> Result<()> {
                let mut writer = None;
                loop {
                    let records = match &mut parser {
                        LogParser::Pg(p) => p.next()?,
                        LogParser::My(p) => p.next()?,
                    };
                    let Some(records) = records else { break };
                    for r in records {
                        if writer.is_none() {
                            let started = match &r {
                                journal::Record::Session { info, .. } => info.t_open,
                                _ => bail!("First log record lacks session metadata"),
                            };
                            writer = Some(dbtap_logs::OrderedWriter::new(
                                journal::Writer::new_at(&file, &format!("{format}:{path}"), started)?,
                                sort_window_ms.checked_mul(1_000_000).context("Sort window is too large")?,
                            ));
                        }
                        writer.as_mut().unwrap().push(r)?;
                    }
                }
                writer.context("No importable units")?.finish()
            })();
            drop(file);
            if let Err(e) = result {
                std::fs::remove_file(&partial).ok();
                return Err(e);
            }
            // Expose the finished file atomically on the same filesystem, without overwriting even in a race.
            std::fs::hard_link(&partial, &out)?;
            std::fs::remove_file(&partial)?;
            let stats = match parser {
                LogParser::Pg(p) => serde_json::to_string_pretty(&p.stats)?,
                LogParser::My(p) => serde_json::to_string_pretty(&p.stats)?,
            };
            println!("{stats}");
            Ok(())
        }
        Cmd::Capture { pcap, iface, vxlan, no_promisc, ring_mb, duration, pg_port, mysql_port, out } => {
            let ports = ports(&pg_port, &mysql_port)?;
            match pcap {
                Some(p) => capture_pcap(&p, ports, &out),
                None => afpacket::capture(&afpacket::LiveOpts {
                    iface: iface.as_deref(),
                    ports,
                    vxlan,
                    promisc: !no_promisc,
                    out: &out,
                    ring_mb,
                    duration,
                }),
            }
        }
        Cmd::Inspect { journal, units, jsonl, top } => inspect(&journal, units, jsonl, top),
        Cmd::Report { reports, out, top } => {
            let mut all = Vec::new();
            for p in &reports {
                let f = std::fs::File::open(p).with_context(|| format!("open {p}"))?;
                let r: report::Report =
                    serde_json::from_reader(std::io::BufReader::new(f)).with_context(|| format!("Cannot read {p}"))?;
                all.push(r);
            }
            let rep = report::merge(all).context("No reports supplied")?;
            report::print(&rep, top);
            if let Some(path) = out {
                journal::write_private(&path, &serde_json::to_vec_pretty(&rep)?)?;
            }
            Ok(())
        }
        Cmd::Replay {
            journal,
            pg,
            mysql,
            map,
            shard,
            shard_by,
            start_at,
            lookahead,
            max_queued,
            user,
            password,
            database,
            tls,
            tls_ca,
            tls_insecure,
            init_sql,
            speed,
            order,
            no_causal,
            causal_timeout_ms,
            lock_grace_ms,
            no_lock_probe,
            debug_no_lock_order,
            report,
            samples,
            run_id,
            top,
        } => {
            if pg.is_none() && mysql.is_none() && map.is_empty() {
                bail!("Specify a target with --pg, --mysql, or --map");
            }
            let map = map
                .iter()
                .map(|m| m.split_once('=').map(|(a, b)| (a.to_string(), b.to_string())))
                .collect::<Option<std::collections::HashMap<_, _>>>()
                .context("--map must be `recorded-ip:port=target-host:port`")?;
            let shard = match shard.as_deref().map(|s| s.split_once('/')) {
                None => None,
                Some(Some((k, n))) => {
                    let (k, n): (usize, usize) = (k.parse()?, n.parse()?);
                    if n == 0 || k >= n {
                        bail!("--shard requires K/N with 0 <= K < N");
                    }
                    Some((k, n))
                }
                Some(None) => bail!("--shard must be K/N"),
            };
            if !speed.is_finite() || speed <= 0.0 {
                bail!("--speed must be finite and positive");
            }
            if !lookahead.is_finite() || lookahead <= 0.0 || lookahead > 86400.0 {
                bail!("--lookahead must be greater than 0 and at most 86400 seconds");
            }
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let opts = replay::Opts {
                pg_target: pg,
                my_target: mysql,
                map,
                shard,
                shard_by_client: shard_by == ShardBy::Client,
                start_at,
                user,
                password,
                database,
                tls: tls.into(),
                tls_cfg: net::TlsConfig::new(tls_ca.as_deref(), tls_insecure)?,
                init_sql,
                speed,
                causal: !no_causal && order != OrderBy::Time,
                by_row: order == OrderBy::Row,
                causal_timeout: std::time::Duration::from_millis(causal_timeout_ms),
                lock_grace: std::time::Duration::from_millis(lock_grace_ms),
                lock_probe: !no_lock_probe,
                no_lock_order: debug_no_lock_order,
                lookahead: std::time::Duration::from_secs_f64(lookahead),
                max_queued: max_queued.max(1),
            };
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            let samples = samples.map(|path| {
                let id = run_id.unwrap_or_else(|| format!("{}-{}", dbtap_core::journal::now_ns(), std::process::id()));
                dbtap_replay::samples::Writer::create(&path, &id, shard)
            }).transpose()?;
            let fin = rt.block_on(replay::replay_with_samples(&journal, opts, samples))?;
            let meta = report::Meta {
                source: fin.captured.source.clone(),
                captured_seconds: fin.captured.t_last.saturating_sub(fin.captured.t_first) as f64 / 1e9,
                replayed_seconds: fin.wall.as_secs_f64(),
                speed,
                connections: fin.captured.conns,
            };
            let rep = report::build(fin.agg, meta);
            report::print(&rep, top);
            if let Some(path) = report {
                journal::write_private(&path, &serde_json::to_vec_pretty(&rep)?)?;
            }
            Ok(())
        }
    }
}
