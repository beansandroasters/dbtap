//! Replay recorded workloads.
//!
//! Recreate each recorded connection and send its requests on the relative schedule.
//! Timing alone can reverse write order when response times change;
//! serializing everything would discard the workload's concurrency.
//! Therefore relevant dependencies take precedence over time (see plan.rs).
//!
//! Target lock order can still differ and form waits that cannot finish.
//! wait_deps detects these cycles and allows progress.
//!
//! produce reconstructs journals into per-connection queues with read-ahead.
//! run_conn sends on schedule; report::Agg folds and discards individual outcomes.
//! Queued units are bounded, but connection metadata and partial requests are retained separately.

use dbtap_proto::extract::{Ev, Extractor};
use dbtap_core::journal::Proto;
use crate::myclient::{MyClient, MyParams};
use crate::net::{TlsConfig, TlsMode, host_of};
use crate::pgclient::{PgClient, PgParams};
use crate::plan::{ConnState, Planner, UnitPlan};
use crate::report::Agg;
use crate::timer::Timer;
use dbtap_core::unit::{ConnInfo, Outcome, Unit};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub struct Opts {
    pub pg_target: Option<String>,
    pub my_target: Option<String>,
    /// Recorded ip:port to target, for routing writers/readers to separate clones.
    pub map: HashMap<String, String>,
    /// Replay shard k of n.
    pub shard: Option<(usize, usize)>,
    /// Partition by recorded client host, keeping its connections on one worker.
    pub shard_by_client: bool,
    /// Shared UNIX start timestamp in seconds for distributed replay.
    pub start_at: Option<f64>,
    pub user: Option<String>,
    pub password: String,
    pub database: Option<String>,
    pub tls: TlsMode,
    pub tls_cfg: TlsConfig,
    /// Initialization SQL for session state predating capture.
    pub init_sql: Vec<String>,
    /// Schedule multiplier; 2.0 halves intervals.
    pub speed: f64,
    /// Enforce causal dependencies.
    pub causal: bool,
    /// Use shared values instead of entire tables for dependency granularity.
    pub by_row: bool,
    /// Maximum dependency wait; on expiration, send and count a timeout.
    pub causal_timeout: Duration,
    /// Fallback grace period for inferring lock reversals from prolonged response waits.
    /// Not used when target lock probes are available.
    pub lock_grace: Duration,
    /// Query target lock state to confirm dependency cycles.
    pub lock_probe: bool,
    /// Testing only: disable lock-order rule 2.
    pub no_lock_order: bool,
    /// Read this far ahead of scheduled sends.
    /// Requests longer than this window may be reconstructed too late to send on time.
    pub lookahead: Duration,
    /// Maximum queued units across all connections, not a byte limit.
    /// High traffic can hit this before the time-based read-ahead limit.
    pub max_queued: usize,
}

#[derive(Debug, Clone)]
pub enum Res {
    Ran {
        out: Outcome,
        latency_ns: u64,
        /// Actual send delay from schedule, including dependency waits.
        lag_ns: u64,
        /// Dependency-wait component of the delay.
        waited_ns: u64,
        order: Order,
    },
    /// Known to be unreplayable from the recording.
    Skipped,
    /// Execution failed, including connection failure.
    Failed(String),
    /// Assigned to another shard.
    Elsewhere,
}

/// Outcome of dependency ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Kept,
    /// Released a wait after detecting a target lock-order reversal.
    Inverted,
    /// Sent after the dependency wait limit expired.
    TimedOut,
}

/// Do not query target lock state until a response has been pending this long.
const PROBE_AFTER_NS: u64 = 3_000_000;

/// Blocker at a causal dependency timeout.
#[derive(Debug, Clone, Copy)]
pub struct Stall {
    pub blocker_conn: u64,
    /// Blocker was awaiting a target response and may be waiting on a DB lock.
    pub blocker_inflight: bool,
}

/// One unit's completion, sent to aggregation.
pub struct Done {
    /// Request bytes have been removed.
    pub unit: Unit,
    pub shape: Arc<str>,
    /// Read overlapped a conflicting recorded write.
    pub racy: bool,
    pub res: Res,
    pub stall: Option<Stall>,
    /// Present only after a send attempt; no invented latency for connection failures/skips.
    pub timing: Option<Timing>,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Timing {
    pub started_unix_ns: u64,
    pub latency_ns: u64,
    pub lag_ns: u64,
    pub waited_ns: u64,
}

enum Msg {
    Unit(Box<(Unit, UnitPlan)>),
    Close(u64),
}

enum Client {
    Pg(PgClient),
    My(MyClient),
}

impl Client {
    fn backend(&self) -> u64 {
        match self {
            Client::Pg(c) => c.backend_pid as u64,
            Client::My(c) => c.conn_id as u64,
        }
    }
}

/// Query which target connections are waiting for others' locks.
///
/// Timing alone cannot distinguish a dependency cycle from a slow operation.
/// A slow operation eventually completes; a cycle requires intervention.
/// Cycles mix local completion waits with target lock waits.
/// Join locally known dependencies to lock relationships queried from the target.
#[derive(Default)]
struct Probe {
    /// Per-target state; None means probes are unavailable.
    targets: tokio::sync::Mutex<HashMap<(Proto, String), Option<ProbeConn>>>,
    /// Per-target mapping from backend ID to replay connection.
    conns: std::sync::Mutex<HashMap<(Proto, String), HashMap<u64, Arc<ConnState>>>>,
}

struct ProbeConn {
    client: Client,
    at: Instant,
    /// Target backend ID to the backend blocking it.
    waits: HashMap<u64, Vec<u64>>,
}

/// Reuse a probe result for this interval.
const PROBE_TTL: Duration = Duration::from_millis(5);

/// MySQL (waiting connection ID, blocking connection ID) pairs.
const MYSQL_LOCK_WAITS: &str = "select wt.processlist_id, bt.processlist_id from performance_schema.data_lock_waits w \
     join performance_schema.threads wt on wt.thread_id = w.requesting_thread_id \
     join performance_schema.threads bt on bt.thread_id = w.blocking_thread_id";

impl Probe {
    fn register(&self, info: &ConnInfo, c: &Arc<ConnState>) {
        let pid = c.backend.load(Ordering::Relaxed);
        self.conns.lock().unwrap().entry((info.proto, info.server.clone())).or_default().insert(pid, c.clone());
    }

    fn unregister(&self, info: &ConnInfo, c: &ConnState) {
        if let Some(m) = self.conns.lock().unwrap().get_mut(&(info.proto, info.server.clone())) {
            m.remove(&c.backend.load(Ordering::Relaxed));
        }
    }

    /// Open the probe connection in advance, when replay connects,
    /// to avoid delaying resolution at the first dependency cycle.
    async fn ensure(&self, sh: &Shared, info: &ConnInfo) {
        let mut g = self.targets.lock().await;
        self.ensure_locked(&mut g, sh, info).await;
    }

    async fn ensure_locked(
        &self,
        g: &mut HashMap<(Proto, String), Option<ProbeConn>>,
        sh: &Shared,
        info: &ConnInfo,
    ) {
        let key = (info.proto, info.server.clone());
        if !g.contains_key(&key) {
            let c = match tokio::time::timeout(Duration::from_secs(5), sh.connect(info)).await {
                Ok(Ok(mut client)) => {
                    // Disabled MySQL performance_schema returns empty lock tables without error.
                    // Treat it as unavailable rather than as proof that no locks are waiting.
                    let usable = match &mut client {
                        Client::My(c) => match c.query_rows("select @@performance_schema").await {
                            Ok(rows) => rows.first().and_then(|r| r.first().cloned().flatten()).as_deref() == Some("1"),
                            Err(_) => false,
                        },
                        Client::Pg(_) => true,
                    };
                    if !usable {
                        eprintln!("  Lock probes unavailable (performance_schema disabled); using timing fallback");
                    }
                    usable.then(|| ProbeConn { client, at: Instant::now() - PROBE_TTL, waits: HashMap::new() })
                }
                _ => None,
            };
            g.insert(key, c);
        }
    }

    /// Whether me waiting for b forms a cycle; None if probing is unavailable.
    async fn cycle(&self, sh: &Shared, info: &ConnInfo, me: &Arc<ConnState>, b: Arc<ConnState>) -> Option<bool> {
        let key = (info.proto, info.server.clone());
        let mut g = self.targets.lock().await;
        self.ensure_locked(&mut g, sh, info).await;
        let pc = g.get_mut(&key)?.as_mut()?;
        let conns = self.conns.lock().unwrap().get(&key).cloned().unwrap_or_default();
        if pc.at.elapsed() >= PROBE_TTL {
            let now = sh.started.elapsed().as_nanos() as u64;
            // Probe only after a response has been pending long enough for a lock wait to appear.
            let pids: Vec<u64> = conns
                .iter()
                .filter(|(_, c)| {
                    let since = c.inflight_since.load(Ordering::Acquire);
                    since != 0 && now.saturating_sub(since - 1) > PROBE_AFTER_NS
                })
                .map(|(pid, _)| *pid)
                .collect();
            let found = if pids.is_empty() {
                Ok(HashMap::new())
            } else {
                match &mut pc.client {
                    Client::Pg(c) => {
                        let list: Vec<String> = pids.iter().map(|p| p.to_string()).collect();
                        let sql = format!("select p, pg_blocking_pids(p) from unnest(array[{}]::int[]) p", list.join(","));
                        c.query_rows(&sql).await.map(|rows| {
                            rows.iter()
                                .filter_map(|r| {
                                    let pid: u64 = r.first()?.as_ref()?.parse().ok()?;
                                    let by = r.get(1)?.as_ref()?.trim_matches(|c| c == '{' || c == '}');
                                    Some((pid, by.split(',').filter_map(|x| x.parse().ok()).collect::<Vec<u64>>()))
                                })
                                .collect::<HashMap<_, _>>()
                        })
                    }
                    // SELECT permission on performance_schema is sufficient.
                    Client::My(c) => c.query_rows(MYSQL_LOCK_WAITS).await.map(|rows| {
                        let mut m: HashMap<u64, Vec<u64>> = HashMap::new();
                        for r in &rows {
                            let pair = (|| Some((r.first()?.as_ref()?.parse().ok()?, r.get(1)?.as_ref()?.parse().ok()?)))();
                            if let Some((w, by)) = pair {
                                m.entry(w).or_default().push(by);
                            }
                        }
                        m
                    }),
                }
            };
            match found {
                Ok(m) => {
                    pc.waits = m;
                    pc.at = Instant::now();
                }
                Err(e) => {
                    // Unsupported or unauthorized probes fall back to timing afterwards.
                    eprintln!("  Target lock probes unavailable; using timing fallback: {e:#}");
                    g.insert(key, None);
                    return None;
                }
            }
        }
        // Follow blockers from b and check whether the path returns to me.
        let me_ptr = Arc::as_ptr(me);
        let mut seen: Vec<*const ConnState> = Vec::new();
        let mut stack = vec![b];
        while let Some(c) = stack.pop() {
            let p = Arc::as_ptr(&c);
            if p == me_ptr {
                return Some(true);
            }
            if seen.contains(&p) || seen.len() > 256 {
                continue;
            }
            seen.push(p);
            if c.inflight_since.load(Ordering::Acquire) != 0 {
                // For an in-flight request, follow its target lock holder.
                // If it is merely executing, the path ends and waiting can succeed.
                let by = pc.waits.get(&c.backend.load(Ordering::Relaxed)).into_iter().flatten();
                stack.extend(by.filter_map(|pid| conns.get(pid).cloned()));
            } else if let Some(next) = c.waiting_on.lock().unwrap().clone() {
                // Local dependency wait.
                stack.push(next);
            }
        }
        Some(false)
    }
}

struct Shared {
    opts: Opts,
    timer: Timer,
    /// Actual replay instant corresponding to the first recorded timestamp, base.
    t0: Instant,
    base: u64,
    started: Instant,
    started_unix_ns: u64,
    done_units: AtomicU64,
    /// Units distributed by the reader but not yet completed.
    queued: AtomicU64,
    /// Furthest recorded timestamp sent by any connection.
    pos: AtomicU64,
    stalls_shown: AtomicU64,
    probe: Probe,
    out: mpsc::Sender<Done>,
}

impl Shared {
    fn at(&self, ts: u64) -> Instant {
        self.t0 + Duration::from_nanos((ts.saturating_sub(self.base) as f64 / self.opts.speed) as u64)
    }

    async fn finish(&self, mut unit: Unit, plan: &UnitPlan, res: Res, stall: Option<Stall>, timing: Option<Timing>) {
        unit.req = Vec::new();
        let racy = plan.racy.as_ref().is_some_and(|c| c.load(Ordering::Relaxed));
        self.done_units.fetch_add(1, Ordering::Relaxed);
        let _ = self.out.send(Done { unit, shape: plan.shape.clone(), racy, res, stall, timing }).await;
        self.queued.fetch_sub(1, Ordering::Relaxed);
    }

    async fn connect(&self, info: &ConnInfo) -> Result<Client> {
        let o = &self.opts;
        let user = o.user.as_deref().or(info.user.as_deref());
        let db = o.database.as_deref().or(info.database.as_deref());
        let mapped = o.map.get(&info.server).map(|s| s.as_str());
        match info.proto {
            Proto::Postgres => {
                let addr = mapped
                    .or(o.pg_target.as_deref())
                    .ok_or_else(|| anyhow::anyhow!("No target for {} (use --map or --pg)", info.server))?;
                let user = user.unwrap_or("postgres");
                let p = PgParams {
                    addr,
                    user,
                    database: db.unwrap_or(user),
                    password: &o.password,
                    params: &info.params,
                    tls: o.tls,
                    tls_cfg: &o.tls_cfg,
                };
                let mut c = PgClient::connect(&p).await?;
                if info.mid_stream {
                    for sql in &o.init_sql {
                        c.query(sql).await?;
                    }
                }
                Ok(Client::Pg(c))
            }
            Proto::Mysql => {
                let addr = mapped
                    .or(o.my_target.as_deref())
                    .ok_or_else(|| anyhow::anyhow!("No target for {} (use --map or --mysql)", info.server))?;
                let p = MyParams {
                    addr,
                    user: user.unwrap_or("root"),
                    database: db,
                    password: &o.password,
                    caps: info.my_caps,
                    charset: info.my_charset,
                    tls: o.tls,
                    tls_cfg: &o.tls_cfg,
                };
                let mut c = MyClient::connect(&p).await?;
                if info.mid_stream {
                    if info.my_autocommit_off {
                        c.query("SET autocommit=0").await?;
                    }
                    for sql in &o.init_sql {
                        c.query(sql).await?;
                    }
                }
                Ok(Client::My(c))
            }
            Proto::Unknown => anyhow::bail!("Connection protocol is unknown"),
        }
    }

    /// Follow local dependencies from c until reaching a connection awaiting a target response;
    /// return that connection and its elapsed response wait in ns.
    fn inflight_end(&self, mut c: Arc<ConnState>) -> Option<(Arc<ConnState>, u64)> {
        let now = self.started.elapsed().as_nanos() as u64;
        for _ in 0..16 {
            let since = c.inflight_since.load(Ordering::Acquire);
            if since != 0 {
                return Some((c, now.saturating_sub(since - 1)));
            }
            let next = c.waiting_on.lock().unwrap().clone();
            c = next?;
        }
        None
    }

    /// Whether waiting for b cannot finish because of a cycle.
    ///
    /// Prefer queried target lock relationships to detect cycles.
    /// Otherwise infer a cycle when we hold a transaction and the peer exceeds
    /// twice its captured duration plus grace. Too little grace can mistake fsync
    /// or ordinary lock waits for cycles and release valid ordering prematurely.
    async fn deadlocked(&self, b: Arc<ConnState>, me: &Arc<ConnState>, info: &ConnInfo, holds: bool) -> bool {
        if self.opts.lock_probe && me.backend.load(Ordering::Relaxed) != 0 {
            if let Some(yes) = self.probe.cycle(self, info, me, b.clone()).await {
                return yes;
            }
        }
        let Some((f, waited)) = self.inflight_end(b) else { return false };
        let dur = f.inflight_dur.load(Ordering::Acquire);
        let grace = (2 * dur + self.opts.lock_grace.as_nanos() as u64).min(self.opts.causal_timeout.as_nanos() as u64);
        holds && waited > grace
    }

    /// Wait for operations that should already be complete.
    ///
    /// Reversed target lock order may make us wait for a peer that needs our lock.
    /// The local dependency and target lock wait then form a cycle.
    /// Periodically check deadlocked and release the wait if a cycle is found.
    async fn wait_deps(&self, plan: &UnitPlan, me: &Arc<ConnState>, info: &ConnInfo) -> (Order, Option<Stall>) {
        let deadline = tokio::time::Instant::now() + self.opts.causal_timeout;
        let mut result = (Order::Kept, None);
        // Wake periodically during long waits to check for cycles.
        // Probe early once the DB can expose a lock wait, then space checks farther apart.
        let mut pause = Duration::from_millis(4);
        'deps: for (tr, need) in &plan.deps {
            loop {
                let step = (tokio::time::Instant::now() + pause).min(deadline);
                pause = Duration::from_millis(10);
                if tr.wait(step, *need).await {
                    break;
                }
                // Blocker is the connection owning the earliest unfinished group member.
                let Some(b) = tr.blocker() else { break };
                *me.waiting_on.lock().unwrap() = Some(b.clone());
                let order = if tokio::time::Instant::now() >= deadline {
                    Order::TimedOut
                } else if self.deadlocked(b.clone(), me, info, plan.holds).await {
                    Order::Inverted
                } else {
                    continue;
                };
                let stall = Stall { blocker_conn: b.conn, blocker_inflight: b.inflight_since.load(Ordering::Acquire) != 0 };
                result = (order, Some(stall));
                break 'deps;
            }
        }
        *me.waiting_on.lock().unwrap() = None;
        result
    }

    /// The reader can update info with metadata inferred from mid-stream traffic.
    /// Read it immediately before connecting.
    async fn run_conn(
        self: Arc<Self>,
        info: Arc<std::sync::Mutex<ConnInfo>>,
        me: Arc<ConnState>,
        mut rx: mpsc::UnboundedReceiver<Msg>,
    ) {
        let first = info.lock().unwrap().clone();
        let info = move || info.lock().unwrap().clone();
        // Open mid-stream connections shortly before their first request.
        let mut pending = None;
        let open_at = if first.mid_stream {
            pending = rx.recv().await;
            match &pending {
                Some(Msg::Unit(b)) => b.0.t_start.saturating_sub(50_000_000),
                _ => first.t_open,
            }
        } else {
            first.t_open
        };
        self.timer.sleep_until(self.at(open_at)).await;
        let cinfo = info();
        let mut client = match tokio::time::timeout(Duration::from_secs(15), self.connect(&cinfo)).await {
            Ok(Ok(c)) => {
                me.backend.store(c.backend(), Ordering::Relaxed);
                self.probe.register(&cinfo, &me);
                if self.opts.causal && self.opts.lock_probe {
                    let (sh, info) = (self.clone(), cinfo.clone());
                    tokio::spawn(async move { sh.probe.ensure(&sh, &info).await });
                }
                Ok(c)
            }
            Ok(Err(e)) => Err(format!("{e:#}")),
            Err(_) => Err("Connection timed out".to_string()),
        };
        loop {
            let msg = match pending.take() {
                Some(m) => m,
                None => match rx.recv().await {
                    Some(m) => m,
                    None => break,
                },
            };
            let (u, plan) = match msg {
                Msg::Unit(b) => *b,
                Msg::Close(ts) => {
                    // Retain the recorded open interval because connection count is part of the workload.
                    self.timer.sleep_until(self.at(ts)).await;
                    break;
                }
            };
            if u.skip.is_some() {
                self.finish(u, &plan, Res::Skipped, None, None).await;
                continue;
            }
            let c = match &mut client {
                Ok(c) => c,
                Err(why) => {
                    // Connection failed or broke; remaining requests cannot run,
                    // but mark them complete to unblock other connections.
                    plan.complete();
                    let why = why.clone();
                    self.finish(u, &plan, Res::Failed(why), None, None).await;
                    continue;
                }
            };
            let sched = self.at(u.t_start);
            self.timer.sleep_until(sched).await;
            let before_wait = Instant::now();
            let (order, stall) =
                if self.opts.causal { self.wait_deps(&plan, &me, &cinfo).await } else { (Order::Kept, None) };
            if let (Order::TimedOut, Some(st)) = (order, &stall) {
                // Print the first few diagnostics immediately instead of waiting for replay to finish.
                if self.stalls_shown.fetch_add(1, Ordering::Relaxed) < 5 {
                    let sql: String = u.sql.chars().take(60).map(|c| if c == '\n' { ' ' } else { c }).collect();
                    eprintln!(
                        "  Causal wait timed out: c{} [{:.6}..{:.6}] {sql}\n    Blocker: connection c{} ({})",
                        u.conn,
                        u.t_start.saturating_sub(self.base) as f64 / 1e9,
                        u.t_end.saturating_sub(self.base) as f64 / 1e9,
                        st.blocker_conn,
                        if st.blocker_inflight { "sent, awaiting response" } else { "not yet sent" },
                    );
                }
            }
            let start = Instant::now();
            me.inflight_dur.store(u.t_end - u.t_start, Ordering::Release);
            me.inflight_since.store(start.duration_since(self.started).as_nanos() as u64 + 1, Ordering::Release);
            let r = match c {
                Client::Pg(c) => c.run(&u.req).await,
                Client::My(c) => c.run(&u.req, u.aux).await,
            };
            let latency_ns = start.elapsed().as_nanos() as u64;
            let lag_ns = start.saturating_duration_since(sched).as_nanos() as u64;
            let waited_ns = start.saturating_duration_since(before_wait).as_nanos() as u64;
            let timing = Some(Timing {
                started_unix_ns: self.started_unix_ns + start.duration_since(self.started).as_nanos() as u64,
                latency_ns, lag_ns, waited_ns,
            });
            me.inflight_since.store(0, Ordering::Release);
            plan.complete();
            self.pos.fetch_max(u.t_start, Ordering::Relaxed);
            match r {
                Ok(out) => {
                    self.finish(u, &plan, Res::Ran { out, latency_ns, lag_ns, waited_ns, order }, stall, timing).await;
                }
                Err(e) => {
                    let why = format!("{e:#}");
                    self.finish(u, &plan, Res::Failed(why.clone()), None, timing).await;
                    client = Err(why);
                }
            }
        }
        self.probe.unregister(&cinfo, &me);
        match client {
            Ok(Client::Pg(c)) => c.close().await,
            Ok(Client::My(c)) => c.close().await,
            Err(_) => {}
        }
    }
}

/// Recording metadata, finalized after reading completes.
pub struct Captured {
    pub source: String,
    pub t_first: u64,
    pub t_last: u64,
    /// Connections replayed by this worker.
    pub conns: usize,
}

/// Dedicated reader thread distributes reconstructed units to connection tasks.
fn produce(mut ex: Extractor, sh: Arc<Shared>, rt: tokio::runtime::Handle) -> Result<Captured> {
    struct Handle {
        tx: Option<mpsc::UnboundedSender<Msg>>,
        state: Arc<ConnState>,
        info: Arc<std::sync::Mutex<ConnInfo>>,
    }
    let mut planner = Planner::new(sh.opts.by_row);
    planner.no_lock_order = sh.opts.no_lock_order;
    let mut conns: HashMap<u64, Handle> = HashMap::new();
    // Deterministic sharding uses only recorded encounter order on every worker.
    let mut seen = 0usize;
    let mut hosts: Vec<String> = Vec::new();
    let mut mine_conns = 0;
    let mut ev = Vec::new();
    let mut paced = 0u64;
    loop {
        let more = ex.step(&mut ev)?;
        // Wait when reading reaches the configured lead over scheduled sending.
        if ex.t_last > paced + 1_000_000 {
            paced = ex.t_last;
            if let Some(d) = sh.at(paced).checked_sub(sh.opts.lookahead).and_then(|t| t.checked_duration_since(Instant::now())) {
                std::thread::sleep(d);
            }
        }
        // Wait for replay if the queue is full; queued earlier work can release capacity.
        while sh.queued.load(Ordering::Relaxed) > 0 && sh.queued.load(Ordering::Relaxed) as usize + ev.len() > sh.opts.max_queued {
            std::thread::sleep(Duration::from_millis(1));
        }
        for e in ev.drain(..) {
            match e {
                Ev::Open(info) => {
                    planner.open(&info);
                    let slot = if sh.opts.shard_by_client {
                        let h = host_of(&info.client);
                        hosts.iter().position(|x| x == h).unwrap_or_else(|| {
                            hosts.push(h.to_string());
                            hosts.len() - 1
                        })
                    } else {
                        seen
                    };
                    seen += 1;
                    let conn = info.conn;
                    let state = ConnState::new(conn);
                    let info = Arc::new(std::sync::Mutex::new(info));
                    let mine = sh.opts.shard.is_none_or(|(k, n)| slot % n == k);
                    let tx = mine.then(|| {
                        mine_conns += 1;
                        let (tx, rx) = mpsc::unbounded_channel();
                        rt.spawn(sh.clone().run_conn(info.clone(), state.clone(), rx));
                        tx
                    });
                    conns.insert(conn, Handle { tx, state, info });
                }
                Ev::Info(info) => {
                    if let Some(h) = conns.get(&info.conn) {
                        *h.info.lock().unwrap() = info;
                    }
                }
                Ev::Unit(u) => {
                    let Some(h) = conns.get(&u.conn) else { continue };
                    let plan = planner.add(&u, &h.state);
                    sh.queued.fetch_add(1, Ordering::Relaxed);
                    match &h.tx {
                        Some(tx) => {
                            if let Err(e) = tx.send(Msg::Unit(Box::new((u, plan)))) {
                                // Receiver ended; mark completion so dependencies do not wait forever.
                                if let Msg::Unit(b) = e.0 {
                                    b.1.complete();
                                    rt.block_on(sh.finish(b.0, &b.1, Res::Failed("Connection task already ended".into()), None, None));
                                }
                            }
                        }
                        None => {
                            // Another worker owns this connection; mark complete locally.
                            // Cross-worker dependencies are not synchronized.
                            plan.complete();
                            rt.block_on(sh.finish(u, &plan, Res::Elsewhere, None, None));
                        }
                    }
                }
                Ev::Close { conn, ts } => {
                    planner.close(conn);
                    if let Some(tx) = conns.remove(&conn).and_then(|h| h.tx) {
                        let _ = tx.send(Msg::Close(ts));
                    }
                }
            }
        }
        if !more {
            break;
        }
    }
    Ok(Captured { source: ex.source.clone(), t_first: ex.t_first, t_last: ex.t_last, conns: mine_conns })
}

pub struct Finished {
    pub agg: Agg,
    pub captured: Captured,
    /// Actual wall-clock replay duration.
    pub wall: Duration,
}

pub async fn replay(paths: &[String], opts: Opts) -> Result<Finished> {
    replay_with_samples(paths, opts, None).await
}

pub async fn replay_with_samples(paths: &[String], opts: Opts, mut samples: Option<crate::samples::Writer>) -> Result<Finished> {
    anyhow::ensure!(opts.speed.is_finite() && opts.speed > 0.0, "speed must be finite and positive");
    anyhow::ensure!(opts.shard.is_none_or(|(k, n)| n > 0 && k < n), "Invalid shard");
    let ex = Extractor::open(paths)?;
    let (out, mut results) = mpsc::channel::<Done>(4096);
    let t0 = match opts.start_at {
        // Map the wall-clock start time to this process's monotonic clock.
        Some(at) => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs_f64();
            anyhow::ensure!(at.is_finite() && at <= now + 86400.0, "--start-at must be finite and no more than 24 hours ahead");
            if at < now {
                anyhow::bail!("--start-at is in the past ({:.1} seconds ago)", now - at);
            }
            Instant::now() + Duration::from_secs_f64(at - now)
        }
        None => Instant::now() + Duration::from_millis(300),
    };
    let sh = Arc::new(Shared {
        opts,
        timer: Timer::new(),
        t0,
        base: ex.t_first,
        started: Instant::now(),
        started_unix_ns: dbtap_core::journal::now_ns(),
        done_units: AtomicU64::new(0),
        queued: AtomicU64::new(0),
        pos: AtomicU64::new(ex.t_first),
        stalls_shown: AtomicU64::new(0),
        probe: Probe::default(),
        out,
    });
    let base = ex.t_first;
    let started = sh.started;

    // Fold incoming results and discard individual units.
    let collect = tokio::spawn(async move {
        let mut agg = Agg::new(base);
        let mut error = None;
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            let write = tokio::select! {
                next = results.recv() => {
                    let Some(d) = next else { break };
                    agg.add(&d);
                    samples.as_mut().map_or(Ok(()), |w| w.add(&d))
                }
                _ = tick.tick() => samples.as_mut().map_or(Ok(()), |w| w.flush()),
            };
            if let Err(e) = write {
                // Preserve output errors; drain in-flight transactions before returning the error.
                error = Some(e);
                samples = None;
            }
        }
        if let Some(e) = error { return Err(e); }
        Ok((agg, samples))
    });
    let progress = {
        let sh = sh.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            tick.tick().await;
            loop {
                tick.tick().await;
                let d = sh.done_units.load(Ordering::Relaxed);
                let pos = sh.pos.load(Ordering::Relaxed).saturating_sub(sh.base) as f64 / 1e9;
                eprintln!("  Replayed {d} units (recorded position {pos:.1} seconds)");
            }
        })
    };
    let captured = {
        let sh = sh.clone();
        let rt = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || produce(ex, sh, rt)).await
    };
    // Aggregation ends once all connection tasks holding Shared have finished.
    progress.abort();
    let _ = progress.await;
    drop(sh);
    let (agg, samples) = collect.await??;
    let captured = captured??;
    if let Some(w) = samples { w.finish()?; }
    Ok(Finished { agg, captured, wall: started.elapsed() })
}
