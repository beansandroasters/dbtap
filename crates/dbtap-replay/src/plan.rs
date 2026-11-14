//! Plan causal dependencies for replay.
//!
//! Two rules apply to operations on the same server/table:
//!
//!  1. If X completed before U started and either writes, finish X before sending U.
//!        This preserves the recorded non-overlap and possible visibility relationship.
//!  2. A write U inferred to have waited on locks follows earlier-completed writes
//!        that may have competed for the same rows.
//!        A competing earlier-completed write acquired the lock first;
//!         sending the waiter first could reverse target lock order and later results.
//!        - Infer waiting by comparing duration to fast executions of the same SQL shape.
//!        - Infer competition from shared bind/literal values.
//!            Equal WHERE id values suggest the same row, but this is a heuristic.
//!            Unknown values conservatively conflict with every row.
//!        - Failed writes follow all earlier-completed writes on the table even without inferred waiting.
//!            Their retained locks may conflict with writes having different values.
//!
//! Do not serialize overlapping writes with no inferred wait, preserving independent concurrency.
//!
//! Units arrive in completion order. Increment per-group completion ranks
//! so planning does not require loading the entire recording first.

use crate::deps::Annotator;
use dbtap_core::journal::Proto;
use dbtap_core::unit::{ConnInfo, Unit, fingerprint};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use xxhash_rust::xxh3::xxh3_64;

/// Runtime connection state used to identify waits that cannot make progress.
pub struct ConnState {
    pub conn: u64,
    /// Zero if not awaiting a response; otherwise send time in ns since replay start plus one.
    pub inflight_since: AtomicU64,
    /// Captured duration of the in-flight request, in ns.
    pub inflight_dur: AtomicU64,
    /// Connection owning the dependency currently awaited.
    pub waiting_on: Mutex<Option<Arc<ConnState>>>,
    /// Target backend PID/connection ID; zero until known.
    pub backend: AtomicU64,
}

impl ConnState {
    pub fn new(conn: u64) -> Arc<Self> {
        Arc::new(ConnState {
            conn,
            inflight_since: AtomicU64::new(0),
            inflight_dur: AtomicU64::new(0),
            waiting_on: Mutex::new(None),
            backend: AtomicU64::new(0),
        })
    }
}

struct Slot {
    done: bool,
    conn: Arc<ConnState>,
}

struct Inner {
    /// Rank of slots[0]; all earlier ranks are complete.
    base: usize,
    slots: VecDeque<Slot>,
    /// Waiters: required completion count and notification channel.
    waiters: Vec<(usize, tokio::sync::oneshot::Sender<()>)>,
}

/// Track group completion by recorded completion rank.
/// mark counts the contiguous completed prefix; waiters require a particular count.
/// Retain only entries beyond that completed prefix.
pub struct Tracker {
    mark: AtomicUsize,
    inner: Mutex<Inner>,
}

impl Tracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Tracker {
            mark: AtomicUsize::new(0),
            inner: Mutex::new(Inner { base: 0, slots: VecDeque::new(), waiters: Vec::new() }),
        })
    }

    /// Add a group member and return its rank; conn owns its replay.
    pub fn register(&self, conn: &Arc<ConnState>) -> usize {
        let mut g = self.inner.lock().unwrap();
        g.slots.push_back(Slot { done: false, conn: conn.clone() });
        g.base + g.slots.len() - 1
    }

    pub fn complete(&self, rank: usize) {
        let mut g = self.inner.lock().unwrap();
        let Some(k) = rank.checked_sub(g.base) else { return };
        let Some(slot) = g.slots.get_mut(k) else { return };
        slot.done = true;
        if k != 0 {
            // An earlier entry is incomplete, so mark cannot advance.
            return;
        }
        while g.slots.front().is_some_and(|s| s.done) {
            g.slots.pop_front();
            g.base += 1;
        }
        let m = g.base;
        self.mark.store(m, Ordering::Release);
        let mut k = 0;
        while k < g.waiters.len() {
            // Also remove expired waiters here.
            if g.waiters[k].0 <= m || g.waiters[k].1.is_closed() {
                let _ = g.waiters.swap_remove(k).1.send(());
            } else {
                k += 1;
            }
        }
    }

    pub fn mark(&self) -> usize {
        self.mark.load(Ordering::Acquire)
    }

    /// Wait for the first need members to finish; false on deadline.
    pub async fn wait(&self, deadline: tokio::time::Instant, need: usize) -> bool {
        if self.mark() >= need {
            return true;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut g = self.inner.lock().unwrap();
            // Recheck under the lock so completion just before registration is not missed.
            if g.base >= need {
                return true;
            }
            g.waiters.push((need, tx));
        }
        tokio::time::timeout_at(deadline, rx).await.is_ok()
    }

    /// Connection owning the earliest unfinished member.
    pub fn blocker(&self) -> Option<Arc<ConnState>> {
        self.inner.lock().unwrap().slots.front().map(|s| s.conn.clone())
    }
}

/// Rule 2 threshold: multiplier of fast duration for the same shape plus a margin.
const BLOCKED_FACTOR: u64 = 3;
const BLOCKED_SLACK_NS: u64 = 200_000;
/// Halve the duration histogram periodically to decay old observations.
const SHAPE_DECAY: u32 = 8192;
/// Maximum remembered SQL shapes; merge excess into one group.
const MAX_SHAPES: usize = 50_000;
/// Retained completion-time history; longer units conservatively wait for more predecessors.
const KEEP_NS: u64 = 120_000_000_000;
/// Keep shorter history for numerous per-value groups.
const KEEP_VAL_NS: u64 = 10_000_000_000;
const SWEEP_EVERY: u64 = 4096;

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
enum Key {
    /// All ordering-relevant operations on the server.
    All(u32),
    /// Writes with unknown tables.
    Global(u32),
    Write(u32),
    Read(u32),
    /// Lock-taking writes on the table, excluding COMMIT/ROLLBACK.
    Lock(u32),
    /// Such writes with unknown values.
    LockAny(u32),
    /// Such writes with a particular (table, value key).
    LockVal(u32, u64),
    /// Row mode: known-value writes/reads and unknown-value writes/reads.
    WriteVal(u32, u64),
    ReadVal(u32, u64),
    WriteAny(u32),
    ReadAny(u32),
}

impl Key {
    /// Per-value group, retired when unused to bound metadata growth.
    fn per_value(&self) -> bool {
        matches!(self, Key::LockVal(..) | Key::WriteVal(..) | Key::ReadVal(..))
    }
}

struct KeyState {
    tracker: Arc<Tracker>,
    server: u32,
    /// Rank of ends[0].
    first_rank: usize,
    /// Recorded completion timestamps in completion order.
    ends: VecDeque<u64>,
    /// Read-group overlap flags aligned with ends.
    cells: VecDeque<Arc<AtomicBool>>,
}

impl KeyState {
    /// Number of members completed in the recording before t.
    fn before(&self, t: u64) -> usize {
        self.first_rank + self.ends.partition_point(|e| *e < t)
    }

    fn count(&self) -> usize {
        self.first_rank + self.ends.len()
    }
}

struct Shape {
    text: Arc<str>,
    /// Duration histogram with two subdivisions per power of two.
    hist: [u32; 128],
    n: u32,
}

impl Shape {
    fn bucket(ns: u64) -> usize {
        if ns < 2 {
            return ns as usize;
        }
        let e = 63 - ns.leading_zeros() as usize;
        (e << 1) | ((ns >> (e - 1)) & 1) as usize
    }

    /// Lower bucket boundary.
    fn floor(b: usize) -> u64 {
        if b < 2 {
            return b as u64;
        }
        let e = b >> 1;
        (1u64 << e) | (((b & 1) as u64) << (e - 1))
    }

    /// Add a duration and return the fast tenth percentile.
    /// A tenth of uncontended executions keeps the baseline stable during frequent contention.
    fn add(&mut self, ns: u64) -> u64 {
        self.hist[Self::bucket(ns)] += 1;
        self.n += 1;
        if self.n >= SHAPE_DECAY {
            self.n = 0;
            for c in &mut self.hist {
                *c /= 2;
                self.n += *c;
            }
        }
        let rank = self.n / 10;
        let mut seen = 0;
        for (b, c) in self.hist.iter().enumerate() {
            seen += c;
            if seen > rank {
                return Self::floor(b);
            }
        }
        ns
    }
}

/// Replay metadata for one unit.
pub struct UnitPlan {
    /// Group to wait on and its required completed-prefix count.
    pub deps: Vec<(Arc<Tracker>, usize)>,
    /// Membership group and rank.
    pub completes: Vec<(Arc<Tracker>, usize)>,
    /// Connection was in a transaction immediately before this unit and may hold locks.
    pub holds: bool,
    /// SQL shape with literals normalized.
    pub shape: Arc<str>,
    /// Read overlapped another write on the same table in the recording.
    /// Traffic alone cannot establish visibility, so differences may be inherently ambiguous.
    /// This flag can be set later when an overlapping write completes.
    pub racy: Option<Arc<AtomicBool>>,
}

impl UnitPlan {
    /// Notify membership groups that replay completed or was deliberately skipped.
    pub fn complete(&self) {
        for (t, r) in &self.completes {
            t.complete(*r);
        }
    }
}

#[derive(Default)]
pub struct Planner {
    /// Apply rule 1 at value/row granularity.
    by_row: bool,
    /// Testing only: disable rule 2 to provoke and exercise lock reversal recovery.
    pub no_lock_order: bool,
    ann: Annotator,
    servers: HashMap<(Proto, String), u32>,
    server_of: HashMap<u64, u32>,
    in_tx: HashMap<u64, bool>,
    keys: HashMap<Key, KeyState>,
    shapes: HashMap<u64, Shape>,
    added: u64,
}

impl Planner {
    /// by_row applies rule 1 only to shared-value operations by default.
    /// This avoids unrelated-row waits, but equality is a heuristic;
    /// ranges and predicates on different columns may miss dependencies.
    ///
    /// Table mode is more conservative but propagates delays across connections.
    /// On measured Aurora with roughly 5 ms COMMIT, even a 30%-utilization workload
    /// had p95 lag of 298 ms in table mode versus 2.8 ms in row mode.
    pub fn new(by_row: bool) -> Self {
        Planner { by_row, ..Default::default() }
    }

    pub fn open(&mut self, info: &ConnInfo) {
        let n = self.servers.len() as u32;
        let s = *self.servers.entry((info.proto, info.server.clone())).or_insert(n);
        self.server_of.insert(info.conn, s);
    }

    pub fn close(&mut self, conn: u64) {
        self.server_of.remove(&conn);
        self.in_tx.remove(&conn);
        self.ann.forget(conn);
    }

    /// Look up SQL shape and its normal duration estimate.
    fn shape(&mut self, u: &Unit) -> (Arc<str>, u64) {
        let fp = fingerprint(&u.sql);
        let mut h = xxh3_64(fp.as_bytes());
        if !self.shapes.contains_key(&h) && self.shapes.len() >= MAX_SHAPES {
            h = 0;
        }
        let sh = self.shapes.entry(h).or_insert_with(|| Shape {
            text: if h == 0 { "(other)".into() } else { fp.into() },
            hist: [0; 128],
            n: 0,
        });
        let fast = if u.observed.duration { sh.add(u.t_end - u.t_start) } else { 0 };
        (sh.text.clone(), fast)
    }

    /// Add one unit in recorded completion order; conn owns its replay.
    pub fn add(&mut self, u: &Unit, conn: &Arc<ConnState>) -> UnitPlan {
        let server = self.server_of.get(&u.conn).copied().unwrap_or(0);
        let t = self.ann.touch(u, server);
        let (shape, fast) = self.shape(u);
        let holds = self.in_tx.insert(u.conn, u.in_tx).unwrap_or(false);
        let mut plan = UnitPlan { deps: Vec::new(), completes: Vec::new(), holds, shape, racy: None };
        if u.skip.is_some() || !(t.write || !t.tables.is_empty()) {
            return plan;
        }

        // Dependencies to wait for.
        let keys = &self.keys;
        let mut want = |k: Key, need: fn(&KeyState, u64) -> usize, at: u64| {
            if let Some(ks) = keys.get(&k) {
                let n = need(ks, at);
                if n > 0 {
                    plan.deps.push((ks.tracker.clone(), n));
                }
            }
        };
        let before = |ks: &KeyState, at: u64| ks.before(at);
        let all = |ks: &KeyState, _: u64| ks.count();
        // Row keys; COMMIT/ROLLBACK inherits the transaction's write values.
        let vals: &[u64] = if t.tx_end { &t.tx_vals } else { &u.vals };
        let by_row = self.by_row && !vals.is_empty();
        if t.global {
            want(Key::All(server), before, u.t_start);
        } else {
            want(Key::Global(server), before, u.t_start);
            for tb in &t.tables {
                if by_row {
                    // Wait only for matching values and unknown-value operations.
                    for v in vals {
                        want(Key::WriteVal(*tb, *v), before, u.t_start);
                    }
                    want(Key::WriteAny(*tb), before, u.t_start);
                    if t.write {
                        for v in vals {
                            want(Key::ReadVal(*tb, *v), before, u.t_start);
                        }
                        want(Key::ReadAny(*tb), before, u.t_start);
                    }
                } else {
                    want(Key::Write(*tb), before, u.t_start);
                    if t.write {
                        want(Key::Read(*tb), before, u.t_start);
                    }
                }
            }
            // Rule 2: all earlier-completed writes potentially competing for the same row.
            // Existing group members completed earlier because insertion follows completion order.
            let waited = u.observed.duration && u.t_end - u.t_start > BLOCKED_FACTOR * fast + BLOCKED_SLACK_NS;
            // Failed writes also follow this rule. Unique violations can retain index locks
            // that conflict with different values, such as MySQL gap locks.
            // Sending them early could block writes that succeeded earlier in the recording.
            let failed = u.out.err.is_some();
            if t.write && !t.tx_end && (waited || failed) && !self.no_lock_order {
                for tb in &t.tables {
                    if u.vals.is_empty() || failed {
                        // Unknown-value writes may compete with every row on the table.
                        want(Key::Lock(*tb), all, 0);
                    } else {
                        for v in &u.vals {
                            want(Key::LockVal(*tb, *v), all, 0);
                        }
                        // Unknown-value writes may compete with anything.
                        want(Key::LockAny(*tb), all, 0);
                    }
                }
            }
        }

        // Mark reads overlapping writes already completed in the recording.
        if !t.write {
            // Overlap exists if the prior write ended after this read started.
            let hit = t.tables.iter().map(|tb| Key::Write(*tb)).chain([Key::Global(server)]).any(|k| {
                self.keys.get(&k).is_some_and(|ks| ks.ends.back().is_some_and(|e| *e > u.t_start))
            });
            plan.racy = Some(Arc::new(AtomicBool::new(hit)));
        }

        // Membership groups for this unit.
        let mut join = |keys: &mut HashMap<Key, KeyState>, k: Key, cell: Option<&Arc<AtomicBool>>| {
            let ks = keys.entry(k).or_insert_with(|| KeyState {
                tracker: Tracker::new(),
                server,
                first_rank: 0,
                ends: VecDeque::new(),
                cells: VecDeque::new(),
            });
            ks.ends.push_back(u.t_end);
            if let Some(c) = cell {
                ks.cells.push_back(c.clone());
            }
            plan.completes.push((ks.tracker.clone(), ks.tracker.register(conn)));
        };
        join(&mut self.keys, Key::All(server), None);
        if t.global {
            join(&mut self.keys, Key::Global(server), None);
        }
        for tb in &t.tables {
            if t.write {
                join(&mut self.keys, Key::Write(*tb), None);
            } else {
                join(&mut self.keys, Key::Read(*tb), plan.racy.as_ref());
            }
            if self.by_row {
                match (t.write, vals.is_empty()) {
                    (true, true) => join(&mut self.keys, Key::WriteAny(*tb), None),
                    (false, true) => join(&mut self.keys, Key::ReadAny(*tb), None),
                    (true, false) => vals.iter().for_each(|v| join(&mut self.keys, Key::WriteVal(*tb, *v), None)),
                    (false, false) => vals.iter().for_each(|v| join(&mut self.keys, Key::ReadVal(*tb, *v), None)),
                }
            }
            if t.write && !t.tx_end {
                join(&mut self.keys, Key::Lock(*tb), None);
                if u.vals.is_empty() {
                    join(&mut self.keys, Key::LockAny(*tb), None);
                }
                for v in &u.vals {
                    join(&mut self.keys, Key::LockVal(*tb, *v), None);
                }
            }
        }

        // Mark prior completed reads that overlapped this write.
        if t.write {
            let mark = |ks: &KeyState| {
                for (e, c) in ks.ends.iter().zip(&ks.cells).rev() {
                    if *e <= u.t_start {
                        break;
                    }
                    c.store(true, Ordering::Relaxed);
                }
            };
            if t.global {
                self.keys.iter().filter(|(k, ks)| matches!(k, Key::Read(_)) && ks.server == server).for_each(|(_, ks)| mark(ks));
            } else {
                t.tables.iter().filter_map(|tb| self.keys.get(&Key::Read(*tb))).for_each(mark);
            }
        }

        self.added += 1;
        if self.added % SWEEP_EVERY == 0 {
            self.sweep(u.t_end);
        }
        plan
    }

    /// Retire old timestamps, retaining only their completed count.
    fn sweep(&mut self, now: u64) {
        self.keys.retain(|k, ks| {
            let keep = if k.per_value() { KEEP_VAL_NS } else { KEEP_NS };
            let cut = now.saturating_sub(keep);
            while ks.ends.front().is_some_and(|e| *e < cut) {
                ks.ends.pop_front();
                ks.cells.pop_front();
                ks.first_rank += 1;
            }
            // Retire unused per-value groups only after all their replays finish.
            // Recreating that value's group later is safe because no pending dependency remains.
            !(k.per_value() && ks.ends.is_empty() && ks.tracker.mark() == ks.count())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbtap_core::unit::Outcome;
    use std::time::Duration;

    #[test]
    fn tracker_advances_only_over_contiguous_prefix() {
        let c = ConnState::new(1);
        let t = Tracker::new();
        for k in 0..4 {
            assert_eq!(t.register(&c), k);
        }
        t.complete(1);
        t.complete(3);
        assert_eq!(t.mark(), 0);
        t.complete(0);
        assert_eq!(t.mark(), 2);
        t.complete(2);
        assert_eq!(t.mark(), 4);
        // Completed entries are retired; later additions continue their ranks.
        assert_eq!(t.register(&c), 4);
        assert!(t.inner.lock().unwrap().slots.len() == 1);
    }

    #[tokio::test]
    async fn tracker_wakes_only_waiters_whose_need_is_met() {
        let (c1, c2) = (ConnState::new(1), ConnState::new(2));
        let t = Tracker::new();
        t.register(&c1);
        t.register(&c2);
        t.register(&c2);
        let far = tokio::time::Instant::now() + Duration::from_secs(5);
        let (a, b) = (t.clone(), t.clone());
        let w1 = tokio::spawn(async move { a.wait(far, 1).await });
        let w3 = tokio::spawn(async move { b.wait(far, 3).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // The earliest unfinished member's connection is the blocker.
        assert_eq!(t.blocker().unwrap().conn, 1);
        t.complete(0);
        assert!(w1.await.unwrap());
        assert!(!w3.is_finished());
        assert_eq!(t.blocker().unwrap().conn, 2);
        // Deadline expiration returns false.
        assert!(!t.wait(tokio::time::Instant::now() + Duration::from_millis(5), 2).await);
        t.complete(1);
        t.complete(2);
        assert!(w3.await.unwrap());
        assert!(t.blocker().is_none());
    }

    fn unit(conn: u64, t_start: u64, t_end: u64, sql: &str) -> Unit {
        Unit {
            conn,
            t_start,
            t_end,
            sql: sql.into(),
            req: vec![],
            write: dbtap_core::unit::is_write(sql),
            many: false,
            skip: None,
            vals: Vec::new(),
            in_tx: false,
            aux: 0,
            out: Outcome::default(),
            observed: Default::default(),
            origin: None,
        }
    }

    /// Plan units by completion order, returning plans in the original units index order.
    fn plan(units: &[Unit]) -> Vec<UnitPlan> {
        plan_with(units, false)
    }

    fn plan_with(units: &[Unit], by_row: bool) -> Vec<UnitPlan> {
        let mut p = Planner::new(by_row);
        let mut order: Vec<usize> = (0..units.len()).collect();
        order.sort_by_key(|i| (units[*i].t_end, *i));
        let mut conns: HashMap<u64, Arc<ConnState>> = HashMap::new();
        let mut out: Vec<Option<UnitPlan>> = units.iter().map(|_| None).collect();
        for i in order {
            let u = &units[i];
            let c = conns.entry(u.conn).or_insert_with(|| {
                p.open(&ConnInfo::new(u.conn, Proto::Postgres, 0, "c".into(), "s:5432".into(), false));
                ConnState::new(u.conn)
            });
            out[i] = Some(p.add(u, c));
        }
        out.into_iter().map(|x| x.unwrap()).collect()
    }

    /// Set of units that unit i must wait for before sending.
    fn waits_for(p: &[UnitPlan], n: usize, i: usize) -> Vec<usize> {
        (0..n)
            .filter(|&j| {
                p[j].completes.iter().any(|(t, r)| p[i].deps.iter().any(|(dt, need)| Arc::ptr_eq(dt, t) && r < need))
            })
            .collect()
    }

    fn racy(p: &[UnitPlan]) -> Vec<bool> {
        p.iter().map(|x| x.racy.as_ref().is_some_and(|c| c.load(Ordering::Relaxed))).collect()
    }

    #[test]
    fn plan_orders_only_conflicting_non_overlapping_operations() {
        let units = vec![
            unit(1, 0, 10, "update a set x = 1"),       // 0
            unit(2, 5, 15, "update a set x = 2"),       // 1: overlaps 0.
            unit(3, 20, 30, "select * from a"),         // 2: after 0 and 1.
            unit(4, 20, 30, "select * from b"),         // 3: another table.
            unit(5, 40, 50, "update a set x = 3"),      // 4: writes also wait for prior completed read 2.
            unit(6, 40, 50, "select 1"),                // 5: touches no table.
            unit(7, 60, 70, "create index i on b (x)"), // 6: unknown-table write waits for everything.
            unit(8, 80, 90, "select * from b"),         // 7: all operations wait for the unknown-table write.
        ];
        let p = plan(&units);
        let n = units.len();
        assert_eq!(waits_for(&p, n, 0), Vec::<usize>::new());
        // Overlaps 0 but both have normal durations, so infer no lock contention.
        assert_eq!(waits_for(&p, n, 1), Vec::<usize>::new());
        assert_eq!(waits_for(&p, n, 2), [0, 1]);
        assert_eq!(waits_for(&p, n, 3), Vec::<usize>::new());
        assert_eq!(waits_for(&p, n, 4), [0, 1, 2]);
        assert_eq!(waits_for(&p, n, 5), Vec::<usize>::new());
        assert_eq!(waits_for(&p, n, 6), [0, 1, 2, 3, 4]);
        assert_eq!(waits_for(&p, n, 7), [6]);
        assert!(!racy(&p).iter().any(|r| *r));
    }

    /// Prepend fast executions of the same shape to establish a normal-duration baseline.
    fn with_fast_samples(sql: &str, mut units: Vec<Unit>) -> (Vec<Unit>, usize) {
        let ms = 1_000_000;
        let mut v: Vec<Unit> = (0..20)
            .map(|k| {
                let mut u = unit(9, k * 2 * ms, (k * 2 + 1) * ms, sql);
                u.vals = vec![dbtap_core::unit::int_key(1000 + k as i64), dbtap_core::unit::int_key(2000 + k as i64)];
                u
            })
            .collect();
        let n = v.len();
        v.append(&mut units);
        (v, n)
    }

    #[test]
    fn write_that_waited_for_a_lock_is_sent_after_the_writes_that_finished_first() {
        let ms = 1_000_000;
        let t = |x: u64| (1000 + x) * ms;
        let (units, o) = with_fast_samples(
            "update a set x = 9",
            vec![
                unit(1, t(0), t(1), "BEGIN"),               // 0
                unit(1, t(10), t(11), "update a set x = 1"), // 1: acquired the lock.
                unit(2, t(9), t(60), "update a set x = 2"),  // 2: sent before 1 but waited until after COMMIT.
                unit(3, t(12), t(13), "update a set x = 3"), // 3: another row, executed during 2.
                unit(1, t(50), t(52), "COMMIT"),             // 4
                unit(4, t(51), t(52), "update a set x = 4"), // 5
            ],
        );
        let p = plan(&units);
        let waits = |i: usize| -> Vec<usize> { waits_for(&p, units.len(), o + i).into_iter().filter_map(|j| j.checked_sub(o)).collect() };
        // Waiter 2 follows earlier-completed writes 1, 3, and 5.
        // It need not wait for COMMIT 4: let the target reproduce the lock wait.
        // These units have unknown values, so they may compete with any row.
        assert_eq!(waits(2), [1, 3, 5]);
        // Normally fast writes 1 and 3 are not constrained merely by overlap.
        assert_eq!(waits(1), Vec::<usize>::new());
        assert_eq!(waits(3), [1]);
        // COMMIT follows only writes completed before it started (rule 1), not in-flight 2.
        assert_eq!(waits(4), [1, 3]);
    }

    #[test]
    fn waited_write_only_follows_writes_that_share_a_value() {
        let ms = 1_000_000;
        let t = |x: u64| (1000 + x) * ms;
        let with = |mut u: Unit, vals: &[i64]| {
            u.vals = vals.iter().map(|v| dbtap_core::unit::int_key(*v)).collect();
            u
        };
        let sql = "update a set x = x + $1 where id = $2";
        let (units, o) = with_fast_samples(
            sql,
            vec![
                with(unit(1, t(10), t(11), sql), &[5, 100]),        // 0: locked id=100.
                with(unit(2, t(12), t(13), sql), &[7, 200]),        // 1: another row.
                with(unit(3, t(9), t(60), sql), &[9, 100]),         // 2: waited for id=100.
                unit(4, t(14), t(15), "update a set y = 0"),        // 3: unknown-value write.
                with(unit(5, t(9), t(70), sql), &[7, 300]),         // 4: waited; different row but shares value 7 with 1.
            ],
        );
        let p = plan(&units);
        let waits = |i: usize| -> Vec<usize> { waits_for(&p, units.len(), o + i).into_iter().filter_map(|j| j.checked_sub(o)).collect() };
        // 2 waits for shared value 100 in 0 and unknown values in 3, not unrelated 1.
        assert_eq!(waits(2), [0, 3]);
        // Shared values are heuristic; incidental equality adds conservative waiting.
        assert_eq!(waits(4), [1, 3]);
    }

    #[test]
    fn failed_write_follows_every_write_that_finished_first_on_the_table() {
        let with = |mut u: Unit, vals: &[i64], err: Option<&str>| {
            u.vals = vals.iter().map(|v| dbtap_core::unit::int_key(*v)).collect();
            u.out.err = err.map(|e| e.to_string());
            u
        };
        let sql = "insert into a (id, ref) values ($1, $2)";
        let units = vec![
            with(unit(1, 12, 20, sql), &[23, 800], None),         // 0: successful INSERT started during 1 and completed first.
            with(unit(2, 10, 22, sql), &[1, 900], Some("1062")),  // 1: unique violation; no shared values with 0.
            with(unit(3, 11, 25, sql), &[5, 700], None),          // 2: normal INSERT overlapping 0 and 1.
        ];
        let p = plan(&units);
        // Failed 1 follows completed 0 so its retained locks do not block 0.
        assert_eq!(waits_for(&p, 3, 1), [0]);
        // Successful overlapping writes remain unconstrained.
        assert_eq!(waits_for(&p, 3, 0), Vec::<usize>::new());
        assert_eq!(waits_for(&p, 3, 2), Vec::<usize>::new());
    }

    #[test]
    fn by_row_orders_only_operations_that_share_a_value() {
        let with = |mut u: Unit, vals: &[i64]| {
            u.vals = vals.iter().map(|v| dbtap_core::unit::int_key(*v)).collect();
            u
        };
        let mut commit = unit(1, 30, 32, "COMMIT");
        commit.in_tx = false;
        let units = vec![
            unit(1, 0, 1, "BEGIN"),                                                  // 0
            with(unit(1, 10, 11, "update a set x = x + $1 where id = $2"), &[5, 100]), // 1
            with(unit(2, 12, 13, "update a set x = x + $1 where id = $2"), &[7, 200]), // 2: another row.
            commit,                                                                  // 3: inherits values 5 and 100 from 1.
            with(unit(3, 40, 41, "select x from a where id = $1"), &[100]),          // 4: reads id=100.
            with(unit(4, 40, 41, "select x from a where id = $1"), &[300]),          // 5: row untouched by other writes.
            unit(5, 40, 41, "select sum(x) from a"),                                 // 6: read without value keys.
            unit(6, 50, 51, "update a set y = 0"),                                   // 7: write without value keys.
            with(unit(7, 60, 61, "select x from a where id = $1"), &[300]),          // 8
        ];
        let n = units.len();
        let row = plan_with(&units, true);
        // Wait for shared-value write 1 and its COMMIT 3, not unrelated row 2.
        assert_eq!(waits_for(&row, n, 4), [1, 3]);
        assert_eq!(waits_for(&row, n, 5), Vec::<usize>::new());
        // Unknown-value operations can touch any row on the table.
        assert_eq!(waits_for(&row, n, 6), [1, 2, 3]);
        assert_eq!(waits_for(&row, n, 7), [1, 2, 3, 4, 5, 6]);
        // Everyone waits for unknown-value write 7.
        assert_eq!(waits_for(&row, n, 8), [7]);
        // Table mode waits for all writes on the same table.
        let table = plan_with(&units, false);
        assert_eq!(waits_for(&table, n, 5), [1, 2, 3]);
    }

    #[test]
    fn read_overlapping_a_conflicting_write_is_racy() {
        let units = vec![
            unit(1, 0, 50, "update a set x = 1"), // 0
            unit(2, 10, 20, "select * from a"),   // 1: starts and ends during 0, which finishes later.
            unit(3, 10, 20, "select * from b"),   // 2: another table.
            unit(2, 50, 60, "select * from a"),   // 3: after 0 completes.
            unit(4, 55, 58, "update a set x = 2"), // 4: starts and ends during 3.
            unit(5, 59, 65, "select * from a"),   // 5: starts after 4 completes.
            unit(5, 57, 59, "select * from a"),   // 6: starts during 4 and finishes after it.
        ];
        let p = plan(&units);
        assert_eq!(racy(&p), [false, true, false, true, false, false, true]);
    }

    #[test]
    fn usual_duration_survives_long_runs_of_blocked_executions() {
        let mut sh = Shape { text: "x".into(), hist: [0; 128], n: 0 };
        for v in [0u64, 1, 2, 3, 1000, 123_456, u64::MAX] {
            let f = Shape::floor(Shape::bucket(v));
            assert!(f <= v && v - f <= v / 2, "{v} -> {f}");
        }
        // The first sample establishes its own baseline and is not considered delayed.
        assert_eq!(sh.add(5_000_000), Shape::floor(Shape::bucket(5_000_000)));
        // Twenty percent at 100 us, eighty percent with 5 ms waits.
        let mut fast = 0;
        for k in 0..20_000u64 {
            fast = sh.add(if k % 5 == 0 { 100_000 } else { 5_000_000 });
        }
        assert!((65_536..=100_000).contains(&fast), "{fast}");
        // Hundreds of delayed samples must not move the baseline away from fast executions.
        for _ in 0..300 {
            fast = sh.add(5_000_000);
        }
        assert!((65_536..=100_000).contains(&fast), "{fast}");
    }

    #[test]
    fn holds_reflects_the_transaction_state_before_the_unit() {
        let mut a = unit(1, 0, 1, "BEGIN");
        a.in_tx = true;
        let mut b = unit(1, 2, 3, "update a set x = 1");
        b.in_tx = true;
        let c = unit(1, 4, 5, "COMMIT");
        let d = unit(1, 6, 7, "select 1");
        let p = plan(&[a, b, c, d]);
        assert_eq!(p.iter().map(|x| x.holds).collect::<Vec<_>>(), [false, true, true, false]);
    }

    #[test]
    fn sweep_forgets_old_times_but_keeps_counts() {
        let mut p = Planner::new(false);
        let c = ConnState::new(1);
        p.open(&ConnInfo::new(1, Proto::Postgres, 0, "c".into(), "s:5432".into(), false));
        let s = 1_000_000_000u64;
        for k in 0..10u64 {
            let mut u = unit(1, k * s, k * s + 1, "update a set x = 1 where id = $1");
            u.vals = vec![k];
            p.add(&u, &c);
        }
        // Keep old per-value groups while replay remains pending; they can still be dependencies.
        p.sweep(400 * s);
        assert_eq!(p.keys.keys().filter(|k| matches!(k, Key::LockVal(..))).count(), 10);
        for ks in p.keys.values() {
            for r in 0..ks.count() {
                ks.tracker.complete(r);
            }
        }
        p.sweep(400 * s);
        // Per-value groups disappear; table groups retain completion counts.
        assert!(!p.keys.keys().any(|k| matches!(k, Key::LockVal(..))));
        let w = p.keys.iter().find(|(k, _)| matches!(k, Key::Write(_))).unwrap().1;
        assert_eq!((w.ends.len(), w.count()), (0, 10));
        // A later read still waits for all ten retired entries through their count.
        let r = p.add(&unit(1, 500 * s, 500 * s + 1, "select * from a"), &c);
        assert_eq!(r.deps.iter().map(|d| d.1).max(), Some(10));
    }
}
