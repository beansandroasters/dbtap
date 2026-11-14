//! Compare recorded and replayed outcomes.
//!
//! Fold and discard individual results in Agg; retain latency distributions in Hist.
//! Histograms can be merged across workers without retaining every sample.

use crate::replay::{Done, Order, Res};
use dbtap_core::unit::{Observed, Outcome, is_nondeterministic};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Verdict {
    /// All observed rows, affected rows, contents, and errors match.
    Match,
    /// Contents differ for a non-deterministic statement, such as time/random functions.
    NonDeterministic,
    /// Same row multiset, different order.
    OrderOnly,
    /// Read overlaps a conflicting write in the recording.
    /// Traffic alone does not establish visibility, so a difference need not indicate replay failure.
    Racy,
    /// Error present on only one side, or differing error codes.
    ErrorDiff,
    RowsDiff,
    AffectedDiff,
    /// Same row count, different contents.
    ContentDiff,
}

pub fn judge(sql: &str, a: &Outcome, b: &Outcome, racy: bool) -> Verdict {
    judge_observed(sql, a, b, racy, Observed::default())
}

pub fn judge_observed(sql: &str, a: &Outcome, b: &Outcome, racy: bool, known: Observed) -> Verdict {
    if known.error && a.err != b.err {
        return Verdict::ErrorDiff;
    }
    if racy && ((known.rows && a.rows != b.rows) || (known.content && a.hash_ordered != b.hash_ordered)) && !is_nondeterministic(sql) {
        return Verdict::Racy;
    }
    if known.rows && a.rows != b.rows {
        return Verdict::RowsDiff;
    }
    if known.affected && a.affected != b.affected {
        return Verdict::AffectedDiff;
    }
    if !known.content || a.hash_ordered == b.hash_ordered {
        return Verdict::Match;
    }
    if is_nondeterministic(sql) {
        return Verdict::NonDeterministic;
    }
    if a.hash_set == b.hash_set {
        return Verdict::OrderOnly;
    }
    Verdict::ContentDiff
}

/// Nanosecond histogram with 32 subdivisions per power of two, about 3% bucket width.
/// Mergeable across workers while retaining quantile estimates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hist {
    /// Bucket index to count.
    buckets: BTreeMap<u16, u64>,
    n: u64,
    sum: f64,
    max: u64,
}

impl Hist {
    fn bucket(v: u64) -> u16 {
        if v < 32 {
            return v as u16;
        }
        let e = 63 - v.leading_zeros() as u64;
        (((e - 4) << 5) | ((v >> (e - 5)) & 31)) as u16
    }

    /// Bucket midpoint.
    fn value(b: u16) -> u64 {
        if b < 32 {
            return b as u64;
        }
        let e = (b >> 5) as u64 + 4;
        let low = (1u64 << e) | (((b & 31) as u64) << (e - 5));
        low + (1u64 << (e - 5)) / 2
    }

    pub fn add(&mut self, v: u64) {
        *self.buckets.entry(Self::bucket(v)).or_default() += 1;
        self.n += 1;
        self.sum += v as f64;
        self.max = self.max.max(v);
    }

    pub fn merge(&mut self, o: &Hist) {
        for (b, c) in &o.buckets {
            *self.buckets.entry(*b).or_default() += c;
        }
        self.n += o.n;
        self.sum += o.sum;
        self.max = self.max.max(o.max);
    }

    fn quantile(&self, q: f64) -> u64 {
        let rank = ((self.n.saturating_sub(1)) as f64 * q).round() as u64;
        let mut seen = 0;
        for (b, c) in &self.buckets {
            seen += c;
            if seen > rank {
                return Self::value(*b).min(self.max);
            }
        }
        self.max
    }

    pub fn pct(&self) -> Pct {
        if self.n == 0 {
            return Pct::default();
        }
        let ms = |v: u64| v as f64 / 1e6;
        Pct {
            p50_ms: ms(self.quantile(0.50)),
            p95_ms: ms(self.quantile(0.95)),
            p99_ms: ms(self.quantile(0.99)),
            max_ms: ms(self.max),
            mean_ms: self.sum / self.n as f64 / 1e6,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy)]
pub struct Pct {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Shape {
    pub sql: String,
    pub count: u64,
    pub mismatches: u64,
    pub captured: Pct,
    pub replayed: Pct,
    /// Mean replay duration divided by mean captured duration.
    pub ratio: f64,
    #[serde(default)]
    pub duration_compared: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub conn: u64,
    pub at_s: f64,
    pub verdict: Verdict,
    pub sql: String,
    pub captured: Outcome,
    pub replayed: Outcome,
    #[serde(default)]
    pub observed: Observed,
}

/// Counts of executed units with each field available for comparison/aggregation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Compared {
    pub error: u64,
    pub rows: u64,
    pub affected: u64,
    pub content: u64,
    pub duration: u64,
}

impl Compared {
    fn add(&mut self, o: Observed) {
        self.error += o.error as u64;
        self.rows += o.rows as u64;
        self.affected += o.affected as u64;
        self.content += o.content as u64;
        self.duration += o.duration as u64;
    }

    fn merge(&mut self, other: &Self) {
        self.error += other.error;
        self.rows += other.rows;
        self.affected += other.affected;
        self.content += other.content;
        self.duration += other.duration;
    }
}

/// One causal dependency timeout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallSample {
    pub conn: u64,
    pub start_s: f64,
    pub end_s: f64,
    pub sql: String,
    /// Blocking connection.
    pub blocker_conn: u64,
    /// Blocker was awaiting a target response, potentially blocked inside the target.
    pub blocker_inflight: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ShapeAgg {
    mismatches: u64,
    captured: Hist,
    replayed: Hist,
    #[serde(default)]
    paired_replayed: Hist,
}

/// Incremental result aggregation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Agg {
    /// First recorded timestamp; example times are seconds relative to it.
    #[serde(skip)]
    base: u64,
    units: u64,
    ran: u64,
    skipped: u64,
    failed: u64,
    elsewhere: u64,
    failures: BTreeMap<String, u64>,
    verdicts: BTreeMap<Verdict, u64>,
    #[serde(default)]
    compared: Compared,
    order_violations: u64,
    lock_inversions: u64,
    latency_captured: Hist,
    latency_replayed: Hist,
    lag: Hist,
    /// Dependency waits lasting at least 0.1 ms.
    order_wait: Hist,
    shapes: BTreeMap<String, ShapeAgg>,
    samples: Vec<Sample>,
    stalls: Vec<StallSample>,
}

const MAX_SAMPLES: usize = 30;

impl Agg {
    pub fn new(base: u64) -> Self {
        Agg { base, ..Default::default() }
    }

    pub fn add(&mut self, d: &Done) {
        let u = &d.unit;
        self.units += 1;
        match &d.res {
            Res::Skipped => self.skipped += 1,
            Res::Elsewhere => self.elsewhere += 1,
            Res::Failed(why) => {
                self.failed += 1;
                *self.failures.entry(why.clone()).or_default() += 1;
            }
            Res::Ran { out, latency_ns, lag_ns, waited_ns, order } => {
                self.ran += 1;
                self.order_violations += (*order == Order::TimedOut) as u64;
                self.lock_inversions += (*order == Order::Inverted) as u64;
                let v = judge_observed(&u.sql, &u.out, out, d.racy, u.observed);
                self.compared.add(u.observed);
                *self.verdicts.entry(v).or_default() += 1;
                let cap = u.t_end - u.t_start;
                if u.observed.duration {
                    self.latency_captured.add(cap);
                    self.latency_replayed.add(*latency_ns);
                }
                self.lag.add(*lag_ns);
                // Under 0.1 ms is treated as checking dependencies, not waiting.
                if *waited_ns > 100_000 {
                    self.order_wait.add(*waited_ns);
                }
                let bad = !matches!(v, Verdict::Match | Verdict::NonDeterministic | Verdict::Racy);
                let s = match self.shapes.get_mut(&*d.shape) {
                    Some(s) => s,
                    None => self.shapes.entry(d.shape.to_string()).or_default(),
                };
                s.mismatches += bad as u64;
                if u.observed.duration {
                    s.captured.add(cap);
                    s.paired_replayed.add(*latency_ns);
                }
                s.replayed.add(*latency_ns);
                if bad && self.samples.len() < MAX_SAMPLES {
                    self.samples.push(Sample {
                        conn: u.conn,
                        at_s: u.t_start.saturating_sub(self.base) as f64 / 1e9,
                        verdict: v,
                        sql: u.sql.chars().take(300).collect(),
                        captured: u.out.clone(),
                        replayed: out.clone(),
                        observed: u.observed,
                    });
                }
                if let (Order::TimedOut, Some(st)) = (order, &d.stall) {
                    if self.stalls.len() < MAX_SAMPLES {
                        self.stalls.push(StallSample {
                            conn: u.conn,
                            start_s: u.t_start.saturating_sub(self.base) as f64 / 1e9,
                            end_s: u.t_end.saturating_sub(self.base) as f64 / 1e9,
                            sql: u.sql.chars().take(120).collect(),
                            blocker_conn: st.blocker_conn,
                            blocker_inflight: st.blocker_inflight,
                        });
                    }
                }
            }
        }
    }

    /// Merge another worker's aggregate.
    pub fn merge(&mut self, o: &Agg) {
        self.compared = self.comparison_counts();
        self.compared.merge(&o.comparison_counts());
        for s in self.shapes.values_mut() {
            if s.paired_replayed.n == 0 && s.captured.n > 0 {
                s.paired_replayed = s.replayed.clone();
            }
        }
        self.units += o.units;
        self.ran += o.ran;
        self.skipped += o.skipped;
        self.failed += o.failed;
        // Elsewhere counts are meaningless after merging: another worker executed those units.
        self.elsewhere = 0;
        for (k, n) in &o.failures {
            *self.failures.entry(k.clone()).or_default() += n;
        }
        for (k, n) in &o.verdicts {
            *self.verdicts.entry(*k).or_default() += n;
        }
        self.order_violations += o.order_violations;
        self.lock_inversions += o.lock_inversions;
        self.latency_captured.merge(&o.latency_captured);
        self.latency_replayed.merge(&o.latency_replayed);
        self.lag.merge(&o.lag);
        self.order_wait.merge(&o.order_wait);
        for (k, s) in &o.shapes {
            let e = self.shapes.entry(k.clone()).or_default();
            e.mismatches += s.mismatches;
            e.captured.merge(&s.captured);
            e.replayed.merge(&s.replayed);
            e.paired_replayed.merge(if s.paired_replayed.n == 0 && s.captured.n > 0 { &s.replayed } else { &s.paired_replayed });
        }
        self.samples.extend(o.samples.iter().take(MAX_SAMPLES.saturating_sub(self.samples.len())).cloned());
        self.stalls.extend(o.stalls.iter().take(MAX_SAMPLES.saturating_sub(self.stalls.len())).cloned());
    }

    fn comparison_counts(&self) -> Compared {
        // Also accept wire reports predating explicit observed-field counts.
        if self.ran > 0 && self.compared.error == 0 {
            Compared { error: self.ran, rows: self.ran, affected: self.ran, content: self.ran, duration: self.ran }
        } else {
            self.compared.clone()
        }
    }
}

/// Metadata for the complete replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub source: String,
    pub captured_seconds: f64,
    pub replayed_seconds: f64,
    pub speed: f64,
    pub connections: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    #[serde(flatten)]
    pub meta: Meta,
    pub units: u64,
    pub ran: u64,
    /// Units known to be unreplayable from the recording.
    pub skipped: u64,
    /// Units whose execution failed, including target connection problems.
    pub failed: u64,
    /// Units assigned to another shard.
    pub elsewhere: u64,
    pub failures: Vec<(String, u64)>,
    pub verdicts: Vec<(Verdict, u64)>,
    #[serde(default)]
    pub compared: Compared,
    /// Units sent after a causal dependency timeout.
    pub order_violations: u64,
    /// Waits released because target lock order differed from the recording.
    pub lock_inversions: u64,
    pub latency_captured: Pct,
    pub latency_replayed: Pct,
    /// Actual send delay relative to schedule.
    pub lag: Pct,
    /// Count and duration of dependency waits lasting at least 0.1 ms.
    pub order_waits: u64,
    pub order_wait: Pct,
    /// SQL shapes ordered by total replay duration.
    pub shapes: Vec<Shape>,
    pub samples: Vec<Sample>,
    /// First causal timeout examples.
    pub stalls: Vec<StallSample>,
    /// Raw aggregate for merging worker reports.
    pub raw: Agg,
}

pub fn build(mut agg: Agg, meta: Meta) -> Report {
    agg.compared = agg.comparison_counts();
    let mut shapes: Vec<(f64, Shape)> = agg
        .shapes
        .iter()
        .map(|(sql, s)| {
            let (captured, replayed) = (s.captured.pct(), s.replayed.pct());
            let paired = if s.paired_replayed.n == 0 && s.captured.n > 0 { replayed } else { s.paired_replayed.pct() };
            let ratio = if captured.mean_ms > 0.0 { paired.mean_ms / captured.mean_ms } else { 0.0 };
            (s.replayed.sum, Shape {
                sql: sql.clone(), count: s.replayed.n, mismatches: s.mismatches, captured, replayed, ratio,
                duration_compared: s.captured.n,
            })
        })
        .collect();
    shapes.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    let mut verdicts: Vec<_> = agg.verdicts.iter().map(|(k, n)| (*k, *n)).collect();
    verdicts.sort_by_key(|v| std::cmp::Reverse(v.1));
    let mut failures: Vec<_> = agg.failures.iter().map(|(k, n)| (k.clone(), *n)).collect();
    failures.sort_by_key(|v| std::cmp::Reverse(v.1));
    Report {
        meta,
        units: agg.units,
        ran: agg.ran,
        skipped: agg.skipped,
        failed: agg.failed,
        elsewhere: agg.elsewhere,
        failures,
        verdicts,
        compared: agg.compared.clone(),
        order_violations: agg.order_violations,
        lock_inversions: agg.lock_inversions,
        latency_captured: agg.latency_captured.pct(),
        latency_replayed: agg.latency_replayed.pct(),
        lag: agg.lag.pct(),
        order_waits: agg.order_wait.n,
        order_wait: agg.order_wait.pct(),
        shapes: shapes.into_iter().map(|s| s.1).collect(),
        samples: agg.samples.clone(),
        stalls: agg.stalls.clone(),
        raw: agg,
    }
}

/// Merge multiple worker reports.
pub fn merge(reports: Vec<Report>) -> Option<Report> {
    let mut it = reports.into_iter();
    let first = it.next()?;
    let (mut agg, mut meta) = (first.raw, first.meta);
    // Each worker's units plus elsewhere equals the combined recording count.
    let total = agg.units;
    for r in it {
        agg.merge(&r.raw);
        meta.connections += r.meta.connections;
        meta.captured_seconds = meta.captured_seconds.max(r.meta.captured_seconds);
        meta.replayed_seconds = meta.replayed_seconds.max(r.meta.replayed_seconds);
    }
    agg.units = total;
    agg.elsewhere = 0;
    Some(build(agg, meta))
}

fn label(v: Verdict) -> &'static str {
    match v {
        Verdict::Match => "Observed fields match",
        Verdict::NonDeterministic => "Non-deterministic statement (content difference ignored)",
        Verdict::OrderOnly => "Row order differs",
        Verdict::Racy => "Read overlaps a conflicting write (visibility undetermined)",
        Verdict::ErrorDiff => "Error status or code differs",
        Verdict::RowsDiff => "Returned row count differs",
        Verdict::AffectedDiff => "Affected row count differs",
        Verdict::ContentDiff => "Result contents differ",
    }
}

pub fn print(r: &Report, top: usize) {
    println!("== Replay results ==");
    let m = &r.meta;
    println!("Recorded {:.3} s -> replayed {:.3} s (speed {}x) / connections {}", m.captured_seconds, m.replayed_seconds, m.speed, m.connections);
    println!("Units {}: ran {} / unreplayable {} / execution failures {}", r.units, r.ran, r.skipped, r.failed);
    if r.elsewhere > 0 {
        println!("  Assigned elsewhere: {} (excluded from this worker's results)", r.elsewhere);
    }
    for (why, n) in &r.failures {
        println!("  - {why}: {n}");
    }
    println!("\n-- Result comparison --");
    let c = &r.compared;
    println!("Compared: errors {} / rows {} / affected {} / content {} / duration {}", c.error, c.rows, c.affected, c.content, c.duration);
    for (v, n) in &r.verdicts {
        println!("{n:>9}  {:5.1}%  {}", 100.0 * *n as f64 / r.ran.max(1) as f64, label(*v));
    }
    println!(
        "Units with dependency waits: {} / lock reversals released: {} / causal timeouts: {}",
        r.order_waits, r.lock_inversions, r.order_violations
    );
    println!("\n-- Response time (ms) --   p50       p95       p99       max      mean");
    if c.duration < r.ran {
        println!("Paired captured/replayed latency covers only {} units with known captured duration", c.duration);
    }
    let row = |name: &str, p: &Pct| {
        println!("{name:<22}{:>10.3}{:>10.3}{:>10.3}{:>10.3}{:>10.3}", p.p50_ms, p.p95_ms, p.p99_ms, p.max_ms, p.mean_ms)
    };
    row("Captured", &r.latency_captured);
    row("Replayed", &r.latency_replayed);
    row("Send lag", &r.lag);
    row("Dependency wait", &r.order_wait);
    if r.lag.p50_ms > 5.0 {
        println!("Warning: more than half of requests were sent over 5 ms late; replay is not keeping the recorded pace");
    }
    println!("\n-- SQL shapes (top {top} by total replay duration) --");
    println!("{:>8} {:>7} {:>8} {:>10} {:>10} {:>7}  SQL shape", "Count", "Diff", "Timed", "Captured", "Replayed", "Ratio");
    for s in r.shapes.iter().take(top) {
        let sql: String = s.sql.chars().take(90).collect();
        let (cap, ratio) = if s.duration_compared > 0 {
            (format!("{:.3}", s.captured.mean_ms), format!("{:.2}x", s.ratio))
        } else { ("?".into(), "?".into()) };
        println!("{:>8} {:>7} {:>8} {cap:>10} {:>10.3} {ratio:>7}  {sql}", s.count, s.mismatches, s.duration_compared, s.replayed.mean_ms);
    }
    if !r.stalls.is_empty() {
        println!("\n-- Causal timeout examples (first 8; recorded start/end in seconds) --");
        for st in r.stalls.iter().take(8) {
            let sql: String = st.sql.chars().take(70).map(|c| if c == '\n' { ' ' } else { c }).collect();
            println!("  Waiting: c{} [{:.6}..{:.6}] {sql}", st.conn, st.start_s, st.end_s);
            println!(
                "  Blocker: connection c{} ({})",
                st.blocker_conn,
                if st.blocker_inflight { "sent, awaiting response" } else { "not yet sent" }
            );
        }
    }
    if !r.samples.is_empty() {
        println!("\n-- Difference examples (first 10 of at most 30) --");
        for s in r.samples.iter().take(10) {
            let sql: String = s.sql.chars().take(100).map(|c| if c == '\n' { ' ' } else { c }).collect();
            println!("[{:>10.6}s c{}] {}: {sql}", s.at_s, s.conn, label(s.verdict));
            let f = |o: &Outcome, known: Observed| format!("rows={} affected={} err={}",
                if known.rows { o.rows.to_string() } else { "?".into() },
                if known.affected { o.affected.to_string() } else { "?".into() },
                if known.error { o.err.as_deref().unwrap_or("-") } else { "?" });
            println!("      Captured: {}\n      Replayed: {}", f(&s.captured, s.observed), f(&s.replayed, Observed::default()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(rows: u64, vals: &[&[u8]]) -> Outcome {
        let mut o = Outcome::default();
        for v in vals {
            o.add_row(v);
        }
        o.rows = rows;
        o
    }

    #[test]
    fn verdicts() {
        let a = o(2, &[b"x", b"y"]);
        assert_eq!(judge("select a from t", &a, &o(2, &[b"x", b"y"]), false), Verdict::Match);
        assert_eq!(judge("select a from t", &a, &o(2, &[b"y", b"x"]), false), Verdict::OrderOnly);
        assert_eq!(judge("select a from t", &a, &o(2, &[b"x", b"z"]), false), Verdict::ContentDiff);
        assert_eq!(judge("select now()", &a, &o(2, &[b"x", b"z"]), false), Verdict::NonDeterministic);
        assert_eq!(judge("select a from t", &a, &o(1, &[b"x"]), false), Verdict::RowsDiff);
        // Classify overlapping reads according to whether their results actually differ.
        assert_eq!(judge("select a from t", &a, &o(2, &[b"x", b"z"]), true), Verdict::Racy);
        assert_eq!(judge("select a from t", &a, &o(2, &[b"x", b"y"]), true), Verdict::Match);
        let mut e = Outcome::default();
        e.err = Some("23505".into());
        assert_eq!(judge("insert into t values (1)", &Outcome::default(), &e, false), Verdict::ErrorDiff);
        assert_eq!(judge("insert into t values (1)", &e, &e.clone(), false), Verdict::Match);
    }

    #[test]
    fn only_observed_fields_are_compared() {
        use dbtap_core::unit::Observed;
        let captured = Outcome::default();
        let actual = o(2, &[b"x", b"y"]);
        let pg = Observed::pg_log(true);
        assert_eq!(judge_observed("select a from t", &captured, &actual, false, pg), Verdict::Match);
        let failed = Outcome { err: Some("23505".into()), ..actual.clone() };
        assert_eq!(judge_observed("select a from t", &captured, &failed, false, pg), Verdict::ErrorDiff);
        let rows = Observed { rows: true, ..pg };
        assert_eq!(judge_observed("select a from t", &captured, &actual, false, rows), Verdict::RowsDiff);
    }

    #[test]
    fn merging_legacy_wire_and_log_counts_works_in_either_order() {
        let old = Agg { ran: 2, ..Default::default() };
        let logs = Agg { ran: 3, compared: Compared { error: 3, duration: 3, ..Default::default() }, ..Default::default() };
        for (mut a, b) in [(old.clone(), logs.clone()), (logs, old)] {
            a.merge(&b);
            assert_eq!(a.compared.error, 5);
            assert_eq!(a.compared.rows, 2);
            assert_eq!(a.compared.duration, 5);
        }
    }

    #[test]
    fn unknown_duration_is_excluded_from_paired_latency_and_report_merge() {
        use dbtap_core::unit::Unit;
        let mut agg = Agg::new(0);
        for (known, latency_ns) in [(true, 2_000_000), (false, 100_000_000)] {
            let u = Unit {
                conn: 1, t_start: 0, t_end: if known { 1_000_000 } else { 0 },
                sql: "select 1".into(), req: vec![], write: false, many: false, skip: None,
                vals: vec![], in_tx: false, aux: 0, out: Outcome::default(),
                observed: Observed::pg_log(known), origin: None,
            };
            agg.add(&Done {
                unit: u, shape: "select ?".into(), racy: false, stall: None, timing: None,
                res: Res::Ran { out: Outcome::default(), latency_ns, lag_ns: 0, waited_ns: 0, order: Order::Kept },
            });
        }
        let copy = agg.clone();
        agg.merge(&copy);
        let r = build(agg, Meta { source: "test".into(), captured_seconds: 0.0, replayed_seconds: 0.0, speed: 1.0, connections: 1 });
        assert_eq!(r.compared.duration, 2);
        assert_eq!(r.compared.rows, 0);
        assert_eq!(r.latency_captured.mean_ms, 1.0);
        assert_eq!(r.latency_replayed.mean_ms, 2.0);
        assert_eq!(r.shapes[0].count, 4);
        assert_eq!(r.shapes[0].ratio, 2.0);
    }

    #[test]
    fn hist_quantiles_are_within_bucket_width_and_merge_adds_up() {
        // Bucket index/midpoint round trip; midpoint within 3.2% of the original.
        for v in [0u64, 1, 31, 32, 33, 1000, 123_456, 9_876_543_210, u64::MAX / 2] {
            let mid = Hist::value(Hist::bucket(v));
            assert!((mid as f64 - v as f64).abs() <= v as f64 * 0.032 + 0.5, "{v} -> {mid}");
            assert_eq!(Hist::bucket(mid), Hist::bucket(v));
        }
        let (mut a, mut b) = (Hist::default(), Hist::default());
        for v in 1..=1000u64 {
            if v % 2 == 0 { &mut a } else { &mut b }.add(v * 1000);
        }
        a.merge(&b);
        let p = a.pct();
        assert!((p.p50_ms - 0.5).abs() < 0.02, "{p:?}");
        assert!((p.p99_ms - 0.99).abs() < 0.04, "{p:?}");
        assert_eq!(p.max_ms, 1.0);
        assert!((p.mean_ms - 0.5005).abs() < 1e-9);
        // Never return above the actual maximum, even for small samples.
        let mut one = Hist::default();
        one.add(1_000_001);
        assert_eq!(one.pct().p50_ms, one.pct().max_ms);
    }
}
