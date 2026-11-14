//! Measured time series for integrations; excludes SQL, request bytes, endpoints, and error text.

use crate::replay::{Done, Res};
use crate::report::judge_observed;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use xxhash_rust::xxh3::xxh3_64;

fn sample(d: &Done, seq: u64) -> Value {
    let (status, success, comparison, error) = match &d.res {
        Res::Ran { out, .. } => (
            "ran", Some(out.err.is_none()),
            Some(judge_observed(&d.unit.sql, &d.unit.out, out, d.racy, d.unit.observed)),
            out.err.as_deref(),
        ),
        Res::Failed(_) => ("failed", d.timing.map(|_| false), None, None),
        Res::Skipped => ("skipped", None, None, None),
        Res::Elsewhere => ("elsewhere", None, None, None),
    };
    // Do not export free-form server text; permit only error-number/SQLSTATE shapes.
    let error = error.filter(|s| s.len() <= 5 && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()));
    json!({
        "type": "sample", "seq": seq, "conn": d.unit.conn,
        "shape_id": format!("{:016x}", xxh3_64(d.shape.as_bytes())),
        "status": status, "request_success": success, "comparison": comparison,
        "error_code": error, "observed": d.unit.observed,
        "captured_start_ns": d.unit.t_start, "captured_end_ns": d.unit.t_end,
        "captured_duration_ns": d.unit.observed.duration.then(|| d.unit.t_end.saturating_sub(d.unit.t_start)),
        "timing": d.timing, "skip": d.unit.skip,
    })
}

/// New tail-readable output file; only an end record establishes completion.
pub struct Writer {
    out: BufWriter<std::fs::File>,
    seq: u64,
}

impl Writer {
    pub fn create(path: &str, run_id: &str, shard: Option<(usize, usize)>) -> Result<Self> {
        ensure!(!run_id.is_empty() && run_id.len() <= 64
            && run_id.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
            "--run-id requires 1–64 ASCII letters, digits, dots, underscores, or hyphens");
        let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        let mut w = Self { out: BufWriter::new(file), seq: 0 };
        let (worker, workers) = shard.unwrap_or((0, 1));
        w.line(&json!({"type": "start", "schema": 1, "run_id": run_id, "worker": worker, "workers": workers}))?;
        w.flush()?;
        Ok(w)
    }

    fn line(&mut self, value: &Value) -> Result<()> {
        serde_json::to_writer(&mut self.out, value)?;
        self.out.write_all(b"\n")?;
        Ok(())
    }

    pub fn add(&mut self, d: &Done) -> Result<()> {
        if matches!(d.res, Res::Elsewhere) {
            return Ok(());
        }
        self.seq += 1;
        self.line(&sample(d, self.seq))
    }

    pub fn flush(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.line(&json!({"type": "end", "samples": self.seq}))?;
        self.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::{Done, Order, Res, Timing};
    use dbtap_core::unit::{Observed, Outcome, Unit};

    fn done(res: Res, attempted: bool) -> Done {
        Done {
            unit: Unit {
                conn: 3, t_start: 10, t_end: 20, sql: "select 'private'".into(),
                req: vec![], write: false, many: false, skip: None, vals: vec![],
                in_tx: false, aux: 0, out: Outcome { err: Some("23505".into()), ..Default::default() },
                observed: Observed::pg_log(false), origin: None,
            },
            shape: "select ?".into(), racy: false, res, stall: None,
            timing: attempted.then_some(Timing {
                started_unix_ns: 1_000_000_000, latency_ns: 123_456,
                lag_ns: 100, waited_ns: 50,
            }),
        }
    }

    #[test]
    fn expected_error_is_separate_from_comparison_and_unknown_duration() {
        let d = done(Res::Ran {
            out: Outcome { err: Some("23505".into()), ..Default::default() },
            latency_ns: 123_456, lag_ns: 100, waited_ns: 50, order: Order::Kept,
        }, true);
        let v = sample(&d, 1);
        assert_eq!(v["request_success"], false);
        assert_eq!(v["comparison"], "Match");
        assert!(v["captured_duration_ns"].is_null());
        assert_eq!(v["timing"]["started_unix_ns"], 1_000_000_000u64);
        assert!(!v.to_string().contains("private"));
        assert!(!v.to_string().contains("select"));
    }

    #[test]
    fn unattempted_and_transport_failure_do_not_become_zero_ms_success() {
        for res in [Res::Skipped, Res::Failed("sensitive detail".into())] {
            let v = sample(&done(res, false), 1);
            assert!(v["timing"].is_null());
            assert!(v["request_success"].is_null());
            assert!(!v.to_string().contains("sensitive"));
        }
        let v = sample(&done(Res::Failed("private".into()), true), 2);
        assert_eq!(v["request_success"], false);
        assert_eq!(v["timing"]["latency_ns"], 123_456);
    }
}
