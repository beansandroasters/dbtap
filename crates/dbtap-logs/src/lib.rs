//! Import database-owned records such as query logs.

pub mod pg;
pub mod mysql;

use anyhow::{Result, ensure};
use dbtap_core::journal::{Record, Writer};
use std::{collections::BTreeMap, io::Write};

/// Sort small completion-time reversals; reject records arriving beyond the window.
pub struct OrderedWriter<W: Write> {
    writer: Writer<W>,
    pending: BTreeMap<(u64, u64), Record>,
    seq: u64,
    latest: u64,
    written: u64,
    window: u64,
}

impl<W: Write> OrderedWriter<W> {
    pub fn new(writer: Writer<W>, window_ns: u64) -> Self {
        Self { writer, pending: BTreeMap::new(), seq: 0, latest: 0, written: 0, window: window_ns }
    }

    pub fn push(&mut self, record: Record) -> Result<()> {
        let ts = match &record {
            Record::Session { ts, .. } | Record::ConnClose { ts, .. } => *ts,
            Record::Unit(u) => u.t_end,
            _ => anyhow::bail!("Not a log record"),
        };
        ensure!(ts >= self.written, "Log timestamp reversal exceeds sort window; increase --sort-window-ms");
        self.latest = self.latest.max(ts);
        self.pending.insert((ts, self.seq), record);
        self.seq += 1;
        self.flush_until(self.latest.saturating_sub(self.window))?;
        ensure!(self.pending.len() <= 1_000_000, "More than one million pending records; reduce the sort window");
        Ok(())
    }

    fn flush_until(&mut self, ts: u64) -> Result<()> {
        while self.pending.first_key_value().is_some_and(|(k, _)| k.0 <= ts) {
            let ((at, _), record) = self.pending.pop_first().unwrap();
            self.writer.write(&record)?;
            self.written = at;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.flush_until(u64::MAX)?;
        self.writer.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbtap_core::journal::Reader;

    #[test]
    fn sorts_log_events_and_rejects_lateness_beyond_window() {
        let mut bytes = Vec::new();
        let mut w = OrderedWriter::new(Writer::new_at(&mut bytes, "test", 0).unwrap(), 10);
        w.push(Record::ConnClose { conn: 1, ts: 20 }).unwrap();
        w.push(Record::ConnClose { conn: 2, ts: 15 }).unwrap();
        w.push(Record::ConnClose { conn: 3, ts: 40 }).unwrap();
        assert!(w.push(Record::ConnClose { conn: 4, ts: 19 }).is_err());
        w.finish().unwrap();
        let mut r = Reader::new(&bytes[..]).unwrap();
        r.next().unwrap();
        assert_eq!(r.next().unwrap(), Some(Record::ConnClose { conn: 2, ts: 15 }));
        assert_eq!(r.next().unwrap(), Some(Record::ConnClose { conn: 1, ts: 20 }));
        assert_eq!(r.next().unwrap(), Some(Record::ConnClose { conn: 3, ts: 40 }));
    }
}
