//! Read journals through per-connection decoders and emit replay units.
//!
//! Emit completed events after each record without retaining the full recording.
//! Units emerge in response-completion order.

use dbtap_core::journal::{Dir, Proto, Reader, Record};
use crate::mysql::MyDecoder;
use crate::pg::PgDecoder;
use dbtap_core::unit::{ConnInfo, Unit};
use anyhow::Result;
use std::collections::HashMap;

enum Dec {
    Pg(PgDecoder),
    My(MyDecoder),
    /// Unknown protocol, inferred from initial bytes.
    Sniff { t_open: u64, client: String, server: String, mid_stream: bool },
    Unknown(ConnInfo),
    Imported(ConnInfo),
}

impl Dec {
    fn feed(&mut self, conn: u64, ts: u64, dir: Dir, bytes: &[u8]) {
        if let Dec::Sniff { t_open, client, server, mid_stream } = self {
            let (t, c, s, m) = (*t_open, std::mem::take(client), std::mem::take(server), *mid_stream);
            // MySQL speaks first with protocol 10; PostgreSQL starts with a length-prefixed client message.
            *self = match dir {
                Dir::ToClient if bytes.len() > 4 && bytes[3] == 0 && bytes[4] == 10 => Dec::My(MyDecoder::new(conn, t, c, s, m)),
                Dir::ToServer if bytes.len() >= 8 && bytes[0] == 0 && bytes[1] == 0 => Dec::Pg(PgDecoder::new(conn, t, c, s, m)),
                _ => {
                    let mut info = ConnInfo::new(conn, Proto::Unknown, t, c, s, m);
                    info.broken = Some("Cannot identify protocol".into());
                    Dec::Unknown(info)
                }
            };
        }
        match self {
            Dec::Pg(d) => d.feed(ts, dir, bytes),
            Dec::My(d) => d.feed(ts, dir, bytes),
            _ => {}
        }
    }

    fn info(&self) -> Option<&ConnInfo> {
        match self {
            Dec::Pg(d) => Some(&d.info),
            Dec::My(d) => Some(&d.info),
            Dec::Unknown(i) | Dec::Imported(i) => Some(i),
            Dec::Sniff { .. } => None,
        }
    }

    fn ready(&self) -> bool {
        match self {
            Dec::Pg(d) => d.ready(),
            Dec::My(d) => d.ready(),
            Dec::Imported(_) => true,
            _ => false,
        }
    }

    fn take_units(&mut self) -> Vec<Unit> {
        match self {
            Dec::Pg(d) => std::mem::take(&mut d.units),
            Dec::My(d) => std::mem::take(&mut d.units),
            _ => Vec::new(),
        }
    }

    fn lost(&mut self, ts: u64) {
        match self {
            Dec::Pg(d) => d.lost(ts),
            Dec::My(d) => d.lost(ts),
            _ => {}
        }
    }

    /// End of connection; closed=false means it remained open at recording end.
    fn close(&mut self, ts: u64, closed: bool) {
        match self {
            Dec::Pg(d) => {
                d.close(ts);
                if !closed {
                    d.info.t_close = None;
                }
            }
            Dec::My(d) => {
                d.close(ts);
                if !closed {
                    d.info.t_close = None;
                }
            }
            Dec::Imported(i) => i.t_close = closed.then_some(ts),
            _ => {}
        }
    }
}

#[derive(Debug)]
pub enum Ev {
    /// Replayable connection discovered; always emitted before its first unit.
    Open(ConnInfo),
    Unit(Unit),
    /// Metadata learned after Open, such as inferred mid-stream capabilities.
    /// Replay connects just before the first request, so earlier metadata updates still apply.
    Info(ConnInfo),
    /// End of an opened connection; open-at-EOF connections use the recording's final timestamp.
    Close { conn: u64, ts: u64 },
}

struct Source {
    rd: Reader<std::fs::File>,
    /// One prefetched record to process next.
    next: Option<Record>,
    /// Journal-local IDs start at one; put the journal index in upper bits to avoid collisions.
    id_base: u64,
}

fn ts_of(r: &Record) -> u64 {
    match r {
        Record::Header { .. } => 0,
        Record::ConnOpen { ts, .. } | Record::Data { ts, .. } | Record::ConnClose { ts, .. } | Record::Lost { ts, .. } => *ts,
        Record::Session { ts, .. } => *ts,
        Record::Unit(u) => u.t_end,
    }
}

/// Merge multiple journals by timestamp into one recording.
/// Timestamps retain each host's clock, requiring synchronized hosts.
pub struct Extractor {
    sources: Vec<Source>,
    decs: HashMap<u64, Dec>,
    /// Opened connections and their published MySQL capabilities/autocommit state.
    announced: HashMap<u64, (u32, bool)>,
    /// Closed connection metadata for summaries, drained by take_closed.
    closed: Vec<ConnInfo>,
    pub source: String,
    /// Capture start in UNIX ns; the target clone must reflect this point.
    pub started_ns: u64,
    pub lost_bytes: u64,
    pub wire_bytes: u64,
    /// First journal timestamp and latest timestamp read.
    pub t_first: u64,
    pub t_last: u64,
    finished: bool,
}

impl Extractor {
    pub fn open(paths: &[String]) -> Result<Self> {
        let mut ex = Extractor {
            sources: Vec::new(),
            decs: HashMap::new(),
            announced: Default::default(),
            closed: Vec::new(),
            source: String::new(),
            started_ns: u64::MAX,
            lost_bytes: 0,
            wire_bytes: 0,
            t_first: u64::MAX,
            t_last: 0,
            finished: false,
        };
        for (k, path) in paths.iter().enumerate() {
            let mut rd = Reader::open(path)?;
            let mut next = rd.next()?;
            // Consume the initial header here.
            while let Some(Record::Header { started_ns, source }) = &next {
                ex.started_ns = ex.started_ns.min(*started_ns);
                if !ex.source.is_empty() {
                    ex.source.push_str(", ");
                }
                ex.source.push_str(source);
                next = rd.next()?;
            }
            if let Some(r) = &next {
                let first = if let Record::Session { info, .. } = r { info.t_open } else { ts_of(r) };
                ex.t_first = ex.t_first.min(first);
            }
            ex.sources.push(Source { rd, next, id_base: (k as u64) << 40 });
        }
        if ex.t_first == u64::MAX {
            ex.t_first = 0;
        }
        if ex.started_ns == u64::MAX {
            ex.started_ns = 0;
        }
        ex.t_last = ex.t_first;
        Ok(ex)
    }

    /// Drain closed connection metadata, including unreplayable connections.
    pub fn take_closed(&mut self) -> Vec<ConnInfo> {
        std::mem::take(&mut self.closed)
    }

    /// Move completed units to out; emit Open on setup completion or before the first unit.
    fn drain(&mut self, conn: u64, out: &mut Vec<Ev>) {
        let Some(d) = self.decs.get_mut(&conn) else { return };
        let units = d.take_units();
        if let Some(info) = d.info() {
            let learned = (info.my_caps, info.my_autocommit_off);
            match self.announced.get_mut(&conn) {
                None if !units.is_empty() || d.ready() => {
                    self.announced.insert(conn, learned);
                    out.push(Ev::Open(info.clone()));
                }
                Some(told) if *told != learned => {
                    *told = learned;
                    out.push(Ev::Info(info.clone()));
                }
                _ => {}
            }
        }
        out.extend(units.into_iter().map(Ev::Unit));
    }

    fn finish_conn(&mut self, conn: u64, ts: u64, closed: bool, out: &mut Vec<Ev>) {
        if let Some(d) = self.decs.get_mut(&conn) {
            d.close(ts, closed);
        }
        self.drain(conn, out);
        if self.announced.remove(&conn).is_some() {
            out.push(Ev::Close { conn, ts });
        }
        if let Some(d) = self.decs.remove(&conn) {
            self.closed.extend(d.info().cloned());
        }
    }

    /// Process one record and append events to out; false at recording end.
    pub fn step(&mut self, out: &mut Vec<Ev>) -> Result<bool> {
        // Read the journal whose next timestamp is earliest.
        let pick = self
            .sources
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.next.as_ref().map(|r| (ts_of(r), i)))
            .min();
        let Some((_, i)) = pick else {
            if !self.finished {
                self.finished = true;
                // Connection remained open until recording end.
                let mut rest: Vec<u64> = self.decs.keys().copied().collect();
                rest.sort_unstable();
                for conn in rest {
                    self.finish_conn(conn, self.t_last, false, out);
                }
            }
            return Ok(false);
        };
        let src = &mut self.sources[i];
        let r = src.next.take().unwrap();
        let base = src.id_base;
        src.next = src.rd.next()?;
        match r {
            // Skip embedded headers from concatenated journals.
            Record::Header { .. } => {}
            Record::Session { ts, mut info } => {
                info.conn += base;
                self.t_last = self.t_last.max(ts);
                if self.decs.contains_key(&info.conn) {
                    anyhow::bail!("Duplicate log connection ID: {}", info.conn);
                }
                let conn = info.conn;
                self.decs.insert(conn, Dec::Imported(info));
                self.drain(conn, out);
            }
            Record::Unit(mut unit) => {
                unit.conn += base;
                if !matches!(self.decs.get(&unit.conn), Some(Dec::Imported(_))) {
                    anyhow::bail!("Missing session metadata for reconstructed unit: {}", unit.conn);
                }
                if unit.t_start > unit.t_end {
                    anyhow::bail!("Unit start is after end");
                }
                self.t_last = self.t_last.max(unit.t_end);
                out.push(Ev::Unit(unit));
            }
            Record::ConnOpen { conn, ts, proto, client, server, mid_stream } => {
                let conn = conn + base;
                self.t_last = self.t_last.max(ts);
                if self.decs.contains_key(&conn) {
                    self.finish_conn(conn, ts, true, out);
                }
                let d = match proto {
                    Proto::Postgres => Dec::Pg(PgDecoder::new(conn, ts, client, server, mid_stream)),
                    Proto::Mysql => Dec::My(MyDecoder::new(conn, ts, client, server, mid_stream)),
                    Proto::Unknown => Dec::Sniff { t_open: ts, client, server, mid_stream },
                };
                self.decs.insert(conn, d);
            }
            Record::Data { conn, ts, dir, bytes } => {
                let conn = conn + base;
                self.t_last = self.t_last.max(ts);
                self.wire_bytes += bytes.len() as u64;
                if let Some(d) = self.decs.get_mut(&conn) {
                    d.feed(conn, ts, dir, &bytes);
                    self.drain(conn, out);
                }
            }
            Record::Lost { conn, ts, bytes } => {
                let conn = conn + base;
                self.t_last = self.t_last.max(ts);
                self.lost_bytes += bytes;
                if let Some(d) = self.decs.get_mut(&conn) {
                    d.lost(ts);
                    self.drain(conn, out);
                }
            }
            Record::ConnClose { conn, ts } => {
                let conn = conn + base;
                self.t_last = self.t_last.max(ts);
                self.finish_conn(conn, ts, true, out);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbtap_core::journal::Writer;
    use crate::pg::tests::{msg, startup};

    #[test]
    fn restored_units_roundtrip_and_are_remapped_between_journals() {
        use dbtap_core::unit::{Observed, Outcome};
        let dir = std::env::temp_dir().join(format!("dbtap-restored-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut paths = Vec::new();
        for n in 0..2 {
            let path = dir.join(format!("{n}.dbtap"));
            paths.push(path.to_str().unwrap().to_string());
            let mut w = Writer::create(&paths[n], "postgres-csv:test").unwrap();
            let mut info = ConnInfo::new(1, Proto::Postgres, 100, "client".into(), "server".into(), true);
            info.user = Some("app".into());
            info.database = Some("shop".into());
            w.write(&Record::Session { ts: 110, info }).unwrap();
            w.write(&Record::Unit(Unit {
                conn: 1, t_start: 105, t_end: 110, sql: "select 1".into(),
                req: msg(b'Q', b"select 1\0"), write: false, many: false, skip: None,
                vals: vec![], in_tx: false, aux: 0, out: Outcome::default(),
                observed: Observed::pg_log(true), origin: None,
            })).unwrap();
            w.finish().unwrap();
        }
        let mut ex = Extractor::open(&paths).unwrap();
        let mut events = vec![];
        while ex.step(&mut events).unwrap() {}
        let ids: Vec<_> = events.iter().filter_map(|e| match e {
            Ev::Open(i) => { assert_eq!(i.database.as_deref(), Some("shop")); None }
            Ev::Unit(u) => { assert!(!u.observed.rows); assert_eq!(u.req, msg(b'Q', b"select 1\0")); Some(u.conn) }
            _ => None,
        }).collect();
        assert_eq!(ids, [1, (1 << 40) + 1]);
        assert_eq!(ex.wire_bytes, 0);
        assert_eq!(ex.take_closed().len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn journal(path: &std::path::Path, t0: u64, sql: &str, close: bool) {
        let mut w = Writer::create(path.to_str().unwrap(), "test").unwrap();
        w.write(&Record::ConnOpen {
            conn: 1,
            ts: t0,
            proto: Proto::Postgres,
            client: "10.0.0.9:5".into(),
            server: "10.0.0.1:5432".into(),
            mid_stream: false,
        })
        .unwrap();
        let mut q = sql.as_bytes().to_vec();
        q.push(0);
        let ready = [msg(b'R', &[0, 0, 0, 0]), msg(b'Z', b"I")].concat();
        let done = [msg(b'C', b"SELECT 1\0"), msg(b'Z', b"I")].concat();
        w.write_data(1, t0 + 1, Dir::ToServer, &startup("app", "shop")).unwrap();
        w.write_data(1, t0 + 2, Dir::ToClient, &ready).unwrap();
        w.write_data(1, t0 + 10, Dir::ToServer, &msg(b'Q', &q)).unwrap();
        w.write_data(1, t0 + 20, Dir::ToClient, &done).unwrap();
        if close {
            w.write(&Record::ConnClose { conn: 1, ts: t0 + 30 }).unwrap();
        }
        w.finish().unwrap();
    }

    #[test]
    fn merges_journals_by_time_and_announces_connections_once() {
        let dir = std::env::temp_dir().join(format!("dbtap-extract-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a.dbtap"), dir.join("b.dbtap"));
        // b starts five earlier; a closes while b remains open.
        journal(&a, 1005, "select 'a'", true);
        journal(&b, 1000, "select 'b'", false);
        let mut ex = Extractor::open(&[a.to_str().unwrap().into(), b.to_str().unwrap().into()]).unwrap();
        assert_eq!(ex.t_first, 1000);
        let mut ev = Vec::new();
        while ex.step(&mut ev).unwrap() {}
        let line: Vec<String> = ev
            .iter()
            .map(|e| match e {
                Ev::Open(i) => format!("open {}", i.conn >> 40),
                Ev::Unit(u) => format!("unit {} {}", u.conn >> 40, u.sql),
                Ev::Info(i) => format!("info {}", i.conn >> 40),
                Ev::Close { conn, ts } => format!("close {} {ts}", conn >> 40),
            })
            .collect();
        // Emit connections after authentication and units in completion order.
        assert_eq!(
            line,
            ["open 1", "open 0", "unit 1 select 'b'", "unit 0 select 'a'", "close 0 1035", "close 1 1035"]
        );
        // Equal IDs in different journals must remain distinct connections.
        assert_eq!(ex.take_closed().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn later_findings_about_a_mid_stream_connection_are_passed_on() {
        use crate::mysql::tests::pkt;
        let dir = std::env::temp_dir().join(format!("dbtap-extract-info-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.dbtap");
        let mut w = Writer::create(path.to_str().unwrap(), "test").unwrap();
        w.write(&Record::ConnOpen {
            conn: 1,
            ts: 100,
            proto: Proto::Mysql,
            client: "10.0.0.9:5".into(),
            server: "10.0.0.1:3306".into(),
            mid_stream: true,
        })
        .unwrap();
        let ok = pkt(1, &[0, 0, 0, 2, 0, 0, 0]);
        // First command is PING; query-attribute support is still unknown.
        w.write_data(1, 110, Dir::ToServer, &pkt(0, &[0x0e])).unwrap();
        w.write_data(1, 111, Dir::ToClient, &ok).unwrap();
        // The next COM_QUERY reveals query attributes.
        w.write_data(1, 120, Dir::ToServer, &pkt(0, b"\x03\x00\x01select 1")).unwrap();
        w.write_data(1, 121, Dir::ToClient, &ok).unwrap();
        w.finish().unwrap();
        let mut ex = Extractor::open(&[path.to_str().unwrap().into()]).unwrap();
        let mut ev = Vec::new();
        while ex.step(&mut ev).unwrap() {}
        let attrs = |i: &ConnInfo| i.my_caps & crate::mysql::CLIENT_QUERY_ATTRIBUTES != 0;
        let line: Vec<String> = ev
            .iter()
            .map(|e| match e {
                Ev::Open(i) => format!("open attrs={}", attrs(i)),
                Ev::Info(i) => format!("info attrs={}", attrs(i)),
                Ev::Unit(u) => format!("unit {}", u.sql),
                Ev::Close { .. } => "close".into(),
            })
            .collect();
        assert_eq!(line, ["open attrs=false", "unit [PING]", "info attrs=true", "unit select 1", "close"]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
