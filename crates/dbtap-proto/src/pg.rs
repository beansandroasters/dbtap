//! Reconstruct PostgreSQL wire protocol v3 into replay units.
//!
//! ReadyForQuery ends a unit. For pipelined batches, seal requests at Query/Sync
//! and enqueue them without waiting for the preceding response.
//! Each ReadyForQuery completes the oldest queued request.

use dbtap_core::journal::{Dir, Proto};
use dbtap_core::unit::{ConnInfo, Outcome, Skip, Unit, int_key, is_write, literal_keys, push_val, val_key};
use std::collections::{HashMap, VecDeque};

const MAX_MSG: usize = 1 << 30;
/// Maximum retained statements per unit; overflow becomes a global dependency.
const MAX_SQLS: usize = 32;
const FE_TYPES: &[u8] = b"QPBEDCSHXFdcfp";
const BE_TYPES: &[u8] = b"RSKZTDCEINA123nstGHWdcv";

pub fn cstr(b: &[u8]) -> (&[u8], &[u8]) {
    match b.iter().position(|&c| c == 0) {
        Some(p) => (&b[..p], &b[p + 1..]),
        None => (b, &[]),
    }
}

/// Fold one backend message into the outcome; Some(status) indicates ReadyForQuery.
#[inline]
pub fn fold_backend(out: &mut Outcome, tag_write: &mut bool, typ: u8, payload: &[u8]) -> Option<u8> {
    match typ {
        b'D' => out.add_row(payload),
        // COPY TO STDOUT row.
        b'd' => out.add_row(payload),
        b'C' => {
            let (tag, _) = cstr(payload);
            let tag = std::str::from_utf8(tag).unwrap_or("");
            if is_write(tag) {
                *tag_write = true;
            }
            let verb = tag.split(' ').next().unwrap_or("");
            if matches!(verb, "INSERT" | "UPDATE" | "DELETE" | "MERGE" | "COPY") {
                if let Some(n) = tag.rsplit(' ').next().and_then(|n| n.parse::<u64>().ok()) {
                    out.affected += n;
                }
            }
        }
        b'E' => {
            if out.err.is_none() {
                out.err = Some(error_field(payload, b'C').unwrap_or_else(|| "?????".into()));
            }
        }
        b'Z' => return Some(payload.first().copied().unwrap_or(b'I')),
        _ => {}
    }
    None
}

pub fn error_field(payload: &[u8], want: u8) -> Option<String> {
    let mut p = payload;
    while let Some(&code) = p.first() {
        if code == 0 {
            break;
        }
        let (val, rest) = cstr(&p[1..]);
        if code == want {
            return Some(String::from_utf8_lossy(val).into_owned());
        }
        p = rest;
    }
    None
}

/// Extract value keys from Bind format codes and parameter values.
fn bind_keys(mut p: &[u8], vals: &mut Vec<u64>, overflow: &mut bool) -> Option<()> {
    let u16at = |p: &[u8]| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?]) as usize);
    let nfmt = u16at(p)?;
    let fmts = p.get(2..2 + nfmt * 2)?;
    p = &p[2 + nfmt * 2..];
    let n = u16at(p)?;
    p = &p[2..];
    for k in 0..n {
        let len = i32::from_be_bytes(p.get(..4)?.try_into().ok()?);
        p = &p[4..];
        if len < 0 {
            continue;
        }
        let v = p.get(..len as usize)?;
        p = &p[len as usize..];
        // Format codes: none means all text, one applies to all, otherwise one per parameter.
        let binary = match nfmt {
            0 => false,
            1 => fmts[1] == 1,
            _ => fmts.get(k * 2 + 1) == Some(&1),
        };
        let key = match (binary, v.len()) {
            (true, 2) => int_key(i16::from_be_bytes([v[0], v[1]]) as i64),
            (true, 4) => int_key(i32::from_be_bytes([v[0], v[1], v[2], v[3]]) as i64),
            (true, 8) => int_key(i64::from_be_bytes(v.try_into().ok()?)),
            _ => val_key(v),
        };
        push_val(vals, overflow, key);
    }
    Some(())
}

/// Typed message at `buf[pos..]`; Ok(None) means incomplete input.
#[inline]
pub fn peek(buf: &[u8], pos: usize) -> Result<Option<(u8, usize)>, ()> {
    if buf.len() < pos + 5 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[pos + 1], buf[pos + 2], buf[pos + 3], buf[pos + 4]]) as usize;
    if !(4..=MAX_MSG).contains(&len) {
        return Err(());
    }
    if buf.len() < pos + 1 + len {
        return Ok(None);
    }
    Ok(Some((buf[pos], 1 + len)))
}

/// Find a plausible message boundary in a mid-stream capture.
/// Accept an exact parse through the tail or three consecutive valid messages.
fn find_sync(buf: &[u8], types: &[u8]) -> Option<usize> {
    'outer: for start in 0..buf.len().min(64 * 1024) {
        let mut pos = start;
        let mut n = 0;
        loop {
            if pos == buf.len() {
                if n > 0 {
                    return Some(start);
                }
                continue 'outer;
            }
            if !types.contains(&buf[pos]) {
                continue 'outer;
            }
            match peek(buf, pos) {
                Ok(Some((_, total))) => {
                    pos += total;
                    n += 1;
                    if n >= 3 {
                        return Some(start);
                    }
                }
                // Allow an incomplete last message if at least one complete message precedes it.
                Ok(None) if n > 0 => return Some(start),
                _ => continue 'outer,
            }
        }
    }
    None
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Phase {
    Startup,
    SslReply,
    Auth,
    Ready,
    Dead,
}

struct Group {
    t_start: u64,
    req: Vec<u8>,
    sqls: Vec<String>,
    sealed: bool,
    skip: Option<Skip>,
    out: Outcome,
    tag_write: bool,
    many: bool,
    vals: Vec<u64>,
    vals_overflow: bool,
}

pub struct PgDecoder {
    pub info: ConnInfo,
    phase: Phase,
    fe: Vec<u8>,
    be: Vec<u8>,
    /// Time the incomplete leading frontend message began arriving, for request start.
    fe_ts: u64,
    fe_synced: bool,
    be_synced: bool,
    /// Statement name to SQL; unnamed statements use an empty name.
    stmts: HashMap<Vec<u8>, String>,
    pending: VecDeque<Group>,
    in_tx: bool,
    pub units: Vec<Unit>,
}

impl PgDecoder {
    pub fn new(conn: u64, t_open: u64, client: String, server: String, mid_stream: bool) -> Self {
        PgDecoder {
            info: ConnInfo::new(conn, Proto::Postgres, t_open, client, server, mid_stream),
            phase: if mid_stream { Phase::Ready } else { Phase::Startup },
            fe: Vec::new(),
            be: Vec::new(),
            fe_ts: 0,
            fe_synced: !mid_stream,
            be_synced: !mid_stream,
            stmts: HashMap::new(),
            pending: VecDeque::new(),
            in_tx: false,
            units: Vec::new(),
        }
    }

    /// Authentication has completed and enough metadata exists to recreate the connection.
    /// For mid-stream connections, this is known only after the first unit.
    pub fn ready(&self) -> bool {
        !self.info.mid_stream && self.phase == Phase::Ready
    }

    pub fn feed(&mut self, ts: u64, dir: Dir, bytes: &[u8]) {
        if self.phase == Phase::Dead {
            return;
        }
        match dir {
            Dir::ToServer => {
                let mut buf = std::mem::take(&mut self.fe);
                let first_ts = if buf.is_empty() { ts } else { self.fe_ts };
                buf.extend_from_slice(bytes);
                let used = self.frontend(ts, first_ts, &buf);
                buf.drain(..used);
                self.fe = buf;
                self.fe_ts = ts;
            }
            Dir::ToClient => {
                if !self.be_synced {
                    // Tail of a response to an unseen request; wait until a request is observed.
                    if self.pending.is_empty() {
                        return;
                    }
                    self.be_synced = true;
                }
                let mut buf = std::mem::take(&mut self.be);
                buf.extend_from_slice(bytes);
                let used = self.backend(ts, &buf);
                buf.drain(..used);
                self.be = buf;
            }
        }
    }

    fn die(&mut self, ts: u64, why: &str) {
        self.info.broken = Some(why.to_string());
        self.phase = Phase::Dead;
        self.flush_incomplete(ts);
    }

    /// After loss, resynchronize boundaries and discard the unreliable statement map.
    pub fn lost(&mut self, ts: u64) {
        if self.phase == Phase::Dead {
            return;
        }
        if self.phase != Phase::Ready {
            return self.die(ts, "Capture loss during connection setup");
        }
        self.flush_incomplete(ts);
        self.fe.clear();
        self.be.clear();
        self.fe_synced = false;
        self.be_synced = false;
        self.stmts.clear();
    }

    pub fn close(&mut self, ts: u64) {
        self.info.t_close = Some(ts);
        self.flush_incomplete(ts);
    }

    fn flush_incomplete(&mut self, ts: u64) {
        while let Some(mut g) = self.pending.pop_front() {
            g.skip = Some(Skip::Incomplete);
            self.emit(g, ts);
        }
    }

    fn emit(&mut self, g: Group, ts: u64) {
        self.emit_tx(g, ts, None)
    }

    /// ReadyForQuery status: I idle, T in transaction, E in failed transaction.
    fn emit_tx(&mut self, g: Group, ts: u64, status: Option<u8>) {
        if let Some(s) = status {
            self.in_tx = s != b'I';
        }
        let sql = if g.sqls.is_empty() { "[sync]".to_string() } else { g.sqls.join(";\n") };
        let write = g.tag_write || g.sqls.iter().any(|s| is_write(s));
        self.units.push(Unit {
            conn: self.info.conn,
            t_start: g.t_start,
            t_end: ts,
            sql,
            req: g.req,
            write,
            many: g.many,
            skip: g.skip,
            vals: g.vals,
            in_tx: self.in_tx,
            aux: 0,
            out: g.out,
            observed: Default::default(),
            origin: None,
        });
    }

    fn startup(&mut self, ts: u64, buf: &[u8]) -> usize {
        if buf.len() < 8 {
            return 0;
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let code = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if !(8..=10_000).contains(&len) {
            self.die(ts, "Invalid StartupMessage");
            return buf.len();
        }
        if buf.len() < len {
            return 0;
        }
        match code {
            // SSLRequest/GSSENCRequest: server next returns a one-byte decision.
            80877103 | 80877104 => self.phase = Phase::SslReply,
            80877102 => self.die(ts, "Cancellation connection"),
            c if c >> 16 == 3 => {
                let mut p = &buf[8..len];
                while !p.is_empty() && p[0] != 0 {
                    let (k, rest) = cstr(p);
                    let (v, rest) = cstr(rest);
                    let k = String::from_utf8_lossy(k).into_owned();
                    let v = String::from_utf8_lossy(v).into_owned();
                    match k.as_str() {
                        "user" => self.info.user = Some(v),
                        "database" => self.info.database = Some(v),
                        _ => self.info.params.push((k, v)),
                    }
                    p = rest;
                }
                if self.info.params.iter().any(|(k, _)| k == "replication") {
                    self.die(ts, "Replication connection");
                    return buf.len();
                }
                self.phase = Phase::Auth;
            }
            _ => {
                self.die(ts, "Unsupported protocol version");
                return buf.len();
            }
        }
        len
    }

    fn frontend(&mut self, ts: u64, first_ts: u64, buf: &[u8]) -> usize {
        let mut pos = 0;
        let mut msg_ts = first_ts;
        if !self.fe_synced {
            match find_sync(buf, FE_TYPES) {
                Some(p) => {
                    pos = p;
                    self.fe_synced = true;
                }
                // Discard chunks without a boundary and retry at the next chunk.
                None => return buf.len(),
            }
        }
        loop {
            match self.phase {
                Phase::Dead => return buf.len(),
                Phase::Startup => {
                    let n = self.startup(ts, &buf[pos..]);
                    if n == 0 {
                        return pos;
                    }
                    pos += n;
                    continue;
                }
                // Wait for the server's negotiation response before processing further client data.
                Phase::SslReply => return pos,
                Phase::Auth | Phase::Ready => {}
            }
            let (typ, total) = match peek(buf, pos) {
                Ok(Some(m)) => m,
                Ok(None) => return pos,
                Err(()) => {
                    self.die(ts, "Invalid frontend message length");
                    return buf.len();
                }
            };
            let raw = &buf[pos..pos + total];
            pos += total;
            if self.phase == Phase::Auth {
                // Authentication exchanges (password/SASL responses) do not form replay units.
                continue;
            }
            if !FE_TYPES.contains(&typ) {
                self.die(ts, "Unknown frontend message");
                return buf.len();
            }
            self.frontend_msg(msg_ts, typ, raw);
            msg_ts = ts;
        }
    }

    fn frontend_msg(&mut self, ts: u64, typ: u8, raw: &[u8]) {
        let payload = &raw[5..];
        match typ {
            b'X' | b'p' => return,
            // COPY data belongs to the prior request even after sealing it.
            b'd' | b'c' | b'f' if !self.pending.is_empty() => {}
            _ => {
                if self.pending.back().is_none_or(|g| g.sealed) {
                    self.pending.push_back(Group {
                        t_start: ts,
                        req: Vec::with_capacity(raw.len() + 64),
                        sqls: Vec::new(),
                        sealed: false,
                        skip: None,
                        out: Outcome::default(),
                        tag_write: false,
                        many: false,
                        vals: Vec::new(),
                        vals_overflow: false,
                    });
                }
            }
        }
        let g = self.pending.back_mut().unwrap();
        g.req.extend_from_slice(raw);
        let note = |g: &mut Group, sql: &str| {
            if g.sqls.iter().any(|s| s == sql) {
                return;
            }
            if g.sqls.len() < MAX_SQLS {
                g.sqls.push(sql.to_string());
            } else {
                g.many = true;
            }
        };
        match typ {
            b'Q' => {
                let (sql, _) = cstr(payload);
                let sql = String::from_utf8_lossy(sql);
                literal_keys(&sql, &mut g.vals, &mut g.vals_overflow);
                note(g, &sql);
                g.sealed = true;
            }
            b'P' => {
                let (name, rest) = cstr(payload);
                let (sql, _) = cstr(rest);
                self.stmts.insert(name.to_vec(), String::from_utf8_lossy(sql).into_owned());
            }
            b'B' => {
                let (_portal, rest) = cstr(payload);
                let (stmt, rest) = cstr(rest);
                match self.stmts.get(stmt) {
                    Some(sql) => {
                        // SQL literals also contribute value keys.
                        literal_keys(sql, &mut g.vals, &mut g.vals_overflow);
                        note(g, sql)
                    }
                    None => g.skip = Some(Skip::UnknownStatement),
                }
                if bind_keys(rest, &mut g.vals, &mut g.vals_overflow).is_none() {
                    g.vals.clear();
                    g.vals_overflow = true;
                }
            }
            b'D' => {
                // Describe Statement is unreplayable if its statement is unknown.
                if payload.first() == Some(&b'S') {
                    let (stmt, _) = cstr(&payload[1..]);
                    if !self.stmts.contains_key(stmt) {
                        g.skip = Some(Skip::UnknownStatement);
                    }
                }
            }
            b'C' => {
                if payload.first() == Some(&b'S') {
                    let (stmt, _) = cstr(&payload[1..]);
                    self.stmts.remove(stmt);
                }
            }
            b'S' | b'F' => g.sealed = true,
            _ => {}
        }
    }

    fn backend(&mut self, ts: u64, buf: &[u8]) -> usize {
        let mut pos = 0;
        if self.phase == Phase::SslReply {
            if buf.is_empty() {
                return 0;
            }
            if buf[0] == b'N' {
                self.phase = Phase::Startup;
                pos = 1;
                // Resume the pending client data.
                let fe = std::mem::take(&mut self.fe);
                let used = self.frontend(ts, self.fe_ts, &fe);
                self.fe = fe[used..].to_vec();
            } else {
                self.info.encrypted = true;
                self.phase = Phase::Dead;
                return buf.len();
            }
        }
        loop {
            if self.phase == Phase::Dead {
                return buf.len();
            }
            let (typ, total) = match peek(buf, pos) {
                Ok(Some(m)) => m,
                Ok(None) => return pos,
                Err(()) => {
                    self.die(ts, "Invalid backend message length");
                    return buf.len();
                }
            };
            if !BE_TYPES.contains(&typ) {
                self.die(ts, "Unknown backend message");
                return buf.len();
            }
            let payload = &buf[pos + 5..pos + total];
            pos += total;
            if self.phase == Phase::Auth {
                match typ {
                    b'Z' => self.phase = Phase::Ready,
                    b'E' => {
                        self.die(ts, "Authentication failed");
                        return buf.len();
                    }
                    _ => {}
                }
                continue;
            }
            let Some(g) = self.pending.front_mut() else { continue };
            if let Some(status) = fold_backend(&mut g.out, &mut g.tag_write, typ, payload) {
                let g = self.pending.pop_front().unwrap();
                self.emit_tx(g, ts, Some(status));
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn msg(typ: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![typ];
        v.extend_from_slice(&(payload.len() as u32 + 4).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    pub fn startup(user: &str, db: &str) -> Vec<u8> {
        let mut p = 196608u32.to_be_bytes().to_vec();
        for (k, v) in [("user", user), ("database", db), ("application_name", "t")] {
            p.extend_from_slice(k.as_bytes());
            p.push(0);
            p.extend_from_slice(v.as_bytes());
            p.push(0);
        }
        p.push(0);
        let mut v = (p.len() as u32 + 4).to_be_bytes().to_vec();
        v.extend(p);
        v
    }

    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    fn parse(name: &str, sql: &str) -> Vec<u8> {
        msg(b'P', &cat(&[name.as_bytes().to_vec(), vec![0], sql.as_bytes().to_vec(), vec![0, 0, 0]]))
    }

    fn bind(stmt: &str) -> Vec<u8> {
        msg(b'B', &cat(&[vec![0], stmt.as_bytes().to_vec(), vec![0, 0, 0, 0, 0, 0, 0]]))
    }

    fn exec() -> Vec<u8> {
        msg(b'E', &[0, 0, 0, 0, 0])
    }

    #[test]
    fn bind_parameters_become_value_keys() {
        let mut d = PgDecoder::new(1, 0, "c".into(), "s".into(), false);
        handshake(&mut d);
        // Two format codes (text/binary), three values (text 7, int4 9, NULL); third format absent.
        let mut b = cat(&[vec![0], b"s1\0".to_vec()]);
        b.extend_from_slice(&[0, 2, 0, 0, 0, 1]);
        b.extend_from_slice(&[0, 3]);
        b.extend_from_slice(&[0, 0, 0, 1, b'7']);
        b.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 9]);
        b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        b.extend_from_slice(&[0, 0]);
        d.feed(10, Dir::ToServer, &cat(&[parse("s1", "update t set a = a + $1 where id = $2 and k = 3"), msg(b'B', &b), exec(), msg(b'S', b"")]));
        d.feed(11, Dir::ToClient, &cat(&[msg(b'C', b"UPDATE 1\0"), msg(b'Z', b"I")]));
        assert_eq!(d.units[0].vals, [val_key(b"3"), val_key(b"7"), int_key(9)]);
    }

    fn row(v: &[u8]) -> Vec<u8> {
        msg(b'D', v)
    }

    fn handshake(d: &mut PgDecoder) {
        d.feed(1, Dir::ToServer, &startup("app", "shop"));
        d.feed(2, Dir::ToClient, &msg(b'R', &[0, 0, 0, 3]));
        d.feed(3, Dir::ToServer, &msg(b'p', b"secret\0"));
        d.feed(4, Dir::ToClient, &cat(&[msg(b'R', &[0, 0, 0, 0]), msg(b'K', &[0; 8]), msg(b'Z', b"I")]));
    }

    #[test]
    fn simple_query_split_across_chunks() {
        let mut d = PgDecoder::new(1, 0, "c".into(), "s".into(), false);
        handshake(&mut d);
        assert_eq!(d.info.user.as_deref(), Some("app"));
        assert_eq!(d.info.database.as_deref(), Some("shop"));
        let q = msg(b'Q', b"select * from t\0");
        d.feed(10, Dir::ToServer, &q[..3]);
        d.feed(11, Dir::ToServer, &q[3..]);
        let resp = cat(&[msg(b'T', &[0, 0]), row(b"a"), row(b"b"), msg(b'C', b"SELECT 2\0"), msg(b'Z', b"I")]);
        d.feed(20, Dir::ToClient, &resp[..9]);
        d.feed(21, Dir::ToClient, &resp[9..]);
        assert_eq!(d.units.len(), 1);
        let u = &d.units[0];
        assert_eq!((u.t_start, u.t_end, u.out.rows, u.write), (10, 21, 2, false));
        assert_eq!(u.sql, "select * from t");
        assert_eq!(u.req, q);
        // Authentication exchanges must not appear in units.
        assert!(!u.req.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn pipelined_extended_batches() {
        let mut d = PgDecoder::new(1, 0, "c".into(), "s".into(), false);
        handshake(&mut d);
        let b1 = cat(&[parse("s1", "update t set a=$1"), bind("s1"), exec(), msg(b'S', b"")]);
        let b2 = cat(&[bind("s1"), exec(), msg(b'S', b"")]);
        // Two batches without waiting for responses.
        d.feed(10, Dir::ToServer, &cat(&[b1.clone(), b2.clone()]));
        d.feed(20, Dir::ToClient, &cat(&[msg(b'1', b""), msg(b'2', b""), msg(b'C', b"UPDATE 3\0"), msg(b'Z', b"I")]));
        d.feed(30, Dir::ToClient, &cat(&[msg(b'2', b""), msg(b'E', b"SERROR\0C23505\0Mdup\0\0"), msg(b'Z', b"I")]));
        assert_eq!(d.units.len(), 2);
        assert_eq!(d.units[0].req, b1);
        assert_eq!((d.units[0].out.affected, d.units[0].write), (3, true));
        assert_eq!(d.units[1].req, b2);
        assert_eq!(d.units[1].out.err.as_deref(), Some("23505"));
        assert!(!d.units[0].in_tx && !d.units[1].in_tx);
        // After BEGIN the server reports an active transaction.
        d.feed(40, Dir::ToServer, &msg(b'Q', b"begin\0"));
        d.feed(41, Dir::ToClient, &cat(&[msg(b'C', b"BEGIN\0"), msg(b'Z', b"T")]));
        assert!(d.units[2].in_tx);
        assert_eq!(d.units[1].sql, "update t set a=$1");
    }

    #[test]
    fn mid_stream_skips_unknown_statement_until_reparsed() {
        let mut d = PgDecoder::new(1, 0, "c".into(), "s".into(), true);
        // Discard the tail of a response to an unseen request.
        d.feed(5, Dir::ToClient, &cat(&[row(b"x"), msg(b'Z', b"I")])[3..]);
        d.feed(10, Dir::ToServer, &cat(&[bind("old"), exec(), msg(b'S', b"")]));
        d.feed(11, Dir::ToClient, &cat(&[msg(b'2', b""), row(b"a"), msg(b'C', b"SELECT 1\0"), msg(b'Z', b"I")]));
        d.feed(20, Dir::ToServer, &cat(&[parse("", "select 1"), bind(""), exec(), msg(b'S', b"")]));
        d.feed(21, Dir::ToClient, &cat(&[msg(b'1', b""), msg(b'2', b""), row(b"a"), msg(b'C', b"SELECT 1\0"), msg(b'Z', b"I")]));
        assert_eq!(d.units.len(), 2);
        assert_eq!(d.units[0].skip, Some(Skip::UnknownStatement));
        assert_eq!(d.units[1].skip, None);
        assert_eq!(d.units[1].out.rows, 1);
    }

    #[test]
    fn ssl_request_marks_encrypted() {
        let mut d = PgDecoder::new(1, 0, "c".into(), "s".into(), false);
        d.feed(1, Dir::ToServer, &[0, 0, 0, 8, 4, 210, 22, 47]);
        d.feed(2, Dir::ToClient, b"S");
        d.feed(3, Dir::ToServer, &[22, 3, 1, 0, 5, 1, 2, 3, 4, 5]);
        assert!(d.info.encrypted);
        assert!(d.units.is_empty());
    }

    #[test]
    fn ssl_refused_then_plain() {
        let mut d = PgDecoder::new(1, 0, "c".into(), "s".into(), false);
        d.feed(1, Dir::ToServer, &[0, 0, 0, 8, 4, 210, 22, 47]);
        d.feed(2, Dir::ToClient, b"N");
        handshake(&mut d);
        d.feed(10, Dir::ToServer, &msg(b'Q', b"commit\0"));
        d.feed(11, Dir::ToClient, &cat(&[msg(b'C', b"COMMIT\0"), msg(b'Z', b"I")]));
        assert_eq!(d.units.len(), 1);
        assert!(d.units[0].write);
    }

    #[test]
    fn copy_in_stays_in_one_unit() {
        let mut d = PgDecoder::new(1, 0, "c".into(), "s".into(), false);
        handshake(&mut d);
        let q = msg(b'Q', b"copy t from stdin\0");
        let data = cat(&[msg(b'd', b"1\n"), msg(b'd', b"2\n"), msg(b'c', b"")]);
        d.feed(10, Dir::ToServer, &q);
        d.feed(11, Dir::ToClient, &msg(b'G', &[0, 0, 0]));
        d.feed(12, Dir::ToServer, &data);
        d.feed(13, Dir::ToClient, &cat(&[msg(b'C', b"COPY 2\0"), msg(b'Z', b"I")]));
        assert_eq!(d.units.len(), 1);
        assert_eq!(d.units[0].req, cat(&[q, data]));
        assert_eq!(d.units[0].out.affected, 2);
    }

    #[test]
    fn close_flushes_pending_as_incomplete() {
        let mut d = PgDecoder::new(1, 0, "c".into(), "s".into(), false);
        handshake(&mut d);
        d.feed(10, Dir::ToServer, &msg(b'Q', b"select pg_sleep(100)\0"));
        d.close(50);
        assert_eq!(d.units[0].skip, Some(Skip::Incomplete));
    }
}
