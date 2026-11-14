//! Reconstruct MySQL client/server protocol into replay units.
//!
//! Each unit is one command and response. Response boundaries depend on command type;
//! the Resp state machine tracks them and is reused by the replay client.

use dbtap_core::journal::{Dir, Proto};
use dbtap_core::unit::{ConnInfo, Outcome, Skip, Unit, int_key, is_write, literal_keys, push_val, val_key};
use std::collections::HashMap;

pub const CLIENT_LONG_PASSWORD: u32 = 0x1;
pub const CLIENT_LONG_FLAG: u32 = 0x4;
pub const CLIENT_CONNECT_WITH_DB: u32 = 0x8;
pub const CLIENT_COMPRESS: u32 = 0x20;
pub const CLIENT_PROTOCOL_41: u32 = 0x200;
pub const CLIENT_SSL: u32 = 0x800;
pub const CLIENT_TRANSACTIONS: u32 = 0x2000;
pub const CLIENT_SECURE_CONNECTION: u32 = 0x8000;
pub const CLIENT_MULTI_STATEMENTS: u32 = 0x1_0000;
pub const CLIENT_MULTI_RESULTS: u32 = 0x2_0000;
pub const CLIENT_PS_MULTI_RESULTS: u32 = 0x4_0000;
pub const CLIENT_PLUGIN_AUTH: u32 = 0x8_0000;
pub const CLIENT_PLUGIN_AUTH_LENENC: u32 = 0x20_0000;
pub const CLIENT_DEPRECATE_EOF: u32 = 0x100_0000;
pub const CLIENT_ZSTD: u32 = 0x400_0000;
pub const CLIENT_QUERY_ATTRIBUTES: u32 = 0x800_0000;

pub const COM_QUIT: u8 = 0x01;
pub const COM_INIT_DB: u8 = 0x02;
pub const COM_QUERY: u8 = 0x03;
pub const COM_FIELD_LIST: u8 = 0x04;
pub const COM_STATISTICS: u8 = 0x09;
pub const COM_CHANGE_USER: u8 = 0x11;
pub const COM_BINLOG_DUMP: u8 = 0x12;
pub const COM_STMT_PREPARE: u8 = 0x16;
pub const COM_STMT_EXECUTE: u8 = 0x17;
pub const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
pub const COM_STMT_CLOSE: u8 = 0x19;
pub const COM_STMT_RESET: u8 = 0x1a;
pub const COM_STMT_FETCH: u8 = 0x1c;
pub const COM_BINLOG_DUMP_GTID: u8 = 0x1e;

const STATUS_IN_TRANS: u16 = 0x0001;
const STATUS_AUTOCOMMIT: u16 = 0x0002;
const STATUS_MORE_RESULTS: u16 = 0x0008;
const STATUS_CURSOR_EXISTS: u16 = 0x0040;
const MAX_PACKET: usize = 0xff_ffff;

pub fn lenenc(p: &[u8]) -> Option<(u64, usize)> {
    match *p.first()? {
        n @ 0..=0xfa => Some((n as u64, 1)),
        0xfc => Some((u16::from_le_bytes(p.get(1..3)?.try_into().ok()?) as u64, 3)),
        0xfd => {
            let b = p.get(1..4)?;
            Some((b[0] as u64 | (b[1] as u64) << 8 | (b[2] as u64) << 16, 4))
        }
        0xfe => Some((u64::from_le_bytes(p.get(1..9)?.try_into().ok()?), 9)),
        _ => None,
    }
}

fn cstr(b: &[u8]) -> (&[u8], &[u8]) {
    match b.iter().position(|&c| c == 0) {
        Some(p) => (&b[..p], &b[p + 1..]),
        None => (b, &[]),
    }
}

pub fn command_name(cmd: u8) -> &'static str {
    match cmd {
        COM_QUIT => "QUIT",
        COM_INIT_DB => "INIT_DB",
        COM_QUERY => "QUERY",
        COM_FIELD_LIST => "FIELD_LIST",
        COM_STATISTICS => "STATISTICS",
        0x0e => "PING",
        COM_CHANGE_USER => "CHANGE_USER",
        COM_STMT_PREPARE => "STMT_PREPARE",
        COM_STMT_EXECUTE => "STMT_EXECUTE",
        COM_STMT_SEND_LONG_DATA => "STMT_SEND_LONG_DATA",
        COM_STMT_CLOSE => "STMT_CLOSE",
        COM_STMT_RESET => "STMT_RESET",
        0x1b => "SET_OPTION",
        COM_STMT_FETCH => "STMT_FETCH",
        0x1f => "RESET_CONNECTION",
        _ => "OTHER",
    }
}

/// Expected response shape for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    None,
    Ok,
    Result,
    Prepare,
    Rows,
    FieldList,
    OnePacket,
    Auth,
    /// Unbounded binlog stream; unsupported.
    Stream,
}

pub fn expect_for(cmd: u8) -> Expect {
    match cmd {
        COM_QUIT | COM_STMT_CLOSE | COM_STMT_SEND_LONG_DATA => Expect::None,
        COM_QUERY | COM_STMT_EXECUTE => Expect::Result,
        COM_STMT_PREPARE => Expect::Prepare,
        COM_STMT_FETCH => Expect::Rows,
        COM_FIELD_LIST => Expect::FieldList,
        COM_STATISTICS => Expect::OnePacket,
        COM_CHANGE_USER => Expect::Auth,
        COM_BINLOG_DUMP | COM_BINLOG_DUMP_GTID => Expect::Stream,
        _ => Expect::Ok,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    First(Expect),
    ColDefs(u64),
    AfterCols,
    Rows,
    /// Remaining parameters/columns; stage 0=params, 1=EOF, 2=columns, 3=EOF, 4=done.
    PrepDefs(u32, u32, u8),
    /// LOAD DATA LOCAL waits for the client to finish sending file contents.
    Infile,
    Done,
}

/// State machine for one command's response.
pub struct Resp {
    st: St,
    pub out: Outcome,
    /// Server statement ID from successful COM_STMT_PREPARE.
    pub stmt_id: Option<u32>,
    /// Server requested LOCAL INFILE.
    pub infile: bool,
    /// Whether CLIENT_DEPRECATE_EOF is set; None learns from response shape.
    pub deprecate_eof: Option<bool>,
    /// Whether PREPARE includes parameter/column definitions.
    prep_had: (bool, bool),
    /// Prepared statement parameter count.
    pub prep_params: usize,
    /// Last server status flags, including autocommit and active transaction.
    pub status: Option<u16>,
}

impl Resp {
    pub fn new(e: Expect, deprecate_eof: Option<bool>) -> Self {
        let st = if matches!(e, Expect::None | Expect::Stream) { St::Done } else { St::First(e) };
        Resp { st, out: Outcome::default(), stmt_id: None, infile: false, deprecate_eof, prep_had: (false, false), prep_params: 0, status: None }
    }

    pub fn done(&self) -> bool {
        self.st == St::Done
    }

    /// Waiting for more client input (LOCAL INFILE or authentication switch response).
    pub fn wants_client(&self) -> bool {
        matches!(self.st, St::Infile | St::First(Expect::Auth))
    }

    /// Waiting for LOCAL INFILE contents.
    pub fn wants_infile(&self) -> bool {
        self.st == St::Infile
    }

    pub fn client_packet(&mut self, p: &[u8]) {
        if self.st == St::Infile && p.is_empty() {
            self.st = St::First(Expect::Ok);
        }
    }

    fn err(&mut self, p: &[u8]) {
        if self.out.err.is_none() {
            let code = p.get(1..3).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0);
            self.out.err = Some(code.to_string());
        }
        self.st = St::Done;
    }

    /// Read affected rows and status flags from an OK packet (0x00 or 0xfe).
    fn ok_fields(p: &[u8]) -> (u64, u16) {
        let mut i = 1;
        let Some((aff, n)) = lenenc(&p[i.min(p.len())..]) else { return (0, 0) };
        i += n;
        let Some((_, n)) = lenenc(&p[i.min(p.len())..]) else { return (aff, 0) };
        i += n;
        let st = p.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0);
        (aff, st)
    }

    fn after_result(&mut self, status: u16) {
        self.status = Some(status);
        self.st = if status & STATUS_MORE_RESULTS != 0 { St::First(Expect::Result) } else { St::Done };
    }

    /// Fold one reassembled server packet into the outcome; true means complete.
    pub fn packet(&mut self, p: &[u8]) -> bool {
        let first = p.first().copied().unwrap_or(0);
        let is_eof5 = first == 0xfe && p.len() == 5;
        match self.st {
            St::Done | St::Infile => {}
            St::First(e) => match (e, first) {
                (Expect::OnePacket, _) => self.st = St::Done,
                (Expect::Auth, 0x01 | 0xfe) => {}
                (_, 0xff) => self.err(p),
                (Expect::Auth, _) => self.st = St::Done,
                (Expect::Prepare, _) => {
                    if p.len() >= 9 {
                        self.stmt_id = Some(u32::from_le_bytes([p[1], p[2], p[3], p[4]]));
                        let cols = u16::from_le_bytes([p[5], p[6]]) as u32;
                        let params = u16::from_le_bytes([p[7], p[8]]) as u32;
                        self.prep_had = (params > 0, cols > 0);
                        self.prep_params = params as usize;
                        self.st = St::PrepDefs(params, cols, 0);
                        self.settle_prepare();
                    } else {
                        self.st = St::Done;
                    }
                }
                (Expect::Rows, _) => {
                    self.st = St::Rows;
                    return self.packet(p);
                }
                (Expect::FieldList, _) => {
                    if first == 0xfe && p.len() < MAX_PACKET {
                        self.st = St::Done;
                    }
                }
                (Expect::Ok, _) => {
                    if first == 0x00 {
                        let (aff, status) = Self::ok_fields(p);
                        self.out.affected += aff;
                        self.status = Some(status);
                    }
                    self.st = St::Done;
                }
                (Expect::Result, 0x00) => {
                    let (aff, status) = Self::ok_fields(p);
                    self.out.affected += aff;
                    self.after_result(status);
                }
                (Expect::Result, 0xfb) => {
                    self.infile = true;
                    self.st = St::Infile;
                }
                (Expect::Result, _) => match lenenc(p) {
                    Some((n, _)) if n > 0 => self.st = St::ColDefs(n),
                    _ => self.st = St::Done,
                },
                (Expect::None | Expect::Stream, _) => self.st = St::Done,
            },
            St::ColDefs(n) => self.st = if n > 1 { St::ColDefs(n - 1) } else { St::AfterCols },
            St::AfterCols => {
                if self.deprecate_eof != Some(true) && is_eof5 {
                    // EOF between column definitions and rows; opening a cursor may return no rows.
                    self.deprecate_eof = Some(false);
                    let status = u16::from_le_bytes([p[3], p[4]]);
                    if status & STATUS_CURSOR_EXISTS != 0 {
                        self.after_result(status);
                    } else {
                        self.st = St::Rows;
                    }
                } else {
                    if self.deprecate_eof.is_none() {
                        self.deprecate_eof = Some(true);
                    }
                    self.st = St::Rows;
                    return self.packet(p);
                }
            }
            St::Rows => {
                if first == 0xff {
                    self.err(p);
                } else if first == 0xfe && p.len() < MAX_PACKET {
                    // End of rows: legacy five-byte EOF or an OK-shaped terminator.
                    let status = if is_eof5 { u16::from_le_bytes([p[3], p[4]]) } else { Self::ok_fields(p).1 };
                    self.after_result(status);
                } else {
                    self.out.add_row(p);
                }
            }
            St::PrepDefs(mut params, mut cols, mut stage) => {
                // Definitions are parameters [EOF] columns [EOF]; DEPRECATE_EOF controls terminators.
                loop {
                    match stage {
                        0 if params > 0 => {
                            params -= 1;
                            break;
                        }
                        0 => stage = if self.prep_had.0 { 1 } else { 2 },
                        1 if self.deprecate_eof == Some(true) => stage = 2,
                        1 if is_eof5 => {
                            self.deprecate_eof = Some(false);
                            stage = 2;
                            break;
                        }
                        1 => {
                            // A column definition where EOF was expected implies EOF suppression.
                            self.deprecate_eof = Some(true);
                            stage = 2;
                        }
                        2 if cols > 0 => {
                            cols -= 1;
                            break;
                        }
                        2 => stage = 3,
                        // Final EOF.
                        _ => break,
                    }
                }
                self.st = St::PrepDefs(params, cols, if stage == 3 { 4 } else { stage });
                self.settle_prepare();
            }
        }
        self.done()
    }

    /// Complete PREPARE without another packet if all required definitions have arrived.
    /// If EOF mode is unknown, assume completion; the caller discards a later EOF.
    fn settle_prepare(&mut self) {
        let St::PrepDefs(params, cols, mut stage) = self.st else { return };
        let (had_params, had_cols) = self.prep_had;
        if stage == 4 {
            self.st = St::Done;
            return;
        }
        if stage == 0 && params == 0 {
            stage = if had_params { 1 } else { 2 };
        }
        if stage == 1 {
            match self.deprecate_eof {
                Some(true) => stage = 2,
                None if cols == 0 => stage = 4,
                _ => {}
            }
        }
        if stage == 2 && cols == 0 {
            stage = if had_cols && self.deprecate_eof == Some(false) { 3 } else { 4 };
        }
        self.st = if stage == 4 { St::Done } else { St::PrepDefs(params, cols, stage) };
    }
}

/// Strip packet framing; maximum-size packets continue into the next packet.
pub struct Framer {
    buf: Vec<u8>,
    joined: Vec<u8>,
}

impl Framer {
    pub fn new() -> Self {
        Framer { buf: Vec::new(), joined: Vec::new() }
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.joined.clear();
    }

    /// Feed bytes and call f(first packet sequence, payload) for each completed packet.
    pub fn push(&mut self, bytes: &[u8], mut f: impl FnMut(u8, &[u8])) -> bool {
        if bytes.len() > dbtap_core::journal::MAX_FIELD.saturating_sub(self.buf.len()) {
            self.clear();
            return false;
        }
        self.buf.extend_from_slice(bytes);
        let mut pos = 0;
        while self.buf.len() >= pos + 4 {
            let len = self.buf[pos] as usize | (self.buf[pos + 1] as usize) << 8 | (self.buf[pos + 2] as usize) << 16;
            let seq = self.buf[pos + 3];
            if self.buf.len() < pos + 4 + len {
                break;
            }
            let payload = &self.buf[pos + 4..pos + 4 + len];
            pos += 4 + len;
            if len == MAX_PACKET || !self.joined.is_empty() {
                if len > dbtap_core::journal::MAX_FIELD.saturating_sub(self.joined.len()) {
                    self.clear();
                    return false;
                }
                self.joined.extend_from_slice(payload);
                if len < MAX_PACKET {
                    f(seq, &self.joined);
                    self.joined.clear();
                }
            } else {
                f(seq, payload);
            }
        }
        self.buf.drain(..pos);
        true
    }
}

/// Extract SQL from COM_QUERY, skipping query attributes if present.
pub fn query_text(payload: &[u8], attrs: bool) -> &[u8] {
    let p = &payload[1.min(payload.len())..];
    if !attrs {
        return p;
    }
    skip_query_attrs(p).unwrap_or(p)
}

fn skip_query_attrs(p: &[u8]) -> Option<&[u8]> {
    let (count, n) = lenenc(p)?;
    let mut i = n;
    let (_sets, n) = lenenc(p.get(i..)?)?;
    i += n;
    if count == 0 {
        return p.get(i..);
    }
    let count = count as usize;
    let bitmap = p.get(i..i + count.div_ceil(8))?;
    i += count.div_ceil(8);
    let bind = *p.get(i)?;
    i += 1;
    if bind != 1 {
        return None;
    }
    let mut types = Vec::with_capacity(count);
    for _ in 0..count {
        types.push(*p.get(i)?);
        i += 2;
        let (l, n) = lenenc(p.get(i..)?)?;
        i += n + l as usize;
    }
    for (k, t) in types.iter().enumerate() {
        if bitmap[k / 8] & (1 << (k % 8)) != 0 {
            continue;
        }
        i += binary_value(*t, p.get(i..)?)?.0;
    }
    p.get(i..)
}

/// One binary value: byte length and normalized value key.
fn binary_value(typ: u8, p: &[u8]) -> Option<(usize, u64)> {
    let int = |n: usize| -> Option<(usize, u64)> {
        let b = p.get(..n)?;
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(b);
        // Interpret signed integers by width to match text representations.
        let x = match n {
            1 => v[0] as i8 as i64,
            2 => i16::from_le_bytes([v[0], v[1]]) as i64,
            4 => i32::from_le_bytes([v[0], v[1], v[2], v[3]]) as i64,
            _ => i64::from_le_bytes(v),
        };
        Some((n, int_key(x)))
    };
    match typ {
        0x01 => int(1),
        0x02 | 0x0d => int(2),
        0x03 | 0x09 => int(4),
        0x08 => int(8),
        0x04 => Some((4, val_key(p.get(..4)?))),
        0x05 => Some((8, val_key(p.get(..8)?))),
        0x06 => Some((0, val_key(b""))),
        0x07 | 0x0a | 0x0b | 0x0c => {
            let n = 1 + *p.first()? as usize;
            Some((n, val_key(p.get(..n)?)))
        }
        _ => {
            let (l, n) = lenenc(p)?;
            Some((n + l as usize, val_key(p.get(n..n + l as usize)?)))
        }
    }
}

/// Retained server-side prepared statement metadata.
struct Stmt {
    sql: String,
    params: usize,
    /// Types from the latest EXECUTE, reused when the next EXECUTE omits them.
    types: Vec<u8>,
}

/// Extract value keys from COM_STMT_EXECUTE parameters; None on decode failure.
fn execute_keys(p: &[u8], st: &mut Stmt, attrs: bool, vals: &mut Vec<u64>, overflow: &mut bool) -> Option<()> {
    // Command(1), statement ID(4), flags(1), iteration count(4).
    let mut i = 10;
    let mut n = st.params;
    // Attribute-capable clients send only the header if there are no parameters or attributes.
    // Treating this as truncation would also discard valid literal keys from SQL.
    if n == 0 && p.len() == i {
        return Some(());
    }
    if attrs {
        let (c, k) = lenenc(p.get(i..)?)?;
        n = c as usize;
        i += k;
    }
    if n == 0 {
        return Some(());
    }
    let bitmap = p.get(i..i + n.div_ceil(8))?;
    i += n.div_ceil(8);
    let bound = *p.get(i)?;
    i += 1;
    if bound == 1 {
        st.types.clear();
        for _ in 0..n {
            st.types.push(*p.get(i)?);
            i += 2;
            if attrs {
                let (l, k) = lenenc(p.get(i..)?)?;
                i += k + l as usize;
            }
        }
    }
    if st.types.len() != n {
        return None;
    }
    for k in 0..n {
        if bitmap[k / 8] & (1 << (k % 8)) != 0 {
            continue;
        }
        let (len, key) = binary_value(st.types[k], p.get(i..)?)?;
        i += len;
        push_val(vals, overflow, key);
    }
    Some(())
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Phase {
    Greeting,
    Login,
    Auth,
    Command,
    Dead,
}

struct Cur {
    unit: Unit,
    resp: Resp,
    cmd: u8,
}

pub struct MyDecoder {
    pub info: ConnInfo,
    phase: Phase,
    fe: Framer,
    be: Framer,
    fe_synced: bool,
    server_caps: u32,
    /// Query-attribute mode, inferred from the first COM_QUERY for mid-stream capture.
    attrs: Option<bool>,
    deprecate_eof: Option<bool>,
    stmts: HashMap<u32, Stmt>,
    cur: Option<Cur>,
    status_seen: bool,
    in_tx: bool,
    /// Autocommit from the latest response flags; None before observation.
    autocommit: Option<bool>,
    pub units: Vec<Unit>,
}

impl MyDecoder {
    pub fn new(conn: u64, t_open: u64, client: String, server: String, mid_stream: bool) -> Self {
        MyDecoder {
            info: ConnInfo::new(conn, Proto::Mysql, t_open, client, server, mid_stream),
            phase: if mid_stream { Phase::Command } else { Phase::Greeting },
            fe: Framer::new(),
            be: Framer::new(),
            fe_synced: !mid_stream,
            server_caps: 0,
            attrs: None,
            deprecate_eof: None,
            stmts: HashMap::new(),
            cur: None,
            status_seen: false,
            in_tx: false,
            autocommit: None,
            units: Vec::new(),
        }
    }

    /// Authentication completed with enough metadata to recreate the connection.
    /// For mid-stream capture, this is known only after the first unit.
    pub fn ready(&self) -> bool {
        !self.info.mid_stream && self.phase == Phase::Command
    }

    pub fn feed(&mut self, ts: u64, dir: Dir, bytes: &[u8]) {
        if self.phase == Phase::Dead {
            return;
        }
        match dir {
            Dir::ToServer => {
                if !self.fe_synced {
                    if !looks_like_command_start(bytes) {
                        return;
                    }
                    self.fe_synced = true;
                }
                let mut fr = std::mem::replace(&mut self.fe, Framer::new());
                if !fr.push(bytes, |seq, p| self.client_packet(ts, seq, p)) {
                    self.die(ts, "MySQL message exceeds the 64 MiB limit");
                }
                self.fe = fr;
            }
            Dir::ToClient => {
                // Server output without a pending command is the tail of an unseen response.
                if self.phase == Phase::Command && self.cur.is_none() {
                    self.be.clear();
                    return;
                }
                let mut fr = std::mem::replace(&mut self.be, Framer::new());
                if !fr.push(bytes, |seq, p| self.server_packet(ts, seq, p)) {
                    self.die(ts, "MySQL message exceeds the 64 MiB limit");
                }
                self.be = fr;
            }
        }
        if self.phase == Phase::Dead {
            self.fe.clear();
            self.be.clear();
        }
    }

    fn die(&mut self, ts: u64, why: &str) {
        self.info.broken = Some(why.to_string());
        self.phase = Phase::Dead;
        self.flush_incomplete(ts);
    }

    pub fn lost(&mut self, ts: u64) {
        if self.phase == Phase::Dead {
            return;
        }
        if self.phase != Phase::Command {
            return self.die(ts, "Capture loss during connection setup");
        }
        self.flush_incomplete(ts);
        self.fe.clear();
        self.be.clear();
        self.fe_synced = false;
        self.stmts.clear();
    }

    pub fn close(&mut self, ts: u64) {
        self.info.t_close = Some(ts);
        self.flush_incomplete(ts);
    }

    fn flush_incomplete(&mut self, ts: u64) {
        if let Some(mut c) = self.cur.take() {
            c.unit.skip = Some(Skip::Incomplete);
            self.finish(c, ts);
        }
    }

    fn finish(&mut self, mut c: Cur, ts: u64) {
        c.unit.t_end = ts;
        if c.resp.infile {
            c.unit.skip = Some(Skip::Interactive);
        }
        if let Some(d) = c.resp.deprecate_eof {
            self.deprecate_eof = Some(d);
        }
        if self.info.mid_stream {
            // Without a handshake, pass inferred protocol settings to replay.
            let mut caps = CLIENT_PROTOCOL_41 | CLIENT_MULTI_STATEMENTS;
            if self.attrs == Some(true) {
                caps |= CLIENT_QUERY_ATTRIBUTES;
            }
            if self.deprecate_eof == Some(true) {
                caps |= CLIENT_DEPRECATE_EOF;
            }
            self.info.my_caps = caps;
            if !self.status_seen {
                if let Some(st) = c.resp.status {
                    // Response status reveals whether autocommit was disabled before capture.
                    self.info.my_autocommit_off = st & STATUS_AUTOCOMMIT == 0;
                    self.status_seen = true;
                }
            }
        }
        if c.cmd == COM_STMT_PREPARE {
            if let Some(id) = c.resp.stmt_id {
                self.stmts.insert(id, Stmt { sql: c.unit.sql.clone(), params: c.resp.prep_params, types: Vec::new() });
                c.unit.aux = id;
            }
        }
        match c.resp.status {
            Some(st) => {
                self.in_tx = st & STATUS_IN_TRANS != 0;
                self.autocommit = Some(st & STATUS_AUTOCOMMIT != 0);
            }
            // Errors have no status flags. With autocommit off or unknown, failed statements
            // can still begin transactions and retain locks, such as duplicate-key errors.
            None if c.resp.out.err.is_some() && self.autocommit != Some(true) => self.in_tx = true,
            None => {}
        }
        c.unit.in_tx = self.in_tx;
        c.unit.out = std::mem::take(&mut c.resp.out);
        self.units.push(c.unit);
    }

    fn client_packet(&mut self, ts: u64, seq: u8, p: &[u8]) {
        match self.phase {
            Phase::Dead | Phase::Greeting => {}
            Phase::Login => self.login(ts, p),
            // Exclude authentication exchanges.
            Phase::Auth => {}
            Phase::Command => {
                if let Some(c) = &mut self.cur {
                    if c.resp.wants_client() && seq != 0 {
                        c.resp.client_packet(p);
                        return;
                    }
                }
                self.command(ts, p);
            }
        }
    }

    fn login(&mut self, ts: u64, p: &[u8]) {
        if p.len() < 32 {
            return self.die(ts, "Invalid HandshakeResponse");
        }
        let caps = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
        if caps & CLIENT_PROTOCOL_41 == 0 {
            return self.die(ts, "Protocol older than 4.1");
        }
        self.info.my_caps = caps;
        self.info.my_charset = p[8];
        if p.len() == 32 && caps & CLIENT_SSL != 0 {
            self.info.encrypted = true;
            self.phase = Phase::Dead;
            return;
        }
        let (user, rest) = cstr(&p[32..]);
        self.info.user = Some(String::from_utf8_lossy(user).into_owned());
        let rest = if caps & CLIENT_PLUGIN_AUTH_LENENC != 0 {
            lenenc(rest).and_then(|(l, n)| rest.get(n + l as usize..)).unwrap_or(&[])
        } else if caps & CLIENT_SECURE_CONNECTION != 0 {
            rest.first().and_then(|&l| rest.get(1 + l as usize..)).unwrap_or(&[])
        } else {
            cstr(rest).1
        };
        if caps & CLIENT_CONNECT_WITH_DB != 0 {
            let (db, _) = cstr(rest);
            if !db.is_empty() {
                self.info.database = Some(String::from_utf8_lossy(db).into_owned());
            }
        }
        let both = caps & self.server_caps;
        self.attrs = Some(both & CLIENT_QUERY_ATTRIBUTES != 0);
        self.deprecate_eof = Some(both & CLIENT_DEPRECATE_EOF != 0);
        self.phase = Phase::Auth;
    }

    fn command(&mut self, ts: u64, p: &[u8]) {
        // A new command before response completion makes the preceding unit incomplete.
        self.flush_incomplete(ts);
        let Some(&cmd) = p.first() else { return };
        if cmd == COM_QUIT {
            return;
        }
        let expect = expect_for(cmd);
        if expect == Expect::Stream {
            return self.die(ts, "Replication connection");
        }
        let stmt_id = || p.get(1..5).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        let mut skip = None;
        let (mut vals, mut overflow) = (Vec::new(), false);
        let sql = match cmd {
            COM_QUERY => {
                let attrs = *self.attrs.get_or_insert_with(|| {
                    // SQL does not begin with small control bytes; infer an attribute count.
                    p.get(1).is_some_and(|&b| b < 0x09)
                });
                let sql = String::from_utf8_lossy(query_text(p, attrs)).into_owned();
                literal_keys(&sql, &mut vals, &mut overflow);
                sql
            }
            COM_STMT_PREPARE => String::from_utf8_lossy(&p[1..]).into_owned(),
            COM_STMT_EXECUTE | COM_STMT_FETCH | COM_STMT_RESET | COM_STMT_SEND_LONG_DATA | COM_STMT_CLOSE => {
                let attrs = self.attrs == Some(true);
                match stmt_id().and_then(|id| self.stmts.get_mut(&id)) {
                    Some(st) if cmd == COM_STMT_EXECUTE => {
                        literal_keys(&st.sql, &mut vals, &mut overflow);
                        if execute_keys(p, st, attrs, &mut vals, &mut overflow).is_none() {
                            vals.clear();
                        }
                        st.sql.clone()
                    }
                    Some(_) => String::new(),
                    None => {
                        skip = Some(Skip::UnknownStatement);
                        String::new()
                    }
                }
            }
            COM_INIT_DB => format!("USE {}", String::from_utf8_lossy(&p[1..])),
            _ => String::new(),
        };
        // Captured authentication responses use the original nonce and cannot authenticate replay.
        if cmd == COM_CHANGE_USER {
            skip = Some(Skip::Interactive);
        }
        // Name commands without SQL for distinct aggregation labels.
        let sql = if sql.is_empty() { format!("[{}]", command_name(cmd)) } else { sql };
        if cmd == COM_STMT_CLOSE {
            if let Some(id) = stmt_id() {
                self.stmts.remove(&id);
            }
        }
        let write = matches!(cmd, COM_QUERY | COM_STMT_EXECUTE) && is_write(&sql);
        let unit = Unit {
            conn: self.info.conn,
            t_start: ts,
            t_end: ts,
            sql,
            req: p.to_vec(),
            write,
            many: false,
            skip,
            vals,
            in_tx: false,
            aux: 0,
            out: Outcome::default(),
            observed: Default::default(),
            origin: None,
        };
        let c = Cur { unit, resp: Resp::new(expect, self.deprecate_eof), cmd };
        if c.resp.done() {
            self.finish(c, ts);
        } else {
            self.cur = Some(c);
        }
    }

    fn server_packet(&mut self, ts: u64, _seq: u8, p: &[u8]) {
        match self.phase {
            Phase::Dead | Phase::Login => {}
            Phase::Greeting => {
                if p.first() != Some(&10) {
                    return self.die(ts, "Unsupported handshake");
                }
                // Version string, connection ID(4), auth data(8), filler(1), lower capabilities(2), charset(1), status(2), upper capabilities(2).
                let (_, rest) = cstr(&p[1..]);
                if let Some(id) = rest.get(..4) {
                    self.info.server_session = Some(u32::from_le_bytes(id.try_into().unwrap()).to_string());
                }
                if let Some(r) = rest.get(13..20) {
                    self.server_caps = u16::from_le_bytes([r[0], r[1]]) as u32 | (u16::from_le_bytes([r[5], r[6]]) as u32) << 16;
                }
                self.phase = Phase::Login;
            }
            Phase::Auth => match p.first() {
                Some(0x00) => {
                    if self.info.my_caps & self.server_caps & (CLIENT_COMPRESS | CLIENT_ZSTD) != 0 {
                        return self.die(ts, "Compressed protocol is unsupported");
                    }
                    self.phase = Phase::Command;
                }
                Some(0xff) => self.die(ts, "Authentication failed"),
                _ => {}
            },
            Phase::Command => {
                let Some(c) = &mut self.cur else { return };
                if c.resp.packet(p) {
                    let c = self.cur.take().unwrap();
                    self.finish(c, ts);
                }
            }
        }
    }
}

/// Whether a mid-stream chunk plausibly begins at a command boundary.
fn looks_like_command_start(b: &[u8]) -> bool {
    let mut pos = 0;
    let mut first = true;
    while b.len() >= pos + 4 {
        let len = b[pos] as usize | (b[pos + 1] as usize) << 8 | (b[pos + 2] as usize) << 16;
        if first && (b[pos + 3] != 0 || len == 0 || b.get(pos + 4).is_none_or(|&c| c > 0x20)) {
            return false;
        }
        first = false;
        pos += 4 + len;
        if len < MAX_PACKET {
            // A complete command at chunk end, or an incomplete long SQL statement.
            return pos >= b.len();
        }
    }
    false
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn pkt(seq: u8, payload: &[u8]) -> Vec<u8> {
        let l = payload.len();
        let mut v = vec![l as u8, (l >> 8) as u8, (l >> 16) as u8, seq];
        v.extend_from_slice(payload);
        v
    }

    pub fn greeting(caps: u32) -> Vec<u8> {
        let mut p = vec![10];
        p.extend_from_slice(b"8.4.0\0");
        p.extend_from_slice(&[1, 0, 0, 0]);
        p.extend_from_slice(&[b'a'; 8]);
        p.push(0);
        p.extend_from_slice(&(caps as u16).to_le_bytes());
        p.push(45);
        p.extend_from_slice(&[2, 0]);
        p.extend_from_slice(&((caps >> 16) as u16).to_le_bytes());
        p.push(21);
        p.extend_from_slice(&[0; 10]);
        p.extend_from_slice(&[b'b'; 13]);
        p.extend_from_slice(b"caching_sha2_password\0");
        pkt(0, &p)
    }

    pub fn login(caps: u32, user: &str, db: &str) -> Vec<u8> {
        let mut p = caps.to_le_bytes().to_vec();
        p.extend_from_slice(&[0, 0, 0, 1, 45]);
        p.extend_from_slice(&[0; 23]);
        p.extend_from_slice(user.as_bytes());
        p.push(0);
        p.extend_from_slice(&[3, 1, 2, 3]);
        p.extend_from_slice(db.as_bytes());
        p.push(0);
        pkt(1, &p)
    }

    const OK: &[u8] = &[0, 0, 0, 2, 0, 0, 0];
    const EOF: &[u8] = &[0xfe, 0, 0, 2, 0];
    const COLDEF: &[u8] = b"\x03def\0\0\0\x011\0\x0c\x3f\0\x01\0\0\0\x08\x81\0\0\0\0";

    fn connect(d: &mut MyDecoder, caps: u32) {
        let caps = caps | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB;
        d.feed(1, Dir::ToClient, &greeting(caps));
        d.feed(2, Dir::ToServer, &login(caps, "app", "shop"));
        d.feed(3, Dir::ToClient, &pkt(2, OK));
    }

    fn com(cmd: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![cmd];
        p.extend_from_slice(body);
        pkt(0, &p)
    }

    #[test]
    fn text_resultset_with_eof() {
        let mut d = MyDecoder::new(1, 0, "c".into(), "s".into(), false);
        connect(&mut d, 0);
        assert_eq!((d.info.user.as_deref(), d.info.database.as_deref()), (Some("app"), Some("shop")));
        assert_eq!(d.info.server_session.as_deref(), Some("1"));
        d.feed(10, Dir::ToServer, &com(COM_QUERY, b"select 1"));
        let resp = [pkt(1, &[1]), pkt(2, COLDEF), pkt(3, EOF), pkt(4, b"\x011"), pkt(5, b"\x012"), pkt(6, EOF)].concat();
        // Decode across chunk boundaries within a packet.
        d.feed(11, Dir::ToClient, &resp[..7]);
        assert!(d.units.is_empty());
        d.feed(12, Dir::ToClient, &resp[7..]);
        assert_eq!(d.units.len(), 1);
        let u = &d.units[0];
        assert_eq!((u.t_start, u.t_end, u.out.rows, u.write), (10, 12, 2, false));
        assert_eq!(u.sql, "select 1");
    }

    #[test]
    fn text_resultset_deprecate_eof() {
        let mut d = MyDecoder::new(1, 0, "c".into(), "s".into(), false);
        connect(&mut d, CLIENT_DEPRECATE_EOF);
        d.feed(10, Dir::ToServer, &com(COM_QUERY, b"select 1"));
        let term = [0xfe, 0, 0, 2, 0, 0, 0];
        d.feed(11, Dir::ToClient, &[pkt(1, &[1]), pkt(2, COLDEF), pkt(3, b"\x011"), pkt(4, &term)].concat());
        assert_eq!(d.units[0].out.rows, 1);
        // Empty result set.
        d.feed(20, Dir::ToServer, &com(COM_QUERY, b"select 1 where false"));
        d.feed(21, Dir::ToClient, &[pkt(1, &[1]), pkt(2, COLDEF), pkt(3, &term)].concat());
        assert_eq!(d.units.len(), 2);
        assert_eq!(d.units[1].out.rows, 0);
    }

    #[test]
    fn dml_error_and_multi_results() {
        let mut d = MyDecoder::new(1, 0, "c".into(), "s".into(), false);
        connect(&mut d, 0);
        d.feed(10, Dir::ToServer, &com(COM_QUERY, b"update t set a=1"));
        d.feed(11, Dir::ToClient, &pkt(1, &[0, 3, 0, 2, 0, 0, 0]));
        d.feed(20, Dir::ToServer, &com(COM_QUERY, b"insert into t values (1)"));
        d.feed(21, Dir::ToClient, &pkt(1, &[0xff, 0x26, 0x04, b'#', b'2', b'3', b'0', b'0', b'0', b'd']));
        // More result sets follow while status flag 0x08 is set.
        d.feed(30, Dir::ToServer, &com(COM_QUERY, b"update t set a=2; update t set a=3"));
        d.feed(31, Dir::ToClient, &pkt(1, &[0, 2, 0, 0x0a, 0, 0, 0]));
        assert_eq!(d.units.len(), 2);
        d.feed(32, Dir::ToClient, &pkt(2, &[0, 5, 0, 2, 0, 0, 0]));
        assert_eq!(d.units.len(), 3);
        assert_eq!((d.units[0].out.affected, d.units[0].write), (3, true));
        assert_eq!(d.units[1].out.err.as_deref(), Some("1062"));
        // Prior OK has autocommit on (0x0002) outside a transaction; an error leaves it outside.
        assert!(!d.units[0].in_tx && !d.units[1].in_tx);
        assert_eq!(d.units[2].out.affected, 7);
    }

    fn prep_ok(id: u32, cols: u16, params: u16) -> Vec<u8> {
        let mut p = vec![0];
        p.extend_from_slice(&id.to_le_bytes());
        p.extend_from_slice(&cols.to_le_bytes());
        p.extend_from_slice(&params.to_le_bytes());
        p.extend_from_slice(&[0, 0, 0]);
        p
    }

    fn exec(id: u32) -> Vec<u8> {
        let mut b = id.to_le_bytes().to_vec();
        b.extend_from_slice(&[0, 1, 0, 0, 0]);
        com(COM_STMT_EXECUTE, &b)
    }

    #[test]
    fn prepared_statement_lifecycle() {
        for deprecate in [false, true] {
            let mut d = MyDecoder::new(1, 0, "c".into(), "s".into(), false);
            connect(&mut d, if deprecate { CLIENT_DEPRECATE_EOF } else { 0 });
            d.feed(10, Dir::ToServer, &com(COM_STMT_PREPARE, b"select a from t where id = ?"));
            let mut resp = vec![pkt(1, &prep_ok(7, 1, 1)), pkt(2, COLDEF)];
            if !deprecate {
                resp.push(pkt(3, EOF));
            }
            resp.push(pkt(4, COLDEF));
            if !deprecate {
                resp.push(pkt(5, EOF));
            }
            d.feed(11, Dir::ToClient, &resp.concat());
            assert_eq!(d.units.len(), 1, "deprecate={deprecate}");
            assert_eq!(d.units[0].aux, 7);

            d.feed(20, Dir::ToServer, &exec(7));
            let mut resp = vec![pkt(1, &[1]), pkt(2, COLDEF)];
            if !deprecate {
                resp.push(pkt(3, EOF));
            }
            resp.push(pkt(4, &[0, 0, 5, 0, 0, 0]));
            resp.push(if deprecate { pkt(5, &[0xfe, 0, 0, 2, 0, 0, 0]) } else { pkt(5, EOF) });
            d.feed(21, Dir::ToClient, &resp.concat());
            assert_eq!(d.units.len(), 2, "deprecate={deprecate}");
            assert_eq!(d.units[1].sql, "select a from t where id = ?");
            assert_eq!(d.units[1].out.rows, 1);

            // CLOSE has no response; the next command follows immediately.
            d.feed(30, Dir::ToServer, &[com(COM_STMT_CLOSE, &7u32.to_le_bytes()), exec(7)].concat());
            assert_eq!(d.units.len(), 3);
            d.feed(31, Dir::ToClient, &pkt(1, &[0xff, 0x4b, 0x05, b'#', b'H', b'Y', b'0', b'0', b'0']));
            assert_eq!(d.units.len(), 4);
            assert_eq!(d.units[3].skip, Some(Skip::UnknownStatement));
        }
    }

    #[test]
    fn execute_parameters_become_value_keys() {
        let mut d = MyDecoder::new(1, 0, "c".into(), "s".into(), false);
        connect(&mut d, CLIENT_DEPRECATE_EOF);
        d.feed(10, Dir::ToServer, &com(COM_STMT_PREPARE, b"update t set a = a + ? where id = ? and k = 3"));
        d.feed(11, Dir::ToClient, &[pkt(1, &prep_ok(7, 0, 2)), pkt(2, COLDEF), pkt(3, COLDEF)].concat());
        // Two typed parameters: LONGLONG 5 and string 42.
        let mut b = 7u32.to_le_bytes().to_vec();
        b.extend_from_slice(&[0, 1, 0, 0, 0]);
        b.extend_from_slice(&[0, 1, 0x08, 0, 0xfd, 0]);
        b.extend_from_slice(&5u64.to_le_bytes());
        b.extend_from_slice(b"\x0242");
        d.feed(20, Dir::ToServer, &com(COM_STMT_EXECUTE, &b));
        d.feed(21, Dir::ToClient, &pkt(1, OK));
        assert_eq!(d.units[1].vals, [val_key(b"3"), int_key(5), val_key(b"42")]);
        // Second execution reuses types and sends values 6 and string 9.
        let mut b = 7u32.to_le_bytes().to_vec();
        b.extend_from_slice(&[0, 1, 0, 0, 0]);
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&6u64.to_le_bytes());
        b.extend_from_slice(b"\x019");
        d.feed(30, Dir::ToServer, &com(COM_STMT_EXECUTE, &b));
        d.feed(31, Dir::ToClient, &pkt(1, OK));
        assert_eq!(d.units[2].vals, [val_key(b"3"), int_key(6), int_key(9)]);
    }

    #[test]
    fn parameterless_execute_with_query_attributes_keeps_sql_literals() {
        let mut st = Stmt { sql: "select 6".into(), params: 0, types: vec![] };
        let mut vals = vec![val_key(b"6")];
        let payload = [COM_STMT_EXECUTE, 1, 0, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(execute_keys(&payload, &mut st, true, &mut vals, &mut false), Some(()));
        assert_eq!(vals, [val_key(b"6")]);
    }

    #[test]
    fn mid_stream_learns_eof_mode() {
        let mut d = MyDecoder::new(1, 0, "c".into(), "s".into(), true);
        // Tail of a response to an unseen request.
        d.feed(1, Dir::ToClient, &[9, 9, 9, 9, 9]);
        // Discard chunks beginning inside a command.
        d.feed(2, Dir::ToServer, b"t where id = 1");
        d.feed(10, Dir::ToServer, &exec(3));
        d.feed(11, Dir::ToClient, &pkt(1, OK));
        d.feed(20, Dir::ToServer, &com(COM_QUERY, b"select 1"));
        d.feed(21, Dir::ToClient, &[pkt(1, &[1]), pkt(2, COLDEF), pkt(3, EOF), pkt(4, b"\x011"), pkt(5, EOF)].concat());
        assert_eq!(d.units.len(), 2);
        assert_eq!(d.units[0].skip, Some(Skip::UnknownStatement));
        assert_eq!((d.units[1].skip, d.units[1].out.rows), (None, 1));
        // OK status 0x0002 indicates autocommit enabled.
        assert!(!d.info.my_autocommit_off);
        assert_eq!(d.info.my_caps & (CLIENT_QUERY_ATTRIBUTES | CLIENT_DEPRECATE_EOF), 0);
    }

    #[test]
    fn failed_statement_without_autocommit_still_holds_a_transaction() {
        let mut d = MyDecoder::new(1, 0, "c".into(), "s".into(), false);
        connect(&mut d, 0);
        // COMMIT response status 0: autocommit off, outside a transaction.
        d.feed(10, Dir::ToServer, &com(COM_QUERY, b"commit"));
        d.feed(11, Dir::ToClient, &pkt(1, &[0, 0, 0, 0, 0, 0, 0]));
        assert!(!d.units[0].in_tx);
        // Duplicate-key error has no status flags but can begin a transaction and retain locks.
        d.feed(20, Dir::ToServer, &com(COM_QUERY, b"insert into t values (1)"));
        d.feed(21, Dir::ToClient, &pkt(1, &[0xff, 0x26, 0x04, b'#', b'2', b'3', b'0', b'0', b'0', b'd']));
        assert!(d.units[1].in_tx);
        d.feed(30, Dir::ToServer, &com(COM_QUERY, b"rollback"));
        d.feed(31, Dir::ToClient, &pkt(1, &[0, 0, 0, 0, 0, 0, 0]));
        assert!(!d.units[2].in_tx);
    }

    #[test]
    fn mid_stream_recovers_session_shape() {
        let mut d = MyDecoder::new(1, 0, "c".into(), "s".into(), true);
        // Query attributes present; status 0x0001 means active transaction without autocommit.
        d.feed(10, Dir::ToServer, &com(COM_QUERY, b"\x00\x01update t set a = 1"));
        d.feed(11, Dir::ToClient, &pkt(1, &[0, 1, 0, 1, 0, 0, 0]));
        assert_eq!(d.units[0].sql, "update t set a = 1");
        assert!(d.units[0].in_tx);
        assert!(d.info.my_autocommit_off);
        assert_ne!(d.info.my_caps & CLIENT_QUERY_ATTRIBUTES, 0);
        // Later autocommit changes must not replace the inferred state at capture start.
        d.feed(20, Dir::ToServer, &com(COM_QUERY, b"\x00\x01set autocommit=1"));
        d.feed(21, Dir::ToClient, &pkt(1, OK));
        assert!(d.info.my_autocommit_off);
    }

    #[test]
    fn query_attributes_are_skipped() {
        let mut d = MyDecoder::new(1, 0, "c".into(), "s".into(), false);
        connect(&mut d, CLIENT_QUERY_ATTRIBUTES);
        d.feed(10, Dir::ToServer, &com(COM_QUERY, b"\x00\x01select 2"));
        d.feed(11, Dir::ToClient, &pkt(1, OK));
        assert_eq!(d.units[0].sql, "select 2");
        // One attribute: string type 0xfe, name k, value v.
        d.feed(20, Dir::ToServer, &com(COM_QUERY, b"\x01\x01\x00\x01\xfe\x00\x01k\x01vselect 3"));
        d.feed(21, Dir::ToClient, &pkt(1, OK));
        assert_eq!(d.units[1].sql, "select 3");
    }

    #[test]
    fn ssl_request_marks_encrypted() {
        let mut d = MyDecoder::new(1, 0, "c".into(), "s".into(), false);
        let caps = CLIENT_PROTOCOL_41 | CLIENT_SSL;
        d.feed(1, Dir::ToClient, &greeting(caps));
        let mut p = caps.to_le_bytes().to_vec();
        p.extend_from_slice(&[0; 28]);
        d.feed(2, Dir::ToServer, &pkt(1, &p));
        d.feed(3, Dir::ToServer, &[22, 3, 1, 0, 5]);
        assert!(d.info.encrypted);
    }

    #[test]
    fn large_packet_is_joined() {
        let mut f = Framer::new();
        let mut big = vec![COM_QUERY];
        big.resize(MAX_PACKET + 10, b'x');
        let mut wire = pkt(0, &big[..MAX_PACKET]);
        wire.extend(pkt(1, &big[MAX_PACKET..]));
        let mut got = Vec::new();
        f.push(&wire, |seq, p| got.push((seq, p.len())));
        assert_eq!(got, vec![(1, MAX_PACKET + 10)]);
    }
}
