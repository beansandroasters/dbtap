//! MySQL 8.4 FILE slow query log with log_slow_extra=ON.

use anyhow::{Context, Result, ensure};
use dbtap_core::{
    journal::{Proto, Record},
    unit::{ConnInfo, LogOrigin, Observed, Outcome, Skip, Unit, is_write, literal_keys},
};
use std::{collections::{BTreeMap, HashMap}, io::{BufRead, BufReader, Read}};
use crate::pg::{sql_tokens, timestamp};

#[derive(Default)]
pub struct Options {
    pub server: String,
    /// Initial database for fragments without an initial use line; filter sessions with thread_ids.
    pub database: Option<String>,
    pub thread_ids: Vec<u64>,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct Stats {
    pub entries: u64,
    pub selected_entries: u64,
    pub units: u64,
    pub errors: u64,
    pub administrative: BTreeMap<String, u64>,
    pub skipped: u64,
}

struct Session {
    info: ConnInfo,
    announced: bool,
    autocommit: bool,
    in_tx: bool,
    unsupported: bool,
    closed: bool,
    last_end: u64,
}

pub struct MysqlSlow<R: Read> {
    reader: BufReader<R>,
    pending: Option<String>,
    line: u64,
    options: Options,
    database: Option<String>,
    sessions: HashMap<u64, Session>,
    pub stats: Stats,
}

impl<R: Read> MysqlSlow<R> {
    pub fn new(input: R, options: Options) -> Self {
        Self {
            reader: BufReader::new(input), pending: None, line: 0, database: options.database.clone(),
            options, sessions: HashMap::new(), stats: Stats::default(),
        }
    }

    fn line(&mut self) -> Result<Option<String>> {
        let mut s = String::new();
        if self.reader.read_line(&mut s)? == 0 { return Ok(None); }
        self.line += 1;
        Ok(Some(s))
    }

    pub fn next(&mut self) -> Result<Option<Vec<Record>>> {
        let mut first = self.pending.take();
        while first.is_none() {
            match self.line()? {
                Some(s) if s.starts_with("# Time: ") => first = Some(s),
                Some(s) if banner(&s) || s.trim().is_empty() => {}
                Some(_) => anyhow::bail!("Invalid slow-log header or record boundary at line {}", self.line),
                None => return Ok(None),
            }
        }
        let start_line = self.line;
        let who = self.line()?.context("Truncated User@Host line")?;
        let fields = self.line()?.context("Truncated Query_time line")?;
        ensure!(who.starts_with("# User@Host: ") && fields.starts_with("# Query_time: "), "Invalid slow-log header");
        let words: Vec<_> = fields[2..].split_ascii_whitespace().collect();
        ensure!(words.len() % 2 == 0, "Invalid number of slow-log fields");
        let fields: HashMap<_, _> = words.chunks_exact(2).map(|p| (p[0].trim_end_matches(':'), p[1])).collect();
        let field = |name| fields.get(name).copied().with_context(|| format!("Missing {name}; log_slow_extra=ON and log_output=FILE are required"));
        let thread: u64 = field("Thread_id")?.parse()?;
        let error: u32 = field("Errno")?.parse()?;
        let rows: u64 = field("Rows_sent")?.parse()?;
        let t_start = timestamp(field("Start")?)?;
        let t_end = timestamp(field("End")?)?;
        ensure!(t_start <= t_end, "Start is after End");
        let mut sql = String::new();
        let mut has_timestamp = false;
        let mut identity = Vec::new();
        let mut boundary = SqlBoundary::default();
        while let Some(s) = self.line()? {
            if s.strip_prefix("# Time: ").is_some_and(|v| timestamp(v.trim()).is_ok()) && boundary.closed() {
                self.pending = Some(s);
                break;
            }
            if banner(&s) && (!has_timestamp || (boundary.terminated && boundary.closed())) { continue; }
            if !has_timestamp {
                if let Some(db) = s.trim().strip_prefix("use ").and_then(|s| s.strip_suffix(';')) {
                    self.database = Some(db.trim_matches('`').replace("``", "`"));
                } else if let Some(vars) = s.trim_end().strip_prefix("SET ").and_then(|v| v.strip_suffix(';')) {
                    for assignment in vars.split(',') {
                        let (name, value) = assignment.split_once('=').context("Invalid SET metadata")?;
                        ensure!(value.parse::<u64>().is_ok(), "Invalid SET metadata value");
                        match name {
                            "timestamp" => has_timestamp = true,
                            "insert_id" | "last_insert_id" => identity.push(assignment.to_string()),
                            _ => anyhow::bail!("Unknown SET metadata: {name}"),
                        }
                    }
                    ensure!(has_timestamp, "SET metadata lacks timestamp");
                } else {
                    ensure!(s.trim().is_empty(), "Unknown line before SET timestamp");
                }
            } else {
                boundary.feed(&s);
                sql.push_str(&s);
            }
        }
        ensure!(has_timestamp, "Missing SET timestamp");
        let sql = sql.trim_end();
        ensure!(boundary.closed() && sql.ends_with(';'), "Truncated statement or entry without SQL at line {start_line}");
        self.stats.entries += 1;
        if !self.options.thread_ids.is_empty() && !self.options.thread_ids.contains(&thread) {
            return Ok(Some(Vec::new()));
        }
        self.stats.selected_entries += 1;
        let id = self.sessions.len() as u64 + 1;
        let s = self.sessions.entry(thread).or_insert_with(|| {
            let mut info = ConnInfo::new(id, Proto::Mysql, t_start, who.trim().into(), self.options.server.clone(), true);
            info.server_session = Some(thread.to_string());
            info.user = who.strip_prefix("# User@Host: ").and_then(|s| s.split_once('[')).map(|(s, _)| s.into());
            if let Some((_, host)) = who.split_once(" @ ") {
                if let Some((_, ip)) = host.split_once('[') {
                    info.client = ip.split(']').next().unwrap_or("").into();
                }
            }
            info.database = self.database.clone();
            info.my_charset = 45; // UTF-8; original session charset is absent from the log.
            // CLIENT_MULTI_STATEMENTS permits entries representing multi-statement requests.
            info.my_caps = 0x0001_0000;
            Session { info, announced: false, autocommit: true, in_tx: false, unsupported: false, closed: false, last_end: 0 }
        });
        ensure!(!s.closed && t_end >= s.last_end, "Thread_id {thread} reused, closed twice, or has reversed timestamps");
        s.last_end = t_end;
        if let Some(command) = sql.strip_prefix("# administrator command: ").and_then(|s| s.strip_suffix(';')) {
            *self.stats.administrative.entry(command.into()).or_default() += 1;
            if command == "Quit" {
                s.closed = true;
                return Ok(Some(if s.announced { vec![Record::ConnClose { conn: s.info.conn, ts: t_end }] } else { vec![] }));
            }
            if !["Prepare", "Close stmt", "Reset stmt", "Ping"].contains(&command) {
                s.unsupported = true;
            }
            return Ok(Some(vec![]));
        }
        let tokens = sql_tokens(sql);
        let first = tokens.first().map(String::as_str).unwrap_or("");
        let flat = sql.to_ascii_lowercase();
        if first == "set" && tokens.iter().any(|t| t == "autocommit") {
            if let Some((_, value)) = flat.split_once('=') {
                s.autocommit = !matches!(value.trim().trim_end_matches(';').trim(), "0" | "off");
                if s.autocommit { s.in_tx = false; }
            } else {
                s.unsupported = true;
            }
        } else if matches!(first, "begin" | "start") {
            s.in_tx = true;
        } else if matches!(first, "commit" | "rollback") && !tokens.iter().any(|t| t == "to") {
            s.in_tx = tokens.iter().any(|t| t == "chain") && !tokens.iter().any(|t| t == "no");
        } else if !s.autocommit && !matches!(first, "set" | "use") {
            s.in_tx = true;
        }
        let skip = if s.unsupported || s.info.database != self.database {
            Some(Skip::LogUnsupported)
        } else if first == "load" || first == "execute" {
            Some(Skip::LogDataMissing)
        } else { None };
        let mut vals = Vec::new();
        literal_keys(sql, &mut vals, &mut false);
        let mut req = Vec::new();
        if skip.is_none() {
            req.push(0x03); // COM_QUERY; original PREPARE/binary execution is not retained.
            if !identity.is_empty() {
                // Replay ID-generation metadata because it affects semantics, unlike timestamp metadata.
                req.extend_from_slice(format!("SET {};\n", identity.join(",")).as_bytes());
            }
            req.extend_from_slice(sql.as_bytes());
        }
        let unit = Unit {
            conn: s.info.conn, t_start, t_end, sql: sql.into(), req,
            write: is_write(sql), many: false, skip, vals, in_tx: s.in_tx, aux: 0,
            out: Outcome { err: (error != 0).then(|| error.to_string()), rows, ..Default::default() },
            observed: Observed { error: true, rows: true, affected: false, content: false, duration: true },
            origin: Some(LogOrigin {
                format: "mysql-slow".into(), session: thread.to_string(), line: start_line,
                phase: "statement".into(), timestamp_precision_ns: 1000,
            }),
        };
        self.stats.units += 1;
        self.stats.errors += (error != 0) as u64;
        self.stats.skipped += skip.is_some() as u64;
        let mut out = Vec::new();
        if !s.announced {
            out.push(Record::Session { ts: t_end, info: s.info.clone() });
            s.announced = true;
        }
        out.push(Record::Unit(unit));
        Ok(Some(out))
    }
}

fn banner(s: &str) -> bool {
    (s.contains(", Version: ") && s.trim_end().ends_with("started with:"))
        || s.starts_with("Tcp port: ") || s.starts_with("Time                 Id Command")
}

/// Distinguish log headers from lines inside SQL strings; retain SQL bytes unchanged.
#[derive(Default)]
struct SqlBoundary {
    quote: Option<u8>,
    block: bool,
    escaped: bool,
    terminated: bool,
}

impl SqlBoundary {
    fn closed(&self) -> bool { self.quote.is_none() && !self.block }

    fn feed(&mut self, line: &str) {
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if self.block {
                if b[i..].starts_with(b"*/") { self.block = false; i += 2; } else { i += 1; }
            } else if let Some(q) = self.quote {
                if self.escaped { self.escaped = false; }
                else if b[i] == b'\\' { self.escaped = true; }
                else if b[i] == q {
                    if b.get(i + 1) == Some(&q) { i += 1; } else { self.quote = None; }
                }
                i += 1;
            } else if b[i] == b'#' || (b[i..].starts_with(b"--") && b.get(i + 2).is_none_or(u8::is_ascii_whitespace)) {
                break;
            } else if b[i..].starts_with(b"/*") {
                self.block = true;
                i += 2;
            } else {
                if matches!(b[i], b'\'' | b'"' | b'`') {
                    self.quote = Some(b[i]);
                    self.terminated = false;
                } else if !b[i].is_ascii_whitespace() {
                    self.terminated = b[i] == b';';
                }
                i += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbtap_core::journal::Record;

    fn entry(sql: &str, error: u32) -> String {
        format!("# Time: 2026-11-14T04:27:00.445161Z\n\
                 # User@Host: app[app] @ localhost [127.0.0.1]  Id: 43\n\
                 # Query_time: 0.000060  Lock_time: 0.000000 Rows_sent: 2 Rows_examined: 2 Thread_id: 43 Errno: {error} Killed: 0 Start: 2026-11-14T04:27:00.445101Z End: 2026-11-14T04:27:00.445161Z\n\
                 use shop;\nSET timestamp=1794630420;\n{sql}\n")
    }

    #[test]
    fn reads_observed_rows_error_and_precise_times_without_replaying_metadata() {
        let text = entry("select 'hello;\\nworld', 14;", 0);
        let mut p = MysqlSlow::new(text.as_bytes(), Options::default());
        let rs = p.next().unwrap().unwrap();
        let u = rs.iter().find_map(|r| if let Record::Unit(u) = r { Some(u) } else { None }).unwrap();
        assert_eq!(&u.req[1..], b"select 'hello;\\nworld', 14;");
        assert_eq!(u.t_end - u.t_start, 60_000);
        assert_eq!(u.out.rows, 2);
        assert!(u.observed.rows && !u.observed.affected && !u.observed.content);
        assert!(p.next().unwrap().is_none());
    }

    #[test]
    fn records_runtime_errors_and_counts_administrative_commands() {
        let text = entry("insert into t values (1);", 1062) + &entry("# administrator command: Prepare;", 0);
        let mut p = MysqlSlow::new(text.as_bytes(), Options::default());
        assert!(p.next().unwrap().unwrap().iter().any(|r| matches!(r, Record::Unit(u) if u.out.err.as_deref() == Some("1062"))));
        assert!(p.next().unwrap().unwrap().is_empty());
        assert_eq!(p.stats.administrative["Prepare"], 1);
    }

    #[test]
    fn rejects_missing_extra_fields_and_truncated_statement() {
        let text = entry("select 1;", 0).replace("Errno: 0 ", "");
        assert!(MysqlSlow::new(text.as_bytes(), Options::default()).next().is_err());
        let text = entry("select unfinished", 0);
        assert!(MysqlSlow::new(text.as_bytes(), Options::default()).next().is_err());
    }

    #[test]
    fn log_like_lines_inside_sql_strings_are_preserved() {
        let sql = "insert into t values ('a\nTcp port: text\n# Time: text\nb');";
        let text = entry(sql, 0);
        let rs = MysqlSlow::new(text.as_bytes(), Options::default()).next().unwrap().unwrap();
        let u = rs.iter().find_map(|r| if let Record::Unit(u) = r { Some(u) } else { None }).unwrap();
        assert_eq!(&u.req[1..], sql.as_bytes());
    }

    #[test]
    fn preserves_insert_identity_metadata_in_the_replay_request() {
        let text = entry("insert into t values (null, LAST_INSERT_ID());", 0)
            .replace("SET timestamp=", "SET last_insert_id=12,insert_id=34,timestamp=");
        let rs = MysqlSlow::new(text.as_bytes(), Options::default()).next().unwrap().unwrap();
        let u = rs.iter().find_map(|r| if let Record::Unit(u) = r { Some(u) } else { None }).unwrap();
        assert_eq!(&u.req[1..], b"SET last_insert_id=12,insert_id=34;\ninsert into t values (null, LAST_INSERT_ID());");
        assert_eq!(u.sql, "insert into t values (null, LAST_INSERT_ID());");
    }
}
