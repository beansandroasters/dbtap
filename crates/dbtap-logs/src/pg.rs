//! PostgreSQL 17 CSV log: one statement/execute per unit.

use anyhow::{Context, Result, bail, ensure};
use dbtap_core::{
    journal::{Proto, Record},
    unit::{ConnInfo, LogOrigin, Observed, Outcome, Skip, Unit, is_write, literal_keys, push_val, val_key},
};
use std::{collections::{BTreeMap, HashMap}, io::Read};

#[derive(Clone, Default)]
pub struct Options {
    pub server: String,
    pub database: Option<String>,
    pub application_prefix: Option<String>,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct Stats {
    pub csv_rows: u64,
    pub selected_rows: u64,
    pub sessions: u64,
    pub units: u64,
    pub parse: u64,
    pub bind: u64,
    pub errors: u64,
    pub skipped: BTreeMap<String, u64>,
    pub ignored: u64,
}

struct Session {
    info: ConnInfo,
    last_line: u64,
    last_ts: u64,
    announced: bool,
    closed: bool,
    in_tx: bool,
}

pub struct PgCsv<R: Read> {
    reader: csv::Reader<R>,
    options: Options,
    sessions: HashMap<String, Session>,
    pub stats: Stats,
}

impl<R: Read> PgCsv<R> {
    pub fn new(input: R, options: Options) -> Self {
        Self {
            reader: csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(input),
            options,
            sessions: HashMap::new(),
            stats: Stats::default(),
        }
    }

    /// Read one CSV record, including quoted multiline SQL/parameters.
    pub fn next(&mut self) -> Result<Option<Vec<Record>>> {
        let mut r = csv::StringRecord::new();
        if !self.reader.read_record(&mut r).context("Cannot read PostgreSQL CSV")? {
            return Ok(None);
        }
        self.stats.csv_rows += 1;
        ensure!(r.len() == 26, "CSV row {}: expected 26 PostgreSQL 17 columns, got {}", self.stats.csv_rows, r.len());
        if &r[23] != "client backend"
            || self.options.database.as_ref().is_some_and(|d| d != &r[2])
            || self.options.application_prefix.as_ref().is_some_and(|a| !r[22].starts_with(a))
        {
            return Ok(Some(Vec::new()));
        }
        self.stats.selected_rows += 1;
        let ts = timestamp(&r[0]).with_context(|| format!("Timestamp in CSV row {}", self.stats.csv_rows))?;
        let line: u64 = r[6].parse().context("Invalid session line number")?;
        ensure!(!r[5].is_empty(), "Missing session ID");
        let id = self.sessions.len() as u64 + 1;
        let s = self.sessions.entry(r[5].into()).or_insert_with(|| {
            self.stats.sessions += 1;
            let mut info = ConnInfo::new(id, Proto::Postgres, ts, r[4].replace('(', ":").replace(')', ""), self.options.server.clone(), true);
            info.user = (!r[1].is_empty()).then(|| r[1].into());
            info.database = (!r[2].is_empty()).then(|| r[2].into());
            info.params = vec![("application_name".into(), r[22].into()), ("client_encoding".into(), "UTF8".into())];
            Session { info, last_line: 0, last_ts: 0, announced: false, closed: false, in_tx: false }
        });
        ensure!(line > s.last_line && !s.closed, "Duplicate or reversed line number in session {}: {line}", &r[5]);
        ensure!(ts >= s.last_ts, "Reversed log timestamp in session {}", &r[5]);
        s.last_line = line;
        s.last_ts = ts;
        let message = &r[13];
        if message.starts_with("connection ") {
            s.info.mid_stream = false;
            if !r[1].is_empty() { s.info.user = Some(r[1].into()); }
            if !r[2].is_empty() { s.info.database = Some(r[2].into()); }
            if !r[22].is_empty() {
                s.info.params[0].1 = r[22].into();
            }
            return Ok(Some(Vec::new()));
        }
        if message.starts_with("disconnection:") {
            s.closed = true;
            return Ok(Some(if s.announced { vec![Record::ConnClose { conn: s.info.conn, ts }] } else { Vec::new() }));
        }
        let (sql, phase, duration) = if &r[11] == "ERROR" && !r[19].is_empty() {
            self.stats.errors += 1;
            (&r[19], "error", None)
        } else if let Some(rest) = message.strip_prefix("duration: ") {
            let (time, rest) = rest.split_once(" ms").context("Invalid duration format")?;
            let duration = decimal_ns(time, 6)?;
            let rest = rest.trim_start();
            if rest.starts_with("parse ") {
                self.stats.parse += 1;
                return Ok(Some(Vec::new()));
            }
            if rest.starts_with("bind ") {
                self.stats.bind += 1;
                return Ok(Some(Vec::new()));
            }
            if let Some(sql) = rest.strip_prefix("statement: ") {
                (sql, "statement", Some(duration))
            } else if let Some(rest) = rest.strip_prefix("execute ") {
                // Portal names may contain ':'; the SQL separator is ': '.
                let (_, sql) = rest.split_once(": ").context("Missing execute SQL")?;
                (sql, if rest.starts_with("fetch from ") { "fetch" } else { "execute" }, Some(duration))
            } else {
                bail!("Duration line lacks SQL; use log_statement=none and log_duration=off");
            }
        } else {
            self.stats.ignored += 1;
            return Ok(Some(Vec::new()));
        };

        let mut skip = None;
        let words = sql_tokens(sql);
        if words.iter().any(|w| w.eq_ignore_ascii_case("copy")) {
            skip = Some(Skip::LogDataMissing);
        }
        // CSV lacks the state needed for separate control requests and cursor continuation.
        if phase == "fetch" || (["BIND", "PARSE"].contains(&&r[7]) && phase == "error") {
            skip = Some(Skip::LogUnsupported);
        }
        let n = parameter_count(sql);
        let param_text = r[14].strip_prefix("Parameters: ").or_else(|| {
            r[18].split_once("parameters: ").map(|(_, p)| p)
        });
        let params = match param_text.map(parameters).transpose() {
            Ok(p) => p,
            Err(_) => { skip = Some(Skip::LogDataMissing); None }
        };
        if phase != "statement" && n > 0 && params.as_ref().is_none_or(|p| p.len() < n) {
            skip = Some(Skip::LogDataMissing);
        }
        let req = if skip.is_some() {
            Vec::new()
        } else {
            request(sql, if phase == "statement" { None } else { params.as_deref() })?
        };
        let mut vals = Vec::new();
        let mut overflow = false;
        literal_keys(sql, &mut vals, &mut overflow);
        if let Some(params) = params {
            for p in params.into_iter().flatten() {
                push_val(&mut vals, &mut overflow, val_key(p.as_bytes()));
            }
        }
        // No ReadyForQuery in logs; approximate state from explicit transaction boundaries.
        // Examine statement prefixes, including multiple statements/AND CHAIN, not words in strings.
        if phase != "error" {
            for stmt in words.split(|w| w == ";") {
                let first = stmt.first().map(String::as_str).unwrap_or("");
                if first.eq_ignore_ascii_case("begin") || first.eq_ignore_ascii_case("start") {
                    s.in_tx = true;
                }
                if ["commit", "end", "rollback", "abort"].iter().any(|w| first.eq_ignore_ascii_case(w))
                    && !stmt.iter().any(|w| w.eq_ignore_ascii_case("to"))
                {
                    s.in_tx = stmt.iter().any(|w| w.eq_ignore_ascii_case("chain"))
                        && !stmt.iter().any(|w| w.eq_ignore_ascii_case("no"));
                }
            }
        }
        let u = Unit {
            conn: s.info.conn, t_start: ts.saturating_sub(duration.unwrap_or(0)), t_end: ts,
            sql: sql.into(), req, write: is_write(sql), many: false, skip, vals, in_tx: s.in_tx, aux: 0,
            out: Outcome { err: (phase == "error").then(|| r[12].into()), ..Default::default() },
            observed: Observed::pg_log(duration.is_some()),
            origin: Some(LogOrigin {
                format: "postgres-csv".into(), session: r[5].into(), line, phase: phase.into(),
                timestamp_precision_ns: 1_000_000,
            }),
        };
        self.stats.units += 1;
        if let Some(why) = skip {
            *self.stats.skipped.entry(format!("{why:?}")).or_default() += 1;
        }
        let mut records = Vec::new();
        if !s.announced {
            s.info.t_open = s.info.t_open.min(u.t_start);
            records.push(Record::Session { ts, info: s.info.clone() });
            s.announced = true;
        }
        records.push(Record::Unit(u));
        Ok(Some(records))
    }
}

/// Accept UTC/GMT or numeric offsets, not ambiguous abbreviations such as CST.
pub(crate) fn timestamp(s: &str) -> Result<u64> {
    let value = if let Some(s) = s.strip_suffix(" UTC").or_else(|| s.strip_suffix(" GMT")) {
        format!("{s} +0000")
    } else { s.to_string() };
    let t = chrono::DateTime::parse_from_str(&value, "%Y-%m-%d %H:%M:%S%.f %z")
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(s))
        .context("Timestamp requires UTC/GMT or a numeric offset (use log_timezone=UTC)")?;
    u64::try_from(t.timestamp_nanos_opt().context("Timestamp out of range")?).context("Timestamp before 1970")
}

pub(crate) fn decimal_ns(s: &str, digits: u32) -> Result<u64> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    ensure!(frac.len() <= digits as usize && frac.bytes().all(|c| c.is_ascii_digit()), "Invalid fractional duration");
    let whole: u64 = whole.parse().context("Invalid duration")?;
    let frac: u64 = if frac.is_empty() { 0 } else { frac.parse()? };
    whole.checked_mul(10u64.pow(digits)).and_then(|v| v.checked_add(frac * 10u64.pow(digits - s.split_once('.').map_or(0, |(_, f)| f.len() as u32))))
        .context("Duration out of range")
}

/// Server logs double quotes within values and preserve backslashes literally.
fn parameters(mut s: &str) -> Result<Vec<Option<String>>> {
    let mut out = Vec::new();
    loop {
        let prefix = format!("${} = ", out.len() + 1);
        s = s.strip_prefix(&prefix).context("Parameter numbers are not consecutive")?;
        if let Some(rest) = s.strip_prefix("NULL") {
            out.push(None);
            s = rest;
        } else {
            s = s.strip_prefix('\'').context("Missing parameter quote")?;
            let mut value = String::new();
            loop {
                let i = s.find('\'').context("Truncated parameter")?;
                value.push_str(&s[..i]);
                s = &s[i + 1..];
                if let Some(rest) = s.strip_prefix('\'') {
                    value.push('\'');
                    s = rest;
                } else {
                    break;
                }
            }
            out.push(Some(value));
        }
        if s.is_empty() { return Ok(out); }
        s = s.strip_prefix(", ").context("Truncated parameter or invalid separator")?;
        ensure!(out.len() < 65535, "Too many parameters");
    }
}

fn message(out: &mut Vec<u8>, tag: u8, data: &[u8]) -> Result<()> {
    out.push(tag);
    out.extend_from_slice(&u32::try_from(data.len() + 4)?.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn request(sql: &str, params: Option<&[Option<String>]>) -> Result<Vec<u8>> {
    ensure!(!sql.contains('\0'), "SQL contains NUL");
    let mut out = Vec::new();
    if let Some(params) = params {
        let mut parse = vec![0]; // Unnamed statement; let the server infer type OIDs absent from logs.
        parse.extend_from_slice(sql.as_bytes());
        parse.extend_from_slice(&[0, 0, 0]);
        message(&mut out, b'P', &parse)?;
        let mut bind = vec![0, 0, 0, 0]; // Unnamed portal/statement; all parameters use text format.
        bind.extend_from_slice(&u16::try_from(params.len())?.to_be_bytes());
        for p in params {
            if let Some(p) = p {
                ensure!(!p.contains('\0'), "Parameter contains NUL");
                bind.extend_from_slice(&i32::try_from(p.len())?.to_be_bytes());
                bind.extend_from_slice(p.as_bytes());
            } else {
                bind.extend_from_slice(&(-1i32).to_be_bytes());
            }
        }
        bind.extend_from_slice(&[0, 0]); // Text results too.
        message(&mut out, b'B', &bind)?;
        message(&mut out, b'E', &[0, 0, 0, 0, 0])?;
        message(&mut out, b'S', &[])?;
    } else {
        let mut q = sql.as_bytes().to_vec();
        q.push(0);
        message(&mut out, b'Q', &q)?;
    }
    Ok(out)
}

fn parameter_count(sql: &str) -> usize {
    sql_tokens(sql).iter().filter_map(|s| s.strip_prefix('$')?.parse().ok()).max().unwrap_or(0)
}

/// Tokenize without splitting statements or inferring types; ignore control words in quotes/comments.
pub(crate) fn sql_tokens(sql: &str) -> Vec<String> {
    let s = sql.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(b"--") {
            i += s[i..].iter().position(|&c| c == b'\n').unwrap_or(s.len() - i);
        } else if s[i..].starts_with(b"/*") {
            i += 2;
            let mut depth = 1;
            while i < s.len() && depth > 0 {
                if s[i..].starts_with(b"/*") { depth += 1; i += 2; }
                else if s[i..].starts_with(b"*/") { depth -= 1; i += 2; }
                else { i += 1; }
            }
        } else if matches!(s[i], b'\'' | b'"' | b'`') {
            let quote = s[i];
            i += 1;
            while i < s.len() {
                if s[i] == quote {
                    i += 1;
                    if s.get(i) != Some(&quote) { break; }
                } else if s[i] == b'\\' {
                    i += 1;
                }
                i = (i + 1).min(s.len());
            }
        } else if s[i] == b'$' && !s.get(i + 1).is_some_and(u8::is_ascii_digit) {
            let start = i;
            i += 1;
            while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == b'_') { i += 1; }
            if s.get(i) == Some(&b'$') {
                i += 1;
                let delim = &sql[start..i];
                i = sql[i..].find(delim).map_or(s.len(), |n| i + n + delim.len());
            }
        } else if s[i].is_ascii_alphabetic() || s[i] == b'_' || s[i] == b'$' {
            let start = i;
            i += 1;
            while i < s.len() && (s[i].is_ascii_alphanumeric() || matches!(s[i], b'_' | b'$')) { i += 1; }
            out.push(sql[start..i].to_ascii_lowercase());
        } else {
            if s[i] == b';' { out.push(";".into()); }
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbtap_core::{journal::Record, unit::Skip};

    fn row(line: u64, message: &str, detail: &str, query: &str, error: bool) -> Vec<u8> {
        let mut r = vec![String::new(); 26];
        for (i, v) in [
            (0, "2026-11-14 02:27:27.509 UTC"), (1, "app"), (2, "shop"),
            (3, "181"), (4, "127.0.0.1:4444"), (5, "6af7c70f.b5"),
            (7, if error { "INSERT" } else { "SELECT" }), (8, "2026-11-14 02:27:27 UTC"),
            (11, if error { "ERROR" } else { "LOG" }), (12, if error { "23505" } else { "00000" }),
            (13, message), (14, detail), (19, query), (22, "test"), (23, "client backend"),
        ] {
            r[i] = v.into();
        }
        r[6] = line.to_string();
        let mut w = csv::WriterBuilder::new().has_headers(false).from_writer(Vec::new());
        w.write_record(r).unwrap();
        w.into_inner().unwrap()
    }

    fn import(rows: Vec<Vec<u8>>) -> Vec<Record> {
        let bytes = rows.concat();
        let mut p = PgCsv::new(&bytes[..], Options::default());
        let mut records = Vec::new();
        while let Some(rs) = p.next().unwrap() {
            records.extend(rs);
        }
        records
    }

    #[test]
    fn csv_multiline_and_extended_execute_are_not_counted_three_times() {
        let sql = "select $1::text,\n$2::text, $3::text";
        let detail = "Parameters: $1 = 'O''Brien, \\\\path', $2 = NULL, $3 = 'NULL'";
        let records = import(vec![
            row(1, &format!("duration: 0.120 ms  parse <unnamed>: {sql}"), "", "", false),
            row(2, &format!("duration: 0.030 ms  bind <unnamed>: {sql}"), detail, "", false),
            row(3, &format!("duration: 0.106 ms  execute <unnamed>: {sql}"), detail, "", false),
        ]);
        let units: Vec<_> = records.iter().filter_map(|r| if let Record::Unit(u) = r { Some(u) } else { None }).collect();
        assert_eq!(units.len(), 1);
        let u = units[0];
        assert_eq!(u.sql, sql);
        assert_eq!(u.t_end - u.t_start, 106_000);
        assert!(!u.observed.rows && !u.observed.content && u.observed.duration);
        assert_eq!(u.skip, None);
        // The existing decoder must accept the reconstructed frontend messages.
        let mut d = dbtap_proto::pg::PgDecoder::new(1, 0, "".into(), "".into(), true);
        d.feed(1, dbtap_core::journal::Dir::ToServer, &u.req);
        d.feed(2, dbtap_core::journal::Dir::ToClient, b"Z\0\0\0\x05I");
        assert_eq!(d.units.len(), 1);
        assert_eq!(d.units[0].sql, sql);
        assert!(u.req.windows(13).any(|s| s == b"O'Brien, \\\\pa"));
    }

    #[test]
    fn errors_have_unknown_duration_and_copy_has_missing_data() {
        let records = import(vec![
            row(1, "duplicate key", "", "insert into t values (1)", true),
            row(2, "duration: 0.230 ms  statement: COPY t FROM STDIN", "", "", false),
        ]);
        let units: Vec<_> = records.iter().filter_map(|r| if let Record::Unit(u) = r { Some(u) } else { None }).collect();
        assert_eq!(units[0].out.err.as_deref(), Some("23505"));
        assert!(!units[0].observed.duration);
        assert_eq!(units[1].skip, Some(Skip::LogDataMissing));
        assert!(units[1].req.is_empty());
    }

    #[test]
    fn portal_fetch_does_not_repeat_the_original_statement() {
        let records = import(vec![row(1, "duration: 0.1 ms  execute fetch from st/p: INSERT INTO t VALUES (1) RETURNING id", "", "", false)]);
        let u = records.iter().find_map(|r| if let Record::Unit(u) = r { Some(u) } else { None }).unwrap();
        assert_eq!(u.skip, Some(Skip::LogUnsupported));
        assert!(u.req.is_empty());
    }

    #[test]
    fn parameters_preserve_null_quotes_and_reject_truncation_or_missing_positions() {
        assert_eq!(parameters("$1 = 'a'',b', $2 = NULL, $3 = 'NULL'").unwrap(),
                   vec![Some("a',b".into()), None, Some("NULL".into())]);
        assert!(parameters("$1 = 'abc'...").is_err());
        assert!(parameters("$2 = 'abc'").is_err());
        assert!(parameters("$1 = 'unfinished").is_err());
        let records = import(vec![row(1, "duration: 0.1 ms  execute p: select $1::int", "", "", false)]);
        assert!(records.iter().any(|r| matches!(r, Record::Unit(u) if u.skip == Some(Skip::LogDataMissing))));
    }

    #[test]
    fn duplicate_or_reordered_session_lines_are_rejected() {
        let bytes = [row(2, "duration: 1 ms  statement: select 1", "", "", false),
                     row(2, "duration: 1 ms  statement: select 1", "", "", false)].concat();
        let mut p = PgCsv::new(&bytes[..], Options::default());
        p.next().unwrap();
        assert!(p.next().is_err());
    }

    #[test]
    fn sql_lexer_ignores_parameters_inside_literals_comments_and_dollar_quotes() {
        assert_eq!(parameter_count("select '$7', $$ $8 $$, \"$9\", $1 /* $3 /* $4 */ */ -- $5\n"), 1);
    }
}
