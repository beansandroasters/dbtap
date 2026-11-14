//! Units for replay and comparison.
//!
//! A wire unit groups a request through the server's readiness for the next request.
//! PostgreSQL ends at ReadyForQuery after Query/Sync; MySQL groups one command and response.
//! Preserve request bytes to retain extended-protocol and binary-parameter behavior.
//! Reconstructing wire input as SQL alone would change the workload.
//! Logs reconstruct one execution per unit; origin and observed record provenance and coverage.

use crate::journal::Proto;
use xxhash_rust::xxh3::xxh3_64;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Outcome {
    /// SQLSTATE (PostgreSQL) or error number (MySQL), if any.
    pub err: Option<String>,
    pub rows: u64,
    pub affected: u64,
    /// Hash including row order.
    pub hash_ordered: u64,
    /// Order-independent row hash, for results without ORDER BY.
    pub hash_set: u64,
}

impl Outcome {
    #[inline]
    pub fn add_row(&mut self, row: &[u8]) {
        let h = xxh3_64(row);
        self.rows += 1;
        self.hash_ordered = (self.hash_ordered.rotate_left(5) ^ h).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        self.hash_set = self.hash_set.wrapping_add(h);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Skip {
    /// References a statement prepared before capture began.
    UnknownStatement,
    /// Interactive exchange such as LOAD DATA LOCAL, requiring a response before more input.
    Interactive,
    /// Response was incomplete at capture end or after loss.
    Incomplete,
    /// Log lacks request payload or parameter values.
    LogDataMissing,
    /// Request shape cannot be reconstructed reliably from logs.
    LogUnsupported,
}

/// Available comparison fields. Unknown rows/duration must not be interpreted as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Observed {
    pub error: bool,
    pub rows: bool,
    pub affected: bool,
    pub content: bool,
    pub duration: bool,
}

impl Default for Observed {
    fn default() -> Self {
        Self { error: true, rows: true, affected: true, content: true, duration: true }
    }
}

impl Observed {
    pub fn pg_log(duration: bool) -> Self {
        Self { error: true, rows: false, affected: false, content: false, duration }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LogOrigin {
    pub format: String,
    pub session: String,
    pub line: u64,
    pub phase: String,
    /// Log timestamp resolution. PostgreSQL start is estimated from end minus duration.
    pub timestamp_precision_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Unit {
    pub conn: u64,
    pub t_start: u64,
    pub t_end: u64,
    /// SQL for display and aggregation, not replay.
    pub sql: String,
    /// PG: concatenated frontend messages. MySQL: command payload without packet headers.
    pub req: Vec<u8>,
    /// Changes visible to other connections, or lock-taking operations requiring causal order.
    pub write: bool,
    /// SQL display is truncated because the unit contains too many statements (large pipeline).
    pub many: bool,
    pub skip: Option<Skip>,
    /// Hashes of bind values or SQL literals.
    /// Used to identify potentially competing writes; empty when there are too many values.
    pub vals: Vec<u64>,
    /// Whether the server reported an active transaction at this unit's response.
    /// Wire: PG ReadyForQuery / MySQL status flags. Logs: approximation from explicit SQL.
    pub in_tx: bool,
    /// Captured MySQL PREPARE statement ID, mapped to the target's ID at replay.
    pub aux: u32,
    pub out: Outcome,
    #[serde(default)]
    pub observed: Observed,
    #[serde(default)]
    pub origin: Option<LogOrigin>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConnInfo {
    pub conn: u64,
    /// Server-assigned connection ID, used to match MySQL Thread_id with traffic.
    #[serde(default)]
    pub server_session: Option<String>,
    pub proto: Proto,
    pub t_open: u64,
    pub t_close: Option<u64>,
    pub client: String,
    pub server: String,
    pub user: Option<String>,
    pub database: Option<String>,
    /// PostgreSQL StartupMessage parameters other than user/database.
    pub params: Vec<(String, String)>,
    /// MySQL client capability flags, inferred for mid-stream connections.
    pub my_caps: u32,
    pub my_charset: u8,
    /// MySQL autocommit was off at capture start, inferred from mid-stream response flags.
    pub my_autocommit_off: bool,
    pub mid_stream: bool,
    /// TLS connection excluded from wire reconstruction.
    pub encrypted: bool,
    /// Reason reconstruction was abandoned.
    pub broken: Option<String>,
}

impl ConnInfo {
    pub fn new(conn: u64, proto: Proto, t_open: u64, client: String, server: String, mid_stream: bool) -> Self {
        ConnInfo {
            conn,
            server_session: None,
            proto,
            t_open,
            t_close: None,
            client,
            server,
            user: None,
            database: None,
            params: Vec::new(),
            my_caps: 0,
            my_charset: 0,
            my_autocommit_off: false,
            mid_stream,
            encrypted: false,
            broken: None,
        }
    }
}

/// Maximum retained values per unit; exceeding this means unknown values and table-wide conflicts.
pub const MAX_VALS: usize = 16;

/// Normalize text and binary integer representations of the same value to one key.
pub fn val_key(text: &[u8]) -> u64 {
    xxh3_64(text.trim_ascii())
}

pub fn int_key(v: i64) -> u64 {
    xxh3_64(v.to_string().as_bytes())
}

/// Add a value; clear all and return false on overflow (stop adding afterwards).
pub fn push_val(vals: &mut Vec<u64>, overflow: &mut bool, k: u64) {
    if *overflow {
        return;
    }
    if !vals.contains(&k) {
        if vals.len() == MAX_VALS {
            vals.clear();
            *overflow = true;
            return;
        }
        vals.push(k);
    }
}

/// Keys for numeric/string SQL literals in statements without bind parameters.
pub fn literal_keys(sql: &str, vals: &mut Vec<u64>, overflow: &mut bool) {
    let s = sql.as_bytes();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == b'\'' {
            let mut lit = Vec::new();
            i += 1;
            while i < s.len() {
                if s[i] == b'\\' && i + 1 < s.len() {
                    lit.push(s[i + 1]);
                    i += 2;
                } else if s[i] == b'\'' {
                    if s.get(i + 1) == Some(&b'\'') {
                        lit.push(b'\'');
                        i += 2;
                    } else {
                        i += 1;
                        break;
                    }
                } else {
                    lit.push(s[i]);
                    i += 1;
                }
            }
            push_val(vals, overflow, val_key(&lit));
        } else if s[i..].starts_with(b"/*") {
            i = s[i + 2..].windows(2).position(|w| w == b"*/").map(|p| i + p + 4).unwrap_or(s.len());
        } else if s[i..].starts_with(b"--") {
            i = s[i..].iter().position(|&c| c == b'\n').map(|p| i + p + 1).unwrap_or(s.len());
        } else if c == b'"' || c == b'`' {
            i = s[i + 1..].iter().position(|&x| x == c).map(|p| i + p + 2).unwrap_or(s.len());
        } else if c.is_ascii_digit() && (i == 0 || !(is_ident(s[i - 1]) || s[i - 1] == b'$')) {
            let st = i;
            while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == b'.') {
                i += 1;
            }
            push_val(vals, overflow, val_key(&s[st..i]));
        } else {
            i += 1;
        }
    }
}

/// Offset after leading whitespace and comments.
fn skip_lead(s: &[u8]) -> &[u8] {
    let mut i = 0;
    loop {
        while i < s.len() && (s[i].is_ascii_whitespace() || s[i] == b'(') {
            i += 1;
        }
        if s[i..].starts_with(b"/*") {
            match s[i + 2..].windows(2).position(|w| w == b"*/") {
                Some(p) => i += p + 4,
                None => return &[],
            }
        } else if s[i..].starts_with(b"--") {
            match s[i..].iter().position(|&c| c == b'\n') {
                Some(p) => i += p + 1,
                None => return &[],
            }
        } else {
            return &s[i..];
        }
    }
}

fn has_word(hay: &[u8], word: &[u8]) -> bool {
    let n = word.len();
    if hay.len() < n {
        return false;
    }
    (0..=hay.len() - n).any(|i| {
        hay[i..i + n].eq_ignore_ascii_case(word)
            && (i == 0 || !is_ident(hay[i - 1]))
            && (i + n == hay.len() || !is_ident(hay[i + n]))
    })
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Whether causal ordering applies. Prefer conservative ordering when uncertain.
pub fn is_write(sql: &str) -> bool {
    // Normalize whitespace to recognize token sequences such as FOR followed by UPDATE.
    let flat: Vec<u8> = sql.split_ascii_whitespace().collect::<Vec<_>>().join(" ").into_bytes();
    let s = skip_lead(&flat);
    let kw_end = s.iter().position(|c| !c.is_ascii_alphabetic()).unwrap_or(s.len());
    let kw = &s[..kw_end];
    let is = |w: &str| kw.eq_ignore_ascii_case(w.as_bytes());
    if is("select") || is("with") || is("table") || is("values") {
        // Lock-taking reads and updates inside CTEs count as writes.
        return has_word(s, b"for update")
            || has_word(s, b"for share")
            || has_word(s, b"for no key update")
            || has_word(s, b"lock in share mode")
            || (is("with") && (has_word(s, b"insert") || has_word(s, b"update") || has_word(s, b"delete") || has_word(s, b"merge")))
            || has_word(s, b"nextval")
            || has_word(s, b"setval")
            || has_word(s, b"pg_advisory_lock")
            || has_word(s, b"get_lock")
            || has_word(s, b"into outfile");
    }
    !(kw.is_empty()
        || is("show")
        || is("explain")
        || is("desc")
        || is("describe")
        || is("begin")
        || is("start")
        || is("set")
        || is("use")
        || is("fetch")
        || is("declare")
        || is("close")
        || is("deallocate")
        || is("discard")
        || is("savepoint")
        || is("release")
        || is("reset")
        || is("listen")
        || is("unlisten"))
}

/// Whether results may vary on every execution, for non-deterministic content classification.
pub fn is_nondeterministic(sql: &str) -> bool {
    const PAT: &[&[u8]] = &[
        b"now", b"current_timestamp", b"current_date", b"current_time", b"localtimestamp", b"localtime",
        b"clock_timestamp", b"statement_timestamp", b"transaction_timestamp", b"timeofday", b"sysdate",
        b"curdate", b"curtime", b"unix_timestamp", b"utc_timestamp", b"random", b"rand", b"uuid",
        b"gen_random_uuid", b"uuid_generate_v4", b"nextval", b"currval", b"lastval", b"last_insert_id",
        b"txid_current", b"pg_backend_pid", b"connection_id", b"pg_stat_activity", b"information_schema",
        b"pg_catalog", b"performance_schema",
    ];
    let s = sql.as_bytes();
    PAT.iter().any(|p| has_word(s, p))
}

/// Replace literals with `?` to group statements by shape.
pub fn fingerprint(sql: &str) -> String {
    let s = sql.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s.len().min(512));
    let mut i = 0;
    let mut space = false;
    let push = |out: &mut Vec<u8>, space: &mut bool, b: &[u8]| {
        if *space && !out.is_empty() {
            out.push(b' ');
        }
        *space = false;
        out.extend_from_slice(b);
    };
    while i < s.len() {
        let c = s[i];
        if c.is_ascii_whitespace() {
            space = true;
            i += 1;
        } else if c == b'\'' {
            i += 1;
            while i < s.len() {
                if s[i] == b'\\' {
                    i += 2;
                } else if s[i] == b'\'' {
                    if s.get(i + 1) == Some(&b'\'') {
                        i += 2;
                    } else {
                        i += 1;
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            push(&mut out, &mut space, b"?");
        } else if s[i..].starts_with(b"/*") {
            i = s[i + 2..].windows(2).position(|w| w == b"*/").map(|p| i + p + 4).unwrap_or(s.len());
            space = true;
        } else if s[i..].starts_with(b"--") {
            i = s[i..].iter().position(|&c| c == b'\n').map(|p| i + p + 1).unwrap_or(s.len());
            space = true;
        } else if c.is_ascii_digit() && (i == 0 || !is_ident(s[i - 1]) ) {
            while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == b'.') {
                i += 1;
            }
            push(&mut out, &mut space, b"?");
        } else if c == b'$' && s.get(i + 1).is_some_and(|d| d.is_ascii_digit()) {
            i += 1;
            while i < s.len() && s[i].is_ascii_digit() {
                i += 1;
            }
            push(&mut out, &mut space, b"?");
        } else {
            push(&mut out, &mut space, &[c]);
            i += 1;
        }
    }
    // Normalize `(?, ?, ?)` and `(?,?)` to the same shape.
    let mut t = String::from_utf8_lossy(&out).into_owned();
    loop {
        let n = t.replace("?, ?", "?").replace("?,?", "?");
        if n.len() == t.len() {
            break;
        }
        t = n;
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_classification() {
        assert!(!is_write("SELECT 1"));
        assert!(!is_write("  /* hint */ select * from t"));
        assert!(is_write("select * from t where id = 1 for\n  update"));
        assert!(is_write("WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x"));
        assert!(!is_write("with x as (select 1) select * from x"));
        assert!(is_write("UPDATE t SET updated_at = 1"));
        assert!(is_write("COMMIT"));
        assert!(!is_write("BEGIN"));
        assert!(!is_write("SET search_path = a"));
        assert!(is_write("select nextval('s')"));
        // A column name containing update does not make a read a write.
        assert!(!is_write("select last_update from t"));
    }

    #[test]
    fn fingerprints() {
        assert_eq!(fingerprint("select *  from t where id = 42 and name = 'a''b'"), "select * from t where id = ? and name = ?");
        assert_eq!(fingerprint("select * from t where id in (1, 2,3)"), "select * from t where id in (?)");
        assert_eq!(fingerprint("select * from t1 where a = $1 -- x\n and b = $2"), "select * from t1 where a = ? and b = ?");
    }

    #[test]
    fn value_keys() {
        let (mut v, mut over) = (Vec::new(), false);
        literal_keys("update t1 set a = a + 5, note = 'it''s' where id = 42 -- 99\n and x = $2", &mut v, &mut over);
        // Digits in table names, comments, and placeholder indices are not values.
        assert_eq!(v, [val_key(b"5"), val_key(b"it's"), val_key(b"42")]);
        // Binary integer 42 and text 42 share a key.
        assert_eq!(int_key(42), val_key(b" 42"));
        // Too many values falls back to unknown.
        let many: String = (0..40).map(|i| format!("{i},")).collect();
        let (mut v, mut over) = (Vec::new(), false);
        literal_keys(&format!("insert into t values ({many}0)"), &mut v, &mut over);
        assert!(over && v.is_empty());
    }

    #[test]
    fn nondeterminism() {
        assert!(is_nondeterministic("select now()"));
        assert!(is_nondeterministic("insert into t values (uuid())"));
        assert!(!is_nondeterministic("select know from t"));
    }
}
