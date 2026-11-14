//! Annotations for causal ordering between units.
//!
//! Order operations on the same server/table when at least one writes.
//! Ordering unrelated operations would let one slow write stall every connection
//! and erase the recorded concurrency.
//!
//! Extract table names with lightweight SQL tokenization.
//! Unknown writes conservatively conflict with all operations on the server.

use dbtap_core::unit::Unit;
use std::collections::HashMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Touch {
    /// Touched tables, identified separately per server.
    pub tables: Vec<u32>,
    /// Visible changes or lock-taking operations.
    pub write: bool,
    /// Unclassified write, ordered against all operations on its server.
    pub global: bool,
    /// COMMIT/ROLLBACK releases locks without taking new ones.
    pub tx_end: bool,
    /// For COMMIT/ROLLBACK: values used by the transaction's writes.
    /// Empty if any write had unknown values, so touched rows cannot be identified.
    pub tx_vals: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum Tok<'a> {
    Word(&'a str),
    /// Contents of a quoted identifier.
    Quoted(&'a str),
    Sym(u8),
}

fn tokens(sql: &str) -> Vec<Tok<'_>> {
    let s = sql.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if s[i..].starts_with(b"--") || c == b'#' {
            i = s[i..].iter().position(|&c| c == b'\n').map(|p| i + p + 1).unwrap_or(s.len());
        } else if s[i..].starts_with(b"/*") {
            i = s[i + 2..].windows(2).position(|w| w == b"*/").map(|p| i + p + 4).unwrap_or(s.len());
        } else if c == b'\'' {
            // Skip string literals.
            i += 1;
            while i < s.len() {
                if s[i] == b'\\' {
                    i += 2;
                } else if s[i] == b'\'' {
                    i += 1;
                    if s.get(i) != Some(&b'\'') {
                        break;
                    }
                    i += 1;
                } else {
                    i += 1;
                }
            }
        } else if c == b'"' || c == b'`' {
            let end = s[i + 1..].iter().position(|&x| x == c).map(|p| i + 1 + p).unwrap_or(s.len());
            out.push(Tok::Quoted(&sql[i + 1..end]));
            i = end + 1;
        } else if c.is_ascii_alphabetic() || c == b'_' || c >= 0x80 {
            let st = i;
            while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == b'_' || s[i] == b'$' || s[i] >= 0x80) {
                i += 1;
            }
            out.push(Tok::Word(&sql[st..i]));
        } else if c.is_ascii_digit() {
            while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == b'.') {
                i += 1;
            }
            out.push(Tok::Sym(b'0'));
        } else {
            out.push(Tok::Sym(c));
            i += 1;
        }
    }
    out
}

fn is_kw(t: &Tok<'_>, kw: &str) -> bool {
    matches!(t, Tok::Word(w) if w.eq_ignore_ascii_case(kw))
}

/// Words allowed after a table name; other words are treated as aliases.
const AFTER_TABLE: &[&str] = &[
    "where", "join", "left", "right", "inner", "outer", "cross", "full", "natural", "on", "using", "group", "order",
    "limit", "having", "union", "set", "values", "for", "window", "returning", "offset", "fetch", "except",
    "intersect", "tablesample", "straight_join", "partition", "force", "use", "ignore", "select", "default", "when",
    "lock", "read", "write", "to", "from", "with", "cascade", "restrict", "add", "drop", "rename", "alter", "nowait",
    "skip", "share", "update", "delete", "insert", "into",
    // Non-tables appearing in table positions, such as COPY destinations and MySQL DUAL.
    "stdin", "stdout", "program", "dual",
];

/// SQL table names, dropping schemas and lowercasing unquoted identifiers.
pub fn tables_of(sql: &str) -> Vec<String> {
    let t = tokens(sql);
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < t.len() {
        let lead = match &t[i] {
            Tok::Word(w) => w.to_ascii_lowercase(),
            _ => {
                i += 1;
                continue;
            }
        };
        let prev_is = |kw: &str| i > 0 && is_kw(&t[i - 1], kw);
        let starts = match lead.as_str() {
            "from" | "join" | "into" | "table" | "tables" | "using" | "copy" | "truncate" | "analyze" | "vacuum" => true,
            // UPDATE in FOR UPDATE / ON DUPLICATE KEY UPDATE does not introduce a table.
            "update" => !(prev_is("for") || prev_is("key") || prev_is("no")),
            _ => false,
        };
        i += 1;
        if !starts {
            continue;
        }
        // Read comma-separated items.
        loop {
            while i < t.len()
                && ["only", "lateral", "table", "if", "exists", "not", "low_priority", "ignore", "concurrently", "local"]
                    .iter()
                    .any(|k| is_kw(&t[i], k))
            {
                i += 1;
            }
            let mut name: Option<String> = None;
            // Keep the last component of schema.table.
            loop {
                match t.get(i) {
                    Some(Tok::Word(w)) if name.is_none() || matches!(t.get(i - 1), Some(Tok::Sym(b'.'))) => {
                        name = Some(w.to_ascii_lowercase());
                        i += 1;
                    }
                    Some(Tok::Quoted(q)) if name.is_none() || matches!(t.get(i - 1), Some(Tok::Sym(b'.'))) => {
                        name = Some(q.to_string());
                        i += 1;
                    }
                    Some(Tok::Sym(b'.')) if name.is_some() => i += 1,
                    _ => break,
                }
            }
            let Some(name) = name else { break };
            // Parentheses after a name indicate a function or INSERT column list.
            let is_call = matches!(t.get(i), Some(Tok::Sym(b'('))) && !matches!(lead.as_str(), "into" | "copy" | "table");
            if !is_call && !AFTER_TABLE.contains(&name.as_str()) && !out.contains(&name) {
                out.push(name);
            }
            if is_call {
                break;
            }
            // Alias.
            if t.get(i).is_some_and(|x| is_kw(x, "as")) {
                i += 2;
            } else if let Some(Tok::Word(w)) = t.get(i) {
                if !AFTER_TABLE.contains(&w.to_ascii_lowercase().as_str()) {
                    i += 1;
                }
            } else if let Some(Tok::Quoted(_)) = t.get(i) {
                i += 1;
            }
            if matches!(t.get(i), Some(Tok::Sym(b','))) && matches!(lead.as_str(), "from" | "update" | "table" | "tables" | "truncate") {
                i += 1;
                continue;
            }
            break;
        }
    }
    out
}

fn first_word(sql: &str) -> String {
    tokens(sql).into_iter().find_map(|t| if let Tok::Word(w) = t { Some(w.to_ascii_lowercase()) } else { None }).unwrap_or_default()
}

/// Synthetic table for ordering function-only writes such as nextval/advisory locks.
const FN_TABLE: &str = "\0fn";

#[derive(Default)]
struct TxState {
    tables: Vec<u32>,
    global: bool,
    vals: Vec<u64>,
    /// A write had unknown values or exceeded the retained-value limit.
    vals_unknown: bool,
}

/// Maximum values retained per transaction.
const MAX_TX_VALS: usize = 64;

/// Annotate units in recorded completion order.
/// Per-connection transaction state requires preserving each connection's unit order.
#[derive(Default)]
pub struct Annotator {
    /// (Server, table name) to ID; different servers use distinct IDs.
    intern: HashMap<(u32, String), u32>,
    tx: HashMap<u64, TxState>,
}

impl Annotator {
    fn table(&mut self, server: u32, name: String) -> u32 {
        let id = self.intern.len() as u32;
        *self.intern.entry((server, name)).or_insert(id)
    }

    /// Discard transaction state when a connection closes.
    pub fn forget(&mut self, conn: u64) {
        self.tx.remove(&conn);
    }

    pub fn touch(&mut self, u: &Unit, server: u32) -> Touch {
        if u.skip.is_some() {
            return Touch::default();
        }
        let mut touch = Touch { write: u.write, ..Default::default() };
        // A unit may contain several statements, such as a PostgreSQL pipeline.
        let mut ends_tx = false;
        let mut begins_tx = false;
        for sql in u.sql.split(";\n") {
            let kw = first_word(sql);
            match kw.as_str() {
                "commit" | "rollback" | "end" | "abort" => {
                    // ROLLBACK TO SAVEPOINT does not end the transaction.
                    if !sql.to_ascii_lowercase().contains("savepoint") {
                        ends_tx = true;
                    }
                    continue;
                }
                "begin" | "start" => {
                    begins_tx = true;
                    continue;
                }
                _ => {}
            }
            let names = tables_of(sql);
            if names.is_empty() && u.write && dbtap_core::unit::is_write(sql) {
                if matches!(kw.as_str(), "select" | "with" | "values") {
                    let id = self.table(server, FN_TABLE.to_string());
                    touch.tables.push(id);
                } else {
                    touch.global = true;
                }
            }
            for n in names {
                let id = self.table(server, n);
                if !touch.tables.contains(&id) {
                    touch.tables.push(id);
                }
            }
        }
        if u.many && u.write {
            touch.global = true;
        }
        let st = self.tx.entry(u.conn).or_default();
        if begins_tx {
            *st = TxState::default();
        }
        if touch.write {
            for t in &touch.tables {
                if !st.tables.contains(t) {
                    st.tables.push(*t);
                }
            }
            st.global |= touch.global;
            if ends_tx {
                // COMMIT/ROLLBACK does not itself access rows.
            } else if u.vals.is_empty() || st.vals.len() + u.vals.len() > MAX_TX_VALS {
                st.vals_unknown = true;
            } else {
                for v in &u.vals {
                    if !st.vals.contains(v) {
                        st.vals.push(*v);
                    }
                }
            }
        }
        if ends_tx {
            // Treat transaction completion as a visibility boundary for its written tables.
            let done = std::mem::take(st);
            for t in done.tables {
                if !touch.tables.contains(&t) {
                    touch.tables.push(t);
                }
            }
            touch.global |= done.global;
            if !done.vals_unknown {
                touch.tx_vals = done.vals;
            }
            // Read-only transaction completion has no ordering conflicts.
            touch.write = touch.global || !touch.tables.is_empty();
            touch.tx_end = true;
        }
        if touch.global {
            touch.tables.clear();
        }
        touch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbtap_core::unit::Outcome;

    fn t(sql: &str) -> Vec<String> {
        tables_of(sql)
    }

    #[test]
    fn extracts_tables() {
        assert_eq!(t("select * from accounts where id = 1"), ["accounts"]);
        assert_eq!(t("SELECT a.x FROM public.Accounts a JOIN \"Order Items\" oi ON a.id = oi.aid"), ["accounts", "Order Items"]);
        assert_eq!(t("select * from a, b as bb, c where a.x = 'from d'"), ["a", "b", "c"]);
        assert_eq!(t("update accounts set balance = balance - 1 where id = 2"), ["accounts"]);
        assert_eq!(t("insert into orders (a, b) values (1, 2)"), ["orders"]);
        assert_eq!(t("insert into t1 select * from t2"), ["t1", "t2"]);
        assert_eq!(t("delete from `orders` where id in (select order_id from refunds)"), ["orders", "refunds"]);
        assert_eq!(t("select * from accounts where id = 1 for update"), ["accounts"]);
        assert_eq!(t("insert into t (a) values (1) on duplicate key update a = 2"), ["t"]);
        assert_eq!(t("select * from generate_series(1, 5) g"), Vec::<String>::new());
        assert_eq!(t("copy bulk (k, v) from stdin"), ["bulk"]);
        assert_eq!(t("truncate table a, b"), ["a", "b"]);
        assert_eq!(t("with x as (select * from src) select * from x"), ["src", "x"]);
        assert_eq!(t("select 1"), Vec::<String>::new());
        assert_eq!(t("select now() -- from nowhere"), Vec::<String>::new());
        assert_eq!(t("merge into tgt using src on tgt.id = src.id when matched then update set a = 1"), ["tgt", "src"]);
    }

    fn unit(conn: u64, sql: &str) -> Unit {
        Unit {
            conn,
            t_start: 0,
            t_end: 0,
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

    #[test]
    fn commit_carries_the_tables_its_transaction_wrote() {
        let units = vec![
            unit(1, "BEGIN"),
            unit(1, "select * from accounts"),
            unit(1, "update accounts set x = 1"),
            unit(2, "BEGIN"),
            unit(2, "select * from orders"),
            unit(1, "insert into orders values (1)"),
            unit(2, "COMMIT"),
            unit(1, "COMMIT"),
            unit(1, "select nextval('s')"),
            unit(1, "create index i on accounts (x)"),
        ];
        let mut ann = Annotator::default();
        let a: Vec<Touch> = units.iter().map(|u| ann.touch(u, 0)).collect();
        assert_eq!(a[0], Touch::default());
        assert!(!a[1].write && a[1].tables.len() == 1);
        let (accounts, orders) = (a[2].tables[0], a[5].tables[0]);
        // Connection 2 only read; its COMMIT has no ordering conflicts.
        assert_eq!(a[6], Touch { tx_end: true, ..Default::default() });
        assert_eq!(a[7], Touch { tables: vec![accounts, orders], write: true, global: false, tx_end: true, tx_vals: vec![] });
        assert!(a[8].write && !a[8].global && a[8].tables.len() == 1);
        // DDL with an unidentified table conflicts with everything.
        assert_eq!(a[9], Touch { tables: vec![], write: true, global: true, tx_end: false, tx_vals: vec![] });
    }

    #[test]
    fn commit_carries_the_values_its_transaction_wrote() {
        let with = |mut u: Unit, vals: &[u64]| {
            u.vals = vals.to_vec();
            u
        };
        let mut ann = Annotator::default();
        let units = vec![
            unit(1, "BEGIN"),
            with(unit(1, "update accounts set x = x + $1 where id = $2"), &[5, 100]),
            with(unit(1, "select * from accounts where id = $1"), &[777]),
            with(unit(1, "insert into orders values ($1, $2)"), &[100, 9]),
            unit(1, "COMMIT"),
            unit(1, "BEGIN"),
            with(unit(1, "update accounts set x = 0 where id = $1"), &[3]),
            unit(1, "update accounts set y = 0"),
            unit(1, "COMMIT"),
        ];
        let a: Vec<Touch> = units.iter().map(|u| ann.touch(u, 0)).collect();
        // Collect only write values, excluding the read's 777.
        assert_eq!(a[4].tx_vals, [5, 100, 9]);
        // Unknown write values make the transaction's touched rows unknown.
        assert!(a[8].tx_end && a[8].tx_vals.is_empty());
    }

    #[test]
    fn same_table_name_on_different_servers_is_distinct() {
        let units = vec![unit(1, "update t set a = 1"), unit(2, "update t set a = 1")];
        let mut ann = Annotator::default();
        let a = [ann.touch(&units[0], 0), ann.touch(&units[1], 1)];
        assert_ne!(a[0].tables, a[1].tables);
    }
}
