//! Minimal MySQL replay client: authenticate, then send recorded commands.
//! Map captured statement IDs to target IDs returned by PREPARE.

use dbtap_proto::mysql::*;
use crate::net::{Conn, TlsConfig, TlsMode, host_of};
use dbtap_core::unit::Outcome;
use anyhow::{Context, Result, bail, ensure};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub struct MyParams<'a> {
    pub addr: &'a str,
    pub user: &'a str,
    pub database: Option<&'a str>,
    pub password: &'a str,
    /// Captured client capabilities; zero means unknown from mid-stream capture.
    pub caps: u32,
    pub charset: u8,
    pub tls: TlsMode,
    pub tls_cfg: &'a TlsConfig,
}

const MAX_PACKET: usize = 0xff_ffff;

fn native_scramble(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let h1 = Sha1::digest(password.as_bytes());
    let h2 = Sha1::digest(h1);
    let mut h = Sha1::new();
    h.update(nonce);
    h.update(h2);
    h1.iter().zip(h.finalize()).map(|(a, b)| a ^ b).collect()
}

fn sha2_scramble(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let h1 = Sha256::digest(password.as_bytes());
    let h2 = Sha256::digest(h1);
    let mut h = Sha256::new();
    h.update(h2);
    h.update(nonce);
    h1.iter().zip(h.finalize()).map(|(a, b)| a ^ b).collect()
}

fn scramble(plugin: &str, password: &str, nonce: &[u8], tls: bool) -> Result<Vec<u8>> {
    ensure!(!nonce.is_empty() && nonce.len() <= 256, "Invalid authentication nonce length");
    Ok(match plugin {
        "mysql_native_password" => native_scramble(password, nonce),
        "caching_sha2_password" => sha2_scramble(password, nonce),
        "mysql_clear_password" => {
            ensure!(tls, "mysql_clear_password requires TLS");
            let mut v = password.as_bytes().to_vec();
            v.push(0);
            v
        }
        p => bail!("Unsupported authentication plugin: {p}"),
    })
}

pub struct MyClient {
    c: Conn,
    seq: u8,
    deprecate_eof: bool,
    query_attrs: bool,
    /// Captured statement ID to target statement ID.
    stmts: HashMap<u32, u32>,
    scratch: Vec<u8>,
    /// Target connection ID for blocking-relationship queries.
    pub conn_id: u32,
}

impl MyClient {
    async fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            self.c.fill(4).await?;
            let h = self.c.peek();
            let len = h[0] as usize | (h[1] as usize) << 8 | (h[2] as usize) << 16;
            self.seq = h[3].wrapping_add(1);
            self.c.fill(4 + len).await?;
            ensure!(out.len() + len <= dbtap_core::journal::MAX_FIELD, "MySQL message exceeds size limit");
            out.extend_from_slice(&self.c.peek()[4..4 + len]);
            self.c.consume(4 + len);
            if len < MAX_PACKET {
                return Ok(out);
            }
        }
    }

    async fn write_packet(&mut self, payload: &[u8]) -> Result<()> {
        let mut rest = payload;
        self.scratch.clear();
        loop {
            let n = rest.len().min(MAX_PACKET);
            self.scratch.extend_from_slice(&[n as u8, (n >> 8) as u8, (n >> 16) as u8, self.seq]);
            self.scratch.extend_from_slice(&rest[..n]);
            self.seq = self.seq.wrapping_add(1);
            rest = &rest[n..];
            // End an exact maximum-size payload with an empty packet.
            if n < MAX_PACKET {
                break;
            }
        }
        let buf = std::mem::take(&mut self.scratch);
        let r = self.c.write_all(&buf).await;
        self.scratch = buf;
        r
    }

    pub async fn connect(p: &MyParams<'_>) -> Result<Self> {
        let c = Conn::connect(p.addr).await?;
        let mut me =
            MyClient { c, seq: 0, deprecate_eof: false, query_attrs: false, stmts: HashMap::new(), scratch: Vec::new(), conn_id: 0 };
        let g = me.read_packet().await?;
        if g.first() == Some(&0xff) {
            bail!("Connection rejected: {}", String::from_utf8_lossy(&g[3.min(g.len())..]));
        }
        if g.first() != Some(&10) {
            bail!("Unsupported handshake");
        }
        let ver_end = g[1..].iter().position(|&b| b == 0).context("Invalid handshake")? + 2;
        let r = g.get(ver_end..).context("Handshake too short")?;
        if r.len() < 31 {
            bail!("Handshake too short");
        }
        me.conn_id = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
        let mut nonce = r[4..12].to_vec();
        let server_caps = u16::from_le_bytes([r[13], r[14]]) as u32 | (u16::from_le_bytes([r[18], r[19]]) as u32) << 16;
        let auth_len = r[20] as usize;
        let more = auth_len.saturating_sub(8).max(13);
        let tail = &r[31..];
        nonce.extend_from_slice(&tail[..more.min(tail.len())]);
        if nonce.last() == Some(&0) {
            nonce.pop();
        }
        let mut plugin = String::from_utf8_lossy(tail.get(more..).unwrap_or(&[]).split(|b| *b == 0).next().unwrap_or(&[])).into_owned();
        if plugin.is_empty() {
            plugin = "mysql_native_password".into();
        }

        // Retain capabilities affecting command/response representation.
        // Otherwise the target cannot interpret recorded bytes in their original form.
        let known = p.caps != 0;
        let inherit = CLIENT_MULTI_STATEMENTS | CLIENT_QUERY_ATTRIBUTES | CLIENT_DEPRECATE_EOF;
        let mut caps = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_PLUGIN_AUTH_LENENC
            | CLIENT_TRANSACTIONS
            | CLIENT_LONG_PASSWORD
            | CLIENT_LONG_FLAG
            | CLIENT_MULTI_RESULTS
            | CLIENT_PS_MULTI_RESULTS
            | (p.caps & inherit)
            | if known { 0 } else { CLIENT_DEPRECATE_EOF };
        if p.database.is_some() {
            caps |= CLIENT_CONNECT_WITH_DB;
        }
        caps &= server_caps | CLIENT_MULTI_STATEMENTS;
        if p.caps & CLIENT_QUERY_ATTRIBUTES & !server_caps != 0 {
            bail!("Recording uses query attributes unsupported by the target");
        }
        me.deprecate_eof = caps & CLIENT_DEPRECATE_EOF != 0;
        me.query_attrs = caps & CLIENT_QUERY_ATTRIBUTES != 0;
        let charset = if p.charset != 0 { p.charset } else { 45 };

        if p.tls != TlsMode::Disable {
            if server_caps & CLIENT_SSL != 0 {
                caps |= CLIENT_SSL;
                let mut b = caps.to_le_bytes().to_vec();
                b.extend_from_slice(&(MAX_PACKET as u32).to_le_bytes());
                b.push(charset);
                b.extend_from_slice(&[0; 23]);
                me.write_packet(&b).await?;
                me.c = me.c.upgrade(p.tls_cfg, host_of(p.addr)).await?;
            } else if p.tls == TlsMode::Require {
                bail!("Server does not support TLS");
            }
        }

        let mut b = caps.to_le_bytes().to_vec();
        b.extend_from_slice(&(MAX_PACKET as u32).to_le_bytes());
        b.push(charset);
        b.extend_from_slice(&[0; 23]);
        b.extend_from_slice(p.user.as_bytes());
        b.push(0);
        let auth = scramble(&plugin, p.password, &nonce, me.c.tls)?;
        b.push(auth.len() as u8);
        b.extend_from_slice(&auth);
        if let Some(db) = p.database {
            b.extend_from_slice(db.as_bytes());
            b.push(0);
        }
        b.extend_from_slice(plugin.as_bytes());
        b.push(0);
        me.write_packet(&b).await?;
        me.auth_loop(p.password, nonce, p.tls == TlsMode::Disable).await?;
        Ok(me)
    }

    async fn auth_loop(&mut self, password: &str, mut nonce: Vec<u8>, allow_unverified_key: bool) -> Result<()> {
        let mut messages = 0;
        loop {
            messages += 1;
            ensure!(messages <= 16, "Too many authentication messages");
            let r = self.read_packet().await?;
            match r.first() {
                Some(0x00) => return Ok(()),
                Some(0xff) => {
                    let code = u16::from_le_bytes(r.get(1..3).context("Authentication ERR too short")?.try_into()?);
                    bail!("Connection rejected: {code} {}", String::from_utf8_lossy(&r[3..]));
                }
                // Authentication method switch.
                Some(0xfe) => {
                    let mut it = r[1..].splitn(2, |b| *b == 0);
                    let plugin = String::from_utf8_lossy(it.next().unwrap_or(&[])).into_owned();
                    nonce = it.next().unwrap_or(&[]).to_vec();
                    if nonce.last() == Some(&0) {
                        nonce.pop();
                    }
                    let a = scramble(&plugin, password, &nonce, self.c.tls)?;
                    self.write_packet(&a).await?;
                }
                Some(0x01) => match r.get(1) {
                    // caching_sha2_password cache hit; expect OK next.
                    Some(0x03) => {}
                    // Cache miss: send the password through the negotiated authentication path.
                    Some(0x04) => {
                        let mut pw = password.as_bytes().to_vec();
                        pw.push(0);
                        if self.c.tls {
                            self.write_packet(&pw).await?;
                        } else {
                            // Allow only explicit --tls disable for isolated tests; the fetched key does not authenticate the server.
                            ensure!(allow_unverified_key, "TLS is required to authenticate the server key (use --tls require)");
                            ensure!(!nonce.is_empty(), "Missing authentication nonce");
                            self.write_packet(&[0x02]).await?;
                            let k = self.read_packet().await?;
                            if k.first() != Some(&0x01) {
                                bail!("Cannot retrieve server public key");
                            }
                            use rsa::pkcs8::DecodePublicKey;
                            let key = rsa::PublicKey::from_public_key_pem(std::str::from_utf8(&k[1..])?)
                                .context("Cannot parse server public key")?;
                            for (i, b) in pw.iter_mut().enumerate() {
                                *b ^= nonce[i % nonce.len()];
                            }
                            let enc = key.oaep_encrypt::<Sha1>(&pw).context("Password encryption failed")?;
                            self.write_packet(&enc).await?;
                        }
                    }
                    _ => bail!("Invalid additional authentication data"),
                },
                _ => bail!("Invalid authentication response (prefix {:02x?})", &r[..r.len().min(8)]),
            }
        }
    }

    /// Send a recorded command and summarize its complete response.
    /// captured_stmt is the original server ID when this command is PREPARE.
    pub async fn run(&mut self, req: &[u8], captured_stmt: u32) -> Result<Outcome> {
        let cmd = *req.first().context("Empty command")?;
        if cmd == COM_CHANGE_USER {
            return Ok(Outcome { err: Some("replay:change-user".into()), ..Default::default() });
        }
        self.seq = 0;
        let uses_stmt =
            matches!(cmd, COM_STMT_EXECUTE | COM_STMT_FETCH | COM_STMT_RESET | COM_STMT_SEND_LONG_DATA | COM_STMT_CLOSE);
        if uses_stmt && req.len() >= 5 {
            let old = u32::from_le_bytes([req[1], req[2], req[3], req[4]]);
            let Some(&new) = self.stmts.get(&old) else {
                // Target PREPARE failed; sending its captured ID could reference an unrelated statement.
                return Ok(Outcome { err: Some("replay:no-stmt".into()), ..Default::default() });
            };
            let mut b = req.to_vec();
            b[1..5].copy_from_slice(&new.to_le_bytes());
            self.write_packet(&b).await?;
            if cmd == COM_STMT_CLOSE {
                self.stmts.remove(&old);
            }
        } else {
            self.write_packet(req).await?;
        }
        let mut resp = Resp::new(expect_for(cmd), Some(self.deprecate_eof));
        while !resp.done() {
            if resp.wants_infile() {
                // Do not replay LOAD DATA LOCAL; send an empty file to avoid leaving the server waiting.
                self.write_packet(&[]).await?;
                resp.client_packet(&[]);
                continue;
            }
            let p = self.read_packet().await?;
            resp.packet(&p);
        }
        if cmd == COM_STMT_PREPARE {
            if let Some(id) = resp.stmt_id {
                self.stmts.insert(captured_stmt, id);
            }
        }
        Ok(resp.out)
    }

    /// Run one initialization statement; propagate a DB error.
    pub async fn query(&mut self, sql: &str) -> Result<()> {
        let mut req = vec![COM_QUERY];
        if self.query_attrs {
            req.extend_from_slice(&[0, 1]);
        }
        req.extend_from_slice(sql.as_bytes());
        let out = self.run(&req, 0).await?;
        if let Some(e) = out.err {
            bail!("`{sql}` failed (error {e})");
        }
        Ok(())
    }

    /// Query target state as text rows, with NULL represented as None.
    pub async fn query_rows(&mut self, sql: &str) -> Result<Vec<Vec<Option<String>>>> {
        let mut req = vec![COM_QUERY];
        if self.query_attrs {
            req.extend_from_slice(&[0, 1]);
        }
        req.extend_from_slice(sql.as_bytes());
        self.seq = 0;
        self.write_packet(&req).await?;
        let first = self.read_packet().await?;
        let fail = |p: &[u8]| anyhow::anyhow!("`{sql}` failed: {}", String::from_utf8_lossy(&p[3.min(p.len())..]));
        match first.first() {
            Some(0xff) => return Err(fail(&first)),
            Some(0x00) | None => return Ok(Vec::new()),
            _ => {}
        }
        let (cols, _) = lenenc(&first).context("Cannot read column count")?;
        for _ in 0..cols {
            self.read_packet().await?;
        }
        if !self.deprecate_eof {
            self.read_packet().await?;
        }
        let mut rows = Vec::new();
        loop {
            let p = self.read_packet().await?;
            match p.first() {
                Some(0xff) => return Err(fail(&p)),
                Some(0xfe) if p.len() < MAX_PACKET => return Ok(rows),
                _ => {}
            }
            let mut row = Vec::with_capacity(cols as usize);
            let mut i = 0;
            for _ in 0..cols {
                if p.get(i) == Some(&0xfb) {
                    row.push(None);
                    i += 1;
                } else {
                    let (l, n) = lenenc(p.get(i..).context("Row too short")?).context("Cannot decode row")?;
                    let v = p.get(i + n..i + n + l as usize).context("Row too short")?;
                    row.push(Some(String::from_utf8_lossy(v).into_owned()));
                    i += n + l as usize;
                }
            }
            rows.push(row);
        }
    }

    pub async fn close(mut self) {
        self.seq = 0;
        let _ = self.write_packet(&[COM_QUIT]).await;
        self.c.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_password_requires_tls_and_nonce_cannot_be_empty() {
        assert!(scramble("mysql_clear_password", "example", b"nonce", false).is_err());
        assert_eq!(scramble("mysql_clear_password", "example", b"nonce", true).unwrap(), b"example\0");
        assert!(scramble("caching_sha2_password", "example", b"", false).is_err());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Expected values independently computed with Python hashlib (e2e/scramble_vectors.py).
    #[test]
    fn scrambles_match_independent_implementation() {
        let nonce: Vec<u8> = (1..=20).collect();
        assert_eq!(hex(&native_scramble("secret", &nonce)), "b32bb3a583e1340c0a1108d58b1be49781ad8c2f");
        assert_eq!(hex(&sha2_scramble("secret", &nonce)), "746ebe205d56a0707acb3e796e834e0dd7b1d61743b26bd5202c7a623230c7c9");
        assert!(native_scramble("", &nonce).is_empty());
    }
}
