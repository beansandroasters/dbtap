//! Minimal PostgreSQL replay client: authenticate, then send recorded request bytes.

use crate::net::{Conn, TlsConfig, TlsMode, host_of};
use dbtap_proto::pg::{error_field, fold_backend, peek};
use dbtap_core::unit::Outcome;
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use sha2::{Digest, Sha256};

pub struct PgParams<'a> {
    pub addr: &'a str,
    pub user: &'a str,
    pub database: &'a str,
    pub password: &'a str,
    /// Captured StartupMessage parameters, such as application_name/client_encoding.
    pub params: &'a [(String, String)],
    pub tls: TlsMode,
    pub tls_cfg: &'a TlsConfig,
}

fn msg(typ: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 5);
    v.push(typ);
    v.extend_from_slice(&(payload.len() as u32 + 4).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn pbkdf2(password: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    let mut first = salt.to_vec();
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac(password, &first);
    let mut out = u;
    for _ in 1..iters {
        u = hmac(password, &u);
        for (o, x) in out.iter_mut().zip(u) {
            *o ^= x;
        }
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

enum Scram {
    First { bare: String, nonce: String },
    Final([u8; 32]),
    Verified,
}

fn scram_reply(password: &str, bare: &str, nonce: &str, first: &str) -> Result<(String, [u8; 32])> {
    ensure!(first.is_ascii() && first.len() <= 4096, "Invalid SCRAM challenge");
    let mut fields = std::collections::HashMap::new();
    for field in first.split(',') {
        let (k, v) = field.split_once('=').context("Invalid SCRAM attribute")?;
        ensure!(fields.insert(k, v).is_none() && k != "m", "Duplicate or unsupported SCRAM attribute");
    }
    let r = *fields.get("r").context("Missing SCRAM nonce")?;
    ensure!(r.starts_with(nonce) && r.len() > nonce.len() && r.len() <= 1024, "Invalid SCRAM nonce");
    let iterations: u32 = fields.get("i").context("Missing SCRAM iteration count")?.parse()?;
    // Bound computation requested by the target; higher iteration settings are unsupported.
    ensure!((1..=200_000).contains(&iterations), "Supported SCRAM iteration range is 1–200000");
    let salt = base64::engine::general_purpose::STANDARD.decode(fields.get("s").context("Missing SCRAM salt")?)?;
    ensure!(!salt.is_empty() && salt.len() <= 1024, "Invalid SCRAM salt length");
    let salted = pbkdf2(password.as_bytes(), &salt, iterations);
    let client_key = hmac(&salted, b"Client Key");
    let stored: [u8; 32] = Sha256::digest(client_key).into();
    let without_proof = format!("c=biws,r={r}");
    let auth = format!("{bare},{first},{without_proof}");
    let signature = hmac(&stored, auth.as_bytes());
    let proof: Vec<u8> = client_key.iter().zip(signature).map(|(a, b)| a ^ b).collect();
    let server_signature = hmac(&hmac(&salted, b"Server Key"), auth.as_bytes());
    Ok((format!("{without_proof},p={}", base64::engine::general_purpose::STANDARD.encode(proof)), server_signature))
}

fn verify_scram_final(final_message: &str, expected: &[u8; 32]) -> Result<()> {
    use subtle::ConstantTimeEq;
    let v = final_message.strip_prefix("v=").context("Invalid SCRAM server-final message")?;
    let signature = base64::engine::general_purpose::STANDARD.decode(v)?;
    ensure!(bool::from(expected.as_slice().ct_eq(&signature)), "SCRAM server signature mismatch");
    Ok(())
}

pub struct PgClient {
    c: Conn,
    /// Target backend PID from BackendKeyData, used to inspect blocking relationships.
    pub backend_pid: u32,
}

impl PgClient {
    async fn read_msg(c: &mut Conn) -> Result<(u8, Vec<u8>)> {
        c.fill(5).await?;
        let (typ, total) = loop {
            match peek(c.peek(), 0) {
                Ok(Some(m)) => break m,
                Ok(None) => {
                    let need = c.peek().len() + 1;
                    c.fill(need).await?;
                }
                Err(()) => bail!("Invalid PostgreSQL server message"),
            }
        };
        let payload = c.peek()[5..total].to_vec();
        c.consume(total);
        Ok((typ, payload))
    }

    pub async fn connect(p: &PgParams<'_>) -> Result<Self> {
        let mut c = Conn::connect(p.addr).await?;
        if p.tls != TlsMode::Disable {
            c.write_all(&[0, 0, 0, 8, 4, 210, 22, 47]).await?;
            match c.read_u8().await? {
                b'S' => c = c.upgrade(p.tls_cfg, host_of(p.addr)).await?,
                b'N' if p.tls == TlsMode::Prefer => {}
                _ => bail!("Server does not support TLS or returned an invalid response"),
            }
        }
        let mut body = 196608u32.to_be_bytes().to_vec();
        let mut put = |k: &str, v: &str| {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        };
        put("user", p.user);
        put("database", p.database);
        for (k, v) in p.params {
            put(k, v);
        }
        body.push(0);
        let mut m = (body.len() as u32 + 4).to_be_bytes().to_vec();
        m.extend(body);
        c.write_all(&m).await?;

        let mut scram = None;
        let mut authenticated = false;
        let mut auth_messages = 0;
        let mut backend_pid = 0;
        loop {
            auth_messages += 1;
            ensure!(auth_messages <= 64, "Too many authentication messages");
            let (typ, pl) = Self::read_msg(&mut c).await?;
            match typ {
                b'R' => {
                    let code = u32::from_be_bytes(pl.get(..4).context("Authentication request too short")?.try_into()?);
                    match code {
                        0 => {
                            ensure!(scram.is_none() || matches!(scram, Some(Scram::Verified)), "SCRAM verification is incomplete");
                            authenticated = true;
                        }
                        3 => {
                            ensure!(c.tls && scram.is_none() && !authenticated, "Cleartext password authentication requires TLS");
                            let mut b = p.password.as_bytes().to_vec();
                            b.push(0);
                            c.write_all(&msg(b'p', &b)).await?;
                        }
                        5 => {
                            ensure!(scram.is_none() && !authenticated, "Invalid authentication sequence");
                            use md5::Md5;
                            let inner = hex(&Md5::digest(format!("{}{}", p.password, p.user)));
                            let mut h = Md5::new();
                            h.update(inner.as_bytes());
                            h.update(pl.get(4..8).context("MD5 authentication salt too short")?);
                            let mut b = format!("md5{}", hex(&h.finalize())).into_bytes();
                            b.push(0);
                            c.write_all(&msg(b'p', &b)).await?;
                        }
                        10 => {
                            ensure!(scram.is_none() && !authenticated, "Invalid SCRAM sequence");
                            if !pl[4..].split(|b| *b == 0).any(|m| m == b"SCRAM-SHA-256") {
                                bail!("Server did not offer SCRAM-SHA-256");
                            }
                            let mut raw = [0u8; 18];
                            rand::fill(&mut raw);
                            let nonce = base64::engine::general_purpose::STANDARD.encode(raw);
                            let bare = format!("n=,r={nonce}");
                            let first = format!("n,,{bare}");
                            let mut b = b"SCRAM-SHA-256\0".to_vec();
                            b.extend_from_slice(&(first.len() as u32).to_be_bytes());
                            b.extend_from_slice(first.as_bytes());
                            c.write_all(&msg(b'p', &b)).await?;
                            scram = Some(Scram::First { bare, nonce });
                        }
                        11 => {
                            let Some(Scram::First { bare, nonce }) = scram.take() else { bail!("Invalid SCRAM sequence") };
                            let server_first = std::str::from_utf8(&pl[4..])?.to_string();
                            let password = p.password.to_owned();
                            let (fin, expected) = tokio::task::spawn_blocking(move || scram_reply(&password, &bare, &nonce, &server_first)).await??;
                            scram = Some(Scram::Final(expected));
                            c.write_all(&msg(b'p', fin.as_bytes())).await?;
                        }
                        12 => {
                            let Some(Scram::Final(expected)) = scram.take() else { bail!("Invalid SCRAM sequence") };
                            verify_scram_final(std::str::from_utf8(&pl[4..])?, &expected)?;
                            scram = Some(Scram::Verified);
                        }
                        n => bail!("Unsupported authentication method (code {n})"),
                    }
                }
                b'E' => {
                    let m = error_field(&pl, b'M').unwrap_or_default();
                    let code = error_field(&pl, b'C').unwrap_or_default();
                    bail!("Connection rejected: {code} {m}");
                }
                b'K' if pl.len() >= 4 => backend_pid = u32::from_be_bytes([pl[0], pl[1], pl[2], pl[3]]),
                b'Z' => {
                    ensure!(authenticated, "Missing authentication completion");
                    break;
                }
                _ => {}
            }
        }
        Ok(PgClient { c, backend_pid })
    }

    /// Send recorded bytes and summarize responses through ReadyForQuery.
    pub async fn run(&mut self, req: &[u8]) -> Result<Outcome> {
        self.c.write_all(req).await?;
        let mut out = Outcome::default();
        let mut tag_write = false;
        loop {
            // Fold received bytes in place without copying.
            let mut pos = 0;
            let mut done = false;
            let buf = self.c.peek();
            while let Some((typ, total)) =
                peek(buf, pos).map_err(|_| anyhow::anyhow!("Invalid PostgreSQL server message"))?
            {
                let payload = &buf[pos + 5..pos + total];
                pos += total;
                if fold_backend(&mut out, &mut tag_write, typ, payload).is_some() {
                    done = true;
                    break;
                }
            }
            let rest = buf.len() - pos;
            self.c.consume(pos);
            if done {
                return Ok(out);
            }
            self.c.fill(rest + 1).await?;
        }
    }

    /// Run one initialization statement; propagate a DB error.
    pub async fn query(&mut self, sql: &str) -> Result<()> {
        let mut b = sql.as_bytes().to_vec();
        b.push(0);
        let out = self.run(&msg(b'Q', &b)).await?;
        if let Some(e) = out.err {
            bail!("`{sql}` failed (SQLSTATE {e})");
        }
        Ok(())
    }

    /// Query target state as text rows, with NULL represented as None.
    pub async fn query_rows(&mut self, sql: &str) -> Result<Vec<Vec<Option<String>>>> {
        let mut b = sql.as_bytes().to_vec();
        b.push(0);
        self.c.write_all(&msg(b'Q', &b)).await?;
        let mut rows = Vec::new();
        let mut err = None;
        loop {
            let (typ, pl) = Self::read_msg(&mut self.c).await?;
            match typ {
                b'D' => {
                    let n = u16::from_be_bytes(pl.get(..2).context("Row too short")?.try_into()?) as usize;
                    let mut p = &pl[2..];
                    let mut row = Vec::with_capacity(n);
                    for _ in 0..n {
                        let len = i32::from_be_bytes(p.get(..4).context("Row too short")?.try_into()?);
                        p = &p[4..];
                        if len < 0 {
                            row.push(None);
                        } else {
                            let v = p.get(..len as usize).context("Row too short")?;
                            row.push(Some(String::from_utf8_lossy(v).into_owned()));
                            p = &p[len as usize..];
                        }
                    }
                    rows.push(row);
                }
                b'E' => err = Some(error_field(&pl, b'M').unwrap_or_default()),
                b'Z' => break,
                _ => {}
            }
        }
        match err {
            Some(e) => bail!("`{sql}` failed: {e}"),
            None => Ok(rows),
        }
    }

    pub async fn close(mut self) {
        let _ = self.c.write_all(&[b'X', 0, 0, 0, 4]).await;
        self.c.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_and_pbkdf2_match_rfc_vectors() {
        // RFC 4231 test case 2.
        assert_eq!(
            hex(&hmac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // RFC 7914 section 11 PBKDF2-HMAC-SHA256; c=1 uses the first 32 bytes of dkLen=64.
        assert_eq!(hex(&pbkdf2(b"passwd", b"salt", 1)), "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
    }

    #[test]
    fn scram_rejects_cost_nonce_and_signature_abuse() {
        for challenge in [
            "r=client-more,s=c2FsdA==,i=4294967295",
            "r=client-more,s=c2FsdA==,i=0",
            "r=client,s=c2FsdA==,i=4096",
            "r=client-more,s=c2FsdA==,i=4096,i=4096",
            "あ=x,r=client-more,s=c2FsdA==,i=4096",
        ] {
            assert!(scram_reply("pencil", "n=,r=client", "client", challenge).is_err());
        }
        let (_, expected) = scram_reply("pencil", "n=,r=client", "client", "r=client-more,s=c2FsdA==,i=4096").unwrap();
        let valid = format!("v={}", base64::engine::general_purpose::STANDARD.encode(expected));
        assert!(verify_scram_final(&valid, &expected).is_ok());
        assert!(verify_scram_final("e=invalid-proof", &expected).is_err());
        assert!(verify_scram_final("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &expected).is_err());
    }

    #[tokio::test]
    async fn rejects_malformed_auth_and_clear_password_without_sending_a_password() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        for payload in [3u32.to_be_bytes().to_vec(), 5u32.to_be_bytes().to_vec()] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let len = stream.read_u32().await.unwrap() as usize;
                let mut startup = vec![0; len - 4];
                stream.read_exact(&mut startup).await.unwrap();
                stream.write_all(&msg(b'R', &payload)).await.unwrap();
                let mut b = [0; 1];
                assert_eq!(stream.read(&mut b).await.unwrap(), 0);
            });
            let tls_cfg = TlsConfig::new(None, false).unwrap();
            let p = PgParams { addr: &addr, user: "test", database: "test", password: "never-send",
                params: &[], tls: TlsMode::Disable, tls_cfg: &tls_cfg };
            assert!(PgClient::connect(&p).await.is_err());
            tokio::time::timeout(std::time::Duration::from_secs(2), server).await.unwrap().unwrap();
        }
    }
}
