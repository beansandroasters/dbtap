//! Shared journal format.
//!
//! All inputs (AF_PACKET, pcap, and DB logs) produce this format.
//! Reconstruction, replay, and comparison consume journals independently of the input source.
//!
//! Format: magic `DBTAPJ1\n`, then a zstd stream containing records.
//! Each record starts with `tag:u8`, followed by varints and length-prefixed byte strings.
//! Encoding is handwritten to avoid allocating for each record on the capture path.
//! Data payloads are copied directly.

use anyhow::{Context, Result, bail};
use std::io::{BufReader, BufWriter, Read, Write};
use crate::unit::{ConnInfo, Unit};

pub const MAGIC: &[u8; 8] = b"DBTAPJ1\n";
/// Maximum byte string allocated from external input at once (64 MiB).
pub const MAX_FIELD: usize = 64 << 20;

pub fn create_private(path: &str) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
        .with_context(|| format!("create new private file {path}"))
}

pub fn write_private(path: &str, bytes: &[u8]) -> Result<()> {
    let mut file = create_private(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Proto {
    Postgres,
    Mysql,
    /// Unknown until initial protocol bytes are available.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Client to server (request).
    ToServer,
    /// Server to client (response).
    ToClient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// One per file. `started_ns` is a UNIX timestamp in ns, identifying the recording's start.
    Header { started_ns: u64, source: String },
    /// `mid_stream` means authentication or PREPARE may precede capture.
    ConnOpen { conn: u64, ts: u64, proto: Proto, client: String, server: String, mid_stream: bool },
    Data { conn: u64, ts: u64, dir: Dir, bytes: Vec<u8> },
    ConnClose { conn: u64, ts: u64 },
    /// Capture loss (ring overflow or truncation); subsequent reconstruction may be incomplete.
    Lost { conn: u64, ts: u64, bytes: u64 },
    /// Session metadata from logs; no wire authentication reconstruction is required.
    Session { ts: u64, info: ConnInfo },
    /// Reconstructed log unit. Older J1 records remain readable.
    Unit(Unit),
}

const T_HEADER: u8 = 1;
const T_OPEN: u8 = 2;
const T_DATA: u8 = 3;
const T_CLOSE: u8 = 4;
const T_LOST: u8 = 5;
const T_SESSION: u8 = 6;
const T_UNIT: u8 = 7;

fn put_var(w: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        w.push((v as u8) | 0x80);
        v >>= 7;
    }
    w.push(v as u8);
}

fn put_bytes(w: &mut Vec<u8>, b: &[u8]) {
    put_var(w, b.len() as u64);
    w.extend_from_slice(b);
}

pub fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

pub struct Writer<W: Write> {
    out: zstd::Encoder<'static, BufWriter<W>>,
    buf: Vec<u8>,
}

impl Writer<std::fs::File> {
    pub fn create(path: &str, source: &str) -> Result<Self> {
        let f = create_private(path)?;
        Writer::new(f, source)
    }
}

impl<W: Write> Writer<W> {
    pub fn new(inner: W, source: &str) -> Result<Self> {
        Self::new_at(inner, source, now_ns())
    }

    /// Log import preserves the recording start, not the conversion time.
    pub fn new_at(inner: W, source: &str, started_ns: u64) -> Result<Self> {
        let mut bw = BufWriter::with_capacity(1 << 20, inner);
        bw.write_all(MAGIC)?;
        // Level 1 minimizes capture CPU cost; repetitive SQL still compresses well.
        let out = zstd::Encoder::new(bw, 1)?;
        let mut w = Writer { out, buf: Vec::with_capacity(1 << 16) };
        w.write(&Record::Header { started_ns, source: source.to_string() })?;
        Ok(w)
    }

    pub fn write(&mut self, r: &Record) -> Result<()> {
        let b = &mut self.buf;
        b.clear();
        match r {
            Record::Header { started_ns, source } => {
                b.push(T_HEADER);
                put_var(b, *started_ns);
                put_bytes(b, source.as_bytes());
            }
            Record::ConnOpen { conn, ts, proto, client, server, mid_stream } => {
                b.push(T_OPEN);
                put_var(b, *conn);
                put_var(b, *ts);
                b.push(match proto {
                    Proto::Postgres => 1,
                    Proto::Mysql => 2,
                    Proto::Unknown => 0,
                });
                put_bytes(b, client.as_bytes());
                put_bytes(b, server.as_bytes());
                b.push(*mid_stream as u8);
            }
            Record::Data { conn, ts, dir, bytes } => return self.write_data(*conn, *ts, *dir, bytes),
            Record::ConnClose { conn, ts } => {
                b.push(T_CLOSE);
                put_var(b, *conn);
                put_var(b, *ts);
            }
            Record::Lost { conn, ts, bytes } => {
                b.push(T_LOST);
                put_var(b, *conn);
                put_var(b, *ts);
                put_var(b, *bytes);
            }
            Record::Session { ts, info } => {
                b.push(T_SESSION);
                put_var(b, *ts);
                put_bytes(b, &serde_json::to_vec(info)?);
            }
            Record::Unit(unit) => {
                b.push(T_UNIT);
                put_bytes(b, &serde_json::to_vec(unit)?);
            }
        }
        if self.buf.len() > MAX_FIELD {
            bail!("Journal record exceeds the 64 MiB limit");
        }
        self.out.write_all(&self.buf)?;
        Ok(())
    }

    /// Write Data without allocating a Vec on the capture hot path.
    pub fn write_data(&mut self, conn: u64, ts: u64, dir: Dir, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_FIELD {
            bail!("Journal Data exceeds the 64 MiB limit");
        }
        let b = &mut self.buf;
        b.clear();
        b.push(T_DATA);
        put_var(b, conn);
        put_var(b, ts);
        b.push(matches!(dir, Dir::ToClient) as u8);
        put_var(b, bytes.len() as u64);
        self.out.write_all(&self.buf)?;
        // Stream the payload directly without adding it to the buffer.
        self.out.write_all(bytes)?;
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        let mut bw = self.out.finish()?;
        bw.flush()?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}

pub struct Reader<R: Read> {
    inp: zstd::Decoder<'static, BufReader<BufReader<R>>>,
}

impl Reader<std::fs::File> {
    pub fn open(path: &str) -> Result<Self> {
        let f = std::fs::File::open(path).with_context(|| format!("open {path}"))?;
        Reader::new(f)
    }
}

impl<R: Read> Reader<R> {
    pub fn new(inner: R) -> Result<Self> {
        let mut br = BufReader::with_capacity(1 << 20, inner);
        let mut m = [0u8; 8];
        br.read_exact(&mut m)?;
        if &m != MAGIC {
            bail!("Not a dbtap journal (magic mismatch)");
        }
        Ok(Reader { inp: zstd::Decoder::new(br)? })
    }

    fn var(&mut self) -> Result<u64> {
        let mut v = 0u64;
        let mut shift = 0;
        loop {
            let mut b = [0u8; 1];
            self.inp.read_exact(&mut b)?;
            if shift == 63 && b[0] > 1 {
                bail!("varint exceeds u64 range");
            }
            v |= ((b[0] & 0x7f) as u64) << shift;
            if b[0] & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
            if shift > 63 {
                bail!("Invalid varint");
            }
        }
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = usize::try_from(self.var()?).context("Byte string is too long")?;
        if n > MAX_FIELD {
            bail!("Journal field exceeds the 64 MiB limit");
        }
        let mut v = vec![0u8; n];
        self.inp.read_exact(&mut v)?;
        Ok(v)
    }

    fn u8(&mut self) -> Result<u8> {
        let mut b = [0u8; 1];
        self.inp.read_exact(&mut b)?;
        Ok(b[0])
    }

    /// None at EOF; retain readable records if a killed writer left a truncated zstd tail.
    pub fn next(&mut self) -> Result<Option<Record>> {
        let tag = match self.u8() {
            Ok(t) => t,
            Err(e) => {
                if let Some(io) = e.downcast_ref::<std::io::Error>() {
                    if io.kind() == std::io::ErrorKind::UnexpectedEof {
                        return Ok(None);
                    }
                }
                return Err(e);
            }
        };
        let r = match tag {
            T_HEADER => Record::Header {
                started_ns: self.var()?,
                source: String::from_utf8_lossy(&self.bytes()?).into_owned(),
            },
            T_OPEN => Record::ConnOpen {
                conn: self.var()?,
                ts: self.var()?,
                proto: match self.u8()? {
                    1 => Proto::Postgres,
                    2 => Proto::Mysql,
                    _ => Proto::Unknown,
                },
                client: String::from_utf8_lossy(&self.bytes()?).into_owned(),
                server: String::from_utf8_lossy(&self.bytes()?).into_owned(),
                mid_stream: self.u8()? != 0,
            },
            T_DATA => {
                let conn = self.var()?;
                let ts = self.var()?;
                let dir = if self.u8()? == 1 { Dir::ToClient } else { Dir::ToServer };
                Record::Data { conn, ts, dir, bytes: self.bytes()? }
            }
            T_CLOSE => Record::ConnClose { conn: self.var()?, ts: self.var()? },
            T_LOST => Record::Lost { conn: self.var()?, ts: self.var()?, bytes: self.var()? },
            T_SESSION => Record::Session { ts: self.var()?, info: serde_json::from_slice(&self.bytes()?)? },
            T_UNIT => {
                let unit: Unit = serde_json::from_slice(&self.bytes()?)?;
                if unit.t_end < unit.t_start {
                    bail!("Unit end precedes its start");
                }
                Record::Unit(unit)
            }
            t => bail!("Unknown record type {t}"),
        };
        Ok(Some(r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_output_never_overwrites_an_existing_file_or_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let path = std::env::temp_dir().join(format!("dbtap-private-{}-{}", std::process::id(), now_ns()));
        let alias = path.with_extension("link");
        write_private(path.to_str().unwrap(), b"original").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(write_private(path.to_str().unwrap(), b"replacement").is_err());
        symlink(&path, &alias).unwrap();
        assert!(write_private(alias.to_str().unwrap(), b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_oversized_lengths_and_overflowing_varints_before_allocation() {
        for length in [vec![255; 10], {
            let mut n = vec![];
            put_var(&mut n, u64::MAX);
            n
        }] {
            let mut body = vec![T_DATA, 1, 1, 1];
            body.extend(length);
            let mut data = MAGIC.to_vec();
            data.extend(zstd::encode_all(&body[..], 1).unwrap());
            assert!(Reader::new(&data[..]).unwrap().next().is_err());
        }
    }

    #[test]
    fn roundtrip() {
        let mut out = Vec::new();
        {
            let mut w = Writer::new(&mut out, "test").unwrap();
            w.write(&Record::ConnOpen {
                conn: 7,
                ts: 123,
                proto: Proto::Mysql,
                client: "1.2.3.4:5".into(),
                server: "5.6.7.8:3306".into(),
                mid_stream: true,
            })
            .unwrap();
            w.write_data(7, 124, Dir::ToServer, b"hello").unwrap();
            w.write(&Record::Data { conn: 7, ts: 125, dir: Dir::ToClient, bytes: vec![0; 300] }).unwrap();
            w.write(&Record::Lost { conn: 7, ts: 126, bytes: 9 }).unwrap();
            w.write(&Record::ConnClose { conn: 7, ts: 127 }).unwrap();
            w.finish().unwrap();
        }
        let mut rd = Reader::new(&out[..]).unwrap();
        let mut rs = Vec::new();
        while let Some(r) = rd.next().unwrap() {
            rs.push(r);
        }
        assert_eq!(rs.len(), 6);
        assert!(matches!(rs[0], Record::Header { .. }));
        assert_eq!(rs[2], Record::Data { conn: 7, ts: 124, dir: Dir::ToServer, bytes: b"hello".to_vec() });
        assert_eq!(rs[3], Record::Data { conn: 7, ts: 125, dir: Dir::ToClient, bytes: vec![0; 300] });
        assert_eq!(rs[5], Record::ConnClose { conn: 7, ts: 127 });
    }
}
