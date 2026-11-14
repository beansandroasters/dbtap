//! Streaming pcap/pcapng reader; no seeking, so `tcpdump -w -` can be piped in.

use crate::tcp::Link;
use anyhow::{Context, Result, bail};
use std::io::{BufReader, Read};

struct Iface {
    link: Option<Link>,
    /// Nanoseconds per timestamp unit.
    unit_ns: f64,
}

enum Kind {
    Classic { swap: bool, nanos: bool, link: Link },
    Ng { swap: bool, ifaces: Vec<Iface> },
}

pub struct Pcap<R: Read> {
    r: BufReader<R>,
    kind: Kind,
    buf: Vec<u8>,
}

fn u32at(b: &[u8], o: usize, swap: bool) -> u32 {
    let v = [b[o], b[o + 1], b[o + 2], b[o + 3]];
    if swap { u32::from_be_bytes(v) } else { u32::from_le_bytes(v) }
}

fn u16at(b: &[u8], o: usize, swap: bool) -> u16 {
    let v = [b[o], b[o + 1]];
    if swap { u16::from_be_bytes(v) } else { u16::from_le_bytes(v) }
}

/// Treat a truncated file (possibly still being written) as EOF after readable records.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => return Ok(false),
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn later_section_headers_have_the_same_size_limit() {
        let mut b = vec![];
        for n in [28u32, u32::MAX] {
            b.extend(0x0a0d0d0au32.to_le_bytes());
            b.extend(n.to_le_bytes());
            b.extend(0x1a2b3c4du32.to_le_bytes());
            if n == 28 { b.extend([0; 16]); }
        }
        assert!(Pcap::new(&b[..]).unwrap().next().is_err());
    }
}

impl<R: Read> Pcap<R> {
    pub fn new(inner: R) -> Result<Self> {
        let mut r = BufReader::with_capacity(1 << 20, inner);
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic).context("Cannot read pcap header")?;
        let kind = match u32::from_le_bytes(magic) {
            0x0a0d_0d0a => {
                // pcapng Section Header Block: the byte-order magic follows its length.
                let mut h = [0u8; 8];
                r.read_exact(&mut h)?;
                let swap = match u32::from_le_bytes([h[4], h[5], h[6], h[7]]) {
                    0x1a2b_3c4d => false,
                    0x4d3c_2b1a => true,
                    _ => bail!("Invalid pcapng byte-order magic"),
                };
                let total = u32at(&h, 0, swap) as usize;
                if !(28..=1 << 24).contains(&total) {
                    bail!("Invalid pcapng section header length");
                }
                let mut rest = vec![0u8; total - 12];
                r.read_exact(&mut rest)?;
                Kind::Ng { swap, ifaces: Vec::new() }
            }
            m => {
                let (swap, nanos) = match m {
                    0xa1b2_c3d4 => (false, false),
                    0xd4c3_b2a1 => (true, false),
                    0xa1b2_3c4d => (false, true),
                    0x4d3c_b2a1 => (true, true),
                    _ => bail!("Input is neither pcap nor pcapng"),
                };
                let mut h = [0u8; 20];
                r.read_exact(&mut h)?;
                let lt = u32at(&h, 16, swap) & 0x0fff_ffff;
                let link = Link::from_pcap(lt).with_context(|| format!("Unsupported link type {lt}"))?;
                Kind::Classic { swap, nanos, link }
            }
        };
        Ok(Pcap { r, kind, buf: Vec::with_capacity(65536) })
    }

    /// Next packet: (timestamp in ns, link type, frame).
    pub fn next(&mut self) -> Result<Option<(u64, Link, &[u8])>> {
        match &mut self.kind {
            Kind::Classic { swap, nanos, link } => {
                let mut h = [0u8; 16];
                if !read_full(&mut self.r, &mut h)? {
                    return Ok(None);
                }
                let sec = u32at(&h, 0, *swap) as u64;
                let frac = u32at(&h, 4, *swap) as u64;
                let caplen = u32at(&h, 8, *swap) as usize;
                if caplen > 1 << 26 {
                    bail!("Invalid pcap packet length");
                }
                self.buf.resize(caplen, 0);
                if !read_full(&mut self.r, &mut self.buf)? {
                    return Ok(None);
                }
                let ts = sec * 1_000_000_000 + if *nanos { frac } else { frac * 1000 };
                Ok(Some((ts, *link, &self.buf)))
            }
            Kind::Ng { swap, ifaces } => loop {
                let mut h = [0u8; 8];
                if !read_full(&mut self.r, &mut h)? {
                    return Ok(None);
                }
                let mut btype = u32at(&h, 0, *swap);
                if btype == 0x0a0d_0d0a {
                    // New section: reset byte order and interface table.
                    let mut m = [0u8; 4];
                    if !read_full(&mut self.r, &mut m)? {
                        return Ok(None);
                    }
                    *swap = match u32::from_le_bytes(m) {
                        0x1a2b_3c4d => false,
                        0x4d3c_2b1a => true,
                        _ => bail!("Invalid pcapng byte-order magic"),
                    };
                    ifaces.clear();
                    let total = u32at(&h, 4, *swap) as usize;
                    if !(28..=1 << 24).contains(&total) {
                        bail!("Invalid pcapng section header length");
                    }
                    self.buf.resize(total - 12, 0);
                    if !read_full(&mut self.r, &mut self.buf)? {
                        return Ok(None);
                    }
                    continue;
                }
                let total = u32at(&h, 4, *swap) as usize;
                if !(12..=1 << 27).contains(&total) {
                    bail!("Invalid pcapng block length");
                }
                self.buf.resize(total - 8, 0);
                if !read_full(&mut self.r, &mut self.buf)? {
                    return Ok(None);
                }
                let body = &self.buf[..total - 12];
                if btype == 1 && body.len() >= 8 {
                    let lt = u16at(body, 0, *swap) as u32;
                    let mut unit_ns = 1000.0;
                    let mut o = 8;
                    while o + 4 <= body.len() {
                        let code = u16at(body, o, *swap);
                        let len = u16at(body, o + 2, *swap) as usize;
                        if code == 0 {
                            break;
                        }
                        // if_tsresol: high bit selects a power of 2; otherwise a power of 10.
                        if code == 9 && len >= 1 && o + 4 < body.len() {
                            let v = body[o + 4];
                            unit_ns = if v & 0x80 != 0 {
                                1e9 / 2f64.powi((v & 0x7f) as i32)
                            } else {
                                1e9 / 10f64.powi(v as i32)
                            };
                        }
                        o += 4 + len.div_ceil(4) * 4;
                    }
                    ifaces.push(Iface { link: Link::from_pcap(lt), unit_ns });
                    btype = 0;
                }
                if btype == 6 && body.len() >= 20 {
                    let ifid = u32at(body, 0, *swap) as usize;
                    let ts = (u32at(body, 4, *swap) as u64) << 32 | u32at(body, 8, *swap) as u64;
                    let caplen = u32at(body, 12, *swap) as usize;
                    let Some(ifc) = ifaces.get(ifid) else { continue };
                    let Some(link) = ifc.link else { continue };
                    if 20 + caplen > body.len() {
                        continue;
                    }
                    let ns = (ts as f64 * ifc.unit_ns) as u64;
                    return Ok(Some((ns, link, &self.buf[20..20 + caplen])));
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_and_truncated_tail() {
        let mut f = Vec::new();
        f.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        f.extend_from_slice(&[2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0]);
        f.extend_from_slice(&1u32.to_le_bytes());
        for (sec, data) in [(5u32, &b"abc"[..]), (6, b"defg")] {
            f.extend_from_slice(&sec.to_le_bytes());
            f.extend_from_slice(&7u32.to_le_bytes());
            f.extend_from_slice(&(data.len() as u32).to_le_bytes());
            f.extend_from_slice(&(data.len() as u32).to_le_bytes());
            f.extend_from_slice(data);
        }
        // Partially written third packet.
        f.extend_from_slice(&[1, 2, 3]);
        let mut p = Pcap::new(&f[..]).unwrap();
        let (ts, link, d) = p.next().unwrap().unwrap();
        assert_eq!((ts, link, d), (5_000_007_000, Link::Ethernet, &b"abc"[..]));
        assert_eq!(p.next().unwrap().unwrap().2, b"defg");
        assert!(p.next().unwrap().is_none());
    }

    #[test]
    fn pcapng_with_nanosecond_resolution() {
        fn block(t: u32, body: &[u8]) -> Vec<u8> {
            let total = (body.len() + 12) as u32;
            let mut v = t.to_le_bytes().to_vec();
            v.extend_from_slice(&total.to_le_bytes());
            v.extend_from_slice(body);
            v.extend_from_slice(&total.to_le_bytes());
            v
        }
        let mut shb = 0x1a2b3c4du32.to_le_bytes().to_vec();
        shb.extend_from_slice(&[1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let mut f = block(0x0a0d0d0a, &shb);
        // linktype 113(SLL), tsresol = 9
        f.extend(block(1, &[113, 0, 0, 0, 0, 0, 4, 0, 9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0]));
        let mut epb = 0u32.to_le_bytes().to_vec();
        epb.extend_from_slice(&1u32.to_le_bytes());
        epb.extend_from_slice(&5u32.to_le_bytes());
        epb.extend_from_slice(&3u32.to_le_bytes());
        epb.extend_from_slice(&3u32.to_le_bytes());
        epb.extend_from_slice(b"xyz\0");
        f.extend(block(6, &epb));
        let mut p = Pcap::new(&f[..]).unwrap();
        let (ts, link, d) = p.next().unwrap().unwrap();
        assert_eq!((ts, link, d), ((1u64 << 32) + 5, Link::Sll, &b"xyz"[..]));
        assert!(p.next().unwrap().is_none());
    }
}
