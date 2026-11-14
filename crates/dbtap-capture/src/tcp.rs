//! Reconstruct packets into per-connection, per-direction TCP byte streams.
//!
//! Only selected ports are considered. Absorb retransmission and reordering.
//! Mark capture gaps explicitly as lost rather than silently joining bytes,
//! which would corrupt subsequent message boundaries.

use dbtap_core::journal::{Dir, Proto};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    Ethernet,
    /// Linux cooked capture v1 / v2(`tcpdump -i any`)
    Sll,
    Sll2,
    RawIp,
    /// BSD loopback
    Null,
}

impl Link {
    pub fn from_pcap(linktype: u32) -> Option<Link> {
        Some(match linktype {
            1 => Link::Ethernet,
            113 => Link::Sll,
            276 => Link::Sll2,
            12 | 101 | 228 | 229 => Link::RawIp,
            0 => Link::Null,
            _ => return None,
        })
    }
}

pub const TH_FIN: u8 = 0x01;
pub const TH_SYN: u8 = 0x02;
pub const TH_RST: u8 = 0x04;
pub const TH_ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Addr {
    ip: [u8; 16],
    v6: bool,
    pub port: u16,
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.v6 {
            write!(f, "[{}]:{}", std::net::Ipv6Addr::from(self.ip), self.port)
        } else {
            write!(f, "{}.{}.{}.{}:{}", self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.port)
        }
    }
}

pub struct Seg<'a> {
    pub src: Addr,
    pub dst: Addr,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: &'a [u8],
    /// Number of trailing bytes lost to capture truncation.
    /// Caused by receiver MTU limits or a short capture snaplen.
    pub missing: u32,
}

const VXLAN_PORT: u16 = 4789;

/// Strip link/IP/TCP headers; unwrap at most one VXLAN layer.
pub fn parse(link: Link, d: &[u8]) -> Option<Seg<'_>> {
    parse_link(link, d, true)
}

fn parse_link(link: Link, d: &[u8], allow_vxlan: bool) -> Option<Seg<'_>> {
    let (mut ethertype, mut off) = match link {
        Link::Ethernet => (u16::from_be_bytes([*d.get(12)?, *d.get(13)?]), 14),
        Link::Sll => (u16::from_be_bytes([*d.get(14)?, *d.get(15)?]), 16),
        Link::Sll2 => (u16::from_be_bytes([*d.first()?, *d.get(1)?]), 20),
        Link::RawIp => (if d.first()? >> 4 == 6 { 0x86dd } else { 0x0800 }, 0),
        Link::Null => (if d.get(4)? >> 4 == 6 { 0x86dd } else { 0x0800 }, 4),
    };
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        ethertype = u16::from_be_bytes([*d.get(off + 2)?, *d.get(off + 3)?]);
        off += 4;
    }
    let ip = d.get(off..)?;
    let missing;
    let (proto, l4, src, dst, v6) = match ethertype {
        0x0800 => {
            let ihl = (*ip.first()? & 0x0f) as usize * 4;
            if ihl < 20 || ip.len() < ihl {
                return None;
            }
            // Non-initial fragments have no TCP header.
            if u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff != 0 {
                return None;
            }
            // Remove Ethernet padding. TSO may report zero length; then use the received length.
            let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
            let end = if total >= ihl && total <= ip.len() { total } else { ip.len() };
            missing = total.saturating_sub(ip.len()) as u32;
            let mut s = [0u8; 16];
            let mut t = [0u8; 16];
            s[..4].copy_from_slice(&ip[12..16]);
            t[..4].copy_from_slice(&ip[16..20]);
            (ip[9], &ip[ihl..end], s, t, false)
        }
        0x86dd => {
            if ip.len() < 40 {
                return None;
            }
            let plen = u16::from_be_bytes([ip[4], ip[5]]) as usize;
            let end = if plen > 0 && 40 + plen <= ip.len() { 40 + plen } else { ip.len() };
            missing = (40 + plen).saturating_sub(ip.len()) as u32;
            let mut next = ip[6];
            let mut o = 40;
            // Skip hop-by-hop, routing, and destination-option extension headers.
            while matches!(next, 0 | 43 | 60) {
                let h = ip.get(o..o + 2)?;
                next = h[0];
                o += (h[1] as usize + 1) * 8;
            }
            let mut s = [0u8; 16];
            let mut t = [0u8; 16];
            s.copy_from_slice(&ip[8..24]);
            t.copy_from_slice(&ip[24..40]);
            (next, ip.get(o..end)?, s, t, true)
        }
        _ => return None,
    };
    match proto {
        6 => {
            if l4.len() < 20 {
                return None;
            }
            let doff = (l4[12] >> 4) as usize * 4;
            if doff < 20 || l4.len() < doff {
                return None;
            }
            Some(Seg {
                src: Addr { ip: src, v6, port: u16::from_be_bytes([l4[0], l4[1]]) },
                dst: Addr { ip: dst, v6, port: u16::from_be_bytes([l4[2], l4[3]]) },
                seq: u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]),
                ack: u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]),
                flags: l4[13],
                payload: &l4[doff..],
                missing,
            })
        }
        17 if allow_vxlan && l4.len() > 16 && u16::from_be_bytes([l4[2], l4[3]]) == VXLAN_PORT => {
            parse_link(Link::Ethernet, &l4[16..], false)
        }
        _ => None,
    }
}

pub trait Sink {
    fn open(&mut self, conn: u64, ts: u64, proto: Proto, client: &Addr, server: &Addr, mid_stream: bool);
    fn data(&mut self, conn: u64, ts: u64, dir: Dir, bytes: &[u8]);
    fn lost(&mut self, conn: u64, ts: u64, bytes: u64);
    fn close(&mut self, conn: u64, ts: u64);
}

/// Segment not yet emitted.
struct Buf {
    seq: u32,
    data: Vec<u8>,
    /// ACK carried by this segment, identifying peer bytes received before it was sent.
    ack: Option<u32>,
    missing: u32,
}

#[derive(Default)]
struct Half {
    /// Next sequence number to emit.
    next: u32,
    init: bool,
    /// FIN position; FIN consumes one sequence number.
    fin_at: Option<u32>,
    fin_done: bool,
    /// Received segments waiting for an earlier gap to close
    /// or for causally prior peer bytes to arrive.
    pend: Vec<Buf>,
    pend_bytes: usize,
    /// Peer acknowledges this position, but we have not emitted it yet.
    gap_since: Option<u64>,
    acked: u32,
}

struct Flow {
    id: u64,
    proto: Proto,
    half: [Half; 2],
    last: u64,
    saw_syn: bool,
    /// Whether capture began at connection setup is still undecided.
    /// Wait briefly for a reordered SYN from the other direction.
    undecided_until: Option<u64>,
    opened: bool,
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub packets: u64,
    pub conns: u64,
    pub mid_stream: u64,
    pub bytes: u64,
    pub lost_bytes: u64,
    pub retransmits: u64,
    pub out_of_order: u64,
    /// Number of truncated packets received.
    pub truncated: u64,
}

const PEND_LIMIT: usize = 8 << 20;
/// After this wait, acknowledged but unseen bytes are considered lost.
/// Allow cross-direction packet reordering before declaring loss.
const GAP_GRACE_NS: u64 = 50_000_000;
/// Wait before classifying a connection without SYN as mid-stream.
const OPEN_GRACE_NS: u64 = 20_000_000;
const IDLE_SWEEP_NS: u64 = 6 * 3600 * 1_000_000_000;

impl Stats {
    /// Summarize capture statistics.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "Packets {} / connections {} (mid-stream {}) / {} bytes / lost {} bytes / retransmits {} / reordered {}",
            self.packets, self.conns, self.mid_stream, self.bytes, self.lost_bytes, self.retransmits, self.out_of_order
        );
        if self.truncated > 0 {
            s += &format!(
                "\nWarning: {} packets were truncated; affected requests/responses cannot be reconstructed.\n\
                                  VXLAN adds 50 bytes and may exceed the mirror receiver MTU.\n\
                                  With a 9001-byte receiver MTU, a client MTU of 8951 or less avoids this truncation",
                self.truncated
            );
        }
        s
    }
}

/// Reconstruct streams in the causal order expressed by TCP:
///
/// - Within a direction: sequence-number order.
/// - Across directions: ACK order. Emit the acknowledged peer bytes
///   before the segment that acknowledges them.
///
/// This handles mirror paths that deliver directions in different orders.
/// Requests reach protocol reconstruction before responses, even if observed later.
pub struct Reassembler<S: Sink> {
    flows: HashMap<(Addr, Addr), Flow>,
    ports: Vec<(u16, Proto)>,
    next_id: u64,
    pub sink: S,
    pub stats: Stats,
}

fn idx(dir: Dir) -> usize {
    matches!(dir, Dir::ToClient) as usize
}

const DIRS: [Dir; 2] = [Dir::ToServer, Dir::ToClient];

impl<S: Sink> Reassembler<S> {
    pub fn new(ports: Vec<(u16, Proto)>, sink: S) -> Self {
        Reassembler { flows: HashMap::new(), ports, next_id: 1, sink, stats: Stats::default() }
    }

    fn proto(&self, port: u16) -> Option<Proto> {
        self.ports.iter().find(|(p, _)| *p == port).map(|(_, pr)| *pr)
    }

    pub fn packet(&mut self, ts: u64, link: Link, data: &[u8]) {
        if let Some(seg) = parse(link, data) {
            self.segment(ts, &seg);
        }
    }

    pub fn segment(&mut self, ts: u64, seg: &Seg<'_>) {
        let (dir, proto, key) = if let Some(p) = self.proto(seg.dst.port) {
            (Dir::ToServer, p, (seg.src, seg.dst))
        } else if let Some(p) = self.proto(seg.src.port) {
            (Dir::ToClient, p, (seg.dst, seg.src))
        } else {
            return;
        };
        self.stats.packets += 1;
        if self.stats.packets % 65536 == 0 {
            self.sweep(ts);
        }
        self.stats.truncated += (seg.missing > 0) as u64;
        let syn = seg.flags & TH_SYN != 0;
        let has_ack = seg.flags & TH_ACK != 0;
        let fresh_syn = syn && !has_ack && dir == Dir::ToServer;
        let i = idx(dir);

        // A new SYN on the same four-tuple indicates port reuse; close the prior connection.
        if fresh_syn && self.flows.get(&key).is_some_and(|f| f.half[0].init && f.half[0].next != seq_add(seg.seq, 1)) {
            let f = self.flows.remove(&key).unwrap();
            self.finish(f, &key, ts);
        }
        if !self.flows.contains_key(&key) {
            // Do not create connections from packets carrying neither data nor SYN.
            if !syn && (seg.payload.is_empty() || seg.flags & TH_RST != 0) {
                return;
            }
            let id = self.next_id;
            self.next_id += 1;
            let mut f = Flow {
                id,
                proto,
                half: [Half::default(), Half::default()],
                last: ts,
                saw_syn: false,
                undecided_until: (!fresh_syn).then_some(ts + OPEN_GRACE_NS),
                opened: false,
            };
            if !fresh_syn && has_ack {
                // Without SYN, infer the peer position from the ACK number.
                let o = &mut f.half[1 - i];
                o.next = seg.ack;
                o.init = true;
            }
            self.flows.insert(key, f);
        }
        let f = self.flows.get_mut(&key).unwrap();
        f.last = ts;
        if fresh_syn {
            f.saw_syn = true;
            f.undecided_until = None;
        } else if f.undecided_until.is_some_and(|t| ts >= t) {
            f.undecided_until = None;
        }
        if syn {
            let h = &mut f.half[i];
            // A late SYN confirms the already inferred position.
            if !h.init || fresh_syn {
                h.next = seq_add(seg.seq, 1);
                h.init = true;
            }
            Self::pump(f, &key, ts, &mut self.sink, &mut self.stats);
            return;
        }
        if seg.flags & TH_RST != 0 {
            let f = self.flows.remove(&key).unwrap();
            self.finish(f, &key, ts);
            return;
        }

        // Track when acknowledged peer bytes began waiting to be emitted.
        if has_ack {
            let o = &mut f.half[1 - i];
            if !o.init {
                // Peer setup (such as SYN-ACK) was missed; infer its position from our ACK.
                o.next = seg.ack;
                o.init = true;
            }
            if seq_diff(seg.ack, o.next) > 0 {
                if o.gap_since.is_none() {
                    o.gap_since = Some(ts);
                    o.acked = seg.ack;
                } else if seq_diff(seg.ack, o.acked) > 0 {
                    o.acked = seg.ack;
                }
            }
        }

        let h = &mut f.half[i];
        if !seg.payload.is_empty() {
            if !h.init {
                h.next = seg.seq;
                h.init = true;
            }
            let d = seq_diff(seg.seq, h.next);
            if d < 0 && (-d) as usize >= seg.payload.len() {
                self.stats.retransmits += 1;
            } else if !h.pend.iter().any(|b| b.seq == seg.seq && b.data.len() >= seg.payload.len()) {
                self.stats.out_of_order += (d > 0) as u64;
                h.pend_bytes += seg.payload.len();
                h.pend.push(Buf { seq: seg.seq, data: seg.payload.to_vec(), ack: has_ack.then_some(seg.ack), missing: seg.missing });
            }
        }
        if seg.flags & TH_FIN != 0 && h.fin_at.is_none() {
            h.fin_at = Some(seq_add(seg.seq, seg.payload.len() as u32 + seg.missing));
        }

        Self::pump(f, &key, ts, &mut self.sink, &mut self.stats);
        // Give up on overdue missing bytes, unblocking dependent peer segments.
        let mut forced = false;
        for k in 0..2 {
            let h = &f.half[k];
            let overdue = h.gap_since.is_some_and(|t| ts.saturating_sub(t) > GAP_GRACE_NS);
            if f.undecided_until.is_none() && (overdue || h.pend_bytes > PEND_LIMIT) {
                let upto = if overdue { h.acked } else { Self::far_end(h) };
                Self::force(f, k, upto, &key, ts, &mut self.sink, &mut self.stats);
                forced = true;
            }
        }
        if forced {
            Self::pump(f, &key, ts, &mut self.sink, &mut self.stats);
        }
        if f.half[0].fin_done && f.half[1].fin_done {
            let f = self.flows.remove(&key).unwrap();
            self.finish(f, &key, ts);
        }
    }

    /// Furthest end among buffered segments.
    fn far_end(h: &Half) -> u32 {
        h.pend
            .iter()
            .map(|b| seq_add(b.seq, b.data.len() as u32 + b.missing))
            .max_by_key(|e| seq_diff(*e, h.next))
            .unwrap_or(h.next)
    }

    fn open(f: &mut Flow, key: &(Addr, Addr), ts: u64, sink: &mut S, stats: &mut Stats) {
        if !f.opened {
            f.opened = true;
            stats.conns += 1;
            stats.mid_stream += !f.saw_syn as u64;
            sink.open(f.id, ts, f.proto, &key.0, &key.1, !f.saw_syn);
        }
    }

    /// Emit the first segment in direction `k`; None means it is not ready.
    fn emit_front(f: &mut Flow, k: usize, hold: bool, key: &(Addr, Addr), ts: u64, sink: &mut S, stats: &mut Stats) -> Option<()> {
        loop {
            let o_next = f.half[1 - k].init.then_some(f.half[1 - k].next);
            let h = &mut f.half[k];
            let (j, d) = h.pend.iter().enumerate().map(|(j, b)| (j, seq_diff(b.seq, h.next))).min_by_key(|x| x.1)?;
            if d > 0 {
                return None;
            }
            let skip = (-d) as usize;
            if skip >= h.pend[j].data.len() {
                // Retransmitted bytes already emitted; check for a new suffix.
                let b = h.pend.swap_remove(j);
                h.pend_bytes -= b.data.len();
                continue;
            }
            // Wait until acknowledged peer bytes have been emitted.
            if hold {
                if let (Some(ack), Some(o_next)) = (h.pend[j].ack, o_next) {
                    if seq_diff(ack, o_next) > 0 {
                        return None;
                    }
                }
            }
            let b = h.pend.swap_remove(j);
            h.pend_bytes -= b.data.len();
            let part = &b.data[skip..];
            h.next = seq_add(h.next, part.len() as u32);
            let id = f.id;
            Self::open(f, key, ts, sink, stats);
            sink.data(id, ts, DIRS[k], part);
            stats.bytes += part.len() as u64;
            let h = &mut f.half[k];
            if b.missing > 0 {
                // Truncated tail cannot be recovered; mark loss and advance.
                sink.lost(id, ts, b.missing as u64);
                stats.lost_bytes += b.missing as u64;
                h.next = seq_add(h.next, b.missing);
            }
            Self::after_advance(h);
            return Some(());
        }
    }

    fn after_advance(h: &mut Half) {
        if seq_diff(h.acked, h.next) <= 0 {
            h.gap_since = None;
        }
        if h.fin_at.is_some_and(|at| seq_diff(at, h.next) <= 0) && !h.fin_done {
            h.fin_done = true;
            if h.fin_at == Some(h.next) {
                h.next = seq_add(h.next, 1);
            }
        }
    }

    /// Emit until no progress is possible; one direction may unblock the other.
    fn pump(f: &mut Flow, key: &(Addr, Addr), ts: u64, sink: &mut S, stats: &mut Stats) {
        if f.undecided_until.is_some() {
            return;
        }
        for k in 0..2 {
            Self::after_advance(&mut f.half[k]);
        }
        loop {
            let mut progressed = false;
            for k in 0..2 {
                while Self::emit_front(f, k, true, key, ts, sink, stats).is_some() {
                    progressed = true;
                }
            }
            if !progressed {
                return;
            }
        }
    }

    /// Force direction `k` through `upto`, emitting available bytes without waiting on peers
    /// and explicitly marking missing intervals as lost.
    fn force(f: &mut Flow, k: usize, upto: u32, key: &(Addr, Addr), ts: u64, sink: &mut S, stats: &mut Stats) {
        f.half[k].gap_since = None;
        loop {
            while seq_diff(upto, f.half[k].next) > 0 && Self::emit_front(f, k, false, key, ts, sink, stats).is_some() {}
            let h = &mut f.half[k];
            if seq_diff(upto, h.next) <= 0 {
                return;
            }
            // Mark the gap up to the next buffered segment, or `upto` if none.
            let ahead = h.pend.iter().map(|b| b.seq).filter(|q| seq_diff(*q, h.next) > 0).min_by_key(|q| seq_diff(*q, h.next));
            let target = match ahead {
                Some(q) if seq_diff(upto, q) >= 0 => q,
                _ => upto,
            };
            let n = seq_diff(target, h.next) as u64;
            let h = &mut f.half[k];
            h.next = target;
            let id = f.id;
            Self::open(f, key, ts, sink, stats);
            sink.lost(id, ts, n);
            stats.lost_bytes += n;
            Self::after_advance(&mut f.half[k]);
        }
    }

    /// Drain on connection/capture end.
    /// After each gap is abandoned, retry normal emission to preserve causal order where possible.
    fn flush(f: &mut Flow, key: &(Addr, Addr), ts: u64, sink: &mut S, stats: &mut Stats) {
        f.undecided_until = None;
        loop {
            Self::pump(f, key, ts, sink, stats);
            // Resolve leading gaps first, up to the next segment or peer-acknowledged position.
            let hole = (0..2).find_map(|k| {
                let h = &f.half[k];
                let front = h.pend.iter().map(|b| b.seq).min_by_key(|q| seq_diff(*q, h.next));
                match front {
                    Some(q) if seq_diff(q, h.next) > 0 => Some((k, q)),
                    None if h.gap_since.is_some() && seq_diff(h.acked, h.next) > 0 => Some((k, h.acked)),
                    _ => None,
                }
            });
            if let Some((k, upto)) = hole {
                Self::force(f, k, upto, key, ts, sink, stats);
                continue;
            }
            // No gaps but no progress means mutual waiting; force one direction forward.
            match (0..2).find(|k| !f.half[*k].pend.is_empty()) {
                Some(k) => {
                    Self::emit_front(f, k, false, key, ts, sink, stats);
                }
                None => return,
            }
        }
    }

    fn finish(&mut self, mut f: Flow, key: &(Addr, Addr), ts: u64) {
        Self::flush(&mut f, key, ts, &mut self.sink, &mut self.stats);
        // Retain even idle connections if their setup was captured.
        if f.saw_syn {
            Self::open(&mut f, key, ts, &mut self.sink, &mut self.stats);
        }
        if f.opened {
            self.sink.close(f.id, ts);
        }
    }

    /// Retire long-idle connections so missed FINs cannot accumulate forever.
    fn sweep(&mut self, ts: u64) {
        let dead: Vec<_> =
            self.flows.iter().filter(|(_, f)| ts.saturating_sub(f.last) > IDLE_SWEEP_NS).map(|(k, _)| *k).collect();
        for k in dead {
            let f = self.flows.remove(&k).unwrap();
            self.finish(f, &k, ts);
        }
    }

    /// Drain at capture end; retain open connections as unclosed.
    pub fn end(&mut self, ts: u64) {
        let mut keys: Vec<_> = self.flows.iter().map(|(k, f)| (f.id, *k)).collect();
        keys.sort_unstable_by_key(|x| x.0);
        for (_, k) in keys {
            let f = self.flows.get_mut(&k).unwrap();
            Self::flush(f, &k, ts, &mut self.sink, &mut self.stats);
        }
    }
}

#[inline]
fn seq_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

#[inline]
fn seq_add(a: u32, n: u32) -> u32 {
    a.wrapping_add(n)
}

impl<W: std::io::Write> Sink for dbtap_core::journal::Writer<W> {
    fn open(&mut self, conn: u64, ts: u64, proto: Proto, client: &Addr, server: &Addr, mid_stream: bool) {
        let r = dbtap_core::journal::Record::ConnOpen {
            conn,
            ts,
            proto,
            client: client.to_string(),
            server: server.to_string(),
            mid_stream,
        };
        self.write(&r).expect("Journal write failed");
    }
    fn data(&mut self, conn: u64, ts: u64, dir: Dir, bytes: &[u8]) {
        self.write_data(conn, ts, dir, bytes).expect("Journal write failed");
    }
    fn lost(&mut self, conn: u64, ts: u64, bytes: u64) {
        self.write(&dbtap_core::journal::Record::Lost { conn, ts, bytes }).expect("Journal write failed");
    }
    fn close(&mut self, conn: u64, ts: u64) {
        self.write(&dbtap_core::journal::Record::ConnClose { conn, ts }).expect("Journal write failed");
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[derive(Default)]
    pub struct Collect {
        pub ev: Vec<String>,
    }

    impl Sink for Collect {
        fn open(&mut self, conn: u64, _ts: u64, _p: Proto, c: &Addr, s: &Addr, mid: bool) {
            self.ev.push(format!("open {conn} {c}->{s} mid={mid}"));
        }
        fn data(&mut self, conn: u64, _ts: u64, dir: Dir, b: &[u8]) {
            let d = if dir == Dir::ToServer { ">" } else { "<" };
            self.ev.push(format!("{conn}{d}{}", String::from_utf8_lossy(b)));
        }
        fn lost(&mut self, conn: u64, _ts: u64, n: u64) {
            self.ev.push(format!("lost {conn} {n}"));
        }
        fn close(&mut self, conn: u64, _ts: u64) {
            self.ev.push(format!("close {conn}"));
        }
    }

    fn addr(last: u8, port: u16) -> Addr {
        let mut ip = [0u8; 16];
        ip[..4].copy_from_slice(&[10, 0, 0, last]);
        Addr { ip, v6: false, port }
    }

    const C: (u8, u16) = (1, 40000);
    const S: (u8, u16) = (2, 5432);

    fn seg(from: (u8, u16), to: (u8, u16), seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Seg<'_> {
        Seg { src: addr(from.0, from.1), dst: addr(to.0, to.1), seq, ack, flags, payload, missing: 0 }
    }

    fn new() -> Reassembler<Collect> {
        Reassembler::new(vec![(5432, Proto::Postgres)], Collect::default())
    }

    const OPEN: &str = "open 1 10.0.0.1:40000->10.0.0.2:5432 mid=false";
    const OPEN_MID: &str = "open 1 10.0.0.1:40000->10.0.0.2:5432 mid=true";

    #[test]
    fn handshake_reorder_and_retransmit() {
        let mut r = new();
        r.segment(1, &seg(C, S, 100, 0, TH_SYN, b""));
        r.segment(2, &seg(S, C, 500, 101, TH_SYN | TH_ACK, b""));
        r.segment(3, &seg(C, S, 101, 501, TH_ACK, b"AB"));
        // Later bytes arrive first.
        r.segment(4, &seg(C, S, 105, 501, TH_ACK, b"EF"));
        r.segment(5, &seg(C, S, 103, 501, TH_ACK, b"CD"));
        // Partially overlapping retransmission.
        r.segment(6, &seg(C, S, 105, 501, TH_ACK, b"EFG"));
        r.segment(7, &seg(S, C, 501, 108, TH_ACK, b"ok"));
        r.segment(8, &seg(C, S, 108, 503, TH_ACK | TH_FIN, b""));
        r.segment(9, &seg(S, C, 503, 109, TH_ACK | TH_FIN, b""));
        assert_eq!(r.sink.ev, [OPEN, "1>AB", "1>CD", "1>EF", "1>G", "1<ok", "close 1"]);
        assert_eq!(r.stats.out_of_order, 1);
    }

    #[test]
    fn response_seen_before_its_request_is_delivered_after_it() {
        let mut r = new();
        r.segment(1, &seg(C, S, 100, 0, TH_SYN, b""));
        r.segment(2, &seg(S, C, 500, 101, TH_SYN | TH_ACK, b""));
        // Response arrives first, acknowledging client bytes through 105.
        r.segment(3, &seg(S, C, 501, 105, TH_ACK, b"resp1"));
        assert_eq!(r.sink.ev, Vec::<String>::new());
        r.segment(4, &seg(C, S, 101, 501, TH_ACK, b"req1"));
        // The next request follows the response, even if observed before its tail.
        r.segment(5, &seg(C, S, 105, 511, TH_ACK, b"req2"));
        r.segment(6, &seg(S, C, 506, 105, TH_ACK, b"more1"));
        assert_eq!(r.sink.ev, [OPEN, "1>req1", "1<resp1", "1<more1", "1>req2"]);
        assert_eq!(r.stats.lost_bytes, 0);
    }

    #[test]
    fn syn_arriving_after_the_first_data_still_marks_a_full_connection() {
        let mut r = new();
        // Server greeting arrives before the client's SYN.
        r.segment(1, &seg(S, C, 501, 101, TH_ACK, b"hello"));
        assert_eq!(r.sink.ev, Vec::<String>::new());
        r.segment(2, &seg(C, S, 100, 0, TH_SYN, b""));
        r.segment(3, &seg(S, C, 500, 101, TH_SYN | TH_ACK, b""));
        r.segment(4, &seg(C, S, 101, 506, TH_ACK, b"login"));
        assert_eq!(r.sink.ev, [OPEN, "1<hello", "1>login"]);
        assert_eq!(r.stats.mid_stream, 0);
    }

    #[test]
    fn mid_stream_and_capture_loss() {
        let mut r = new();
        // Mid-stream: a data-free ACK does not create a connection.
        r.segment(1, &seg(S, C, 900, 300, TH_ACK, b""));
        r.segment(2, &seg(C, S, 300, 900, TH_ACK, b"req1"));
        // Wait briefly in case a SYN arrives later.
        assert_eq!(r.sink.ev, Vec::<String>::new());
        let t = OPEN_GRACE_NS + 10;
        r.segment(t, &seg(S, C, 900, 304, TH_ACK, b"resp1"));
        assert_eq!(r.sink.ev, [OPEN_MID, "1>req1", "1<resp1"]);
        // Capture missed ten client bytes that the server acknowledges.
        r.segment(t + 1, &seg(S, C, 905, 314, TH_ACK, b"resp2"));
        assert_eq!(r.sink.ev.len(), 3);
        // The next packet after the grace period confirms loss, before the corresponding response.
        r.segment(t + GAP_GRACE_NS + 2, &seg(C, S, 314, 910, TH_ACK, b"req3"));
        assert_eq!(r.sink.ev[3..], ["lost 1 10", "1<resp2", "1>req3"]);
        assert_eq!(r.stats.lost_bytes, 10);
    }

    #[test]
    fn late_segment_within_grace_is_not_lost() {
        let mut r = new();
        r.segment(1, &seg(C, S, 100, 0, TH_SYN, b""));
        r.segment(2, &seg(C, S, 101, 900, TH_ACK, b"a"));
        // ACK arrives before the data, which follows shortly afterwards.
        r.segment(3, &seg(S, C, 900, 104, TH_ACK, b"x"));
        r.segment(4, &seg(C, S, 102, 900, TH_ACK, b"bc"));
        r.segment(4 + GAP_GRACE_NS * 2, &seg(C, S, 104, 901, TH_ACK, b"d"));
        assert_eq!(r.sink.ev[1..], ["1>a", "1>bc", "1<x", "1>d"]);
        assert_eq!(r.stats.lost_bytes, 0);
    }

    #[test]
    fn high_sequence_numbers_do_not_confuse_loss_detection() {
        // Sequence numbers exceed 2^31; an early ACK must not cause a huge false gap.
        let base = 3_822_706_000u32;
        let mut r = new();
        r.segment(1, &seg(C, S, base, 0, TH_SYN, b""));
        r.segment(2, &seg(S, C, 500, base + 1, TH_SYN | TH_ACK, b""));
        r.segment(3, &seg(S, C, 501, base + 5, TH_ACK, b"resp"));
        r.segment(4, &seg(C, S, base + 1, 501, TH_ACK, b"req1"));
        // Next packet arrives after the grace period.
        r.segment(4 + GAP_GRACE_NS * 2, &seg(C, S, base + 5, 505, TH_ACK, b"req2"));
        assert_eq!(r.sink.ev, [OPEN, "1>req1", "1<resp", "1>req2"]);
        assert_eq!(r.stats.lost_bytes, 0);
    }

    #[test]
    fn truncated_segment_is_reported_as_loss_right_away() {
        let mut r = new();
        r.segment(1, &seg(C, S, 100, 0, TH_SYN, b""));
        r.segment(2, &seg(S, C, 500, 101, TH_SYN | TH_ACK, b""));
        // Receiver MTU truncated the final 49 bytes.
        let mut cut = seg(S, C, 501, 101, TH_ACK, b"head");
        cut.missing = 49;
        r.segment(3, &cut);
        r.segment(4, &seg(S, C, 554, 101, TH_ACK, b"next"));
        assert_eq!(r.sink.ev, [OPEN, "1<head", "lost 1 49", "1<next"]);
        assert_eq!((r.stats.truncated, r.stats.lost_bytes), (1, 49));
    }

    #[test]
    fn port_reuse_starts_new_connection() {
        let mut r = new();
        r.segment(1, &seg(C, S, 100, 0, TH_SYN, b""));
        r.segment(2, &seg(C, S, 101, 1, TH_ACK, b"a"));
        r.segment(3, &seg(C, S, 7000, 0, TH_SYN, b""));
        r.segment(4, &seg(C, S, 7001, 1, TH_ACK, b"b"));
        assert_eq!(r.sink.ev[1..], ["1>a", "close 1", "open 2 10.0.0.1:40000->10.0.0.2:5432 mid=false", "2>b"]);
    }

    #[test]
    fn end_flushes_what_is_still_held() {
        let mut r = new();
        r.segment(1, &seg(C, S, 100, 0, TH_SYN, b""));
        r.segment(2, &seg(C, S, 101, 900, TH_ACK, b"req"));
        // Later bytes arrive while the first five remain missing.
        r.segment(3, &seg(S, C, 905, 104, TH_ACK, b"tail"));
        // Response waits for unseen peer bytes.
        r.segment(4, &seg(C, S, 104, 909, TH_ACK, b"req2"));
        r.end(5);
        assert_eq!(r.sink.ev[1..], ["1>req", "lost 1 5", "1<tail", "1>req2"]);
    }

    #[test]
    fn parses_ethernet_ipv4_with_padding_and_vxlan() {
        // IPv4 + TCP, two-byte payload, four-byte Ethernet padding.
        let mut ip = vec![0x45, 0, 0, 42, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        let mut tcp = vec![0x9c, 0x40, 0x15, 0x38, 0, 0, 0, 100, 0, 0, 0, 0, 0x50, TH_ACK, 0, 0, 0, 0, 0, 0];
        tcp.extend_from_slice(b"hi");
        ip.extend(tcp);
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend(&ip);
        let mut padded = eth.clone();
        padded.extend_from_slice(&[0; 4]);
        let s = parse(Link::Ethernet, &padded).unwrap();
        assert_eq!((s.src.port, s.dst.port, s.seq, s.payload), (40000, 5432, 100, &b"hi"[..]));

        // Outer IPv4 + UDP 4789 + eight-byte VXLAN header.
        let inner_len = eth.len();
        let mut outer = vec![0u8; 12];
        outer.extend_from_slice(&[0x08, 0x00]);
        let total = (20 + 8 + 8 + inner_len) as u16;
        outer.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2]);
        outer.extend_from_slice(&[0xff, 0xff, 0x12, 0xb5, 0, 0, 0, 0]);
        outer.extend_from_slice(&[8, 0, 0, 0, 0, 0, 1, 0]);
        outer.extend(&eth);
        let s = parse(Link::Ethernet, &outer).unwrap();
        assert_eq!((s.dst.port, s.payload), (5432, &b"hi"[..]));
    }
}
