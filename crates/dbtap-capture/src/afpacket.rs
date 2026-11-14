//! Live capture with AF_PACKET TPACKET_V3, using a shared kernel mmap ring.
//!
//! - Read kernel-provided blocks without per-packet system calls or copies.
//! - A cBPF filter drops unrelated ports in the kernel.
//! - Drain remaining kernel blocks on shutdown to preserve the tail.

use dbtap_core::journal::{self, Proto};
use crate::tcp::{Link, Reassembler};
use anyhow::{Context, Result, bail};
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

const TPACKET_V3: libc::c_int = 2;
const PACKET_VERSION: libc::c_int = 10;
const PACKET_RX_RING: libc::c_int = 5;
const PACKET_STATISTICS: libc::c_int = 6;
const TP_STATUS_USER: u32 = 1;
const TP_STATUS_KERNEL: u32 = 0;

#[repr(C)]
struct TpacketReq3 {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
    tp_retire_blk_tov: u32,
    tp_sizeof_priv: u32,
    tp_feature_req_word: u32,
}

#[repr(C)]
#[derive(Default)]
struct TpacketStatsV3 {
    tp_packets: u32,
    tp_drops: u32,
    tp_freeze_q_cnt: u32,
}

// cBPF offsets use the network-layer start (SKF_NET_OFF), independent of link type.
const SKF_NET_OFF: u32 = (-0x100000i32) as u32;
const SKF_AD_PROTOCOL: u32 = (-0x1000i32) as u32;
const LD_W_ABS: u16 = 0x20;
const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_H_IND: u16 = 0x48;
const LDX_B_MSH: u16 = 0xb1;
const JEQ: u16 = 0x15;
const JSET: u16 = 0x45;
const RET: u16 = 0x06;

#[derive(Clone, Copy, PartialEq)]
enum To {
    Next,
    Accept,
    Drop,
    /// Jump forward by an instruction offset.
    Skip(u8),
}

struct Asm {
    code: Vec<(u16, To, To, u32)>,
}

impl Asm {
    fn op(&mut self, code: u16, k: u32) {
        self.code.push((code, To::Next, To::Next, k));
    }
    fn jmp(&mut self, code: u16, k: u32, jt: To, jf: To) {
        self.code.push((code, jt, jf, k));
    }
    /// Accept if the port in A matches a selected port.
    fn ports(&mut self, ports: &[u16], miss: To) {
        for (i, p) in ports.iter().enumerate() {
            let last = i + 1 == ports.len();
            self.jmp(JEQ, *p as u32, To::Accept, if last { miss } else { To::Next });
        }
    }
    fn build(self) -> Vec<libc::sock_filter> {
        let n = self.code.len();
        let (accept, drop) = (n, n + 1);
        let mut out: Vec<libc::sock_filter> = self
            .code
            .iter()
            .enumerate()
            .map(|(i, (code, jt, jf, k))| {
                let rel = |t: &To| match t {
                    To::Next => 0,
                    To::Accept => (accept - i - 1) as u8,
                    To::Drop => (drop - i - 1) as u8,
                    To::Skip(s) => *s,
                };
                libc::sock_filter { code: *code, jt: rel(jt), jf: rel(jf), k: *k }
            })
            .collect();
        out.push(libc::sock_filter { code: RET, jt: 0, jf: 0, k: 0x0004_0000 });
        out.push(libc::sock_filter { code: RET, jt: 0, jf: 0, k: 0 });
        out
    }
}

/// Accept TCP source/destination ports; also UDP 4789 when VXLAN is enabled.
fn filter(ports: &[u16], vxlan: bool) -> Vec<libc::sock_filter> {
    let np = ports.len() as u8;
    let mut a = Asm { code: Vec::new() };
    a.op(LD_W_ABS, SKF_AD_PROTOCOL);
    // Place IPv6 after IPv4 and jump over the IPv4 block.
    let v4_len = 2 + if vxlan { 4 } else { 0 } + 2 + 1 + 1 + np + 1 + np;
    a.jmp(JEQ, 0x0800, To::Skip(1), To::Next);
    a.jmp(JEQ, 0x86dd, To::Skip(v4_len), To::Drop);
    // --- IPv4 ---
    a.op(LD_B_ABS, SKF_NET_OFF + 9);
    if vxlan {
        // TCP skips the following four UDP instructions.
        a.jmp(JEQ, 6, To::Skip(4), To::Next);
        a.jmp(JEQ, 17, To::Next, To::Drop);
        a.op(LDX_B_MSH, SKF_NET_OFF);
        a.op(LD_H_IND, SKF_NET_OFF + 2);
        a.jmp(JEQ, 4789, To::Accept, To::Drop);
    } else {
        a.jmp(JEQ, 6, To::Next, To::Drop);
    }
    a.op(LD_H_ABS, SKF_NET_OFF + 6);
    a.jmp(JSET, 0x1fff, To::Drop, To::Next);
    a.op(LDX_B_MSH, SKF_NET_OFF);
    a.op(LD_H_IND, SKF_NET_OFF);
    a.ports(ports, To::Next);
    a.op(LD_H_IND, SKF_NET_OFF + 2);
    a.ports(ports, To::Drop);
    // IPv6 (extension headers excluded).
    a.op(LD_B_ABS, SKF_NET_OFF + 6);
    a.jmp(JEQ, 6, To::Next, To::Drop);
    a.op(LD_H_ABS, SKF_NET_OFF + 40);
    a.ports(ports, To::Next);
    a.op(LD_H_ABS, SKF_NET_OFF + 42);
    a.ports(ports, To::Drop);
    a.build()
}

fn check(ret: libc::c_int, what: &str) -> Result<()> {
    if ret < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EPERM) {
            bail!("{what}: permission denied; run as root or use `sudo setcap cap_net_raw+ep <dbtap-path>`");
        }
        bail!("{what}: {e}");
    }
    Ok(())
}

pub struct LiveOpts<'a> {
    /// Interface name; None selects all interfaces.
    pub iface: Option<&'a str>,
    pub ports: Vec<(u16, Proto)>,
    pub vxlan: bool,
    /// Receive frames not addressed to this host when an interface is specified.
    pub promisc: bool,
    pub out: &'a str,
    /// Ring size in MiB; overflow drops packets in the kernel.
    pub ring_mb: usize,
    /// Stop automatically after this many seconds.
    pub duration: Option<u64>,
}

pub fn capture(o: &LiveOpts<'_>) -> Result<()> {
    const BLOCK: usize = 1 << 22;
    if o.ring_mb > 4096 || o.ports.len() > 32 {
        bail!("Ring must be at most 4096 MiB and at most 32 ports may be selected");
    }
    let nblocks = (o.ring_mb.max(8) << 20) / BLOCK;
    unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as libc::c_int);
        check(fd, "Cannot open packet socket")?;
        let set = |level, name, val: *const libc::c_void, len: usize, what: &str| {
            check(libc::setsockopt(fd, level, name, val, len as libc::socklen_t), what)
        };
        let v = TPACKET_V3;
        set(libc::SOL_PACKET, PACKET_VERSION, &v as *const _ as _, 4, "Cannot set TPACKET_V3")?;

        // Attach the filter before bind so unfiltered packets cannot enter the ring.
        let port_list: Vec<u16> = o.ports.iter().map(|p| p.0).collect();
        let prog = filter(&port_list, o.vxlan);
        let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut _ };
        set(
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as _,
            std::mem::size_of::<libc::sock_fprog>(),
            "Cannot attach packet filter",
        )?;

        let req = TpacketReq3 {
            tp_block_size: BLOCK as u32,
            tp_block_nr: nblocks as u32,
            tp_frame_size: 1 << 11,
            tp_frame_nr: (BLOCK / (1 << 11) * nblocks) as u32,
            // Deliver the block after this interval (ms), even at low traffic rates.
            tp_retire_blk_tov: 20,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        set(libc::SOL_PACKET, PACKET_RX_RING, &req as *const _ as _, std::mem::size_of::<TpacketReq3>(), "Cannot allocate packet ring")?;
        let ring = libc::mmap(
            std::ptr::null_mut(),
            BLOCK * nblocks,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if ring == libc::MAP_FAILED {
            bail!("Cannot mmap packet ring: {}", std::io::Error::last_os_error());
        }
        let ring = ring as *mut u8;

        let ifindex = match o.iface {
            Some(name) => {
                let c = std::ffi::CString::new(name)?;
                let i = libc::if_nametoindex(c.as_ptr());
                if i == 0 {
                    bail!("Interface {name} not found");
                }
                i as libc::c_int
            }
            None => 0,
        };
        let lo_index = libc::if_nametoindex(c"lo".as_ptr()) as i32;
        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifindex;
        check(
            libc::bind(fd, &sll as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32),
            "Cannot bind to interface",
        )?;

        if ifindex != 0 && o.promisc {
            // Receive non-local frames, needed for bridge transit and mirror traffic.
            let mut mr: libc::packet_mreq = std::mem::zeroed();
            mr.mr_ifindex = ifindex;
            mr.mr_type = libc::PACKET_MR_PROMISC as u16;
            set(
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mr as *const _ as _,
                std::mem::size_of::<libc::packet_mreq>(),
                "Cannot enable promiscuous mode",
            )?;
        }

        libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as usize);
        libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as usize);

        let source = format!("live:{}", o.iface.unwrap_or("any"));
        let w = journal::Writer::create(o.out, &source)?;
        let mut re = Reassembler::new(o.ports.clone(), w);
        eprintln!("Recording started ({source}); press Ctrl-C to stop");
        let started = std::time::Instant::now();
        let mut last_flush = started;
        let mut last_ts = 0u64;
        let mut blk = 0usize;
        // After shutdown is requested, this many empty polls means the kernel is drained.
        let mut idle_after_stop = 0;
        loop {
            let b = ring.add(blk * BLOCK);
            // Block header: version(4), offset_to_priv(4), block_status(4), num_pkts(4), offset_to_first_pkt(4), ...
            let status = std::ptr::read_volatile(b.add(8) as *const u32);
            if status & TP_STATUS_USER == 0 {
                let stopping = STOP.load(Ordering::Relaxed) || o.duration.is_some_and(|d| started.elapsed().as_secs() >= d);
                if stopping {
                    idle_after_stop += 1;
                    if idle_after_stop > 3 {
                        break;
                    }
                }
                let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
                libc::poll(&mut pfd, 1, 40);
                if last_flush.elapsed().as_millis() > 1000 {
                    re.sink.flush()?;
                    last_flush = std::time::Instant::now();
                }
                continue;
            }
            idle_after_stop = 0;
            let num = std::ptr::read(b.add(12) as *const u32);
            let mut off = std::ptr::read(b.add(16) as *const u32) as usize;
            for _ in 0..num {
                let p = b.add(off);
                // tpacket3_hdr: next_offset(4) sec(4) nsec(4) snaplen(4) len(4) status(4) mac(2) net(2) ...
                let next = std::ptr::read(p as *const u32) as usize;
                let sec = std::ptr::read(p.add(4) as *const u32) as u64;
                let nsec = std::ptr::read(p.add(8) as *const u32) as u64;
                let snaplen = std::ptr::read(p.add(12) as *const u32) as usize;
                let mac = std::ptr::read(p.add(24) as *const u16) as usize;
                let net = std::ptr::read(p.add(26) as *const u16) as usize;
                // sockaddr_ll follows the 48-byte header: ifindex at +4, pkttype at +10.
                // Loopback shows each packet twice; discard the outgoing copy.
                let ifi = std::ptr::read(p.add(48 + 4) as *const i32);
                let pkttype = std::ptr::read(p.add(48 + 10));
                if pkttype == libc::PACKET_OUTGOING as u8 && ifi == lo_index {
                    if next == 0 {
                        break;
                    }
                    off += next;
                    continue;
                }
                // Read from the network layer, independent of Ethernet/loopback/tunnel framing.
                if net >= mac && net - mac <= snaplen {
                    let data = std::slice::from_raw_parts(p.add(net), snaplen - (net - mac));
                    last_ts = sec * 1_000_000_000 + nsec;
                    re.packet(last_ts, Link::RawIp, data);
                }
                if next == 0 {
                    break;
                }
                off += next;
            }
            // Return the block to the kernel.
            std::ptr::write_volatile(b.add(8) as *mut u32, TP_STATUS_KERNEL);
            blk = (blk + 1) % nblocks;
        }

        let mut st = TpacketStatsV3::default();
        let mut len = std::mem::size_of::<TpacketStatsV3>() as libc::socklen_t;
        libc::getsockopt(fd, libc::SOL_PACKET, PACKET_STATISTICS, &mut st as *mut _ as _, &mut len);
        re.end(last_ts);
        let s = re.stats.clone();
        re.sink.finish().context("Cannot finish journal")?;
        libc::munmap(ring as _, BLOCK * nblocks);
        libc::close(fd);
        eprintln!("{}", s.summary());
        if st.tp_drops > 0 {
            eprintln!(
                "Warning: kernel ring overflow dropped {} packets; increase --ring-mb",
                st.tp_drops
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small filter interpreter; `net` begins at the network layer.
    fn run(prog: &[libc::sock_filter], ethertype: u32, net: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let at = |k: u32, n: usize| -> Option<u32> {
            let o = k.wrapping_sub(SKF_NET_OFF) as usize;
            let b = net.get(o..o + n)?;
            Some(b.iter().fold(0u32, |v, c| v << 8 | *c as u32))
        };
        loop {
            let i = &prog[pc];
            pc += 1;
            match i.code {
                LD_W_ABS if i.k == SKF_AD_PROTOCOL => a = ethertype,
                LD_H_ABS => match at(i.k, 2) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LD_B_ABS => match at(i.k, 1) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LD_H_IND => match at(i.k.wrapping_add(x), 2) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LDX_B_MSH => match at(i.k, 1) {
                    Some(v) => x = (v & 0xf) * 4,
                    None => return 0,
                },
                JEQ => pc += if a == i.k { i.jt } else { i.jf } as usize,
                JSET => pc += if a & i.k != 0 { i.jt } else { i.jf } as usize,
                RET => return i.k,
                c => panic!("Unsupported instruction {c:#x}"),
            }
        }
    }

    fn v4(proto: u8, ihl: u8, frag: u16, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; ihl as usize * 4];
        p[0] = 0x40 | ihl;
        p[6..8].copy_from_slice(&frag.to_be_bytes());
        p[9] = proto;
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 16]);
        p
    }

    fn v6(next: u8, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = next;
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 16]);
        p
    }

    #[test]
    fn filter_accepts_only_target_tcp_ports() {
        for vxlan in [false, true] {
            let f = filter(&[5432, 3306], vxlan);
            let ok = |eth, pkt: &[u8]| run(&f, eth, pkt) != 0;
            assert!(ok(0x0800, &v4(6, 5, 0, 40000, 5432)), "vxlan={vxlan}");
            assert!(ok(0x0800, &v4(6, 5, 0, 3306, 40000)));
            // Read ports correctly with IPv4 options (24-byte header).
            assert!(ok(0x0800, &v4(6, 6, 0, 40000, 3306)));
            assert!(!ok(0x0800, &v4(6, 5, 0, 40000, 80)));
            assert!(!ok(0x0800, &v4(17, 5, 0, 40000, 5432)));
            // Non-initial fragments have no TCP header.
            assert!(!ok(0x0800, &v4(6, 5, 0x00b9, 40000, 5432)));
            assert!(ok(0x86dd, &v6(6, 5432, 40000)));
            assert!(ok(0x86dd, &v6(6, 40000, 3306)));
            assert!(!ok(0x86dd, &v6(6, 40000, 443)));
            assert!(!ok(0x86dd, &v6(17, 40000, 5432)));
            assert!(!ok(0x0806, &v4(6, 5, 0, 40000, 5432)));
            assert_eq!(ok(0x0800, &v4(17, 5, 0, 55555, 4789)), vxlan);
        }
    }
}
