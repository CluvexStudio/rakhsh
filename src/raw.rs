use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::atomic::{
    AtomicU32, AtomicU64, AtomicUsize,
    Ordering::{Relaxed, SeqCst},
};
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;
use tracing::info;

mod spoof_test;
pub use spoof_test::{parse_candidates, recv as spoof_test_recv, send as spoof_test_send};

use crate::carrier::{
    split_bytes_unbuffered, BoxRx, BoxTx, FrameRx, FrameTx, RawTuning, TcpHeader,
};
use crate::wire::{read_frame, write_frame};

pub const RAW_LANES: u64 = 1;

#[derive(Clone, Copy)]
pub struct RawParams {
    key: [u8; 32],
}

struct LaneParams {
    conv: u32,
    icmp_id: u16,
    port_a: u16,
    port_b: u16,
}

impl RawParams {
    pub fn derive(token: &str) -> RawParams {
        RawParams {
            key: blake3::derive_key("rakhsh-raw-v1", token.as_bytes()),
        }
    }

    fn lane(&self, lane: u64) -> LaneParams {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(&lane.to_be_bytes());
        let k = *h.finalize().as_bytes();
        let conv = u32::from_be_bytes([k[0], k[1], k[2], k[3]]).max(1);
        let icmp_id = u16::from_be_bytes([k[4], k[5]]);
        let port_a = 20000 + (u16::from_be_bytes([k[6], k[7]]) % 20000);
        let mut port_b = 20000 + (u16::from_be_bytes([k[8], k[9]]) % 20000);
        if port_b == port_a {
            port_b = port_a.wrapping_add(1);
        }
        LaneParams {
            conv,
            icmp_id,
            port_a,
            port_b,
        }
    }
}

pub fn lane_ports(token: &str) -> (u16, u16) {
    let lp = RawParams::derive(token).lane(0);
    (lp.port_a, lp.port_b)
}

struct AsyncRaw {
    fd: AsyncFd<Socket>,
}

impl AsyncRaw {
    fn new(proto: Protocol, hdrincl: bool) -> Result<AsyncRaw> {
        Self::with_bufs(proto, hdrincl, None)
    }

    fn with_bufs(proto: Protocol, hdrincl: bool, sockbuf: Option<usize>) -> Result<AsyncRaw> {
        let s = Socket::new_raw(Domain::IPV4, Type::RAW, Some(proto))?;
        s.set_nonblocking(true)?;
        if hdrincl {
            s.set_header_included_v4(true)?;
        }
        match sockbuf {
            Some(n) => {
                let _ = s.set_send_buffer_size(n);
                let _ = s.set_recv_buffer_size(n);
            }
            None => {
                let _ = s.set_recv_buffer_size(RAW_RECV_BUF as usize);
            }
        }
        Ok(AsyncRaw {
            fd: unsafe { AsyncFd::register(s)? },
        })
    }

    async fn send_to(&self, buf: &[u8], dst: Ipv4Addr) -> std::io::Result<()> {
        let addr = SockAddr::from(SocketAddrV4::new(dst, 0));
        retry_io(&self.fd, Side::Write, |sock| {
            sock.send_to(buf, &addr).map(|_| ())
        })
        .await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, Ipv4Addr)> {
        retry_io(&self.fd, Side::Read, |sock| {
            let mut src: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut slen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let n = io_count(unsafe {
                libc::recvfrom(
                    sock.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut src as *mut _ as *mut libc::sockaddr,
                    &mut slen,
                )
            })?;
            Ok((n, Ipv4Addr::from(u32::from_be(src.sin_addr.s_addr))))
        })
        .await
    }
}

fn scratch64k() -> Vec<u8> {
    vec![0u8; 65535]
}

struct BufPool {
    free: Mutex<Vec<Vec<u8>>>,
    keep: usize,
}

impl BufPool {
    const fn new(keep: usize) -> BufPool {
        BufPool {
            free: Mutex::new(Vec::new()),
            keep,
        }
    }

    fn rx(&self) -> Buf<'_> {
        let buf = self.free.lock().unwrap().pop();
        let buf = match buf {
            Some(b) if b.len() == 65535 => b,
            _ => scratch64k(),
        };
        Buf { pool: self, buf }
    }

    fn build(&self) -> Buf<'_> {
        let mut buf = self.free.lock().unwrap().pop().unwrap_or_default();
        buf.clear();
        Buf { pool: self, buf }
    }
}

struct Buf<'a> {
    pool: &'a BufPool,
    buf: Vec<u8>,
}

impl Buf<'_> {
    fn vec(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}

impl Drop for Buf<'_> {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buf);
        let mut free = self.pool.free.lock().unwrap();
        if free.len() < self.pool.keep {
            free.push(buf);
        }
    }
}

impl std::ops::Deref for Buf<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl std::ops::DerefMut for Buf<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

static RX_POOL: BufPool = BufPool::new(8);
static TX_POOL: BufPool = BufPool::new(8);

pub(crate) struct RawCounters {
    tx_pkts: AtomicU64,
    tx_bytes: AtomicU64,
    tx_err: AtomicU64,
    rx_pkts: AtomicU64,
    rx_bytes: AtomicU64,
    fec_groups: AtomicU64,
    fec_missing: AtomicU64,
    fec_recovered: AtomicU64,
    fec_lost: AtomicU64,
    fec_tx_data: AtomicU64,
    fec_tx_parity: AtomicU64,
    fec_rx_data: AtomicU64,
    fec_rx_parity: AtomicU64,
    fec_encode_err: AtomicU64,
    fec_groups_lossy: AtomicU64,
    fec_decode_err: AtomicU64,
}

impl RawCounters {
    const fn new() -> RawCounters {
        RawCounters {
            tx_pkts: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_err: AtomicU64::new(0),
            rx_pkts: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            fec_groups: AtomicU64::new(0),
            fec_missing: AtomicU64::new(0),
            fec_recovered: AtomicU64::new(0),
            fec_lost: AtomicU64::new(0),
            fec_tx_data: AtomicU64::new(0),
            fec_tx_parity: AtomicU64::new(0),
            fec_rx_data: AtomicU64::new(0),
            fec_rx_parity: AtomicU64::new(0),
            fec_encode_err: AtomicU64::new(0),
            fec_groups_lossy: AtomicU64::new(0),
            fec_decode_err: AtomicU64::new(0),
        }
    }
}

pub(crate) static RAW: RawCounters = RawCounters::new();

static RAW_QUIC: Mutex<Option<quinn::Connection>> = Mutex::new(None);

fn udp_drops(port: u16) -> Option<u64> {
    let table = std::fs::read_to_string("/proc/net/udp").ok()?;
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 13 {
            continue;
        }
        let local = f[1].rsplit_once(':')?;
        if u16::from_str_radix(local.1, 16).ok()? == port {
            return f.last()?.parse().ok();
        }
    }
    None
}

fn spawn_reporter(link: Arc<dyn RawLink>, consumer_port: u16, bridge_port: u16) {
    static STARTED: AtomicU64 = AtomicU64::new(0);
    if STARTED.swap(1, SeqCst) != 0 {
        return;
    }
    tokio::spawn(async move {
        let mut last = (0u64, 0u64);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            let (tx, rx) = (RAW.tx_pkts.load(Relaxed), RAW.rx_pkts.load(Relaxed));
            if (tx, rx) == last {
                continue;
            }
            last = (tx, rx);
            let kdrops = link.kernel_drops();
            let quic = RAW_QUIC.lock().unwrap().clone();
            let inner = match quic {
                Some(c) => {
                    let st = c.stats().path;
                    format!(
                        " | inner quic rtt {:.0}ms, lost {} of {} sent, {} congestion events, cwnd {}",
                        c.rtt().as_secs_f64() * 1000.0,
                        st.lost_packets,
                        st.sent_packets,
                        st.congestion_events,
                        st.cwnd,
                    )
                }
                None => String::new(),
            };
            let groups = RAW.fec_groups.load(Relaxed);
            let missing = RAW.fec_missing.load(Relaxed);
            let lossy = RAW.fec_groups_lossy.load(Relaxed);
            let shards = groups.saturating_mul(FEC_GROUP_HINT.load(Relaxed)).max(1);
            info!(
                "raw: tx {tx} pkt / {:.1} MiB ({} err), rx {rx} pkt / {:.1} MiB | \
                 fec {groups} groups, path loss {missing} ({:.2}%) -> {} repaired, {} through | \
                 fec wire tx {}d+{}p ({} refused), rx {}d+{}p | {} lossy groups ({:.1} lost each, \
                 {} decode refused) | kernel drops {kdrops} | loopback drops {}/{}{inner}",
                RAW.tx_bytes.load(Relaxed) as f64 / 1_048_576.0,
                RAW.tx_err.load(Relaxed),
                RAW.rx_bytes.load(Relaxed) as f64 / 1_048_576.0,
                100.0 * missing as f64 / shards as f64,
                RAW.fec_recovered.load(Relaxed),
                RAW.fec_lost.load(Relaxed),
                RAW.fec_tx_data.load(Relaxed),
                RAW.fec_tx_parity.load(Relaxed),
                RAW.fec_encode_err.load(Relaxed),
                RAW.fec_rx_data.load(Relaxed),
                RAW.fec_rx_parity.load(Relaxed),
                lossy,
                missing as f64 / lossy.max(1) as f64,
                RAW.fec_decode_err.load(Relaxed),
                udp_drops(consumer_port).unwrap_or(0),
                udp_drops(bridge_port).unwrap_or(0),
            );
        }
    });
}

static FEC_GROUP_HINT: AtomicU64 = AtomicU64::new(0);

fn checksum(data: &[u8], init: u32) -> u16 {
    let mut sum = init;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_sum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, seg_len: usize) -> u32 {
    let (s, d) = (src.octets(), dst.octets());
    u16::from_be_bytes([s[0], s[1]]) as u32
        + u16::from_be_bytes([s[2], s[3]]) as u32
        + u16::from_be_bytes([d[0], d[1]]) as u32
        + u16::from_be_bytes([d[2], d[3]]) as u32
        + proto as u32
        + seg_len as u32
}

#[async_trait]
pub(crate) trait RawLink: Send + Sync {
    async fn send(&self, payload: &[u8]) -> std::io::Result<()>;
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;

    fn kernel_drops(&self) -> u64 {
        0
    }
}

#[derive(Clone)]
struct Peer(Arc<Mutex<Option<Ipv4Addr>>>);
impl Peer {
    fn new(known: Option<Ipv4Addr>) -> Peer {
        Peer(Arc::new(Mutex::new(known)))
    }
    fn get(&self) -> Option<Ipv4Addr> {
        *self.0.lock().unwrap()
    }
    fn learn(&self, ip: Ipv4Addr) {
        let mut g = self.0.lock().unwrap();
        if g.is_none() {
            *g = Some(ip);
        }
    }
}

struct IcmpLink {
    sock: AsyncRaw,
    peer: Peer,
    id: u16,
    seq: AtomicU32,
    initiator: bool,
}

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TO_LISTENER: u8 = 1;
const ICMP_TO_INITIATOR: u8 = 2;

impl IcmpLink {
    fn outgoing(&self) -> (u8, u8, u16) {
        if self.initiator {
            let seq = self.seq.fetch_add(1, SeqCst) as u16;
            (ICMP_ECHO_REQUEST, ICMP_TO_LISTENER, seq)
        } else {
            let seq = self.seq.load(SeqCst) as u16;
            (ICMP_ECHO_REPLY, ICMP_TO_INITIATOR, seq)
        }
    }

    fn incoming(&self) -> (u8, u8) {
        if self.initiator {
            (ICMP_ECHO_REPLY, ICMP_TO_INITIATOR)
        } else {
            (ICMP_ECHO_REQUEST, ICMP_TO_LISTENER)
        }
    }
}

#[async_trait]
impl RawLink for IcmpLink {
    async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        let Some(peer) = self.peer.get() else {
            return Ok(());
        };
        let (kind, dir, seq) = self.outgoing();
        let mut pkt = Vec::with_capacity(9 + payload.len());
        pkt.extend_from_slice(&[kind, 0, 0, 0]);
        pkt.extend_from_slice(&self.id.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.push(dir);
        pkt.extend_from_slice(payload);
        let c = checksum(&pkt, 0);
        pkt[2..4].copy_from_slice(&c.to_be_bytes());
        self.sock.send_to(&pkt, peer).await
    }

    async fn recv(&self, out: &mut [u8]) -> std::io::Result<usize> {
        let (want_kind, want_dir) = self.incoming();
        let mut buf = RX_POOL.rx();
        loop {
            let (n, src) = self.sock.recv_from(&mut buf).await?;
            if n < 20 {
                continue;
            }
            let ihl = ((buf[0] & 0x0f) as usize) * 4;
            if n < ihl + 9 {
                continue;
            }
            let icmp = &buf[ihl..n];
            if icmp[0] != want_kind || icmp[8] != want_dir {
                continue;
            }
            let id = u16::from_be_bytes([icmp[4], icmp[5]]);
            if id != self.id {
                continue;
            }
            if !self.initiator {
                let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
                self.seq.store(seq as u32, SeqCst);
            }
            self.peer.learn(src);
            let payload = &icmp[9..];
            let m = payload.len().min(out.len());
            out[..m].copy_from_slice(&payload[..m]);
            return Ok(m);
        }
    }
}

struct FakeTcpLink {
    sock: AsyncRaw,
    peer: Peer,
    src_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: AtomicU32,
    header: TcpHeader,
    ts: AtomicU32,
}

impl FakeTcpLink {
    fn build_into(&self, peer: Ipv4Addr, payload: &[u8], seg: &mut Vec<u8>) {
        let c = TcpCraft {
            src_ip: self.src_ip,
            peer,
            sport: self.sport,
            dport: self.dport,
            seq: self.seq.fetch_add(payload.len().max(1) as u32, SeqCst),
            ts: match self.header {
                TcpHeader::Bare => None,
                TcpHeader::Linux => Some(self.ts.fetch_add(1, SeqCst)),
            },
        };
        craft_tcp_segment(&c, payload, seg);
    }
}

struct TcpCraft {
    src_ip: Ipv4Addr,
    peer: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ts: Option<u32>,
}

const TCP_OPTS: usize = 20;

fn push_tcp_options(buf: &mut Vec<u8>, tsval: u32) {
    buf.extend_from_slice(&[2, 4, 0x05, 0xb4]);
    buf.push(1);
    buf.extend_from_slice(&[3, 3, 7]);
    buf.push(1);
    buf.push(1);
    buf.extend_from_slice(&[8, 10]);
    buf.extend_from_slice(&tsval.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
}

fn craft_tcp_segment(c: &TcpCraft, payload: &[u8], seg: &mut Vec<u8>) {
    let opts = if c.ts.is_some() { TCP_OPTS } else { 0 };
    seg.clear();
    seg.reserve(20 + opts + payload.len());
    seg.extend_from_slice(&c.sport.to_be_bytes());
    seg.extend_from_slice(&c.dport.to_be_bytes());
    seg.extend_from_slice(&c.seq.to_be_bytes());
    seg.extend_from_slice(&0u32.to_be_bytes());
    seg.push((((20 + opts) / 4) << 4) as u8);
    seg.push(0b0001_1000);
    seg.extend_from_slice(&65535u16.to_be_bytes());
    seg.extend_from_slice(&[0, 0]);
    seg.extend_from_slice(&[0, 0]);
    if let Some(ts) = c.ts {
        push_tcp_options(seg, ts);
    }
    seg.extend_from_slice(payload);
    let sum = checksum(seg, pseudo_sum(c.src_ip, c.peer, 6, seg.len()));
    seg[16..18].copy_from_slice(&sum.to_be_bytes());
}

#[async_trait]
impl RawLink for FakeTcpLink {
    async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        let Some(peer) = self.peer.get() else {
            return Ok(());
        };
        let mut pkt = TX_POOL.build();
        self.build_into(peer, payload, pkt.vec());
        self.sock.send_to(&pkt, peer).await
    }

    async fn recv(&self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut buf = RX_POOL.rx();
        loop {
            let (n, src) = self.sock.recv_from(&mut buf).await?;
            if n < 20 {
                continue;
            }
            let ihl = ((buf[0] & 0x0f) as usize) * 4;
            if n < ihl + 20 {
                continue;
            }
            let tcp = &buf[ihl..n];
            let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
            if sport != self.dport || dport != self.sport {
                continue;
            }
            let doff = ((tcp[12] >> 4) as usize) * 4;
            if tcp.len() <= doff {
                continue;
            }
            self.peer.learn(src);
            let payload = &tcp[doff..];
            let m = payload.len().min(out.len());
            out[..m].copy_from_slice(&payload[..m]);
            return Ok(m);
        }
    }
}

#[derive(Clone, Copy)]
struct Net4 {
    net: u32,
    mask: u32,
}

impl Net4 {
    fn parse(s: &str) -> Option<Net4> {
        let (ip, len) = match s.split_once('/') {
            Some((a, b)) => (a, b.trim().parse::<u32>().ok()?),
            None => (s, 32),
        };
        if len > 32 {
            return None;
        }
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        Some(Net4 {
            net: u32::from(ip.trim().parse::<Ipv4Addr>().ok()?) & mask,
            mask,
        })
    }
    fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask == self.net
    }
}

struct SpoofLink {
    sock: AsyncRaw,
    peer: Peer,
    pool: Vec<Ipv4Addr>,
    epoch_secs: u64,
    base: u64,
    sport: u16,
    dport: u16,
    ip_id: AtomicU32,
    ttl_jitter: bool,
    dscp_jitter: bool,
    accept: Vec<Net4>,
    _sink: Option<std::net::UdpSocket>,
}

impl SpoofLink {
    fn epoch(&self) -> u64 {
        if self.epoch_secs == 0 {
            return 0;
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / self.epoch_secs)
            .unwrap_or(0)
    }

    fn build(&self, peer: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let id = self.ip_id.fetch_add(1, SeqCst);
        let e = self.epoch();
        let h = blake3::hash(&[&self.base.to_be_bytes()[..], &e.to_be_bytes()[..]].concat());
        let hb = h.as_bytes();
        let src = self.pool
            [(u32::from_be_bytes([hb[0], hb[1], hb[2], hb[3]]) as usize) % self.pool.len()];
        let ttl = if self.ttl_jitter {
            [64u8, 128, 255][(hb[4] as usize) % 3]
        } else {
            64
        };
        let tos = if self.dscp_jitter {
            [0u8, 0x20, 0x28, 0x48, 0x88][(hb[5] as usize) % 5]
        } else {
            0
        };

        let mut ip = Vec::with_capacity(total);
        ip.push(0x45);
        ip.push(tos);
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&(id as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.push(ttl);
        ip.push(17);
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(&src.octets());
        ip.extend_from_slice(&peer.octets());
        let c = checksum(&ip, 0);
        ip[10..12].copy_from_slice(&c.to_be_bytes());

        let mut udp = Vec::with_capacity(udp_len);
        udp.extend_from_slice(&self.sport.to_be_bytes());
        udp.extend_from_slice(&self.dport.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(payload);
        let mut pseudo = Vec::with_capacity(12);
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&peer.octets());
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
        let init: u32 = pseudo
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]) as u32)
            .sum();
        let mut uc = checksum(&udp, init);
        if uc == 0 {
            uc = 0xffff;
        }
        udp[6..8].copy_from_slice(&uc.to_be_bytes());
        ip.extend_from_slice(&udp);
        ip
    }
}

#[async_trait]
impl RawLink for SpoofLink {
    async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        let Some(peer) = self.peer.get() else {
            return Ok(());
        };
        let pkt = self.build(peer, payload);
        self.sock.send_to(&pkt, peer).await
    }

    async fn recv(&self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut buf = RX_POOL.rx();
        loop {
            let (n, src) = self.sock.recv_from(&mut buf).await?;
            if n < 28 {
                continue;
            }
            let ihl = ((buf[0] & 0x0f) as usize) * 4;
            if n < ihl + 8 {
                continue;
            }
            let udp = &buf[ihl..n];
            let sport = u16::from_be_bytes([udp[0], udp[1]]);
            let dport = u16::from_be_bytes([udp[2], udp[3]]);
            if sport != self.dport || dport != self.sport {
                continue;
            }
            if !self.accept.is_empty() {
                let pkt_src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                let _ = src;
                if !self.accept.iter().any(|a| a.contains(pkt_src)) {
                    continue;
                }
            }
            let payload = &udp[8..];
            let m = payload.len().min(out.len());
            out[..m].copy_from_slice(&payload[..m]);
            return Ok(m);
        }
    }
}

enum Rule {
    Iptables(Vec<String>),
    Nft(String),
}

static RULES: Mutex<Vec<Rule>> = Mutex::new(Vec::new());

fn quiet(cmd: &str, args: &[&str]) -> bool {
    std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn nft_load(script: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let Ok(mut child) = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let wrote = child
        .stdin
        .take()
        .map(|mut s| s.write_all(script.as_bytes()).is_ok())
        .unwrap_or(false);
    child.wait().map(|s| s.success()).unwrap_or(false) && wrote
}

fn text(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if out.status.success() {
        String::from_utf8(out.stdout).ok()
    } else {
        None
    }
}

fn running(pid: &str) -> bool {
    !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn owner(tag: &str) -> Option<(&str, &str, &str)> {
    let rest = tag.strip_prefix("rakhsh-")?;
    let (what, rest) = rest.split_once('-')?;
    let (port, pid) = rest.split_once('-')?;
    if port.parse::<u16>().is_ok() && !pid.contains('-') {
        Some((what, port, pid))
    } else {
        None
    }
}

fn sweep_stale() {
    for (table, chain) in [
        ("filter", "OUTPUT"),
        ("raw", "PREROUTING"),
        ("raw", "OUTPUT"),
    ] {
        let Some(listing) = text("iptables", &["-t", table, "-S", chain]) else {
            continue;
        };
        for line in listing.lines() {
            let Some(tag) = line
                .split("--comment ")
                .nth(1)
                .map(|r| r.trim_start_matches('"'))
                .and_then(|r| r.split(['"', ' ']).next())
            else {
                continue;
            };
            let Some((what, port, pid)) = owner(tag) else {
                continue;
            };
            if running(pid) {
                continue;
            }
            let del = match what {
                "faketcp" => rst_rule(port, tag, "-D"),
                "l2" if chain == "PREROUTING" => {
                    notrack_rule("PREROUTING", "--dport", port, tag, "-D")
                }
                "l2" => notrack_rule("OUTPUT", "--sport", port, tag, "-D"),
                _ => continue,
            };
            let a: Vec<&str> = del.iter().map(String::as_str).collect();
            if quiet("iptables", &a) {
                info!("raw: removed {tag}, left behind by a run that is gone");
            }
        }
    }
    let Some(listing) = text("nft", &["list", "tables", "inet"]) else {
        return;
    };
    for name in listing
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2))
        .filter(|n| n.starts_with("rakhsh_"))
    {
        let Some(pid) = name.rsplit('_').next() else {
            continue;
        };
        if running(pid) {
            continue;
        }
        if quiet("nft", &["delete", "table", "inet", name]) {
            info!("raw: removed nft table {name}, left behind by a run that is gone");
        }
    }
}

fn install(table: &str, iptables_rules: &[Vec<String>], nft_chains: &str) {
    static SWEPT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    SWEPT.get_or_init(sweep_stale);
    let mut added = Vec::new();
    for r in iptables_rules {
        let a: Vec<&str> = r.iter().map(String::as_str).collect();
        if !quiet("iptables", &a) {
            break;
        }
        let mut del = r.clone();
        if let Some(x) = del.iter_mut().find(|x| *x == "-I" || *x == "-A") {
            *x = "-D".into();
        }
        added.push(del);
    }
    if added.len() == iptables_rules.len() {
        RULES
            .lock()
            .unwrap()
            .extend(added.into_iter().map(Rule::Iptables));
        return;
    }
    for del in added {
        let a: Vec<&str> = del.iter().map(String::as_str).collect();
        quiet("iptables", &a);
    }
    quiet("nft", &["delete", "table", "inet", table]);
    if nft_load(&format!("table inet {table} {{\n{nft_chains}\n}}\n")) {
        info!("raw: installed {table} with nft (no usable iptables on this host)");
        RULES.lock().unwrap().push(Rule::Nft(table.to_string()));
        return;
    }
    tracing::warn!(
        "raw: neither iptables nor nft worked for {table}, so the kernel answers this carrier's \
         packets on its own"
    );
}

fn rst_rule(sport: &str, tag: &str, verb: &str) -> Vec<String> {
    [
        verb,
        "OUTPUT",
        "-p",
        "tcp",
        "--sport",
        sport,
        "--tcp-flags",
        "RST",
        "RST",
        "-m",
        "comment",
        "--comment",
        tag,
        "-j",
        "DROP",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn install_rst_drop(sport: u16) {
    let me = std::process::id();
    let tag = format!("rakhsh-faketcp-{sport}-{me}");
    install(
        &format!("rakhsh_rst_{sport}_{me}"),
        &[rst_rule(&sport.to_string(), &tag, "-I")],
        &format!(
            "chain out {{ type filter hook output priority 0; policy accept; \
             tcp sport {sport} tcp flags & rst == rst drop; }}"
        ),
    );
}

fn notrack_rule(chain: &str, dir: &str, port: &str, tag: &str, verb: &str) -> Vec<String> {
    [
        "-t",
        "raw",
        verb,
        chain,
        "-p",
        "tcp",
        dir,
        port,
        "-m",
        "comment",
        "--comment",
        tag,
        "-j",
        "NOTRACK",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn install_notrack(port: u16) {
    let me = std::process::id();
    let tag = format!("rakhsh-l2-{port}-{me}");
    let port = port.to_string();
    let rules: Vec<Vec<String>> = [("PREROUTING", "--dport"), ("OUTPUT", "--sport")]
        .iter()
        .map(|(chain, dir)| notrack_rule(chain, dir, &port, &tag, "-I"))
        .collect();
    install(
        &format!("rakhsh_notrack_{port}_{me}"),
        &rules,
        &format!(
            "chain pre {{ type filter hook prerouting priority -300; policy accept; \
             tcp dport {port} notrack; }}\n\
             chain out {{ type filter hook output priority -300; policy accept; \
             tcp sport {port} notrack; }}"
        ),
    );
}

pub fn cleanup() {
    let rules = std::mem::take(&mut *RULES.lock().unwrap());
    for r in rules {
        match r {
            Rule::Iptables(del) => {
                let a: Vec<&str> = del.iter().map(String::as_str).collect();
                quiet("iptables", &a);
            }
            Rule::Nft(table) => {
                quiet("nft", &["delete", "table", "inet", &table]);
            }
        }
    }
}

struct AeadLink {
    inner: Arc<dyn RawLink>,
    seal: ring::aead::LessSafeKey,
    open: ring::aead::LessSafeKey,
    prefix: [u8; 4],
    ctr: std::sync::atomic::AtomicU64,
}

impl AeadLink {
    fn wrap(inner: Arc<dyn RawLink>, key: &[u8; 32], initiator: bool) -> Arc<dyn RawLink> {
        let k_up = blake3::derive_key("rakhsh raw-link aead up v1", key);
        let k_down = blake3::derive_key("rakhsh raw-link aead down v1", key);
        let (ks, ko) = if initiator {
            (k_up, k_down)
        } else {
            (k_down, k_up)
        };
        let mk = |k: [u8; 32]| {
            ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &k).expect("aes256 key"),
            )
        };
        let mut prefix = [0u8; 4];
        let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut prefix);
        Arc::new(AeadLink {
            inner,
            seal: mk(ks),
            open: mk(ko),
            prefix,
            ctr: std::sync::atomic::AtomicU64::new(0),
        })
    }
}

#[async_trait]
impl RawLink for AeadLink {
    async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        let n = self.ctr.fetch_add(1, SeqCst);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.prefix);
        nonce[4..].copy_from_slice(&n.to_be_bytes());
        let mut buf = TX_POOL.build();
        let v = buf.vec();
        v.reserve(12 + payload.len() + 16);
        v.extend_from_slice(&nonce);
        v.extend_from_slice(payload);
        let tag = self
            .seal
            .seal_in_place_separate_tag(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::empty(),
                &mut v[12..],
            )
            .map_err(|_| std::io::Error::other("aead seal"))?;
        v.extend_from_slice(tag.as_ref());
        self.inner.send(&buf).await
    }

    async fn recv(&self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let n = self.inner.recv(out).await?;
            if n < 12 + 16 {
                continue;
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&out[..12]);
            if let Ok(plain) = self.open.open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::empty(),
                &mut out[12..n],
            ) {
                let m = plain.len();
                out.copy_within(12..12 + m, 0);
                return Ok(m);
            }
        }
    }

    fn kernel_drops(&self) -> u64 {
        self.inner.kernel_drops()
    }
}

fn kcp_config() -> tokio_kcp::KcpConfig {
    crate::carrier::kcp_profile(1300, true)
}

async fn bridge(link: Arc<dyn RawLink>) -> Result<(std::net::UdpSocket, SocketAddr)> {
    let consumer = std::net::UdpSocket::bind("127.0.0.1:0")?;
    consumer.set_nonblocking(true)?;
    let consumer_addr = consumer.local_addr()?;
    let consumer_buf = set_loopback_buf(consumer.as_raw_fd());
    let bridge_std = std::net::UdpSocket::bind("127.0.0.1:0")?;
    bridge_std.set_nonblocking(true)?;
    let bridge_buf = set_loopback_buf(bridge_std.as_raw_fd());
    let bridge = Arc::new(tokio::net::UdpSocket::from_std(bridge_std)?);
    let bridge_addr = bridge.local_addr()?;
    if consumer_buf < LOOPBACK_BUF || bridge_buf < LOOPBACK_BUF {
        tracing::warn!(
            "raw: the kernel clamped the loopback hand-off buffers to {}/{} KiB (wanted {} KiB each) — \
             run `rakhsh optimize` to raise net.core.rmem_max/wmem_max, or bursts will be dropped \
             on the way to the reliability layer and look like packet loss",
            consumer_buf / 2048,
            bridge_buf / 2048,
            LOOPBACK_BUF / 1024,
        );
    }

    let reporter_link = link.clone();
    let mut up = tokio::spawn({
        let link = link.clone();
        let sock = bridge.clone();
        async move {
            let mut buf = RX_POOL.rx();
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) if from == consumer_addr => match link.send(&buf[..n]).await {
                        Ok(()) => {
                            RAW.tx_pkts.fetch_add(1, Relaxed);
                            RAW.tx_bytes.fetch_add(n as u64, Relaxed);
                        }
                        Err(_) => {
                            RAW.tx_err.fetch_add(1, Relaxed);
                        }
                    },
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    });
    let mut down = tokio::spawn(async move {
        let mut buf = RX_POOL.rx();
        loop {
            match link.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    RAW.rx_pkts.fetch_add(1, Relaxed);
                    RAW.rx_bytes.fetch_add(n as u64, Relaxed);
                    let _ = bridge.send_to(&buf[..n], consumer_addr).await;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        tokio::select! {
            _ = &mut up => down.abort(),
            _ = &mut down => up.abort(),
        }
    });
    spawn_reporter(reporter_link, consumer_addr.port(), bridge_addr.port());
    Ok((consumer, bridge_addr))
}

const LOOPBACK_BUF: libc::c_int = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Side {
    Read,
    Write,
}

async fn retry_io<S, T>(
    fd: &AsyncFd<S>,
    side: Side,
    mut call: impl FnMut(&S) -> std::io::Result<T>,
) -> std::io::Result<T>
where
    S: AsRawFd,
{
    loop {
        let mut ready = match side {
            Side::Read => fd.readable().await?,
            Side::Write => fd.writable().await?,
        };
        match ready.try_io(|inner| call(inner.get_ref())) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

fn io_count(n: isize) -> std::io::Result<usize> {
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

const RAW_RECV_BUF: libc::c_int = 8 * 1024 * 1024;

fn resize_sock_buf(fd: std::os::fd::RawFd, opt: libc::c_int, want: libc::c_int) -> libc::c_int {
    let mut got: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &want as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &mut got as *mut _ as *mut libc::c_void,
            &mut len,
        );
    }
    got
}

fn set_recv_buf(fd: std::os::fd::RawFd, want: libc::c_int) -> libc::c_int {
    resize_sock_buf(fd, libc::SO_RCVBUF, want)
}

fn set_loopback_buf(fd: std::os::fd::RawFd) -> libc::c_int {
    [libc::SO_RCVBUF, libc::SO_SNDBUF]
        .into_iter()
        .map(|opt| resize_sock_buf(fd, opt, LOOPBACK_BUF))
        .min()
        .unwrap_or(0)
}

async fn kcp_over_raw(link: Arc<dyn RawLink>, conv: u32) -> Result<(BoxTx, BoxRx)> {
    let (consumer, bridge_addr) = bridge(link).await?;
    let udp = tokio::net::UdpSocket::from_std(consumer)?;
    let s = tokio_kcp::KcpStream::connect_with_socket_conv(&kcp_config(), conv, udp, bridge_addr)
        .await
        .map_err(|e| anyhow!("kcp over raw: {e}"))?;
    Ok(split_bytes_unbuffered(s))
}

struct QuinnTx {
    s: quinn::SendStream,
    _ep: quinn::Endpoint,
    _conn: quinn::Connection,
}
struct QuinnRx {
    r: quinn::RecvStream,
    _ep: quinn::Endpoint,
    _conn: quinn::Connection,
}

#[async_trait]
impl FrameTx for QuinnTx {
    async fn send(&mut self, frame: Vec<u8>) -> std::io::Result<()> {
        write_frame(&mut self.s, &frame).await
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.s.flush().await
    }
}
#[async_trait]
impl FrameRx for QuinnRx {
    async fn recv(&mut self) -> std::io::Result<bytes::BytesMut> {
        read_frame(&mut self.r)
            .await
            .map(crate::carrier::into_bytes_mut)
    }
}

async fn quic_over_raw(
    link: Arc<dyn RawLink>,
    initiator: bool,
    tuning: RawTuning,
) -> Result<(BoxTx, BoxRx)> {
    let (consumer, bridge_addr) = bridge(link).await?;
    let (scfg, ccfg) = crate::carrier::raw_quic_configs(tuning)?;
    let rt = Arc::new(quinn::TokioRuntime);
    let (send, recv, ep, conn) = if initiator {
        let mut ep = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, consumer, rt)?;
        ep.set_default_client_config(ccfg);
        let conn = ep
            .connect(bridge_addr, "rakhsh")
            .map_err(|e| anyhow!("quic-over-raw connect: {e}"))?
            .await?;
        let (s, r) = conn.open_bi().await?;
        (s, r, ep, conn)
    } else {
        let ep = quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(scfg), consumer, rt)?;
        let conn = ep
            .accept()
            .await
            .ok_or_else(|| anyhow!("quic-over-raw endpoint closed"))?
            .await?;
        let (s, r) = conn.accept_bi().await?;
        (s, r, ep, conn)
    };
    *RAW_QUIC.lock().unwrap() = Some(conn.clone());
    Ok((
        Box::new(QuinnTx {
            s: send,
            _ep: ep.clone(),
            _conn: conn.clone(),
        }),
        Box::new(QuinnRx {
            r: recv,
            _ep: ep,
            _conn: conn,
        }),
    ))
}

fn src_ip_for(peer: Ipv4Addr) -> Result<Ipv4Addr> {
    let u = std::net::UdpSocket::bind("0.0.0.0:0")?;
    u.connect(SocketAddrV4::new(peer, 9))?;
    match u.local_addr()?.ip() {
        std::net::IpAddr::V4(a) => Ok(a),
        _ => Err(anyhow!("no ipv4 source")),
    }
}

#[derive(Clone, Default)]
pub struct SpoofOpts {
    pub pool: Vec<Ipv4Addr>,
    pub sockbuf: Option<usize>,
    pub ttl_jitter: bool,
    pub dscp_jitter: bool,
    pub rotate_secs: u64,
    pub peer_src: Vec<String>,
    pub link_encrypt: bool,
}

static SPOOF_SEQ: AtomicUsize = AtomicUsize::new(0);

pub struct Dial<'a> {
    pub kind: &'a str,
    pub params: &'a RawParams,
    pub spoof: &'a SpoofOpts,
    pub fec: Option<(usize, usize)>,
    pub reliability: &'a str,
    pub header: TcpHeader,
    pub tuning: RawTuning,
}

pub async fn connect(
    d: Dial<'_>,
    initiator: bool,
    peer: Option<Ipv4Addr>,
    lane: u64,
) -> Result<(BoxTx, BoxRx)> {
    let Dial {
        kind,
        params: p,
        spoof,
        fec,
        reliability,
        header,
        tuning,
    } = d;
    let lp = p.lane(lane);
    let (sport, dport) = if initiator {
        (lp.port_a, lp.port_b)
    } else {
        (lp.port_b, lp.port_a)
    };
    let link: Arc<dyn RawLink> = match kind {
        "icmp" => Arc::new(IcmpLink {
            sock: AsyncRaw::new(Protocol::ICMPV4, false)?,
            peer: Peer::new(peer),
            id: lp.icmp_id,
            seq: AtomicU32::new(1),
            initiator,
        }),
        "faketcp" => {
            let anchor = peer.unwrap_or(Ipv4Addr::new(8, 8, 8, 8));
            let link = FakeTcpLink {
                sock: AsyncRaw::new(Protocol::TCP, false)?,
                peer: Peer::new(peer),
                src_ip: src_ip_for(anchor)?,
                sport,
                dport,
                seq: AtomicU32::new(1),
                header,
                ts: AtomicU32::new(1),
            };
            install_rst_drop(sport);
            Arc::new(link)
        }
        "l2tcp" => l2_link(sport, dport, peer)?,
        "spoof" => {
            let anchor = peer.context("spoof needs a known peer ip")?;
            let pool = if spoof.pool.is_empty() {
                vec![src_ip_for(anchor)?]
            } else {
                spoof.pool.clone()
            };
            let base = {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos() as u64)
                    .unwrap_or(1);
                nanos ^ ((SPOOF_SEQ.fetch_add(1, SeqCst) as u64) << 32) ^ ((sport as u64) << 16)
            };
            let sink = std::net::UdpSocket::bind(("0.0.0.0", sport))
                .ok()
                .inspect(|u| {
                    let _ = socket2::SockRef::from(u).set_recv_buffer_size(2048);
                    let _ = u.set_nonblocking(true);
                });
            Arc::new(SpoofLink {
                sock: AsyncRaw::with_bufs(Protocol::UDP, true, spoof.sockbuf)?,
                peer: Peer::new(peer),
                pool,
                epoch_secs: spoof.rotate_secs,
                base,
                sport,
                dport,
                ip_id: AtomicU32::new((base & 0xffff) as u32),
                ttl_jitter: spoof.ttl_jitter,
                dscp_jitter: spoof.dscp_jitter,
                accept: spoof
                    .peer_src
                    .iter()
                    .filter_map(|s| Net4::parse(s))
                    .collect(),
                _sink: sink,
            })
        }
        other => return Err(anyhow!("unknown raw carrier {other}")),
    };
    let link: Arc<dyn RawLink> = if spoof.link_encrypt {
        AeadLink::wrap(link, &p.key, initiator)
    } else {
        link
    };
    let link: Arc<dyn RawLink> = match fec {
        Some((d, p)) if d > 0 && p > 0 => FecLink::new(link, d, p),
        _ => link,
    };
    match reliability {
        "quic" => quic_over_raw(link, initiator, tuning).await,
        _ => kcp_over_raw(link, lp.conv).await,
    }
}

use std::os::fd::{FromRawFd, OwnedFd};

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *mut SockFilter,
}

fn bpf_tcp_dport(port: u16) -> [SockFilter; 11] {
    let p = port as u32;
    [
        SockFilter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 12,
        },
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 8,
            k: 0x0800,
        },
        SockFilter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 23,
        },
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 6,
            k: 6,
        },
        SockFilter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 20,
        },
        SockFilter {
            code: 0x45,
            jt: 4,
            jf: 0,
            k: 0x1fff,
        },
        SockFilter {
            code: 0xb1,
            jt: 0,
            jf: 0,
            k: 14,
        },
        SockFilter {
            code: 0x48,
            jt: 0,
            jf: 0,
            k: 16,
        },
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: p,
        },
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0xffff_ffff,
        },
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ]
}

struct Afp {
    fd: AsyncFd<OwnedFd>,
}

impl Afp {
    fn open(ifindex: i32, dport: u16) -> Result<Afp> {
        let eth_p_ip: libc::c_int = (0x0800u16.to_be()) as libc::c_int;
        let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_ip) };
        if raw < 0 {
            return Err(anyhow!(
                "AF_PACKET socket (need root): {}",
                std::io::Error::last_os_error()
            ));
        }
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = 0x0800u16.to_be();
        sll.sll_ifindex = ifindex;
        let r = unsafe {
            libc::bind(
                raw,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if r < 0 {
            return Err(anyhow!(
                "bind AF_PACKET: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut prog = bpf_tcp_dport(dport);
        let fprog = SockFprog {
            len: prog.len() as u16,
            filter: prog.as_mut_ptr(),
        };
        unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const _ as *const libc::c_void,
                std::mem::size_of::<SockFprog>() as libc::socklen_t,
            );
            let fl = libc::fcntl(raw, libc::F_GETFL);
            libc::fcntl(raw, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        set_recv_buf(raw, RAW_RECV_BUF);
        Ok(Afp {
            fd: unsafe { AsyncFd::register(owned)? },
        })
    }

    fn stats(&self) -> (u64, u64) {
        #[repr(C)]
        #[derive(Default)]
        struct TpacketStats {
            tp_packets: libc::c_uint,
            tp_drops: libc::c_uint,
        }
        let mut s = TpacketStats::default();
        let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                self.fd.get_ref().as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                &mut s as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if r < 0 {
            return (0, 0);
        }
        (s.tp_packets as u64, s.tp_drops as u64)
    }

    async fn send(&self, frame: &[u8]) -> std::io::Result<()> {
        retry_io(&self.fd, Side::Write, |fd| {
            io_count(unsafe {
                libc::send(fd.as_raw_fd(), frame.as_ptr() as *const _, frame.len(), 0)
            })
            .map(|_| ())
        })
        .await
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        retry_io(&self.fd, Side::Read, |fd| {
            io_count(unsafe {
                libc::recv(fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len(), 0)
            })
        })
        .await
    }
}

struct L2Params {
    ifindex: i32,
    src_mac: [u8; 6],
    gw_mac: [u8; 6],
    src_ip: Ipv4Addr,
}

fn discover_l2(anchor: Ipv4Addr) -> Result<L2Params> {
    let link = shabdiz::carrier::l2::discover(anchor)?;
    Ok(L2Params {
        ifindex: link.ifindex,
        src_mac: link.src_mac,
        gw_mac: link.gateway_mac,
        src_ip: link.src_ip,
    })
}

struct L2Link {
    sock: Afp,
    src_mac: [u8; 6],
    gw_mac: [u8; 6],
    src_ip: Ipv4Addr,
    peer: Peer,
    sport: u16,
    dport: u16,
    seq: AtomicU32,
    ip_id: AtomicU32,
    ts: AtomicU32,
}

const ETH_HDR: usize = 14;
const IP4_HDR: usize = 20;

struct L2Craft {
    src_mac: [u8; 6],
    gw_mac: [u8; 6],
    src_ip: Ipv4Addr,
    peer: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    tsval: u32,
    ip_id: u16,
}

impl L2Link {
    fn build_into(&self, peer: Ipv4Addr, payload: &[u8], frame: &mut Vec<u8>) {
        let c = L2Craft {
            src_mac: self.src_mac,
            gw_mac: self.gw_mac,
            src_ip: self.src_ip,
            peer,
            sport: self.sport,
            dport: self.dport,
            seq: self.seq.fetch_add(payload.len().max(1) as u32, SeqCst),
            tsval: self.ts.fetch_add(1, SeqCst),
            ip_id: self.ip_id.fetch_add(1, SeqCst) as u16,
        };
        craft_l2_frame(&c, payload, frame);
    }
}

fn craft_l2_frame(c: &L2Craft, payload: &[u8], frame: &mut Vec<u8>) {
    frame.clear();
    frame.reserve(ETH_HDR + IP4_HDR + 20 + TCP_OPTS + payload.len());
    frame.extend_from_slice(&c.gw_mac);
    frame.extend_from_slice(&c.src_mac);
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&[0x45, 0x28]);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&c.ip_id.to_be_bytes());
    frame.extend_from_slice(&0x4000u16.to_be_bytes());
    frame.push(64);
    frame.push(6);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&c.src_ip.octets());
    frame.extend_from_slice(&c.peer.octets());
    frame.extend_from_slice(&c.sport.to_be_bytes());
    frame.extend_from_slice(&c.dport.to_be_bytes());
    frame.extend_from_slice(&c.seq.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.push((((20 + TCP_OPTS) / 4) << 4) as u8);
    frame.push(0b0001_1000);
    frame.extend_from_slice(&65535u16.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0, 0]);
    push_tcp_options(frame, c.tsval);
    frame.extend_from_slice(payload);

    let ip = ETH_HDR;
    let tcp = ETH_HDR + IP4_HDR;
    let total = frame.len() - ip;
    frame[ip + 2..ip + 4].copy_from_slice(&(total as u16).to_be_bytes());
    let sum = checksum(
        &frame[tcp..],
        pseudo_sum(c.src_ip, c.peer, 6, total - IP4_HDR),
    );
    frame[tcp + 16..tcp + 18].copy_from_slice(&sum.to_be_bytes());
    let ic = checksum(&frame[ip..tcp], 0);
    frame[ip + 10..ip + 12].copy_from_slice(&ic.to_be_bytes());
}

#[async_trait]
impl RawLink for L2Link {
    async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        let Some(peer) = self.peer.get() else {
            return Ok(());
        };
        let mut frame = TX_POOL.build();
        self.build_into(peer, payload, frame.vec());
        self.sock.send(&frame).await
    }

    async fn recv(&self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut buf = RX_POOL.rx();
        loop {
            let n = self.sock.recv(&mut buf).await?;
            if n < 14 + 20 + 20 || buf[12] != 0x08 || buf[13] != 0x00 {
                continue;
            }
            let ip = &buf[14..n];
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            if ip.len() < ihl + 20 || ip[9] != 6 {
                continue;
            }
            let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
            let tcp = &ip[ihl..];
            let sp = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dp = u16::from_be_bytes([tcp[2], tcp[3]]);
            if dp != self.sport || sp != self.dport {
                continue;
            }
            let doff = ((tcp[12] >> 4) as usize) * 4;
            if tcp.len() <= doff {
                continue;
            }
            self.peer.learn(src);
            let payload = &tcp[doff..];
            let m = payload.len().min(out.len());
            out[..m].copy_from_slice(&payload[..m]);
            return Ok(m);
        }
    }

    fn kernel_drops(&self) -> u64 {
        self.sock.stats().1
    }
}

fn l2_link(sport: u16, dport: u16, peer: Option<Ipv4Addr>) -> Result<Arc<dyn RawLink>> {
    let anchor = peer.unwrap_or(Ipv4Addr::new(8, 8, 8, 8));
    let l2 = discover_l2(anchor)?;
    let sock = Afp::open(l2.ifindex, sport)?;
    install_rst_drop(sport);
    install_notrack(sport);
    Ok(Arc::new(L2Link {
        sock,
        src_mac: l2.src_mac,
        gw_mac: l2.gw_mac,
        src_ip: l2.src_ip,
        peer: Peer::new(peer),
        sport,
        dport,
        seq: AtomicU32::new(1),
        ip_id: AtomicU32::new(1),
        ts: AtomicU32::new(1),
    }))
}

use std::collections::{HashMap, VecDeque};

const FEC_HDR: usize = 10;

struct FecTx {
    group_id: u32,
    shards: Vec<Vec<u8>>,
}

struct GroupRx {
    data: u8,
    parity: u8,
    shard_bytes: usize,
    originals: HashMap<usize, Vec<u8>>,
    recovery: HashMap<usize, Vec<u8>>,
    delivered: u32,
    recovered: bool,
}

struct FecRx {
    groups: HashMap<u32, GroupRx>,
    order: VecDeque<u32>,
    queue: VecDeque<Vec<u8>>,
}

pub struct FecLink {
    inner: Arc<dyn RawLink>,
    data: usize,
    parity: usize,
    tx: tokio::sync::Mutex<FecTx>,
    rx: tokio::sync::Mutex<FecRx>,
}

impl FecLink {
    pub fn new(inner: Arc<dyn RawLink>, data: usize, parity: usize) -> Arc<FecLink> {
        Arc::new(FecLink {
            inner,
            data,
            parity,
            tx: tokio::sync::Mutex::new(FecTx {
                group_id: 0,
                shards: Vec::new(),
            }),
            rx: tokio::sync::Mutex::new(FecRx {
                groups: HashMap::new(),
                order: VecDeque::new(),
                queue: VecDeque::new(),
            }),
        })
    }

    fn frame_into(
        out: &mut Vec<u8>,
        group: u32,
        idx: usize,
        data: u8,
        parity: u8,
        shard_bytes: usize,
        body: &[u8],
    ) {
        out.clear();
        out.reserve(FEC_HDR + body.len());
        out.extend_from_slice(&group.to_be_bytes());
        out.extend_from_slice(&(idx as u16).to_be_bytes());
        out.push(data);
        out.push(parity);
        out.extend_from_slice(&(shard_bytes as u16).to_be_bytes());
        out.extend_from_slice(body);
    }
}

#[async_trait]
impl RawLink for FecLink {
    async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        let mut wire = TX_POOL.build();
        let (group, mut data_shards) = {
            let mut tx = self.tx.lock().await;
            let mut body = Vec::with_capacity(2 + payload.len());
            body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            body.extend_from_slice(payload);
            tx.shards.push(body);
            if tx.shards.len() < self.data {
                let idx = tx.shards.len() - 1;
                let (data, parity) = (self.data as u8, self.parity as u8);
                Self::frame_into(
                    wire.vec(),
                    tx.group_id,
                    idx,
                    data,
                    parity,
                    0,
                    &tx.shards[idx],
                );
                drop(tx);
                RAW.fec_tx_data.fetch_add(1, Relaxed);
                return self.inner.send(&wire).await;
            }
            let g = tx.group_id;
            tx.group_id = tx.group_id.wrapping_add(1);
            let shards = std::mem::take(&mut tx.shards);
            (g, shards)
        };
        let shard_bytes = {
            let m = data_shards.iter().map(|s| s.len()).max().unwrap_or(2);
            m + (m & 1)
        };
        let (data, parity) = (self.data as u8, self.parity as u8);
        let last = data_shards.len() - 1;
        Self::frame_into(
            wire.vec(),
            group,
            last,
            data,
            parity,
            shard_bytes,
            &data_shards[last],
        );
        RAW.fec_tx_data.fetch_add(1, Relaxed);
        self.inner.send(&wire).await?;
        for s in &mut data_shards {
            s.resize(shard_bytes, 0);
        }
        match reed_solomon_simd::encode(self.data, self.parity, &data_shards) {
            Ok(recovery) => {
                for (i, r) in recovery.iter().enumerate() {
                    Self::frame_into(
                        wire.vec(),
                        group,
                        self.data + i,
                        data,
                        parity,
                        shard_bytes,
                        r,
                    );
                    RAW.fec_tx_parity.fetch_add(1, Relaxed);
                    let _ = self.inner.send(&wire).await;
                }
            }
            Err(_) => {
                RAW.fec_encode_err.fetch_add(1, Relaxed);
            }
        }
        Ok(())
    }

    async fn recv(&self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut buf = RX_POOL.rx();
        loop {
            {
                let mut rx = self.rx.lock().await;
                if let Some(pkt) = rx.queue.pop_front() {
                    let m = pkt.len().min(out.len());
                    out[..m].copy_from_slice(&pkt[..m]);
                    return Ok(m);
                }
            }
            let n = self.inner.recv(&mut buf).await?;
            if n < FEC_HDR {
                continue;
            }
            let w = &buf[..n];
            let group = u32::from_be_bytes([w[0], w[1], w[2], w[3]]);
            let idx = u16::from_be_bytes([w[4], w[5]]) as usize;
            let data = w[6];
            let parity = w[7];
            let shard_bytes = u16::from_be_bytes([w[8], w[9]]) as usize;
            let body = w[FEC_HDR..].to_vec();

            let mut rx = self.rx.lock().await;
            let mut deliver: Vec<Vec<u8>> = Vec::new();
            if !rx.groups.contains_key(&group) {
                FEC_GROUP_HINT.store(data as u64, Relaxed);
                rx.order.push_back(group);
                rx.groups.insert(
                    group,
                    GroupRx {
                        data,
                        parity,
                        shard_bytes: 0,
                        originals: HashMap::new(),
                        recovery: HashMap::new(),
                        delivered: 0,
                        recovered: false,
                    },
                );
            }
            {
                let g = rx.groups.get_mut(&group).unwrap();
                if shard_bytes > g.shard_bytes {
                    g.shard_bytes = shard_bytes;
                }
                if idx < data as usize {
                    RAW.fec_rx_data.fetch_add(1, Relaxed);
                    if g.delivered & (1 << idx) == 0 && body.len() >= 2 {
                        let len = u16::from_be_bytes([body[0], body[1]]) as usize;
                        if 2 + len <= body.len() {
                            deliver.push(body[2..2 + len].to_vec());
                        }
                        g.delivered |= 1 << idx;
                    }
                    g.originals.insert(idx, body);
                } else {
                    RAW.fec_rx_parity.fetch_add(1, Relaxed);
                    g.recovery.insert(idx - data as usize, body);
                }
                recover_into(g, &mut deliver);
            }
            while rx.order.len() > 64 {
                let Some(old) = rx.order.pop_front() else {
                    break;
                };
                if let Some(g) = rx.groups.remove(&old) {
                    let data = g.data as u64;
                    let missing = data.saturating_sub(g.originals.len() as u64);
                    let delivered = g.delivered.count_ones() as u64;
                    RAW.fec_groups.fetch_add(1, Relaxed);
                    RAW.fec_missing.fetch_add(missing, Relaxed);
                    if missing > 0 {
                        RAW.fec_groups_lossy.fetch_add(1, Relaxed);
                    }
                    RAW.fec_recovered
                        .fetch_add(delivered.saturating_sub(data - missing), Relaxed);
                    RAW.fec_lost
                        .fetch_add(data.saturating_sub(delivered), Relaxed);
                }
            }
            rx.queue.extend(deliver);
            if let Some(pkt) = rx.queue.pop_front() {
                let m = pkt.len().min(out.len());
                out[..m].copy_from_slice(&pkt[..m]);
                return Ok(m);
            }
        }
    }

    fn kernel_drops(&self) -> u64 {
        self.inner.kernel_drops()
    }
}

fn recover_into(g: &mut GroupRx, deliver: &mut Vec<Vec<u8>>) {
    if g.recovered || g.shard_bytes == 0 {
        return;
    }
    let data = g.data as usize;
    let parity = g.parity as usize;
    if g.originals.len() + g.recovery.len() < data || g.originals.len() == data {
        return;
    }
    let orig: Vec<(usize, Vec<u8>)> = g
        .originals
        .iter()
        .map(|(i, s)| {
            let mut p = s.clone();
            p.resize(g.shard_bytes, 0);
            (*i, p)
        })
        .collect();
    let rec: Vec<(usize, Vec<u8>)> = g.recovery.iter().map(|(i, s)| (*i, s.clone())).collect();
    let restored = reed_solomon_simd::decode(
        data,
        parity,
        orig.iter().map(|(i, s)| (*i, s.as_slice())),
        rec.iter().map(|(i, s)| (*i, s.as_slice())),
    );
    if restored.is_err() {
        RAW.fec_decode_err.fetch_add(1, Relaxed);
    }
    if let Ok(map) = restored {
        for (i, shard) in map {
            if i < data && g.delivered & (1u32 << i) == 0 && shard.len() >= 2 {
                let len = u16::from_be_bytes([shard[0], shard[1]]) as usize;
                if 2 + len <= shard.len() {
                    deliver.push(shard[2..2 + len].to_vec());
                    g.delivered |= 1u32 << i;
                }
            }
        }
        g.recovered = true;
    }
}

#[cfg(test)]
#[path = "../tests/unit/raw_aead.rs"]
mod aead_tests;

#[cfg(test)]
#[path = "../tests/unit/raw_frames.rs"]
mod frame_tests;
