use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use tokio::io;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::carrier::{into_bytes_mut, BoxRx, BoxTx};
use crate::craft::{ethernet_payload, local_src_ip, tcp_payload, Link, Rx, Segment, Tx};

const NEEDS_ROOT: &str =
    "faketcp on macOS opens /dev/bpf and a raw socket, so run rakhsh with sudo";
const PFCTL: &str = "/sbin/pfctl";
const ORDER_UNKNOWN: u8 = 0;
const ORDER_HOST: u8 = 1;
const ORDER_WIRE: u8 = 2;

#[repr(C)]
struct BpfProgram {
    len: u32,
    insns: *mut c_void,
}

#[repr(C)]
struct PktHdr {
    ts: libc::timeval,
    caplen: u32,
    len: u32,
}

#[link(name = "pcap")]
extern "C" {
    fn pcap_create(source: *const c_char, errbuf: *mut c_char) -> *mut c_void;
    fn pcap_set_snaplen(p: *mut c_void, snaplen: c_int) -> c_int;
    fn pcap_set_promisc(p: *mut c_void, promisc: c_int) -> c_int;
    fn pcap_set_timeout(p: *mut c_void, ms: c_int) -> c_int;
    fn pcap_set_immediate_mode(p: *mut c_void, on: c_int) -> c_int;
    fn pcap_activate(p: *mut c_void) -> c_int;
    fn pcap_datalink(p: *mut c_void) -> c_int;
    fn pcap_compile(
        p: *mut c_void,
        prog: *mut BpfProgram,
        expr: *const c_char,
        optimize: c_int,
        netmask: u32,
    ) -> c_int;
    fn pcap_setfilter(p: *mut c_void, prog: *mut BpfProgram) -> c_int;
    fn pcap_freecode(prog: *mut BpfProgram);
    fn pcap_next_ex(p: *mut c_void, hdr: *mut *mut PktHdr, data: *mut *const u8) -> c_int;
    fn pcap_geterr(p: *mut c_void) -> *const c_char;
    fn pcap_close(p: *mut c_void);
}

pub fn connect_faketcp(
    params: &crate::raw::RawParams,
    peer: Option<Ipv4Addr>,
    initiator: bool,
    lane: u64,
) -> Result<(BoxTx, BoxRx)> {
    let peer = peer.context(
        "faketcp on macOS must dial a known peer; set it on the side that has the server address",
    )?;
    let (a, b) = params.lane_ports(lane);
    let (sport, dport) = if initiator { (a, b) } else { (b, a) };
    let seg = Segment::new(local_src_ip(peer)?, peer, sport, dport);
    let ifname = interface_of(seg.src)?;
    let cap = Capture::open(&ifname, &seg)?;
    let out = RawSocket::open()?;
    let rule = PfRule::add(&seg);
    let (chan_tx, chan_rx) = mpsc::channel::<BytesMut>(1024);
    std::thread::spawn(move || cap.run(sport, dport, chan_tx));
    info!("faketcp: sending through a raw socket and capturing on {ifname}");
    let link = MacLink {
        out,
        peer,
        _rule: rule,
    };
    Ok((
        Box::new(Tx::new(Box::new(link), seg)),
        Box::new(Rx::new(chan_rx)),
    ))
}

fn text(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn interface_of(src: Ipv4Addr) -> Result<String> {
    let mut list: *mut libc::ifaddrs = null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        bail!(
            "listing the network interfaces failed: {}",
            io::Error::last_os_error()
        );
    }
    let mut found = None;
    let mut p = list;
    while !p.is_null() {
        let ifa = unsafe { &*p };
        if !ifa.ifa_addr.is_null()
            && c_int::from(unsafe { (*ifa.ifa_addr).sa_family }) == libc::AF_INET
        {
            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            if Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)) == src {
                found = Some(text(ifa.ifa_name));
                break;
            }
        }
        p = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(list) };
    found.with_context(|| format!("no network interface holds {src}, the address toward the peer"))
}

fn link_payload(link: c_int, frame: &[u8]) -> Option<&[u8]> {
    match link {
        1 => ethernet_payload(frame),
        0 => frame.get(4..),
        12 => Some(frame),
        _ => None,
    }
}

struct Capture {
    p: *mut c_void,
    link: c_int,
}

unsafe impl Send for Capture {}

impl Capture {
    fn open(ifname: &str, seg: &Segment) -> Result<Capture> {
        let dev = CString::new(ifname)?;
        let mut err = [0 as c_char; 256];
        let p = unsafe { pcap_create(dev.as_ptr(), err.as_mut_ptr()) };
        if p.is_null() {
            bail!("libpcap could not open {ifname}: {}", text(err.as_ptr()));
        }
        let mut cap = Capture { p, link: 0 };
        unsafe {
            pcap_set_snaplen(p, 65535);
            pcap_set_promisc(p, 0);
            pcap_set_timeout(p, 200);
            pcap_set_immediate_mode(p, 1);
            if pcap_activate(p) < 0 {
                bail!(
                    "libpcap could not start on {ifname}: {}; {NEEDS_ROOT}",
                    text(pcap_geterr(p))
                );
            }
        }
        let filter = CString::new(format!(
            "ip and tcp and src host {} and dst host {} and src port {} and dst port {}",
            seg.peer, seg.src, seg.dport, seg.sport
        ))?;
        let mut prog = BpfProgram {
            len: 0,
            insns: null_mut(),
        };
        unsafe {
            if pcap_compile(p, &mut prog, filter.as_ptr(), 1, u32::MAX) != 0 {
                bail!(
                    "libpcap rejected the capture filter: {}",
                    text(pcap_geterr(p))
                );
            }
            let set = pcap_setfilter(p, &mut prog);
            pcap_freecode(&mut prog);
            if set != 0 {
                bail!(
                    "libpcap could not apply the capture filter: {}",
                    text(pcap_geterr(p))
                );
            }
        }
        cap.link = unsafe { pcap_datalink(p) };
        if ![0, 1, 12].contains(&cap.link) {
            bail!(
                "faketcp cannot read {ifname}: unknown link type {}",
                cap.link
            );
        }
        Ok(cap)
    }

    fn run(self, sport: u16, dport: u16, chan: mpsc::Sender<BytesMut>) {
        while !chan.is_closed() {
            let mut hdr: *mut PktHdr = null_mut();
            let mut data: *const u8 = null();
            let rc = unsafe { pcap_next_ex(self.p, &mut hdr, &mut data) };
            if rc == 0 {
                continue;
            }
            if rc < 0 || hdr.is_null() || data.is_null() {
                break;
            }
            let frame = unsafe { std::slice::from_raw_parts(data, (*hdr).caplen as usize) };
            if let Some(payload) =
                link_payload(self.link, frame).and_then(|ip| tcp_payload(ip, sport, dport))
            {
                if chan
                    .blocking_send(into_bytes_mut(payload.to_vec()))
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        unsafe { pcap_close(self.p) };
    }
}

struct RawSocket {
    fd: c_int,
    order: AtomicU8,
}

impl RawSocket {
    fn open() -> Result<RawSocket> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            bail!(
                "opening a raw socket failed: {}; {NEEDS_ROOT}",
                io::Error::last_os_error()
            );
        }
        let on: c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                (&on as *const c_int).cast(),
                std::mem::size_of::<c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            bail!("setting IP_HDRINCL on the raw socket failed: {e}");
        }
        Ok(RawSocket {
            fd,
            order: AtomicU8::new(ORDER_UNKNOWN),
        })
    }

    fn send_as(&self, packet: &[u8], peer: Ipv4Addr, host_order: bool) -> io::Result<()> {
        let mut p = packet.to_vec();
        if host_order {
            for at in [2, 6] {
                let v = u16::from_be_bytes([p[at], p[at + 1]]);
                p[at..at + 2].copy_from_slice(&v.to_ne_bytes());
            }
        }
        let addr = libc::sockaddr_in {
            sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(peer.octets()),
            },
            sin_zero: [0; 8],
        };
        let n = unsafe {
            libc::sendto(
                self.fd,
                p.as_ptr().cast(),
                p.len(),
                0,
                (&addr as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn send(&self, packet: &[u8], peer: Ipv4Addr) -> io::Result<()> {
        match self.order.load(Ordering::Relaxed) {
            ORDER_HOST => self.send_as(packet, peer, true),
            ORDER_WIRE => self.send_as(packet, peer, false),
            _ => match self.send_as(packet, peer, true) {
                Ok(()) => {
                    self.order.store(ORDER_HOST, Ordering::Relaxed);
                    Ok(())
                }
                Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                    self.send_as(packet, peer, false)?;
                    self.order.store(ORDER_WIRE, Ordering::Relaxed);
                    Ok(())
                }
                Err(e) => Err(e),
            },
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

struct MacLink {
    out: RawSocket,
    peer: Ipv4Addr,
    _rule: Option<PfRule>,
}

impl Link for MacLink {
    fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.out.send(packet, self.peer)
    }
}

struct PfRule {
    anchor: String,
    token: Option<String>,
}

impl PfRule {
    fn add(seg: &Segment) -> Option<PfRule> {
        let anchor = format!("com.apple/rakhsh-faketcp-{}", seg.sport);
        let rule = format!(
            "block drop in quick proto tcp from {} port {} to {} port {}\n",
            seg.peer, seg.dport, seg.src, seg.sport
        );
        let token = pf_enable();
        if pfctl(&["-a", &anchor, "-f", "-"], Some(&rule)) {
            return Some(PfRule { anchor, token });
        }
        if let Some(t) = &token {
            pfctl(&["-X", t], None);
        }
        warn!(
            "faketcp: could not add the pf rule for port {}, so macOS may answer the peer with \
             resets; run rakhsh with sudo",
            seg.sport
        );
        None
    }
}

impl Drop for PfRule {
    fn drop(&mut self) {
        pfctl(&["-a", &self.anchor, "-F", "rules"], None);
        if let Some(t) = &self.token {
            pfctl(&["-X", t], None);
        }
    }
}

fn pf_enable() -> Option<String> {
    let out = Command::new(PFCTL)
        .arg("-E")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    said.lines()
        .find_map(|l| l.trim().strip_prefix("Token : "))
        .map(|t| t.trim().to_string())
}

fn pfctl(args: &[&str], input: Option<&str>) -> bool {
    let mut cmd = Command::new(PFCTL);
    cmd.args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        if stdin.write_all(text.as_bytes()).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

#[cfg(test)]
#[path = "../tests/unit/mac_frames.rs"]
mod tests;
