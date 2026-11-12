use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io;
use tokio::sync::mpsc;
use tracing::{info, warn};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersInfo, GetBestInterface, GetBestRoute, SendARP, IP_ADAPTER_INFO, MIB_IPFORWARDROW,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_FLAGS, LOAD_WITH_ALTERED_SEARCH_PATH,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

use crate::carrier::{into_bytes_mut, BoxRx, BoxTx, FrameRx, FrameTx};

const IP_HDR: usize = 20;
const TCP_HDR: usize = 20;
const ETH_HDR: usize = 14;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const NO_DRIVER: &str = "faketcp on Windows needs a packet driver: install Npcap \
     (https://npcap.com), or put WinDivert.dll and WinDivert64.sys \
     (https://reqrypt.org/windivert.html) next to rakhsh.exe, then run it as Administrator";

pub fn connect_faketcp(
    params: &crate::raw::RawParams,
    peer: Option<Ipv4Addr>,
    initiator: bool,
    lane: u64,
) -> Result<(BoxTx, BoxRx)> {
    let peer = peer.context(
        "faketcp on Windows must dial a known peer; set it on the side that has the server address",
    )?;
    let (a, b) = params.lane_ports(lane);
    let (sport, dport) = if initiator { (a, b) } else { (b, a) };
    let seg = Segment {
        src: local_src_ip(peer)?,
        peer,
        sport,
        dport,
        seq: AtomicU32::new(1),
    };
    let ifidx = best_interface(peer)?;
    let (chan_tx, chan_rx) = mpsc::channel::<BytesMut>(1024);
    let link = open_link(&seg, ifidx, chan_tx)?;
    Ok((Box::new(Tx { link, seg }), Box::new(Rx { chan: chan_rx })))
}

fn open_link(seg: &Segment, ifidx: u32, chan: mpsc::Sender<BytesMut>) -> Result<Box<dyn Link>> {
    let mut divert_err = None;
    if let Some(api) = divert_api() {
        match Divert::open(api, seg, ifidx, chan.clone()) {
            Ok(link) => {
                info!("faketcp: sending and capturing through WinDivert");
                return Ok(Box::new(link));
            }
            Err(e) => divert_err = Some(e),
        }
    }
    if let Some(api) = pcap_api() {
        if let Some(e) = &divert_err {
            warn!("faketcp: {e:#}; trying Npcap instead");
        }
        let link = Npcap::open(api, seg, ifidx, chan)?;
        info!("faketcp: sending and capturing through Npcap");
        return Ok(Box::new(link));
    }
    Err(divert_err.unwrap_or_else(|| anyhow!(NO_DRIVER)))
}

fn local_src_ip(peer: Ipv4Addr) -> Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").context("probing the local source address")?;
    s.connect((peer, 9))
        .context("probing the route to the peer")?;
    match s
        .local_addr()
        .context("reading the local source address")?
        .ip()
    {
        std::net::IpAddr::V4(v4) => Ok(v4),
        std::net::IpAddr::V6(_) => {
            bail!("faketcp rides on IPv4; this host routed the peer over IPv6")
        }
    }
}

fn best_interface(peer: Ipv4Addr) -> Result<u32> {
    let mut idx: u32 = 0;
    let rc = unsafe { GetBestInterface(u32::from_ne_bytes(peer.octets()), &mut idx) };
    if rc != 0 {
        bail!("no route to {peer} for faketcp (GetBestInterface error {rc})");
    }
    Ok(idx)
}

struct Segment {
    src: Ipv4Addr,
    peer: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: AtomicU32,
}

impl Segment {
    fn frame(&self, payload: &[u8]) -> Vec<u8> {
        let seq = self.seq.fetch_add(payload.len().max(1) as u32, SeqCst);
        let total = IP_HDR + TCP_HDR + payload.len();
        let mut p = Vec::with_capacity(total);
        p.push(0x45);
        p.push(0);
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&0x4000u16.to_be_bytes());
        p.push(64);
        p.push(6);
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&self.src.octets());
        p.extend_from_slice(&self.peer.octets());
        p.extend_from_slice(&self.sport.to_be_bytes());
        p.extend_from_slice(&self.dport.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.push(5 << 4);
        p.push(0b0001_1000);
        p.extend_from_slice(&65535u16.to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        let ipc = checksum(&p[..IP_HDR], 0);
        p[10..12].copy_from_slice(&ipc.to_be_bytes());
        let tcp_len = p.len() - IP_HDR;
        let tcpc = checksum(&p[IP_HDR..], pseudo_sum(self.src, self.peer, 6, tcp_len));
        p[IP_HDR + 16..IP_HDR + 18].copy_from_slice(&tcpc.to_be_bytes());
        p
    }
}

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

fn tcp_payload(pkt: &[u8], our_sport: u16, our_dport: u16) -> Option<&[u8]> {
    if pkt.len() < IP_HDR || pkt[0] >> 4 != 4 || pkt[9] != 6 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let tcp = pkt.get(ihl..)?;
    if tcp.len() < TCP_HDR {
        return None;
    }
    let src = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst = u16::from_be_bytes([tcp[2], tcp[3]]);
    if src != our_dport || dst != our_sport {
        return None;
    }
    let doff = ((tcp[12] >> 4) as usize) * 4;
    let payload = tcp.get(doff..)?;
    if payload.is_empty() {
        return None;
    }
    Some(payload)
}

fn ethernet_payload(frame: &[u8]) -> Option<&[u8]> {
    match frame.get(12..14)? {
        [0x08, 0x00] => frame.get(ETH_HDR..),
        [0x81, 0x00] if frame.get(16..18)? == [0x08, 0x00] => frame.get(ETH_HDR + 4..),
        _ => None,
    }
}

trait Link: Send {
    fn send(&self, packet: &[u8]) -> io::Result<()>;
}

struct Tx {
    link: Box<dyn Link>,
    seg: Segment,
}

#[async_trait]
impl FrameTx for Tx {
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        let packet = self.seg.frame(&frame);
        self.link.send(&packet)
    }
}

struct Rx {
    chan: mpsc::Receiver<BytesMut>,
}

#[async_trait]
impl FrameRx for Rx {
    async fn recv(&mut self) -> io::Result<BytesMut> {
        self.chan
            .recv()
            .await
            .ok_or_else(|| io::Error::other("faketcp capture thread stopped"))
    }
}

struct Handle(*mut c_void);

unsafe impl Send for Handle {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn load_library(path: &str, flags: LOAD_LIBRARY_FLAGS) -> Option<*mut c_void> {
    let name = wide(path);
    let lib = unsafe { LoadLibraryExW(name.as_ptr(), null_mut(), flags) };
    (!lib.is_null()).then_some(lib)
}

type RawProc = unsafe extern "system" fn() -> isize;

fn symbol(lib: *mut c_void, name: &CStr) -> Option<RawProc> {
    unsafe { GetProcAddress(lib, name.as_ptr().cast()) }
}

fn text(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

#[repr(C)]
struct DivertAddress {
    timestamp: i64,
    bits: u32,
    reserved: u32,
    data: [u8; 64],
}

type DivertOpen = unsafe extern "C" fn(*const c_char, c_int, i16, u64) -> *mut c_void;
type DivertRecv =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut u32, *mut DivertAddress) -> c_int;
type DivertSend =
    unsafe extern "C" fn(*mut c_void, *const c_void, u32, *mut u32, *const DivertAddress) -> c_int;
type DivertClose = unsafe extern "C" fn(*mut c_void) -> c_int;

#[derive(Clone, Copy)]
struct DivertApi {
    open: DivertOpen,
    recv: DivertRecv,
    send: DivertSend,
    close: DivertClose,
}

fn divert_api() -> Option<DivertApi> {
    static API: OnceLock<Option<DivertApi>> = OnceLock::new();
    *API.get_or_init(|| {
        let lib = load_library("WinDivert.dll", 0)?;
        unsafe {
            Some(DivertApi {
                open: std::mem::transmute::<RawProc, DivertOpen>(symbol(lib, c"WinDivertOpen")?),
                recv: std::mem::transmute::<RawProc, DivertRecv>(symbol(lib, c"WinDivertRecv")?),
                send: std::mem::transmute::<RawProc, DivertSend>(symbol(lib, c"WinDivertSend")?),
                close: std::mem::transmute::<RawProc, DivertClose>(symbol(lib, c"WinDivertClose")?),
            })
        }
    })
}

fn divert_error(what: &str) -> anyhow::Error {
    let code = unsafe { GetLastError() };
    let hint = match code {
        2 => ": WinDivert64.sys must sit next to WinDivert.dll",
        5 => ": run rakhsh as Administrator",
        577 | 1275 => {
            ": Windows refused to load the WinDivert driver, check Defender and Secure Boot"
        }
        654 => ": an older WinDivert driver is still loaded, reboot once",
        _ => "",
    };
    anyhow!("WinDivert could not open its {what} handle (error {code}){hint}")
}

struct Divert {
    api: DivertApi,
    out: Handle,
    ifidx: u32,
}

impl Divert {
    fn open(
        api: DivertApi,
        seg: &Segment,
        ifidx: u32,
        chan: mpsc::Sender<BytesMut>,
    ) -> Result<Divert> {
        let filter = CString::new(format!(
            "inbound and ip.SrcAddr == {} and tcp.SrcPort == {} and tcp.DstPort == {}",
            seg.peer, seg.dport, seg.sport
        ))?;
        let cap = unsafe { (api.open)(filter.as_ptr(), 0, 0, 0) };
        if cap as isize == -1 {
            return Err(divert_error("capture"));
        }
        let out = unsafe { (api.open)(c"false".as_ptr(), 0, 0, 0x8) };
        if out as isize == -1 {
            let err = divert_error("inject");
            unsafe { (api.close)(cap) };
            return Err(err);
        }
        let (sport, dport, cap) = (seg.sport, seg.dport, Handle(cap));
        std::thread::spawn(move || divert_reader(api, cap, sport, dport, chan));
        Ok(Divert {
            api,
            out: Handle(out),
            ifidx,
        })
    }
}

impl Link for Divert {
    fn send(&self, packet: &[u8]) -> io::Result<()> {
        let mut addr = DivertAddress {
            timestamp: 0,
            bits: 1 << 17,
            reserved: 0,
            data: [0; 64],
        };
        addr.data[..4].copy_from_slice(&self.ifidx.to_ne_bytes());
        let ok = unsafe {
            (self.api.send)(
                self.out.0,
                packet.as_ptr().cast(),
                packet.len() as u32,
                null_mut(),
                &addr,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(io::Error::other(format!(
                "WinDivert send failed (error {code})"
            )));
        }
        Ok(())
    }
}

impl Drop for Divert {
    fn drop(&mut self) {
        unsafe { (self.api.close)(self.out.0) };
    }
}

fn divert_reader(
    api: DivertApi,
    cap: Handle,
    sport: u16,
    dport: u16,
    chan: mpsc::Sender<BytesMut>,
) {
    let mut buf = vec![0u8; 65535];
    let mut addr = DivertAddress {
        timestamp: 0,
        bits: 0,
        reserved: 0,
        data: [0; 64],
    };
    loop {
        let mut len = 0u32;
        let ok = unsafe {
            (api.recv)(
                cap.0,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut len,
                &mut addr,
            )
        };
        if ok == 0 {
            break;
        }
        if let Some(payload) = tcp_payload(&buf[..len as usize], sport, dport) {
            if chan
                .blocking_send(into_bytes_mut(payload.to_vec()))
                .is_err()
            {
                break;
            }
        }
    }
    unsafe { (api.close)(cap.0) };
}

#[repr(C)]
struct BpfProgram {
    len: u32,
    insns: *mut c_void,
}

#[repr(C)]
struct PktHdr {
    sec: i32,
    usec: i32,
    caplen: u32,
    len: u32,
}

type PcapCreate = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_void;
type PcapSetInt = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type PcapActivate = unsafe extern "C" fn(*mut c_void) -> c_int;
type PcapCompile =
    unsafe extern "C" fn(*mut c_void, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type PcapSetFilter = unsafe extern "C" fn(*mut c_void, *mut BpfProgram) -> c_int;
type PcapFreeCode = unsafe extern "C" fn(*mut BpfProgram);
type PcapNextEx = unsafe extern "C" fn(*mut c_void, *mut *mut PktHdr, *mut *const u8) -> c_int;
type PcapSendPacket = unsafe extern "C" fn(*mut c_void, *const u8, c_int) -> c_int;
type PcapGetErr = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type PcapClose = unsafe extern "C" fn(*mut c_void);

#[derive(Clone, Copy)]
struct PcapApi {
    create: PcapCreate,
    set_snaplen: PcapSetInt,
    set_promisc: PcapSetInt,
    set_timeout: PcapSetInt,
    set_immediate: PcapSetInt,
    activate: PcapActivate,
    compile: PcapCompile,
    setfilter: PcapSetFilter,
    freecode: PcapFreeCode,
    next_ex: PcapNextEx,
    sendpacket: PcapSendPacket,
    geterr: PcapGetErr,
    close: PcapClose,
}

fn system_dir() -> Option<String> {
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0 && n < buf.len()).then(|| String::from_utf16_lossy(&buf[..n]))
}

fn pcap_api() -> Option<PcapApi> {
    static API: OnceLock<Option<PcapApi>> = OnceLock::new();
    *API.get_or_init(|| {
        let path = format!("{}\\Npcap\\wpcap.dll", system_dir()?);
        let lib = load_library(&path, LOAD_WITH_ALTERED_SEARCH_PATH)?;
        unsafe {
            Some(PcapApi {
                create: std::mem::transmute::<RawProc, PcapCreate>(symbol(lib, c"pcap_create")?),
                set_snaplen: std::mem::transmute::<RawProc, PcapSetInt>(symbol(
                    lib,
                    c"pcap_set_snaplen",
                )?),
                set_promisc: std::mem::transmute::<RawProc, PcapSetInt>(symbol(
                    lib,
                    c"pcap_set_promisc",
                )?),
                set_timeout: std::mem::transmute::<RawProc, PcapSetInt>(symbol(
                    lib,
                    c"pcap_set_timeout",
                )?),
                set_immediate: std::mem::transmute::<RawProc, PcapSetInt>(symbol(
                    lib,
                    c"pcap_set_immediate_mode",
                )?),
                activate: std::mem::transmute::<RawProc, PcapActivate>(symbol(
                    lib,
                    c"pcap_activate",
                )?),
                compile: std::mem::transmute::<RawProc, PcapCompile>(symbol(lib, c"pcap_compile")?),
                setfilter: std::mem::transmute::<RawProc, PcapSetFilter>(symbol(
                    lib,
                    c"pcap_setfilter",
                )?),
                freecode: std::mem::transmute::<RawProc, PcapFreeCode>(symbol(
                    lib,
                    c"pcap_freecode",
                )?),
                next_ex: std::mem::transmute::<RawProc, PcapNextEx>(symbol(lib, c"pcap_next_ex")?),
                sendpacket: std::mem::transmute::<RawProc, PcapSendPacket>(symbol(
                    lib,
                    c"pcap_sendpacket",
                )?),
                geterr: std::mem::transmute::<RawProc, PcapGetErr>(symbol(lib, c"pcap_geterr")?),
                close: std::mem::transmute::<RawProc, PcapClose>(symbol(lib, c"pcap_close")?),
            })
        }
    })
}

fn open_pcap(api: PcapApi, device: &CStr) -> Result<Handle> {
    let mut err = [0 as c_char; 256];
    let p = unsafe { (api.create)(device.as_ptr(), err.as_mut_ptr()) };
    if p.is_null() {
        bail!("Npcap could not open the adapter: {}", text(err.as_ptr()));
    }
    unsafe {
        (api.set_snaplen)(p, 65535);
        (api.set_promisc)(p, 0);
        (api.set_timeout)(p, 200);
        (api.set_immediate)(p, 1);
        if (api.activate)(p) < 0 {
            let msg = text((api.geterr)(p));
            (api.close)(p);
            bail!("Npcap could not start on the adapter: {msg}");
        }
    }
    Ok(Handle(p))
}

struct Adapter {
    name: String,
    mac: [u8; 6],
}

fn adapter(ifidx: u32) -> Result<Adapter> {
    let mut len = 0u32;
    unsafe { GetAdaptersInfo(null_mut(), &mut len) };
    if len == 0 {
        bail!("Windows lists no network adapters");
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    let rc = unsafe { GetAdaptersInfo(buf.as_mut_ptr().cast(), &mut len) };
    if rc != 0 {
        bail!("listing the network adapters failed (error {rc})");
    }
    let mut p = buf.as_ptr() as *const IP_ADAPTER_INFO;
    while !p.is_null() {
        let a = unsafe { &*p };
        if a.Index == ifidx {
            if a.AddressLength != 6 {
                bail!("faketcp over Npcap needs an Ethernet or Wi-Fi adapter toward the peer");
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&a.Address[..6]);
            return Ok(Adapter {
                name: text(a.AdapterName.as_ptr().cast()),
                mac,
            });
        }
        p = a.Next.cast_const();
    }
    bail!("the adapter that routes to the peer (index {ifidx}) is missing from the adapter list")
}

fn next_hop_mac(peer: Ipv4Addr, src: Ipv4Addr) -> Result<[u8; 6]> {
    let mut row: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
    let rc = unsafe { GetBestRoute(u32::from_ne_bytes(peer.octets()), 0, &mut row) };
    if rc != 0 {
        bail!("no route to {peer} for faketcp (GetBestRoute error {rc})");
    }
    let hop = Ipv4Addr::from(row.dwForwardNextHop.to_ne_bytes());
    let target = if hop.is_unspecified() || hop == src {
        peer
    } else {
        hop
    };
    let mut raw = [0u32; 2];
    let mut len = 6u32;
    let rc = unsafe {
        SendARP(
            u32::from_ne_bytes(target.octets()),
            0,
            raw.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 || len < 6 {
        bail!("could not find the MAC address of {target} (SendARP error {rc})");
    }
    let mut mac = [0u8; 6];
    mac[..4].copy_from_slice(&raw[0].to_ne_bytes());
    mac[4..].copy_from_slice(&raw[1].to_ne_bytes()[..2]);
    Ok(mac)
}

struct FirewallRule {
    name: String,
}

impl FirewallRule {
    fn add(port: u16, peer: Ipv4Addr) -> Option<FirewallRule> {
        let name = format!("name=rakhsh-faketcp-{port}");
        netsh(&["delete", "rule", &name]);
        let added = netsh(&[
            "add",
            "rule",
            &name,
            "dir=in",
            "action=block",
            "protocol=TCP",
            &format!("localport={port}"),
            &format!("remoteip={peer}"),
        ]);
        if added {
            Some(FirewallRule { name })
        } else {
            warn!(
                "faketcp: could not add the Windows Firewall rule for port {port}, so Windows may \
                 answer the peer with resets; run rakhsh as Administrator"
            );
            None
        }
    }
}

impl Drop for FirewallRule {
    fn drop(&mut self) {
        netsh(&["delete", "rule", &self.name]);
    }
}

fn netsh(args: &[&str]) -> bool {
    Command::new("netsh")
        .args(["advfirewall", "firewall"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

struct Npcap {
    api: PcapApi,
    out: Handle,
    eth: [u8; ETH_HDR],
    _rule: Option<FirewallRule>,
}

impl Npcap {
    fn open(
        api: PcapApi,
        seg: &Segment,
        ifidx: u32,
        chan: mpsc::Sender<BytesMut>,
    ) -> Result<Npcap> {
        let nic = adapter(ifidx)?;
        let gateway = next_hop_mac(seg.peer, seg.src)?;
        let device = CString::new(format!("\\Device\\NPF_{}", nic.name))?;
        let filter = CString::new(format!(
            "ip and tcp and src host {} and dst host {} and src port {} and dst port {}",
            seg.peer, seg.src, seg.dport, seg.sport
        ))?;
        let cap = open_pcap(api, &device)?;
        let mut prog = BpfProgram {
            len: 0,
            insns: null_mut(),
        };
        unsafe {
            if (api.compile)(cap.0, &mut prog, filter.as_ptr(), 1, u32::MAX) != 0 {
                let msg = text((api.geterr)(cap.0));
                (api.close)(cap.0);
                bail!("Npcap rejected the capture filter: {msg}");
            }
            let set = (api.setfilter)(cap.0, &mut prog);
            (api.freecode)(&mut prog);
            if set != 0 {
                let msg = text((api.geterr)(cap.0));
                (api.close)(cap.0);
                bail!("Npcap could not apply the capture filter: {msg}");
            }
        }
        let out = match open_pcap(api, &device) {
            Ok(h) => h,
            Err(e) => {
                unsafe { (api.close)(cap.0) };
                return Err(e);
            }
        };
        let rule = FirewallRule::add(seg.sport, seg.peer);
        let mut eth = [0u8; ETH_HDR];
        eth[..6].copy_from_slice(&gateway);
        eth[6..12].copy_from_slice(&nic.mac);
        eth[12..].copy_from_slice(&[0x08, 0x00]);
        let (sport, dport) = (seg.sport, seg.dport);
        std::thread::spawn(move || pcap_reader(api, cap, sport, dport, chan));
        Ok(Npcap {
            api,
            out,
            eth,
            _rule: rule,
        })
    }
}

impl Link for Npcap {
    fn send(&self, packet: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(ETH_HDR + packet.len());
        frame.extend_from_slice(&self.eth);
        frame.extend_from_slice(packet);
        let rc = unsafe { (self.api.sendpacket)(self.out.0, frame.as_ptr(), frame.len() as c_int) };
        if rc != 0 {
            let msg = text(unsafe { (self.api.geterr)(self.out.0) });
            return Err(io::Error::other(format!("Npcap send failed: {msg}")));
        }
        Ok(())
    }
}

impl Drop for Npcap {
    fn drop(&mut self) {
        unsafe { (self.api.close)(self.out.0) };
    }
}

fn pcap_reader(api: PcapApi, cap: Handle, sport: u16, dport: u16, chan: mpsc::Sender<BytesMut>) {
    while !chan.is_closed() {
        let mut hdr: *mut PktHdr = null_mut();
        let mut data: *const u8 = null();
        let rc = unsafe { (api.next_ex)(cap.0, &mut hdr, &mut data) };
        if rc == 0 {
            continue;
        }
        if rc < 0 || hdr.is_null() || data.is_null() {
            break;
        }
        let frame = unsafe { std::slice::from_raw_parts(data, (*hdr).caplen as usize) };
        if let Some(payload) = ethernet_payload(frame).and_then(|ip| tcp_payload(ip, sport, dport))
        {
            if chan
                .blocking_send(into_bytes_mut(payload.to_vec()))
                .is_err()
            {
                break;
            }
        }
    }
    unsafe { (api.close)(cap.0) };
}

#[cfg(test)]
#[path = "../tests/unit/win_frames.rs"]
mod tests;
