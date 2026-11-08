use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io;
use tokio::sync::mpsc;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::prelude::WinDivertFlags;
use windivert::WinDivert;

use crate::carrier::{into_bytes_mut, BoxRx, BoxTx, FrameRx, FrameTx};

const IP_HDR: usize = 20;
const TCP_HDR: usize = 20;

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
    let src_ip = local_src_ip(peer)?;
    let ifidx = best_interface(peer)?;

    let recv_filter = format!("inbound and tcp.SrcPort == {dport} and tcp.DstPort == {sport}");
    let recv = WinDivert::<NetworkLayer>::network(&recv_filter, 0, WinDivertFlags::new())
        .context("opening the WinDivert capture handle (run as Administrator)")?;
    let send =
        WinDivert::<NetworkLayer>::network("false", 0, WinDivertFlags::new().set_send_only())
            .context("opening the WinDivert inject handle (run as Administrator)")?;

    let (chan_tx, chan_rx) = mpsc::channel::<BytesMut>(1024);
    std::thread::spawn(move || reader(recv, sport, dport, chan_tx));

    let tx = Tx {
        handle: send,
        src_ip,
        peer,
        sport,
        dport,
        ifidx,
        seq: AtomicU32::new(1),
    };
    let rx = Rx { chan: chan_rx };
    Ok((Box::new(tx), Box::new(rx)))
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
    use windows::Win32::NetworkManagement::IpHelper::GetBestInterface;
    let dest = u32::from_ne_bytes(peer.octets());
    let mut idx: u32 = 0;
    let rc = unsafe { GetBestInterface(dest, &mut idx) };
    if rc != 0 {
        bail!("no route to {peer} for faketcp (GetBestInterface error {rc})");
    }
    Ok(idx)
}

struct Tx {
    handle: WinDivert<NetworkLayer>,
    src_ip: Ipv4Addr,
    peer: Ipv4Addr,
    sport: u16,
    dport: u16,
    ifidx: u32,
    seq: AtomicU32,
}

impl Tx {
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
        p.extend_from_slice(&self.src_ip.octets());
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
        let tcpc = checksum(&p[IP_HDR..], pseudo_sum(self.src_ip, self.peer, 6, tcp_len));
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

#[async_trait]
impl FrameTx for Tx {
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        let bytes = self.frame(&frame);
        let mut packet = unsafe { WinDivertPacket::<NetworkLayer>::new(bytes) };
        packet.address.set_outbound(true);
        packet.address.set_interface_index(self.ifidx);
        self.handle
            .send(&packet)
            .map(|_| ())
            .map_err(|e| io::Error::other(format!("windivert inject: {e}")))
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
            .ok_or_else(|| io::Error::other("windivert capture thread stopped"))
    }
}

fn reader(handle: WinDivert<NetworkLayer>, sport: u16, dport: u16, chan: mpsc::Sender<BytesMut>) {
    let mut buf = vec![0u8; 65535];
    loop {
        let packet = match handle.recv(Some(&mut buf)) {
            Ok(p) => p,
            Err(_) => break,
        };
        if let Some(payload) = parse(&packet.data, sport, dport) {
            if chan
                .blocking_send(into_bytes_mut(payload.to_vec()))
                .is_err()
            {
                break;
            }
        }
    }
}

fn parse(pkt: &[u8], our_sport: u16, our_dport: u16) -> Option<&[u8]> {
    if pkt.len() < IP_HDR {
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
