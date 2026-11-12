use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io;
use tokio::sync::mpsc;

use crate::carrier::{FrameRx, FrameTx};

pub(crate) const IP_HDR: usize = 20;
pub(crate) const TCP_HDR: usize = 20;
pub(crate) const ETH_HDR: usize = 14;

pub(crate) fn local_src_ip(peer: Ipv4Addr) -> Result<Ipv4Addr> {
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

pub(crate) struct Segment {
    pub(crate) src: Ipv4Addr,
    pub(crate) peer: Ipv4Addr,
    pub(crate) sport: u16,
    pub(crate) dport: u16,
    seq: AtomicU32,
}

impl Segment {
    pub(crate) fn new(src: Ipv4Addr, peer: Ipv4Addr, sport: u16, dport: u16) -> Segment {
        Segment {
            src,
            peer,
            sport,
            dport,
            seq: AtomicU32::new(1),
        }
    }

    pub(crate) fn frame(&self, payload: &[u8]) -> Vec<u8> {
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

pub(crate) fn checksum(data: &[u8], init: u32) -> u16 {
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

pub(crate) fn pseudo_sum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, seg_len: usize) -> u32 {
    let (s, d) = (src.octets(), dst.octets());
    u16::from_be_bytes([s[0], s[1]]) as u32
        + u16::from_be_bytes([s[2], s[3]]) as u32
        + u16::from_be_bytes([d[0], d[1]]) as u32
        + u16::from_be_bytes([d[2], d[3]]) as u32
        + proto as u32
        + seg_len as u32
}

pub(crate) fn tcp_payload(pkt: &[u8], our_sport: u16, our_dport: u16) -> Option<&[u8]> {
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

pub(crate) fn ethernet_payload(frame: &[u8]) -> Option<&[u8]> {
    match frame.get(12..14)? {
        [0x08, 0x00] => frame.get(ETH_HDR..),
        [0x81, 0x00] if frame.get(16..18)? == [0x08, 0x00] => frame.get(ETH_HDR + 4..),
        _ => None,
    }
}

pub(crate) trait Link: Send {
    fn send(&self, packet: &[u8]) -> io::Result<()>;
}

pub(crate) struct Tx {
    link: Box<dyn Link>,
    seg: Segment,
}

impl Tx {
    pub(crate) fn new(link: Box<dyn Link>, seg: Segment) -> Tx {
        Tx { link, seg }
    }
}

#[async_trait]
impl FrameTx for Tx {
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        let packet = self.seg.frame(&frame);
        self.link.send(&packet)
    }
}

pub(crate) struct Rx {
    chan: mpsc::Receiver<BytesMut>,
}

impl Rx {
    pub(crate) fn new(chan: mpsc::Receiver<BytesMut>) -> Rx {
        Rx { chan }
    }
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

#[cfg(test)]
#[path = "../tests/unit/craft_frames.rs"]
mod tests;
