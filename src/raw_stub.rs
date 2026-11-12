use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{bail, Result};

use crate::carrier::{BoxRx, BoxTx};

pub const RAW_LANES: u64 = 1;

#[cfg(target_os = "windows")]
const UNSUPPORTED: &str =
    "on Windows the only raw-packet carrier is faketcp, through Npcap or WinDivert; l2tcp, icmp \
     and spoof need Linux, so use faketcp or a stream carrier such as quic, wss or tls";

#[cfg(target_os = "macos")]
const UNSUPPORTED: &str =
    "on macOS the only raw-packet carrier is faketcp, run with sudo; l2tcp, icmp and spoof need \
     Linux, so use faketcp or a stream carrier such as quic, wss or tls";

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
const UNSUPPORTED: &str =
    "raw-packet carriers (faketcp, l2tcp, icmp, spoof) need Linux; on this platform use a \
     stream carrier such as quic, wss or tls";

#[derive(Clone, Copy)]
#[cfg_attr(not(any(target_os = "windows", target_os = "macos")), allow(dead_code))]
pub struct RawParams {
    key: [u8; 32],
}

impl RawParams {
    pub fn derive(token: &str) -> RawParams {
        RawParams {
            key: blake3::derive_key("rakhsh-raw-v1", token.as_bytes()),
        }
    }

    #[cfg_attr(not(any(target_os = "windows", target_os = "macos")), allow(dead_code))]
    pub(crate) fn lane_ports(&self, lane: u64) -> (u16, u16) {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(&lane.to_be_bytes());
        let k = *h.finalize().as_bytes();
        let port_a = 20000 + (u16::from_be_bytes([k[6], k[7]]) % 20000);
        let mut port_b = 20000 + (u16::from_be_bytes([k[8], k[9]]) % 20000);
        if port_b == port_a {
            port_b = port_a.wrapping_add(1);
        }
        (port_a, port_b)
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct SpoofOpts {
    pub pool: Vec<Ipv4Addr>,
    pub sockbuf: Option<usize>,
    pub ttl_jitter: bool,
    pub dscp_jitter: bool,
    pub rotate_secs: u64,
    pub peer_src: Vec<String>,
    pub link_encrypt: bool,
}

#[allow(dead_code)]
pub struct Dial<'a> {
    pub kind: &'a str,
    pub params: &'a RawParams,
    pub spoof: &'a SpoofOpts,
    pub fec: Option<(usize, usize)>,
    pub reliability: &'a str,
    pub header: crate::carrier::TcpHeader,
    pub tuning: crate::carrier::RawTuning,
}

pub async fn connect(
    d: Dial<'_>,
    initiator: bool,
    peer: Option<Ipv4Addr>,
    lane: u64,
) -> Result<(BoxTx, BoxRx)> {
    #[cfg(target_os = "windows")]
    if d.kind == "faketcp" {
        return crate::win_raw::connect_faketcp(d.params, peer, initiator, lane);
    }
    #[cfg(target_os = "macos")]
    if d.kind == "faketcp" {
        return crate::mac_raw::connect_faketcp(d.params, peer, initiator, lane);
    }
    let _ = (&d, initiator, peer, lane);
    bail!(UNSUPPORTED)
}

pub fn cleanup() {}

pub fn lane_ports(token: &str) -> (u16, u16) {
    let key = blake3::derive_key("rakhsh-raw-v1", token.as_bytes());
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(&0u64.to_be_bytes());
    let k = *h.finalize().as_bytes();
    let port_a = 20000 + (u16::from_be_bytes([k[6], k[7]]) % 20000);
    let mut port_b = 20000 + (u16::from_be_bytes([k[8], k[9]]) % 20000);
    if port_b == port_a {
        port_b = port_a.wrapping_add(1);
    }
    (port_a, port_b)
}

pub fn parse_candidates(_spec: &str) -> Result<Vec<Ipv4Addr>> {
    bail!(UNSUPPORTED)
}

pub fn spoof_test_send(
    _to: Ipv4Addr,
    _port: u16,
    _candidates: &[Ipv4Addr],
    _probes: u16,
    _token: &str,
    _iface: Option<&str>,
) -> Result<()> {
    bail!(UNSUPPORTED)
}

pub fn spoof_test_recv(
    _port: u16,
    _seconds: u64,
    _probes: u16,
    _threshold_loss: f64,
    _token: &str,
    _out: Option<&Path>,
) -> Result<()> {
    bail!(UNSUPPORTED)
}
