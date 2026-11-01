use anyhow::{anyhow, Context, Result};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::info;

use crate::config::Config;
use crate::wire;

pub struct L3 {
    dev: Arc<tun_rs::AsyncDevice>,
    out: Arc<Mutex<Vec<mpsc::Sender<Vec<u8>>>>>,
    rr: AtomicUsize,
    mss: Option<u16>,
    gre: bool,
    paths: Option<usize>,
}

impl L3 {
    pub fn add_lane(&self, tx: mpsc::Sender<Vec<u8>>) {
        self.out.lock().unwrap().push(tx);
    }

    pub async fn write_pkt(&self, pkt: &[u8]) {
        let inner = if self.gre { gre_unwrap(pkt) } else { Some(pkt) };
        let Some(inner) = inner else { return };
        let mut buf = inner.to_vec();
        if let Some(mss) = self.mss {
            clamp_mss(&mut buf, mss);
        }
        let _ = self.dev.send(&buf).await;
    }

    fn pick(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        let mut v = self.out.lock().unwrap();
        v.retain(|t| !t.is_closed());
        if v.is_empty() {
            return None;
        }
        let span = self.paths.map(|p| p.min(v.len())).unwrap_or(v.len()).max(1);
        let i = self.rr.fetch_add(1, SeqCst) % span;
        Some(v[i].clone())
    }
}

pub fn setup(cfg: &Config) -> Result<Option<Arc<L3>>> {
    let Some(addr_cidr) = cfg.l3_addr.as_deref() else {
        return Ok(None);
    };
    let addrs = parse_addrs(addr_cidr)?;
    let gre = cfg.l3_gre.unwrap_or(false);
    let mtu = if cfg.l3_auto_mtu.unwrap_or(false) {
        let kinds = std::iter::once(cfg.carrier.as_deref().unwrap_or("tcp"))
            .chain(cfg.link.iter().map(|l| l.carrier.as_str()));
        kinds.map(|k| auto_mtu(k, gre)).min().unwrap_or(1380)
    } else {
        cfg.l3_mtu.unwrap_or(1380)
    };

    let mut b = tun_rs::DeviceBuilder::new().mtu(mtu);
    for (ip, prefix) in &addrs {
        match ip {
            IpAddr::V4(v4) => b = b.ipv4(*v4, *prefix, None),
            IpAddr::V6(v6) => b = b.ipv6(*v6, *prefix),
        }
    }
    let dev = b.build_async().context("creating TUN device")?;
    let dev = Arc::new(dev);

    if let Ok(name) = dev.name() {
        if let Some(q) = cfg.l3_txqueuelen {
            run(&["ip", "link", "set", &name, "txqueuelen", &q.to_string()]);
        }
        if let Some(qd) = cfg.l3_qdisc.as_deref() {
            run(&["tc", "qdisc", "replace", "dev", &name, "root", qd]);
        }
    }

    let l3 = Arc::new(L3 {
        dev: dev.clone(),
        out: Arc::new(Mutex::new(Vec::new())),
        rr: AtomicUsize::new(0),
        mss: cfg.mss_clamp,
        gre,
        paths: cfg.l3_paths,
    });
    let addr_list: Vec<String> = addrs.iter().map(|(ip, p)| format!("{ip}/{p}")).collect();
    info!(
        "layer-3 up: TUN {} mtu {mtu}{}{}",
        addr_list.join(","),
        if gre { " gre" } else { "" },
        cfg.mss_clamp
            .map(|m| format!(" mss-clamp {m}"))
            .unwrap_or_default(),
    );

    let reader = l3.clone();
    let (mss, gre, gre_key) = (cfg.mss_clamp, gre, cfg.gre_key);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match dev.recv(&mut buf).await {
                Ok(0) | Err(_) => continue,
                Ok(n) => {
                    let mut pkt = buf[..n].to_vec();
                    if let Some(m) = mss {
                        clamp_mss(&mut pkt, m);
                    }
                    let framed = if gre { gre_wrap(&pkt, gre_key) } else { pkt };
                    if let Some(tx) = reader.pick() {
                        let _ = tx.send(wire::l3(&framed)).await;
                    }
                }
            }
        }
    });
    Ok(Some(l3))
}

fn run(args: &[&str]) {
    let _ = std::process::Command::new(args[0])
        .args(&args[1..])
        .status();
}

fn auto_mtu(carrier: &str, gre: bool) -> u16 {
    let base: u16 = match carrier {
        "wss" | "ws" | "tls" => 1340,
        "quic" | "quicv2" | "quic-quinn" => 1300,
        "faketcp" | "l2tcp" | "icmp" | "spoof" | "kcp" => 1360,
        _ => 1380,
    };
    if gre {
        base - 8
    } else {
        base
    }
}

fn parse_addrs(s: &str) -> Result<Vec<(IpAddr, u8)>> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (ip, pfx) = part.split_once('/').unwrap_or((part, ""));
        let addr: IpAddr = ip.parse().with_context(|| format!("bad l3 address {ip}"))?;
        let default_pfx = if addr.is_ipv6() { 64 } else { 24 };
        let prefix: u8 = if pfx.is_empty() {
            default_pfx
        } else {
            pfx.parse().map_err(|_| anyhow!("bad l3 prefix {pfx}"))?
        };
        out.push((addr, prefix));
    }
    if out.is_empty() {
        return Err(anyhow!("no l3 address in {s}"));
    }
    Ok(out)
}

fn inner_is_v6(pkt: &[u8]) -> bool {
    pkt.first().map(|b| b >> 4 == 6).unwrap_or(false)
}

fn gre_wrap(pkt: &[u8], key: Option<u32>) -> Vec<u8> {
    let proto: u16 = if inner_is_v6(pkt) { 0x86DD } else { 0x0800 };
    let flags: u16 = if key.is_some() { 0x2000 } else { 0 };
    let mut out = Vec::with_capacity(pkt.len() + 8);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&proto.to_be_bytes());
    if let Some(k) = key {
        out.extend_from_slice(&k.to_be_bytes());
    }
    out.extend_from_slice(pkt);
    out
}

fn gre_unwrap(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 4 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[0], buf[1]]);
    let mut off = 4;
    if flags & 0x8000 != 0 {
        off += 4;
    }
    if flags & 0x2000 != 0 {
        off += 4;
    }
    if flags & 0x1000 != 0 {
        off += 4;
    }
    buf.get(off..)
}

fn clamp_mss(pkt: &mut [u8], mss: u16) {
    if pkt.is_empty() {
        return;
    }
    let (l4_off, proto) = match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return;
            }
            (((pkt[0] & 0x0f) as usize) * 4, pkt[9])
        }
        6 => {
            if pkt.len() < 40 {
                return;
            }
            (40, pkt[6])
        }
        _ => return,
    };
    if proto != 6 || pkt.len() < l4_off + 20 {
        return;
    }
    let tcp = &mut pkt[l4_off..];
    if tcp[13] & 0x02 == 0 {
        return;
    }
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    if tcp.len() < data_off || data_off < 20 {
        return;
    }
    let mut i = 20;
    while i + 1 < data_off {
        match tcp[i] {
            0 => break,
            1 => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let len = tcp[i + 1] as usize;
        if len < 2 || i + len > data_off {
            break;
        }
        if tcp[i] == 2 && len == 4 {
            let cur = u16::from_be_bytes([tcp[i + 2], tcp[i + 3]]);
            if cur > mss {
                tcp[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
                let old_ck = u16::from_be_bytes([tcp[16], tcp[17]]);
                let new_ck = fix16(old_ck, cur, mss);
                tcp[16..18].copy_from_slice(&new_ck.to_be_bytes());
            }
            return;
        }
        i += len;
    }
}

fn fix16(hc: u16, old: u16, new: u16) -> u16 {
    let mut sum: u32 = (!hc) as u32 + (!old) as u32 + new as u32;
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
