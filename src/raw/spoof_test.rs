use super::checksum;
use anyhow::{anyhow, bail, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

const MAGIC: &[u8; 6] = b"RKSPT1";
const MAX_CANDIDATES: usize = 65_536;

fn tag(token: &str, claimed: Ipv4Addr, seq: u16) -> [u8; 8] {
    let key = blake3::derive_key("rakhsh spoof-test v1", token.as_bytes());
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(&claimed.octets());
    h.update(&seq.to_be_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize().as_bytes()[..8]);
    out
}

fn payload(token: &str, claimed: Ipv4Addr, seq: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(6 + 8 + 4 + 2);
    p.extend_from_slice(MAGIC);
    p.extend_from_slice(&tag(token, claimed, seq));
    p.extend_from_slice(&claimed.octets());
    p.extend_from_slice(&seq.to_be_bytes());
    p
}

pub fn parse_candidates(spec: &str) -> Result<Vec<Ipv4Addr>> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let push_item = |item: &str, out: &mut Vec<Ipv4Addr>| -> Result<()> {
        let item = item.trim();
        if item.is_empty() || item.starts_with('#') {
            return Ok(());
        }
        if let Some((a, b)) = item.split_once('-') {
            let (a, b): (Ipv4Addr, Ipv4Addr) = (a.trim().parse()?, b.trim().parse()?);
            let (lo, hi) = (u32::from(a), u32::from(b));
            if hi < lo || (hi - lo) as usize >= MAX_CANDIDATES {
                bail!("bad or too-large range {item}");
            }
            out.extend((lo..=hi).map(Ipv4Addr::from));
        } else if let Some((ip, len)) = item.split_once('/') {
            let ip: Ipv4Addr = ip.trim().parse()?;
            let len: u32 = len.trim().parse()?;
            if !(16..=32).contains(&len) {
                bail!("CIDR /{len} not allowed (use /16../32)");
            }
            let base = u32::from(ip) & (u32::MAX << (32 - len));
            let n = 1u32 << (32 - len);
            let (start, end) = if len <= 30 { (1, n - 1) } else { (0, n) };
            out.extend((start..end).map(|i| Ipv4Addr::from(base + i)));
        } else {
            out.push(
                item.parse()
                    .with_context(|| format!("bad address {item:?}"))?,
            );
        }
        Ok(())
    };
    for part in spec.split(',') {
        let part = part.trim();
        if let Some(path) = part.strip_prefix('@') {
            let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
            for line in text.lines() {
                push_item(line, &mut out)?;
            }
        } else {
            push_item(part, &mut out)?;
        }
    }
    out.dedup();
    if out.is_empty() {
        bail!("no candidate addresses given");
    }
    if out.len() > MAX_CANDIDATES {
        bail!("{} candidates exceeds the {MAX_CANDIDATES} cap", out.len());
    }
    Ok(out)
}

fn build_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    data: &[u8],
    id: u16,
) -> Vec<u8> {
    let udp_len = 8 + data.len();
    let total = 20 + udp_len;
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0x4000u16.to_be_bytes());
    p.extend_from_slice(&[64, 17, 0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let ck = checksum(&p, 0);
    p[10..12].copy_from_slice(&ck.to_be_bytes());
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(data);
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
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
    p.extend_from_slice(&udp);
    p
}

pub fn send(
    to: Ipv4Addr,
    port: u16,
    candidates: &[Ipv4Addr],
    probes: u16,
    token: &str,
    iface: Option<&str>,
) -> Result<()> {
    let sock = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(libc::IPPROTO_RAW)),
    )
    .context("opening a raw socket (needs root / CAP_NET_RAW)")?;
    if let Some(dev) = iface {
        sock.bind_device(Some(dev.as_bytes()))
            .with_context(|| format!("binding to interface {dev}"))?;
    }
    let dst = socket2::SockAddr::from(SocketAddrV4::new(to, 0));
    let mut id: u16 = 1;
    println!(
        "sending {probes} probe(s) x {} candidate source(s) to {to}:{port} …",
        candidates.len()
    );
    for ip in candidates {
        for seq in 0..probes {
            let pkt = build_udp(*ip, to, 45001, port, &payload(token, *ip, seq), id);
            id = id.wrapping_add(1);
            if let Err(e) = sock.send_to(&pkt, &dst) {
                eprintln!("  {ip}: send failed: {e}");
                break;
            }
            std::thread::sleep(Duration::from_micros(1500));
        }
    }
    println!("done. Now read the table on the receiver.");
    Ok(())
}

pub fn recv(
    port: u16,
    seconds: u64,
    probes: u16,
    threshold_loss: f64,
    token: &str,
    out: Option<&std::path::Path>,
) -> Result<()> {
    let sock = UdpSocket::bind(("0.0.0.0", port))
        .with_context(|| format!("binding udp/{port} (open it in the firewall)"))?;
    sock.set_read_timeout(Some(Duration::from_millis(400)))?;
    println!("listening on udp/{port} for {seconds}s — start the sender now …");
    let mut seen: HashMap<Ipv4Addr, (std::collections::HashSet<u16>, bool, Option<Ipv4Addr>)> =
        HashMap::new();
    let end = Instant::now() + Duration::from_secs(seconds);
    let mut buf = [0u8; 256];
    while Instant::now() < end {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) => return Err(anyhow!("recv: {e}")),
        };
        if n != 6 + 8 + 4 + 2 || &buf[..6] != MAGIC {
            continue;
        }
        let claimed = Ipv4Addr::new(buf[14], buf[15], buf[16], buf[17]);
        let seq = u16::from_be_bytes([buf[18], buf[19]]);
        if buf[6..14] != tag(token, claimed, seq) {
            continue;
        }
        let observed = match from {
            std::net::SocketAddr::V4(a) => *a.ip(),
            _ => continue,
        };
        let e = seen
            .entry(claimed)
            .or_insert_with(|| (Default::default(), true, None));
        e.0.insert(seq);
        if observed != claimed {
            e.1 = false;
        }
        e.2 = Some(observed);
    }

    let mut rows: Vec<_> = seen.into_iter().collect();
    rows.sort_by_key(|(ip, _)| u32::from(*ip));
    println!(
        "\n{:<18} {:>8} {:>8}  SOURCE SEEN",
        "SPOOF_IP", "ARRIVED", "LOSS%"
    );
    let mut passing: Vec<Ipv4Addr> = Vec::new();
    for (ip, (set, src_ok, observed)) in &rows {
        let got = set.len() as f64;
        let loss = (1.0 - got / probes as f64).max(0.0) * 100.0;
        let ok = *src_ok && loss <= threshold_loss;
        if ok {
            passing.push(*ip);
        }
        println!(
            "{:<18} {:>5}/{:<2} {:>7.0}%  {}",
            ip.to_string(),
            set.len(),
            probes,
            loss,
            if *src_ok {
                "forged source preserved".to_string()
            } else {
                format!("REWRITTEN to {}", observed.unwrap())
            }
        );
    }
    println!(
        "\n{} address(es) passed (source preserved, loss <= {threshold_loss:.0}%).",
        passing.len()
    );
    if rows.is_empty() {
        println!("Nothing arrived. Check the token, the port/firewall — or the provider drops forged sources entirely (no setting fixes that).");
    }
    if let Some(path) = out {
        let body: String = passing.iter().map(|ip| format!("{ip}\n")).collect();
        std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))?;
        println!(
            "wrote {} passing address(es) to {}",
            passing.len(),
            path.display()
        );
    }
    if !passing.is_empty() {
        let list: Vec<String> = passing.iter().take(8).map(|i| format!("\"{i}\"")).collect();
        println!(
            "use as:  spoof_src_pool = \"{}\"{}",
            passing
                .iter()
                .take(8)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(","),
            if passing.len() > 8 {
                "  # …and more in the file"
            } else {
                ""
            }
        );
        let _ = list;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/raw_spoof_test.rs"]
mod tests;
