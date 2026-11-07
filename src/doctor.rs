use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::info;

use crate::carrier::{BoxRx, BoxTx, Carrier};
use crate::config::Config;
use crate::noise::{Enc, Keys};

pub const PORT: u16 = 7900;
pub const CONTROL: &str = "rakhsh-doctor/1";
pub const HEADER: &str = "  carrier       state              goodput  note";

const HANDSHAKE_BUDGET: Duration = Duration::from_secs(6);
const DGRAM_BUDGET: Duration = Duration::from_secs(12);
const DGRAM_BURST: usize = 32;
const DGRAM_IDLE: Duration = Duration::from_secs(1);
const RECORD: usize = 16 * 1024;
const SETTLE: Duration = Duration::from_millis(400);

pub const STREAM_CARRIERS: &[&str] = &["tcp", "tls", "ws", "wss", "quic", "quicv2", "kcp"];
pub const RAW_CARRIERS: &[&str] = &["faketcp", "l2tcp", "icmp"];
pub const DATAGRAM_CARRIERS: &[&str] = &[
    "shabdiz-udp",
    "shabdiz-tcp",
    "shabdiz-gre",
    "shabdiz-esp",
    "shabdiz-l2",
];

pub const PROTOCOLS: &[(u8, &str)] = &[
    (4, "IPv4-in-IPv4"),
    (41, "IPv6-in-IPv4"),
    (47, "GRE"),
    (50, "ESP"),
    (97, "ETHERIP"),
    (115, "L2TP"),
    (137, "MPLS-in-IP"),
];

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub carrier: String,
    pub reached: bool,
    pub handshook: bool,
    pub held: bool,
    pub mbit: f64,
    pub note: String,
}

impl Verdict {
    fn refused(carrier: &str, why: impl std::fmt::Display) -> Verdict {
        Verdict {
            carrier: carrier.to_string(),
            reached: false,
            handshook: false,
            held: false,
            mbit: 0.0,
            note: why.to_string(),
        }
    }

    pub fn usable(&self) -> bool {
        self.handshook && self.held
    }

    pub fn line(&self) -> String {
        let state = if self.usable() {
            "ok"
        } else if self.handshook {
            "cut"
        } else if self.reached {
            "no handshake"
        } else {
            "unreachable"
        };
        let speed = if self.mbit > 0.0 {
            format!("{:>8.1} Mbit/s", self.mbit)
        } else {
            "        —      ".to_string()
        };
        format!(
            "  {:<13} {:<13}{}  {}",
            self.carrier, state, speed, self.note
        )
    }
}

pub const CEILING: Duration = Duration::from_secs(300);

pub struct Plan {
    pub carriers: Vec<String>,
    pub seconds: u64,
    pub protocols: bool,
}

impl Plan {
    pub fn new(only: &[String], seconds: u64, protocols: bool) -> Result<Plan> {
        let carriers: Vec<String> = if only.is_empty() {
            STREAM_CARRIERS.iter().map(|s| s.to_string()).collect()
        } else {
            for name in only {
                if name == "spoof" {
                    bail!(
                        "spoof needs forged source addresses (spoof_src_ip, spoof_peer_src) that \
                         the doctor cannot choose for you; measure it with `rakhsh spoof-test`"
                    );
                }
                if !known(name) {
                    bail!("{name:?} is not a carrier rakhsh has");
                }
            }
            only.to_vec()
        };
        let plan = Plan {
            carriers,
            seconds,
            protocols,
        };
        if plan.budget() > CEILING {
            bail!(
                "that plan would take about {}s; keep a run under {}s by lowering --seconds \
                 or naming fewer carriers",
                plan.budget().as_secs(),
                CEILING.as_secs()
            );
        }
        Ok(plan)
    }

    pub fn budget(&self) -> Duration {
        let per = Duration::from_secs(self.seconds) + HANDSHAKE_BUDGET + SETTLE;
        per * self.carriers.len() as u32
            + if self.protocols {
                Duration::from_secs(self.seconds.min(6)) + SETTLE
            } else {
                Duration::ZERO
            }
    }

    pub fn privileged(&self) -> Vec<&str> {
        self.carriers
            .iter()
            .filter(|c| needs_root(c))
            .map(|c| c.as_str())
            .collect()
    }
}

pub fn known(name: &str) -> bool {
    STREAM_CARRIERS.contains(&name)
        || RAW_CARRIERS.contains(&name)
        || DATAGRAM_CARRIERS.contains(&name)
}

pub fn needs_root(name: &str) -> bool {
    RAW_CARRIERS.contains(&name) || matches!(name, "shabdiz-gre" | "shabdiz-esp" | "shabdiz-l2")
}

pub fn needs_public_address(name: &str) -> bool {
    matches!(name, "shabdiz-gre" | "shabdiz-esp")
}

pub fn private_source(peer: &str) -> Option<Ipv4Addr> {
    let host = peer.rsplit_once(':').map_or(peer, |(h, _)| h);
    let addr: Ipv4Addr = host.parse().ok()?;
    if addr.is_private() || addr.is_loopback() {
        return None;
    }
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect((addr, 9)).ok()?;
    match sock.local_addr().ok()? {
        std::net::SocketAddr::V4(a) if a.ip().is_private() => Some(*a.ip()),
        _ => None,
    }
}

fn probe_config(base: &Config, carrier: &str, port: u16, peer: Option<&str>) -> Config {
    let mut cfg = base.clone();
    cfg.carrier = Some(carrier.to_string());
    cfg.lanes = Some(1);
    cfg.link.clear();
    cfg.backup_connect.clear();
    cfg.forward.clear();
    cfg.inbound.clear();
    cfg.outbound.clear();
    cfg.dns = None;
    cfg.openvpn = None;
    cfg.tunnel_listen = Some(format!("0.0.0.0:{port}"));
    cfg.tunnel_connect = peer.map(|p| p.to_string());
    cfg
}

async fn lane(carrier: &Carrier, addr: &str) -> Result<(BoxTx, BoxRx)> {
    tokio::time::timeout(HANDSHAKE_BUDGET, carrier.dial(addr))
        .await
        .context("the carrier did not answer in time")?
}

async fn push(enc: &Enc, tx: &mut BoxTx, seconds: u64) -> Result<u64> {
    let payload = vec![0u8; RECORD];
    let until = Instant::now() + Duration::from_secs(seconds);
    let mut sent = 0u64;
    while Instant::now() < until {
        let mut rec = payload.clone();
        enc.seal_in_place(&mut rec);
        let n = rec.len() as u64;
        match tx.send(rec).await {
            Ok(()) => sent += n,
            Err(e) => bail!("the lane stopped carrying data after {sent} bytes: {e}"),
        }
    }
    tx.flush().await.ok();
    Ok(sent)
}

async fn drain(enc: &Enc, rx: &mut BoxRx, seconds: u64) -> u64 {
    let until = Instant::now() + Duration::from_secs(seconds) + HANDSHAKE_BUDGET + SETTLE;
    let mut got = 0u64;
    while Instant::now() < until {
        let left = until.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Ok(rec)) => {
                let len = rec.len() as u64;
                if enc.open_bytes(rec).is_ok() {
                    got += len;
                }
            }
            _ => break,
        }
    }
    got
}

async fn measure_dgram(base: &Config, carrier: &str, peer: &str, seconds: u64) -> Verdict {
    let mut cfg = probe_config(base, carrier, 0, Some(peer));
    cfg.peer_ip = peer.rsplit_once(':').map(|(host, _)| host.to_string());
    let handle = match tokio::time::timeout(DGRAM_BUDGET, crate::dgram::open(&cfg, true)).await {
        Ok(Ok((handle, _))) => handle,
        Ok(Err(e)) => return Verdict::refused(carrier, first_line(&format!("{e:#}"))),
        Err(_) => return Verdict::refused(carrier, "the carrier did not answer in time"),
    };
    let payload = vec![0u8; handle.payload_mtu().clamp(64, 1400)];
    let until = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < until && !handle.is_closed() {
        for _ in 0..DGRAM_BURST {
            handle.send(1, &payload);
        }
        tokio::task::yield_now().await;
    }
    Verdict {
        carrier: carrier.to_string(),
        reached: true,
        handshook: true,
        held: true,
        mbit: 0.0,
        note: String::new(),
    }
}

async fn accept_dgram(
    base: &Config,
    carrier: &str,
    port: u16,
    seconds: u64,
    from: IpAddr,
) -> Result<u64> {
    let mut cfg = probe_config(base, carrier, port, None);
    cfg.peer_ip = Some(from.to_string());
    let (handle, _) = tokio::time::timeout(
        DGRAM_BUDGET + Duration::from_secs(seconds),
        crate::dgram::open(&cfg, false),
    )
    .await
    .context("the peer never completed a shabdiz handshake")??;
    let hard = Instant::now() + Duration::from_secs(seconds) + DGRAM_BUDGET;
    let mut got = 0u64;
    let mut batch = Vec::with_capacity(64);
    loop {
        let left = hard.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let wait = if got == 0 { left } else { DGRAM_IDLE.min(left) };
        match tokio::time::timeout(wait, handle.recv_batch(&mut batch, 64)).await {
            Ok(0) | Err(_) => break,
            Ok(_) => got += batch.iter().map(|(_, p)| p.len() as u64).sum::<u64>(),
        }
    }
    Ok(got)
}

pub async fn measure(base: &Config, carrier: &str, peer: &str, seconds: u64) -> Verdict {
    let mut v = measure_inner(base, carrier, peer, seconds).await;
    if !v.usable() && needs_public_address(carrier) {
        if let Some(local) = private_source(peer) {
            v.note = nat_note(local, &v.note);
        }
    }
    v
}

fn nat_note(local: Ipv4Addr, had: &str) -> String {
    let because = if had.is_empty() {
        String::new()
    } else {
        format!(" ({had})")
    };
    format!(
        "this host sends from {local}, a translated address{because}. On a home or mobile \
         connection that is the reason: with no ports to translate, the far end cannot address \
         one host behind a shared one. One address per host, as a cloud instance has, works."
    )
}

async fn measure_inner(base: &Config, carrier: &str, peer: &str, seconds: u64) -> Verdict {
    if crate::dgram::is_datagram(carrier) {
        return measure_dgram(base, carrier, peer, seconds).await;
    }
    let cfg = probe_config(base, carrier, 0, Some(peer));
    let built = match Carrier::from_cfg(&cfg) {
        Ok(c) => c,
        Err(e) => return Verdict::refused(carrier, e),
    };
    let keys = match Keys::from_cfg(&cfg) {
        Ok(k) => k,
        Err(e) => return Verdict::refused(carrier, e),
    };
    let peer_key = match cfg.peer_key() {
        Ok(k) => k,
        Err(e) => return Verdict::refused(carrier, e),
    };

    let (mut tx, mut rx) = match lane(&built, peer).await {
        Ok(v) => v,
        Err(e) => return Verdict::refused(carrier, first_line(&e.to_string())),
    };
    let mut v = Verdict {
        carrier: carrier.to_string(),
        reached: true,
        handshook: false,
        held: false,
        mbit: 0.0,
        note: String::new(),
    };

    let enc = match tokio::time::timeout(
        HANDSHAKE_BUDGET,
        keys.connect_to(&peer_key, &mut *tx, &mut *rx),
    )
    .await
    {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => {
            v.note = first_line(&e.to_string());
            return v;
        }
        Err(_) => {
            v.note = "reached the peer but the handshake never completed".into();
            return v;
        }
    };
    v.handshook = true;

    let started = Instant::now();
    match push(&enc, &mut tx, seconds).await {
        Ok(sent) => {
            let secs = started.elapsed().as_secs_f64().max(0.001);
            v.held = true;
            v.mbit = (sent as f64 * 8.0) / secs / 1_000_000.0;
        }
        Err(e) => v.note = first_line(&e.to_string()),
    }
    v
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or(s).trim().to_string()
}

pub async fn serve(base: &Config, port: u16) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("binding the doctor control port {port}"))?;
    info!("doctor: waiting on tcp {port} for a peer to drive the tests");

    loop {
        let (sock, from) = listener.accept().await.context("accepting a doctor peer")?;
        info!("doctor: {from} connected");
        if let Err(e) = session(base, sock).await {
            info!("doctor: that run ended: {e:#}");
        }
    }
}

async fn session(base: &Config, sock: TcpStream) -> Result<()> {
    let from = sock.peer_addr().context("reading the peer address")?.ip();
    let (read, mut write) = sock.into_split();
    let mut lines = BufReader::new(read).lines();

    write.write_all(format!("{CONTROL}\n").as_bytes()).await?;
    while let Some(line) = lines.next_line().await? {
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("CARRIER") => {
                let name = parts.next().unwrap_or_default().to_string();
                let port: u16 = parts.next().unwrap_or("0").parse().unwrap_or(0);
                let seconds: u64 = parts.next().unwrap_or("8").parse().unwrap_or(8);
                match accept_one(base, &name, port, seconds, from).await {
                    Ok(bytes) => {
                        write
                            .write_all(format!("GOT {bytes}\n").as_bytes())
                            .await
                            .ok();
                    }
                    Err(e) => {
                        write
                            .write_all(
                                format!("FAILED {}\n", first_line(&e.to_string())).as_bytes(),
                            )
                            .await
                            .ok();
                    }
                }
            }
            Some("PROTOS") => {
                let seconds: u64 = parts.next().unwrap_or("4").parse().unwrap_or(4);
                let counts = watch_protocols(&base.token, seconds).await;
                let body = counts
                    .iter()
                    .map(|(n, seen, note)| {
                        if note.is_empty() {
                            format!("{n}={seen}")
                        } else {
                            format!("{n}=!{note}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                write
                    .write_all(format!("PROTOS {body}\n").as_bytes())
                    .await
                    .ok();
            }
            Some("DONE") | None => break,
            Some(other) => {
                write
                    .write_all(format!("FAILED unknown request {other}\n").as_bytes())
                    .await
                    .ok();
            }
        }
    }
    Ok(())
}

async fn accept_one(
    base: &Config,
    carrier: &str,
    port: u16,
    seconds: u64,
    from: IpAddr,
) -> Result<u64> {
    if crate::dgram::is_datagram(carrier) {
        return accept_dgram(base, carrier, port, seconds, from).await;
    }
    let cfg = probe_config(base, carrier, port, None);
    let built = Carrier::from_cfg(&cfg).with_context(|| format!("building {carrier}"))?;
    let keys = Keys::from_cfg(&cfg)?;
    let bound = built
        .bind(&format!("0.0.0.0:{port}"))
        .await
        .with_context(|| format!("binding {carrier} on {port}"))?;

    let (mut tx, mut rx) = tokio::time::timeout(HANDSHAKE_BUDGET * 2, bound.accept())
        .await
        .context("no lane arrived")??;
    let (enc, _) = tokio::time::timeout(HANDSHAKE_BUDGET, keys.accept(&mut *tx, &mut *rx))
        .await
        .context("the lane never finished its handshake")??;
    Ok(drain(&enc, &mut rx, seconds).await)
}

pub struct Report {
    pub verdicts: Vec<Verdict>,
    pub protocols: Vec<(u8, String, usize, String)>,
}

impl Report {
    pub fn ordered(&self) -> Vec<&Verdict> {
        let mut good: Vec<&Verdict> = self.verdicts.iter().filter(|v| v.usable()).collect();
        good.sort_by(|a, b| b.mbit.total_cmp(&a.mbit));
        good
    }

    pub fn crossing(&self) -> Vec<String> {
        self.protocols
            .iter()
            .filter(|(_, _, seen, note)| *seen > 0 && note.is_empty())
            .map(|(n, name, _, _)| format!("{name} ({n})"))
            .collect()
    }

    pub fn config(&self, peer: &str, port: u16, dialing: bool) -> String {
        let good = self.ordered();
        if good.is_empty() {
            return String::from(
                "# No carrier completed a handshake and held it.\n\
                 # Nothing here would work; try a different port or address.\n",
            );
        }
        let mut s = String::from(
            "# Measured on this path, best first. The primary is the fastest that held;\n\
             # the rest are fallbacks in the same order.\n",
        );
        let crossing = self.crossing();
        if !crossing.is_empty() {
            s.push_str(&format!(
                "# IP protocols that also crossed: {}\n",
                crossing.join(", ")
            ));
        }
        let addr = |i: usize| {
            if dialing {
                format!("{peer}:{}", port + i as u16)
            } else {
                format!("0.0.0.0:{}", port + i as u16)
            }
        };
        s.push_str(&if dialing {
            "# This side dials, so each address is where to connect. The side that \
             accepts\n# needs the same carriers with its own bind addresses.\n"
                .to_string()
        } else {
            "# This side accepts lanes, so each address is where to bind. The side that \
             dials\n# needs the same carriers pointed at this host.\n"
                .to_string()
        });
        let carrier = good[0].carrier.as_str();
        let datagram = carrier.starts_with("shabdiz-");
        let one_lane = matches!(carrier, "faketcp" | "l2tcp" | "icmp" | "spoof");
        s.push_str(&format!("carrier = \"{carrier}\"\n"));
        s.push_str(&format!(
            "{} = \"{}\"\n",
            if dialing {
                "tunnel_connect"
            } else {
                "tunnel_listen"
            },
            addr(0)
        ));
        if one_lane || matches!(carrier, "shabdiz-gre" | "shabdiz-esp" | "shabdiz-l2") {
            s.push_str(&format!(
                "peer_ip = \"{peer}\"\n# this carrier forges its own packets, so the far end \
                 needs peer_ip pointed back here\n"
            ));
        }
        if one_lane {
            s.push_str(&format!("lanes = {}\n", crate::raw::RAW_LANES));
        } else if !datagram {
            s.push_str("lanes = 4\n");
        }
        if datagram {
            s.push_str(
                "\n# A datagram carrier replaces the lane machinery: it reads no lanes and no\n\
                 # [[link]]s, and carries exactly one udp forward — the one below is a\n\
                 # placeholder, so change it to what this tunnel should carry.\n\
                 # The carriers that also held, in measured order: ",
            );
            let rest: Vec<&str> = good.iter().skip(1).map(|v| v.carrier.as_str()).collect();
            s.push_str(&if rest.is_empty() {
                "none.\n".to_string()
            } else {
                format!("{}.\n", rest.join(", "))
            });
            s.push_str(
                "\n[[forward]]\nlisten = \"0.0.0.0:1194\"\ntarget = \"127.0.0.1:1194\"\n\
                 udp = true\n",
            );
            return s;
        }
        for (i, v) in good.iter().enumerate().skip(1) {
            s.push_str(&format!(
                "\n[[link]]\ncarrier = \"{}\"\naddr = \"{}\"\n",
                v.carrier,
                addr(i)
            ));
        }
        s
    }
}

pub async fn run(base: &Config, peer: &str, port: u16, plan: Plan) -> Result<Report> {
    let control = format!("{peer}:{port}");
    let sock = tokio::time::timeout(HANDSHAKE_BUDGET, TcpStream::connect(&control))
        .await
        .with_context(|| format!("reaching the doctor on {control}"))?
        .with_context(|| format!("reaching the doctor on {control}"))?;
    let (read, mut write) = sock.into_split();
    let mut lines = BufReader::new(read).lines();

    let hello = lines.next_line().await?.unwrap_or_default();
    if hello.trim() != CONTROL {
        bail!("{control} answered {hello:?}, which is not a rakhsh doctor");
    }

    let host = peer.split(':').next().unwrap_or(peer).to_string();
    let mut verdicts = Vec::new();
    for (i, carrier) in plan.carriers.iter().enumerate() {
        let lane_port = port + 1 + i as u16;
        write
            .write_all(format!("CARRIER {carrier} {lane_port} {}\n", plan.seconds).as_bytes())
            .await?;
        tokio::time::sleep(SETTLE).await;

        let target = format!("{host}:{lane_port}");
        let mut v = measure(base, carrier, &target, plan.seconds).await;

        let answer = lines.next_line().await?.unwrap_or_default();
        if let Some(rest) = answer.strip_prefix("GOT ") {
            let got: u64 = rest.trim().parse().unwrap_or(0);
            if got == 0 && v.handshook {
                v.held = false;
                v.mbit = 0.0;
                v.note = "handshake completed, then no data arrived at the far end".into();
            } else if crate::dgram::is_datagram(carrier) && v.handshook {
                v.mbit = got as f64 * 8.0 / plan.seconds.max(1) as f64 / 1_000_000.0;
            }
        } else if let Some(why) = answer.strip_prefix("FAILED ") {
            if v.note.is_empty() {
                v.note = format!("far end: {}", why.trim());
            }
        }
        println!("{}", v.line());
        verdicts.push(v);
    }
    let protocols = match peer.parse::<Ipv4Addr>() {
        Ok(ip) if plan.protocols => {
            println!();
            println!("  which IP protocol numbers cross this path");
            write
                .write_all(format!("PROTOS {}\n", plan.seconds.min(6)).as_bytes())
                .await?;
            tokio::time::sleep(SETTLE).await;
            let sent = send_protocols(&base.token, ip).await;
            let answer = lines.next_line().await?.unwrap_or_default();
            let counts = parse_protocol_counts(answer.strip_prefix("PROTOS ").unwrap_or(""));
            let mut rows = Vec::new();
            for (n, name, send_note) in sent {
                let (seen, note) = counts
                    .iter()
                    .find(|(m, _, _)| *m == n)
                    .map(|(_, s, note)| (*s, note.clone()))
                    .unwrap_or((0, String::new()));
                let note = if !send_note.is_empty() {
                    send_note
                } else {
                    note
                };
                let line = protocol_line(n, name, seen, &note);
                println!("{line}");
                rows.push((n, name.to_string(), seen, note));
            }
            rows
        }
        _ => Vec::new(),
    };

    write.write_all(b"DONE\n").await.ok();
    Ok(Report {
        verdicts,
        protocols,
    })
}

fn parse_protocol_counts(s: &str) -> Vec<(u8, usize, String)> {
    s.split(',')
        .filter_map(|kv| kv.split_once('='))
        .filter_map(|(n, v)| {
            let n: u8 = n.trim().parse().ok()?;
            match v.strip_prefix('!') {
                Some(note) => Some((n, 0, note.to_string())),
                None => Some((n, v.trim().parse().unwrap_or(0), String::new())),
            }
        })
        .collect()
}

const PROTO_MAGIC: usize = 8;
const PROTO_SHOTS: usize = 5;
const PROTO_BODY: usize = 64;

fn magic(token: &str) -> [u8; PROTO_MAGIC] {
    let full = blake3::derive_key("rakhsh doctor protocol probe", token.as_bytes());
    let mut m = [0u8; PROTO_MAGIC];
    m.copy_from_slice(&full[..PROTO_MAGIC]);
    m
}

fn raw_socket(proto: u8, timeout_ms: i64) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, proto as libc::c_int) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    if timeout_ms > 0 {
        let tv = libc::timeval {
            tv_sec: (timeout_ms / 1000) as _,
            tv_usec: ((timeout_ms % 1000) * 1000) as _,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    }
    Ok(owned)
}

fn send_protocol(proto: u8, peer: Ipv4Addr, body: &[u8]) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = raw_socket(proto, 0)?;
    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(peer.octets()),
        },
        sin_zero: [0; 8],
    };
    for _ in 0..PROTO_SHOTS {
        let r = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                body.as_ptr() as *const libc::c_void,
                body.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn count_protocol(proto: u8, want: [u8; PROTO_MAGIC], until: Instant) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd;
    let fd = raw_socket(proto, 250)?;
    let mut buf = vec![0u8; 2048];
    let mut seen = 0;
    while Instant::now() < until {
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n <= 0 {
            continue;
        }
        let d = &buf[..n as usize];
        let ihl = match d.first() {
            Some(b) if b >> 4 == 4 => ((b & 0x0f) as usize) * 4,
            _ => continue,
        };
        if d.len() >= ihl + PROTO_MAGIC && d[ihl..ihl + PROTO_MAGIC] == want {
            seen += 1;
        }
    }
    Ok(seen)
}

pub fn protocol_body(token: &str) -> Vec<u8> {
    let mut body = magic(token).to_vec();
    body.resize(PROTO_BODY, 0);
    body
}

pub async fn send_protocols(token: &str, peer: Ipv4Addr) -> Vec<(u8, &'static str, String)> {
    let body = protocol_body(token);
    let mut out = Vec::new();
    for (n, name) in PROTOCOLS {
        let note = match send_protocol(*n, peer, &body) {
            Ok(()) => String::new(),
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => "needs CAP_NET_RAW".into(),
            Err(e) => first_line(&e.to_string()),
        };
        out.push((*n, *name, note));
    }
    out
}

pub async fn watch_protocols(token: &str, seconds: u64) -> Vec<(u8, usize, String)> {
    let want = magic(token);
    let until = Instant::now() + Duration::from_secs(seconds);
    let mut handles = Vec::new();
    for (n, _) in PROTOCOLS {
        let n = *n;
        handles.push((
            n,
            tokio::task::spawn_blocking(move || count_protocol(n, want, until)),
        ));
    }
    let mut out = Vec::new();
    for (n, h) in handles {
        match h.await {
            Ok(Ok(seen)) => out.push((n, seen, String::new())),
            Ok(Err(e)) if e.raw_os_error() == Some(libc::EPERM) => {
                out.push((n, 0, "needs CAP_NET_RAW".into()))
            }
            Ok(Err(e)) => out.push((n, 0, first_line(&e.to_string()))),
            Err(e) => out.push((n, 0, first_line(&e.to_string()))),
        }
    }
    out
}

pub fn protocol_line(n: u8, name: &str, seen: usize, note: &str) -> String {
    let state = if !note.is_empty() {
        note.to_string()
    } else if seen == 0 {
        "blocked".to_string()
    } else if seen >= PROTO_SHOTS {
        format!("passes ({seen}/{PROTO_SHOTS})")
    } else {
        format!("partial ({seen}/{PROTO_SHOTS})")
    };
    format!("  protocol {n:<4} {name:<14} {state}")
}

pub fn parse_peer(s: &str, default: u16) -> Result<(String, u16)> {
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => {
            let port = p
                .parse()
                .with_context(|| format!("{p:?} is not a port number"))?;
            Ok((h.to_string(), port))
        }
        _ => Ok((s.to_string(), default)),
    }
}

#[cfg(test)]
#[path = "../tests/unit/doctor.rs"]
mod tests;
