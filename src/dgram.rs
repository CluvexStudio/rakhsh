use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use std::sync::Mutex;
use tokio::net::UdpSocket;
use tracing::{info, warn};

use shabdiz::carrier::{esp, gre, l2, tagged, tcp::Tcp, udp::Udp, Carrier};
use shabdiz::handshake;
use shabdiz::session::{self, Handle, Role};

use crate::config::Config;

const MAX_FLOWS: usize = 4096;

const FLOW_IDLE: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Gre,
    Esp,
    Tagged,
    L2,
    Udp,
    Tcp,
}

struct Tagged {
    proto: libc::c_int,
    name: &'static str,
    context: &'static str,
}

const TAGGED: &[(&str, Tagged)] = &[
    (
        "shabdiz-ipip",
        Tagged {
            proto: 4,
            name: "IPIP",
            context: "shabdiz-ipip-tags-v1",
        },
    ),
    (
        "shabdiz-6to4",
        Tagged {
            proto: 41,
            name: "6to4",
            context: "shabdiz-6to4-tags-v1",
        },
    ),
    (
        "shabdiz-etherip",
        Tagged {
            proto: 97,
            name: "EtherIP",
            context: "shabdiz-etherip-tags-v1",
        },
    ),
    (
        "shabdiz-l2tp",
        Tagged {
            proto: 115,
            name: "L2TPv3",
            context: "shabdiz-l2tp-tags-v1",
        },
    ),
    (
        "shabdiz-mpls",
        Tagged {
            proto: 137,
            name: "MPLS-in-IP",
            context: "shabdiz-mpls-tags-v1",
        },
    ),
];

fn tagged_spec(carrier: &str) -> Option<&'static Tagged> {
    TAGGED.iter().find(|(n, _)| *n == carrier).map(|(_, s)| s)
}

fn kind_of(carrier: &str) -> Option<Kind> {
    match carrier {
        "shabdiz-gre" => Some(Kind::Gre),
        "shabdiz-esp" => Some(Kind::Esp),
        "shabdiz-l2" => Some(Kind::L2),
        "shabdiz-udp" => Some(Kind::Udp),
        "shabdiz-tcp" => Some(Kind::Tcp),
        _ if tagged_spec(carrier).is_some() => Some(Kind::Tagged),
        _ => None,
    }
}

pub fn selected(cfg: &Config) -> bool {
    cfg.carrier.as_deref().and_then(kind_of).is_some()
}

pub fn is_datagram(carrier: &str) -> bool {
    kind_of(carrier).is_some()
}

pub async fn open(cfg: &Config, dialer: bool) -> Result<(Arc<Handle>, Arc<dyn Carrier>)> {
    let kind = cfg
        .carrier
        .as_deref()
        .and_then(kind_of)
        .ok_or_else(|| anyhow!("not a shabdiz carrier"))?;
    let carrier = build_carrier(cfg, kind, dialer).await?;
    let (local, peer, psk) = (
        cfg.secret_key()?,
        cfg.peer_key()?,
        crate::noise::derive_psk(&cfg.token),
    );
    let config = session::Config {
        ring: 1024,
        ..session::Config::default()
    };
    let handle = if dialer {
        let (keys, params) =
            handshake::dial(&*carrier, &local, &peer, &psk, Duration::from_secs(3), 10)
                .await
                .context("shabdiz handshake")?;
        info!("shabdiz up: payload mtu {}", params.payload_mtu);
        session::start(carrier.clone(), keys, params, Role::Dialer, config, None)
    } else {
        let a = handshake::accept(&*carrier, &local, &peer, &psk)
            .await
            .context("shabdiz handshake")?;
        info!("shabdiz up: payload mtu {}", a.params.payload_mtu);
        session::start(
            carrier.clone(),
            a.keys,
            a.params,
            Role::Responder,
            config,
            Some(session::Handshake {
                first: a.first,
                reply: a.reply,
            }),
        )
    };
    Ok((Arc::new(handle), carrier))
}

pub fn describe(cfg: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let Some(kind) = cfg.carrier.as_deref().and_then(kind_of) else {
        return out;
    };
    let dialer = dials(cfg);
    out.push(
        "shabdiz: the datagram tunnel — rakhsh's reliable session is not used, so a lost packet \
         costs that packet and nothing behind it"
            .to_string(),
    );
    out.push(format!(
        "  carrier {kind:?}, this end {}",
        if dialer {
            "opens the flow"
        } else {
            "waits to be spoken to"
        }
    ));
    if dialer && cfg.role == "entry" {
        out.push(
            "  WARNING: the entry is opening the flow. On a filtered path that measured 29% loss \
             against 0.001% when the exit opened it — set dial = \"exit\"."
                .to_string(),
        );
    }
    if kind == Kind::Gre {
        out.push(
            "  IP protocol 47, as a bridged Ethernet frame. Measured on the Iranian path: \
             213 Mbit/s outbound at 0.29% loss (100 Mbit/s at 0.00%), 100 Mbit/s inbound at \
             1.39% — against 32 Mbit/s at 0.5-8% for shabdiz-l2."
                .to_string(),
        );
        out.push(
            "  needs root (CAP_NET_RAW), and has no ports, so both ends need a public address — \
             it cannot cross NAT. Either end may open the flow."
                .to_string(),
        );
        if cfg.peer_ip.is_none() && cfg.tunnel_connect.is_none() {
            out.push(
                "  ERROR: set peer_ip (or tunnel_connect) so this end knows where to send".into(),
            );
        }
    }
    if kind == Kind::Esp {
        out.push(
            "  IP protocol 50, shaped as an ESP packet (SPI and sequence number). Measured on \
             the Iranian path: it crossed where protocol 47 was dropped outright, because \
             blocking ESP would break corporate IPsec."
                .to_string(),
        );
        out.push(
            "  needs root (CAP_NET_RAW), and has no ports, so both ends need a public address — \
             it cannot cross NAT. Either end may open the flow."
                .to_string(),
        );
        if cfg.peer_ip.is_none() && cfg.tunnel_connect.is_none() {
            out.push(
                "  ERROR: set peer_ip (or tunnel_connect) so this end knows where to send".into(),
            );
        }
    }
    if kind == Kind::Tagged {
        let spec = cfg
            .carrier
            .as_deref()
            .and_then(tagged_spec)
            .expect("a tagged kind always has a spec");
        let (proto, name) = (spec.proto, spec.name);
        out.push(format!(
            "  IP protocol {proto}, shaped as {name} but carrying a token-derived tag and \
             sequence number instead of an inner packet. The tag never begins with 4 or 6, so \
             nothing downstream reads the payload as an IP header — the shape that was measured \
             to be dropped on protocol 47."
        ));
        out.push(
            "  UNMEASURED at volume on the Iranian path: a three-packet probe crossed, but that \
             is exactly the trap sustained UDP fell into. Measure with `rakhsh doctor` before \
             relying on it."
                .to_string(),
        );
        out.push(
            "  needs root (CAP_NET_RAW), and has no ports, so both ends need a public address — \
             it cannot cross NAT. Either end may open the flow."
                .to_string(),
        );
        if cfg.peer_ip.is_none() && cfg.tunnel_connect.is_none() {
            out.push(
                "  ERROR: set peer_ip (or tunnel_connect) so this end knows where to send".into(),
            );
        }
    }
    if kind == Kind::L2 {
        let (a, b) = shabdiz_ports(&cfg.token);
        out.push(format!(
            "  crafted-TCP ports: the dialling end sends {a} -> {b} (derived from the token; both \
             ends compute the same pair, and it is what to filter a capture on)"
        ));
        out.push(
            "  needs root (CAP_NET_RAW), and drops the kernel's resets for its own port".into(),
        );
        if cfg.peer_ip.is_none() && cfg.tunnel_connect.is_none() {
            out.push(
                "  ERROR: no peer_ip and no tunnel_connect — nothing to craft frames to".into(),
            );
        }
    }
    match one_udp_forward(cfg) {
        Ok((l, t)) => out.push(format!("  carries udp {l} -> {t}")),
        Err(e) => out.push(format!("  ERROR: {e}")),
    }
    let ign = ignored(cfg);
    if !ign.is_empty() {
        out.push(format!(
            "  WARNING: a datagram carrier replaces the lane and stream machinery, so these are \
             not read here: {}",
            ign.join(", ")
        ));
    }
    out
}

pub fn ignored(cfg: &Config) -> Vec<&'static str> {
    let mut v = Vec::new();
    if cfg.lanes.is_some() {
        v.push("lanes");
    }
    if cfg.resume {
        v.push("resume");
    }
    if !cfg.link.is_empty() {
        v.push("[[link]]");
    }
    if !cfg.backup_connect.is_empty() {
        v.push("backup_connect");
    }
    if !cfg.peers.is_empty() {
        v.push("[[peer]]");
    }
    if !cfg.inbound.is_empty() {
        v.push("[[inbound]]");
    }
    if cfg.dns.is_some() {
        v.push("[dns]");
    }
    if cfg.max_connections.is_some() {
        v.push("max_connections");
    }
    if cfg.mss_clamp.is_some() {
        v.push("mss_clamp");
    }
    if cfg.encryption.is_some() {
        v.push("encryption (shabdiz always encrypts)");
    }
    if cfg.l3_addr.is_some() {
        v.push("l3_addr");
    }
    let l = &cfg.limits;
    if l.limit.is_some()
        || l.limit_up.is_some()
        || l.limit_down.is_some()
        || l.limit_per_stream.is_some()
        || l.quota.is_some()
    {
        v.push("the limit and quota keys");
    }
    if cfg.forward.iter().any(|f| !f.udp) {
        v.push("every [[forward]] without udp = true");
    }
    v
}

pub fn validate(cfg: &Config) -> Result<()> {
    let Some(kind) = cfg.carrier.as_deref().and_then(kind_of) else {
        return Ok(());
    };
    one_udp_forward(cfg)?;
    if matches!(kind, Kind::Gre | Kind::Esp | Kind::Tagged | Kind::L2) {
        peer_host(cfg, cfg.carrier.as_deref().unwrap_or("shabdiz"))?;
    }
    Ok(())
}

pub async fn run(cfg: Config) -> Result<()> {
    let kind = cfg
        .carrier
        .as_deref()
        .and_then(kind_of)
        .ok_or_else(|| anyhow!("not a shabdiz carrier"))?;
    let fwd = one_udp_forward(&cfg)?;
    let dialer = dials(&cfg);
    if dialer && cfg.role == "entry" {
        warn!(
            "dial = \"entry\" with shabdiz: on a filtered path the side that opens the flow loses \
             far more — measured 29% against 0.001% — so the exit should dial"
        );
    }
    info!(
        "shabdiz {}: carrier {:?}, {} udp {} -> {}",
        cfg.role,
        kind,
        if dialer { "dialling," } else { "listening," },
        fwd.0,
        fwd.1
    );
    let ign = ignored(&cfg);
    if !ign.is_empty() {
        warn!(
            "a datagram carrier does not read these, so they have no effect: {}",
            ign.join(", ")
        );
    }

    let mut backoff = Duration::from_millis(500);
    loop {
        match serve_once(&cfg, dialer, fwd).await {
            Ok(()) => backoff = Duration::from_millis(500),
            Err(e) => {
                warn!("shabdiz session ended: {e:#}");
                backoff = (backoff * 2).min(Duration::from_secs(15));
            }
        }
        tokio::time::sleep(backoff).await;
    }
}

fn dials(cfg: &Config) -> bool {
    match cfg.dial.as_deref().unwrap_or("exit") {
        "entry" => cfg.role == "entry",
        _ => cfg.role == "exit",
    }
}

fn one_udp_forward(cfg: &Config) -> Result<(SocketAddr, SocketAddr)> {
    let udp: Vec<_> = cfg.forward.iter().filter(|f| f.udp).collect();
    match udp.len() {
        0 => bail!("a shabdiz carrier needs one `[[forward]]` with `udp = true`"),
        1 => {}
        n => bail!("{n} udp forwards: shabdiz carries one per tunnel, so give each its own config"),
    }
    let f = udp[0];
    Ok((
        f.listen
            .parse()
            .with_context(|| format!("forward listen {}", f.listen))?,
        f.target
            .parse()
            .with_context(|| format!("forward target {}", f.target))?,
    ))
}

async fn serve_once(cfg: &Config, dialer: bool, fwd: (SocketAddr, SocketAddr)) -> Result<()> {
    let (handle, carrier) = open(cfg, dialer).await?;
    let label = if dialer { "dialer" } else { "responder" };
    let probe = {
        let handle = handle.clone();
        let openvpn = cfg.openvpn.clone();
        tokio::spawn(async move { announce_path_mtu(handle, openvpn).await })
    };
    let report = {
        let handle = handle.clone();
        let carrier = carrier.clone();
        tokio::spawn(async move { report(handle, carrier).await })
    };
    let res = if cfg.role == "entry" {
        entry_bridge(handle.clone(), fwd.0).await
    } else {
        exit_bridge(handle.clone(), fwd.1).await
    };
    report.abort();
    probe.abort();
    info!("shabdiz {label} session closed: {:?}", handle.snapshot());
    res
}

async fn announce_path_mtu(handle: Arc<Handle>, openvpn: Option<crate::openvpn::OpenVpn>) {
    let settled = handle.mtu_settled().await;
    let assumed = handle.mtu().assumed();
    if settled >= assumed {
        info!("shabdiz: the path carries the full {assumed}-byte payload (probed)");
        return;
    }
    warn!(
        "shabdiz: the path carries {settled} bytes, not the {assumed} this carrier assumes \
         (probed) — large datagrams would have been lost"
    );
    if let Some(ov) = openvpn {
        let was = assumed.saturating_sub(ov.overhead_bytes());
        let now = settled.saturating_sub(ov.overhead_bytes());
        warn!(
            "openvpn: set tun-mtu {now} on both ends, not the {was} derived from the assumed \
             path, and mssfix {now} mtu with it"
        );
    }
}

fn apply_pacing(cfg: &Config, c: &Arc<dyn Carrier>) {
    let Some(p) = c.pacer() else { return };
    if cfg.pace_auto.unwrap_or(false) {
        p.enable_auto_rate();
        info!("shabdiz pacing: adapting the rate from the loss the far end reports");
        return;
    }
    if cfg.pace_burst.is_none() && cfg.pace_gap_us.is_none() && cfg.pace_pps.is_none() {
        info!("shabdiz pacing: shaping bursts only; set pace_pps for a measured rate limit");
        return;
    }
    p.set_manual();
    if let Some(b) = cfg.pace_burst {
        p.set_burst(b);
    }
    if let Some(g) = cfg.pace_gap_us {
        p.set_gap(Duration::from_micros(g));
    }
    if let Some(r) = cfg.pace_pps {
        p.set_rate_pps(r);
    }
    info!(
        "shabdiz pacing (fixed): {} datagram(s) per write, {} us between groups, {} datagrams/s",
        p.burst(),
        cfg.pace_gap_us.unwrap_or(0),
        p.rate_pps()
    );
}

async fn build_carrier(cfg: &Config, kind: Kind, dialer: bool) -> Result<Arc<dyn Carrier>> {
    let c = build_carrier_inner(cfg, kind, dialer).await?;
    apply_pacing(cfg, &c);
    Ok(c)
}

async fn build_carrier_inner(cfg: &Config, kind: Kind, dialer: bool) -> Result<Arc<dyn Carrier>> {
    match kind {
        Kind::Udp => {
            if dialer {
                let peer: SocketAddr = cfg
                    .tunnel_connect
                    .as_deref()
                    .ok_or_else(|| anyhow!("shabdiz-udp needs tunnel_connect on the dialling end"))?
                    .parse()
                    .context("tunnel_connect")?;
                let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                Ok(Arc::new(
                    Udp::connect(local, peer)
                        .await
                        .context("binding the udp carrier")?,
                ))
            } else {
                let local: SocketAddr = cfg
                    .tunnel_listen
                    .as_deref()
                    .ok_or_else(|| anyhow!("shabdiz-udp needs tunnel_listen on the listening end"))?
                    .parse()
                    .context("tunnel_listen")?;
                Ok(Arc::new(
                    Udp::bind(local).await.context("binding the udp carrier")?,
                ))
            }
        }
        Kind::Tcp => {
            if dialer {
                let peer: SocketAddr = cfg
                    .tunnel_connect
                    .as_deref()
                    .ok_or_else(|| anyhow!("shabdiz-tcp needs tunnel_connect on the dialling end"))?
                    .parse()
                    .context("tunnel_connect")?;
                Ok(Arc::new(
                    Tcp::connect(peer)
                        .await
                        .context("dialling the tcp carrier")?,
                ))
            } else {
                let local: SocketAddr = cfg
                    .tunnel_listen
                    .as_deref()
                    .ok_or_else(|| anyhow!("shabdiz-tcp needs tunnel_listen on the listening end"))?
                    .parse()
                    .context("tunnel_listen")?;
                let l = tokio::net::TcpListener::bind(local)
                    .await
                    .context("tcp carrier listen")?;
                Ok(Arc::new(
                    Tcp::accept(&l).await.context("accepting the tcp carrier")?,
                ))
            }
        }
        Kind::Gre => {
            let peer_ip = peer_addr(cfg, "shabdiz-gre").await?;
            let (entry_mac, exit_mac) = gre::macs(cfg.token.as_bytes());
            let (local, peer) = if cfg.role == "entry" {
                (entry_mac, exit_mac)
            } else {
                (exit_mac, entry_mac)
            };
            let mtu = gre::path_mtu(1500);
            info!(
                "shabdiz-gre: {peer_ip} on IP protocol 47, mtu {mtu}, up to {} datagrams per syscall",
                shabdiz::carrier::BATCH
            );
            Ok(Arc::new(
                gre::open(peer_ip, local, peer, mtu)
                    .context("opening the GRE carrier (needs root)")?,
            ))
        }
        Kind::Esp => {
            let peer_ip = peer_addr(cfg, "shabdiz-esp").await?;
            let (entry_spi, exit_spi) = esp::spis(cfg.token.as_bytes());
            let (local, peer) = if cfg.role == "entry" {
                (entry_spi, exit_spi)
            } else {
                (exit_spi, entry_spi)
            };
            let mtu = esp::path_mtu(1500);
            info!(
                "shabdiz-esp: {peer_ip} on IP protocol 50, spi {local:#010x} <- {peer:#010x}, \
                 mtu {mtu}, up to {} datagrams per syscall",
                shabdiz::carrier::BATCH
            );
            Ok(Arc::new(
                esp::open(peer_ip, local, peer, mtu)
                    .context("opening the ESP carrier (needs root)")?,
            ))
        }
        Kind::Tagged => {
            let which = cfg.carrier.as_deref().unwrap_or("shabdiz-ipip");
            let spec = tagged_spec(which).expect("a tagged kind always has a spec");
            let peer_ip = peer_addr(cfg, which).await?;
            let (entry_tag, exit_tag) = tagged::tags(cfg.token.as_bytes(), spec.context);
            let (local, peer) = if cfg.role == "entry" {
                (entry_tag, exit_tag)
            } else {
                (exit_tag, entry_tag)
            };
            let mtu = tagged::path_mtu(1500);
            info!(
                "{which}: {peer_ip} on IP protocol {} ({}), tag {local:#010x} <- {peer:#010x}, \
                 mtu {mtu}, up to {} datagrams per syscall",
                spec.proto,
                spec.name,
                shabdiz::carrier::BATCH
            );
            Ok(Arc::new(
                tagged::open(spec.proto, spec.name, peer_ip, local, peer, mtu)
                    .with_context(|| format!("opening the {which} carrier (needs root)"))?,
            ))
        }
        Kind::L2 => {
            let peer_ip = peer_addr(cfg, "shabdiz-l2").await?;
            let (a, b) = shabdiz_ports(&cfg.token);
            let (sport, dport) = if dialer { (a, b) } else { (b, a) };
            let link = l2::discover(peer_ip).context("discovering the interface for shabdiz-l2")?;
            info!(
                "shabdiz-l2: if#{} mtu {}, crafting {sport} -> {dport}, offload available",
                link.ifindex, link.mtu
            );
            Ok(Arc::new(
                l2::L2::open(link, peer_ip, sport, dport, l2::Options::default())
                    .context("opening the layer-2 carrier (needs root)")?,
            ))
        }
    }
}

pub(crate) fn peer_host<'a>(cfg: &'a Config, what: &str) -> Result<&'a str> {
    let host = match (&cfg.peer_ip, &cfg.tunnel_connect) {
        (Some(h), _) => h.trim(),
        (None, Some(c)) => c.rsplit_once(':').map(|(h, _)| h).unwrap_or(c).trim(),
        (None, None) => bail!("{what} needs peer_ip (or tunnel_connect) to reach the far end"),
    };
    if host.is_empty() {
        bail!("{what}: peer_ip is empty");
    }
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        bail!("{what}: {host} is IPv6; this carrier rides on IPv4");
    }
    Ok(host)
}

async fn peer_addr(cfg: &Config, what: &str) -> Result<Ipv4Addr> {
    match (&cfg.peer_ip, &cfg.tunnel_connect) {
        (Some(h), _) => peer_ipv4(h, "peer_ip").await,
        (None, Some(c)) => {
            let host = c.rsplit_once(':').map(|(h, _)| h).unwrap_or(c);
            peer_ipv4(host, "tunnel_connect").await
        }
        (None, None) => bail!("{what} needs peer_ip (or tunnel_connect) to reach the far end"),
    }
}

fn shabdiz_ports(token: &str) -> (u16, u16) {
    let k = blake3::derive_key("shabdiz-v1 l2 ports", token.as_bytes());
    let a = 20000 + (u16::from_be_bytes([k[0], k[1]]) % 20000);
    let mut b = 20000 + (u16::from_be_bytes([k[2], k[3]]) % 20000);
    if b == a {
        b = a.wrapping_add(1);
    }
    (a, b)
}

struct Flows {
    by_addr: HashMap<SocketAddr, (u16, Instant)>,
    by_id: HashMap<u16, SocketAddr>,
    next: u16,
}

impl Flows {
    fn new() -> Flows {
        Flows {
            by_addr: HashMap::new(),
            by_id: HashMap::new(),
            next: 1,
        }
    }

    fn id_for(&mut self, addr: SocketAddr) -> u16 {
        let now = Instant::now();
        if let Some((id, seen)) = self.by_addr.get_mut(&addr) {
            *seen = now;
            return *id;
        }
        self.expire(now);
        if self.by_addr.len() >= MAX_FLOWS {
            if let Some((&oldest, _)) = self.by_addr.iter().min_by_key(|(_, (_, seen))| *seen) {
                if let Some((id, _)) = self.by_addr.remove(&oldest) {
                    self.by_id.remove(&id);
                }
            }
        }
        self.next = self.next.checked_add(1).unwrap_or(1).max(1);
        let id = self.next;
        self.by_addr.insert(addr, (id, now));
        self.by_id.insert(id, addr);
        id
    }

    fn addr_for(&self, id: u16) -> Option<SocketAddr> {
        self.by_id.get(&id).copied()
    }

    fn expire(&mut self, now: Instant) {
        let gone: Vec<SocketAddr> = self
            .by_addr
            .iter()
            .filter(|(_, (_, seen))| now.duration_since(*seen) > FLOW_IDLE)
            .map(|(a, _)| *a)
            .collect();
        for a in gone {
            if let Some((id, _)) = self.by_addr.remove(&a) {
                self.by_id.remove(&id);
            }
        }
    }
}

async fn entry_bridge(h: Arc<Handle>, listen: SocketAddr) -> Result<()> {
    let sock = Arc::new(
        UdpSocket::bind(listen)
            .await
            .with_context(|| format!("bind {listen}"))?,
    );
    let flows = Arc::new(Mutex::new(Flows::new()));
    info!("shabdiz entry: forwarding udp {listen} over the tunnel");

    let up = {
        let (sock, flows, h) = (sock.clone(), flows.clone(), h.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, from) = match sock.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let flow = flows.lock().expect("flow table").id_for(from);
                h.send(flow, &buf[..n]);
            }
        })
    };

    let mut got = Vec::with_capacity(64);
    let mut last: Option<(u16, SocketAddr)> = None;
    loop {
        if h.recv_batch(&mut got, 64).await == 0 {
            break;
        }
        for (flow, payload) in got.drain(..) {
            let to = match last {
                Some((f, a)) if f == flow => Some(a),
                _ => {
                    let a = flows.lock().expect("flow table").addr_for(flow);
                    if let Some(a) = a {
                        last = Some((flow, a));
                    }
                    a
                }
            };
            if let Some(to) = to {
                let _ = sock.send_to(&payload, to).await;
            }
        }
    }
    up.abort();
    bail!("the session ended")
}

async fn exit_bridge(h: Arc<Handle>, target: SocketAddr) -> Result<()> {
    let socks: Arc<Mutex<HashMap<u16, Arc<UdpSocket>>>> = Arc::new(Mutex::new(HashMap::new()));
    info!("shabdiz exit: delivering to udp {target}");

    let mut got = Vec::with_capacity(64);
    loop {
        if h.recv_batch(&mut got, 64).await == 0 {
            break;
        }
        for (flow, payload) in got.drain(..) {
            let known = socks.lock().expect("flow sockets").get(&flow).cloned();
            let sock = match known {
                Some(s) => s,
                None => {
                    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                    let Ok(s) = UdpSocket::bind(local).await else {
                        continue;
                    };
                    if s.connect(target).await.is_err() {
                        continue;
                    }
                    let s = Arc::new(s);
                    let mut map = socks.lock().expect("flow sockets");
                    if map.len() >= MAX_FLOWS {
                        continue;
                    }
                    match map.entry(flow) {
                        std::collections::hash_map::Entry::Occupied(e) => e.get().clone(),
                        std::collections::hash_map::Entry::Vacant(e) => {
                            e.insert(s.clone());
                            drop(map);
                            let (h, socks, s2) = (h.clone(), socks.clone(), s.clone());
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 65535];
                                loop {
                                    match s2.recv(&mut buf).await {
                                        Ok(n) if n > 0 => h.send(flow, &buf[..n]),
                                        Ok(_) => {}
                                        Err(_) => break,
                                    }
                                    if h.is_closed() {
                                        break;
                                    }
                                }
                                socks.lock().expect("flow sockets").remove(&flow);
                            });
                            s
                        }
                    }
                }
            };
            let _ = sock.send(&payload).await;
        }
    }
    bail!("the session ended")
}

async fn report(h: Arc<Handle>, carrier: Arc<dyn Carrier>) {
    let mut last = (0u64, 0u64);
    loop {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let s = h.snapshot();
        if (s.tx_datagrams, s.rx_datagrams) == last {
            continue;
        }
        last = (s.tx_datagrams, s.rx_datagrams);
        info!(
            "shabdiz: tx {} / {:.1} MiB ({} err, {} dropped), rx {} / {:.1} MiB ({} dropped) | \
             loss in {:.2}% out {:.2}% | rtt {} jitter {:.1} ms | {} rejected{}",
            s.tx_datagrams,
            s.tx_bytes as f64 / 1_048_576.0,
            s.tx_errors,
            s.tx_dropped,
            s.rx_datagrams,
            s.rx_bytes as f64 / 1_048_576.0,
            s.rx_dropped,
            s.loss_ratio() * 100.0,
            s.peer_loss_ratio() * 100.0,
            if s.rtt_us == 0 {
                "— (the dialling end measures it)".to_string()
            } else {
                format!("{:.1} ms", s.rtt_us as f64 / 1000.0)
            },
            s.jitter_us as f64 / 1000.0,
            s.rejected,
            match carrier.pacer() {
                Some(p) => format!(
                    " | pacing {} per write, {}",
                    p.burst(),
                    match p.rate_pps() {
                        0 => "no rate limit".to_string(),
                        r => format!("{r} datagrams/s"),
                    }
                ),
                None => String::new(),
            },
        );
    }
}

pub(crate) async fn peer_ipv4(host: &str, what: &str) -> anyhow::Result<std::net::Ipv4Addr> {
    use anyhow::{bail, Context};
    let host = host.trim();
    if host.is_empty() {
        bail!("{what} is empty");
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(ip);
    }
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        bail!("{what} {host} is IPv6; this carrier rides on IPv4");
    }
    let found = tokio::net::lookup_host((host, 0))
        .await
        .with_context(|| format!("resolving {what} {host}"))?
        .find_map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        });
    match found {
        Some(ip) => {
            tracing::info!("{what} {host} resolved to {ip}");
            Ok(ip)
        }
        None => bail!("{what} {host} has no A record; this carrier rides on IPv4"),
    }
}

#[cfg(test)]
#[path = "../tests/unit/dgram_peer.rs"]
mod peer_tests;
