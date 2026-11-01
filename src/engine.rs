use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::{Config, Outbound};
use crate::entry::Pool;
use crate::limits::Meter;
use crate::proxy::{self, Auth, Kind};
use crate::route::{Dest, Host, Router};

pub(crate) enum Out {
    Direct,
    Block,
    Tunnel,
    Socks {
        server: String,
        auth: Option<(String, String)>,
    },
}

pub(crate) struct Engine {
    pub(crate) router: Router,
    pub(crate) outs: HashMap<String, Out>,
    pub(crate) pool: Option<Pool>,
    access_log: bool,
}

fn build(cfg: &Config, has_pool: bool) -> Result<(HashMap<String, Out>, Router)> {
    let declared: Vec<Outbound> = if cfg.outbound.is_empty() {
        let mk = |tag: &str| Outbound {
            tag: tag.into(),
            kind: tag.into(),
            server: None,
            username: None,
            password: None,
        };
        let mut v = Vec::new();
        if has_pool {
            v.push(mk("tunnel"));
        }
        v.push(mk("direct"));
        v
    } else {
        cfg.outbound.clone()
    };
    let mut outs = HashMap::new();
    let mut tags = Vec::new();
    for o in &declared {
        let out = match o.kind.as_str() {
            "direct" => Out::Direct,
            "block" => Out::Block,
            "tunnel" => {
                if !has_pool {
                    bail!("outbound {:?}: type \"tunnel\" sends over the rakhsh lanes, so it needs role = \"entry\"", o.tag);
                }
                Out::Tunnel
            }
            "socks" => {
                let server = o.server.clone().with_context(|| {
                    format!("outbound {:?}: type \"socks\" needs `server`", o.tag)
                })?;
                let auth = match (&o.username, &o.password) {
                    (Some(u), Some(p)) => Some((u.clone(), p.clone())),
                    _ => None,
                };
                Out::Socks { server, auth }
            }
            other => bail!(
                "outbound {:?}: unknown type {other:?} (direct, tunnel, block, socks)",
                o.tag
            ),
        };
        if outs.insert(o.tag.clone(), out).is_some() {
            bail!("duplicate outbound tag {:?}", o.tag);
        }
        tags.push(o.tag.clone());
    }
    let router = Router::compile(&cfg.route, &tags, &tags[0])?;
    for ib in &cfg.inbound {
        if !matches!(ib.kind.as_str(), "socks" | "http" | "mixed") {
            bail!(
                "inbound {:?}: unknown type {:?} (socks, http, mixed)",
                ib.listen,
                ib.kind
            );
        }
        if ib.username.is_some() != ib.password.is_some() {
            bail!(
                "inbound {:?}: set both username and password, or neither",
                ib.listen
            );
        }
    }
    Ok((outs, router))
}

pub fn validate(cfg: &Config) -> Result<String> {
    let (outs, router) = build(cfg, cfg.role == "entry")?;
    let mut tags: Vec<&String> = outs.keys().collect();
    tags.sort();
    Ok(format!(
        "{} inbound(s), outbounds {:?}, {} route rule(s), final -> {}{}",
        cfg.inbound.len(),
        tags,
        cfg.route.rule.len(),
        router.fallback,
        cfg.dns
            .as_ref()
            .map(|d| format!(", dns on {}", d.listen))
            .unwrap_or_default()
    ))
}

pub async fn spawn(cfg: &Config, pool: Option<Pool>) -> Result<usize> {
    if cfg.inbound.is_empty() && cfg.dns.is_none() {
        return Ok(0);
    }
    let (outs, router) = build(cfg, pool.is_some())?;
    let engine = Arc::new(Engine {
        router,
        outs,
        pool,
        access_log: cfg.access_log.unwrap_or(false),
    });

    for ib in &cfg.inbound {
        let auth = match (&ib.username, &ib.password) {
            (Some(u), Some(p)) => Some(Auth {
                user: u.clone(),
                pass: p.clone(),
            }),
            _ => None,
        };
        let tag = ib.tag.clone().unwrap_or_else(|| ib.listen.clone());
        let l = TcpListener::bind(&ib.listen)
            .await
            .with_context(|| format!("binding {} inbound {}", ib.kind, ib.listen))?;
        let bound = l.local_addr()?;
        if auth.is_none() && !bound.ip().is_loopback() {
            warn!("inbound {tag} on {bound} has NO authentication — anyone who can reach it can use it; set username/password");
        }
        info!(
            "{} inbound {tag} listening on {bound} (default outbound: {})",
            ib.kind, engine.router.fallback
        );
        let meter = match &engine.pool {
            Some(p) => p
                .limits
                .meter(&format!("inbound {tag}"), &ib.limits, p.limits.global())?,
            None => None,
        };
        tokio::spawn(accept_loop(
            engine.clone(),
            l,
            ib.kind.clone(),
            auth,
            tag,
            meter,
        ));
    }
    let dns = usize::from(crate::dns::spawn(cfg, engine.clone()).await?);
    Ok(cfg.inbound.len() + dns)
}

pub async fn run_node(cfg: Config) -> Result<()> {
    crate::stats::spawn_logger();
    let _m = crate::status::init(&cfg, "node");
    tokio::spawn(crate::status::serve(crate::status::socket_path(&cfg)));
    let n = spawn(&cfg, None).await?;
    if n == 0 {
        bail!("role \"node\" needs at least one [[inbound]] (or a [dns] section)");
    }
    info!("node up: {n} inbound(s); outbounds: direct / block / socks (no tunnel peer)");
    std::future::pending::<()>().await;
    Ok(())
}

async fn accept_loop(
    e: Arc<Engine>,
    l: TcpListener,
    mode: String,
    auth: Option<Auth>,
    tag: String,
    meter: Option<Arc<Meter>>,
) {
    let auth = Arc::new(auth);
    loop {
        let (sock, peer) = match l.accept().await {
            Ok(x) => x,
            Err(err) => {
                warn!("inbound {tag}: accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (e, mode, auth, tag, meter) = (
            e.clone(),
            mode.clone(),
            auth.clone(),
            tag.clone(),
            meter.clone(),
        );
        tokio::spawn(async move {
            if let Err(err) = handle(&e, sock, peer, &mode, &auth, &tag, &meter).await {
                debug!("inbound {tag} {peer}: {err:#}");
            }
        });
    }
}

async fn handle(
    e: &Engine,
    mut sock: TcpStream,
    peer: SocketAddr,
    mode: &str,
    auth: &Option<Auth>,
    tag: &str,
    meter: &Option<Arc<Meter>>,
) -> Result<()> {
    sock.set_nodelay(true).ok();
    let req = timeout(
        Duration::from_secs(15),
        proxy::accept(&mut sock, mode, auth),
    )
    .await
    .map_err(|_| anyhow!("handshake timed out"))??;
    if req.kind == Kind::SocksUdp {
        return udp_associate(e, sock, peer, tag).await;
    }
    let dec = e.router.route(tag, &req.dest).await;
    let out = e
        .outs
        .get(&dec.outbound)
        .ok_or_else(|| anyhow!("router chose unknown outbound {}", dec.outbound))?;
    if e.access_log {
        info!("{peer} -> {} => {}", req.dest.target(), dec.outbound);
    }

    match out {
        Out::Block => {
            reply_denied(&mut sock, req.kind).await;
            Ok(())
        }
        Out::Tunnel => {
            let pool = e
                .pool
                .as_ref()
                .ok_or_else(|| anyhow!("tunnel outbound without a pool"))?;
            let sm = match meter {
                Some(m) => match m.open() {
                    Some(s) => Some(Arc::new(s)),
                    None => {
                        reply_denied(&mut sock, req.kind).await;
                        bail!("quota used up");
                    }
                },
                None => None,
            };
            let Some(ts) = pool.open_tcp(&req.dest.target()).await else {
                reply_failed(&mut sock, req.kind, 1).await;
                bail!("tunnel unavailable (no live lane, or connection cap reached)");
            };
            reply_ok(&mut sock, req.kind).await?;
            ts.relay(sock, &req.early, sm).await;
            Ok(())
        }
        Out::Direct | Out::Socks { .. } => {
            let up = match out {
                Out::Direct => connect_direct(&req.dest, &dec.resolved)
                    .await
                    .map_err(anyhow::Error::from),
                Out::Socks { server, auth } => connect_socks(server, auth, &req.dest).await,
                _ => unreachable!(),
            };
            let mut up = match up {
                Ok(u) => u,
                Err(err) => {
                    let code = err
                        .downcast_ref::<std::io::Error>()
                        .map(proxy::socks_code)
                        .unwrap_or(1);
                    reply_failed(&mut sock, req.kind, code).await;
                    return Err(err);
                }
            };
            reply_ok(&mut sock, req.kind).await?;
            if !req.early.is_empty() {
                up.write_all(&req.early).await?;
            }
            let (a, b) = tokio::io::copy_bidirectional(&mut sock, &mut up)
                .await
                .unwrap_or((0, 0));
            crate::stats::add_tx(a as usize);
            crate::stats::add_rx(b as usize);
            Ok(())
        }
    }
}

async fn udp_associate(e: &Engine, mut ctl: TcpStream, peer: SocketAddr, tag: &str) -> Result<()> {
    use std::collections::HashMap;
    use tokio::net::UdpSocket;

    let local = ctl.local_addr()?;
    let relay = Arc::new(UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await?);
    let bnd = relay.local_addr()?;
    let direct = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    proxy::socks_reply_addr(&mut ctl, bnd).await?;
    if e.access_log {
        info!("{peer} udp-associate relay on {bnd}");
    }

    let client_addr: Arc<std::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(None));

    let (relay_r, direct_r, client_r) = (relay.clone(), direct.clone(), client_addr.clone());
    let back_direct = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = direct_r.recv_from(&mut buf).await {
            let Some(c) = *client_r.lock().unwrap() else {
                continue;
            };
            let mut out = proxy::udp_reply_header(&Dest {
                host: Host::Ip(from.ip()),
                port: from.port(),
            });
            out.extend_from_slice(&buf[..n]);
            let _ = relay_r.send_to(&out, c).await;
        }
    });

    let mut flows: HashMap<String, (crate::entry::TunnelUdp, tokio::task::JoinHandle<()>)> =
        HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut ctl_buf = [0u8; 1];
    let mut idle = 0u32;
    loop {
        tokio::select! {
            r = ctl.read(&mut ctl_buf) => { let _ = r; break; }
            r = tokio::time::timeout(Duration::from_secs(30), relay.recv_from(&mut buf)) => {
                let Ok(Ok((n, from))) = r else {
                    idle += 1;
                    if idle > 20 { break; }
                    continue;
                };
                idle = 0;
                if from.ip() != peer.ip() {
                    continue;
                }
                *client_addr.lock().unwrap() = Some(from);
                let Some((dest, off)) = proxy::parse_udp_datagram(&buf[..n]) else { continue };
                let data = &buf[off..n];
                let dec = e.router.route(tag, &dest).await;
                match e.outs.get(&dec.outbound) {
                    Some(Out::Block) | None => {}
                    Some(Out::Tunnel) => {
                        let key = dest.target();
                        if !flows.contains_key(&key) {
                            let Some(pool) = e.pool.as_ref() else { continue };
                            let Some(mut tu) = pool.open_udp(&key).await else { continue };
                            let (relay_t, client_t, dest_t) = (relay.clone(), client_addr.clone(), dest.clone());
                            let mut rx = std::mem::replace(&mut tu.rx, tokio::sync::mpsc::unbounded_channel().1);
                            let h = tokio::spawn(async move {
                                while let Some(b) = rx.recv().await {
                                    let Some(c) = *client_t.lock().unwrap() else { continue };
                                    let mut out = proxy::udp_reply_header(&dest_t);
                                    out.extend_from_slice(&b);
                                    let _ = relay_t.send_to(&out, c).await;
                                }
                            });
                            flows.insert(key.clone(), (tu, h));
                        }
                        if let Some((tu, _)) = flows.get(&key) {
                            let _ = tu.send(data).await;
                        }
                    }
                    Some(Out::Direct) => {
                        let ip = match &dest.host {
                            Host::Ip(ip) => Some(*ip),
                            Host::Domain(d) => tokio::net::lookup_host((d.as_str(), dest.port)).await.ok().and_then(|mut a| a.next()).map(|a| a.ip()),
                        };
                        if let Some(ip) = ip {
                            let _ = direct.send_to(data, SocketAddr::new(ip, dest.port)).await;
                        }
                    }
                    Some(Out::Socks { .. }) => {}
                }
            }
        }
    }
    back_direct.abort();
    for (_, (tu, h)) in flows.drain() {
        h.abort();
        tu.close().await;
    }
    Ok(())
}

async fn reply_ok(s: &mut TcpStream, k: Kind) -> Result<()> {
    match k {
        Kind::Socks | Kind::SocksUdp => proxy::socks_reply(s, 0).await?,
        Kind::HttpConnect => proxy::http_connected(s).await?,
        Kind::HttpPlain => {}
    }
    Ok(())
}

async fn reply_failed(s: &mut TcpStream, k: Kind, code: u8) {
    match k {
        Kind::Socks | Kind::SocksUdp => {
            let _ = proxy::socks_reply(s, code).await;
        }
        _ => proxy::http_fail(s, "502 Bad Gateway").await,
    }
}

async fn reply_denied(s: &mut TcpStream, k: Kind) {
    match k {
        Kind::Socks | Kind::SocksUdp => {
            let _ = proxy::socks_reply(s, 2).await;
        }
        _ => proxy::http_fail(s, "403 Forbidden").await,
    }
}

async fn connect_direct(dest: &Dest, resolved: &[IpAddr]) -> std::io::Result<TcpStream> {
    let mut addrs: Vec<SocketAddr> = match &dest.host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, dest.port)],
        Host::Domain(d) => {
            if resolved.is_empty() {
                tokio::net::lookup_host((d.as_str(), dest.port))
                    .await?
                    .collect()
            } else {
                resolved
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, dest.port))
                    .collect()
            }
        }
    };
    addrs.sort_by_key(|a| a.is_ipv6());
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses for host");
    for a in addrs {
        match timeout(Duration::from_secs(6), TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                s.set_nodelay(true).ok();
                return Ok(s);
            }
            Ok(Err(err)) => last = err,
            Err(_) => last = std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"),
        }
    }
    Err(last)
}

async fn connect_socks(
    server: &str,
    auth: &Option<(String, String)>,
    dest: &Dest,
) -> Result<TcpStream> {
    let mut s = timeout(Duration::from_secs(10), TcpStream::connect(server))
        .await
        .map_err(|_| anyhow!("upstream socks {server}: connect timed out"))??;
    s.set_nodelay(true).ok();
    if auth.is_some() {
        s.write_all(&[5, 2, 0, 2]).await?;
    } else {
        s.write_all(&[5, 1, 0]).await?;
    }
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await?;
    if m[0] != 5 || m[1] == 0xff {
        bail!("upstream socks {server} refused our auth methods");
    }
    if m[1] == 2 {
        let (u, p) = auth
            .as_ref()
            .ok_or_else(|| anyhow!("upstream socks wants auth but none is configured"))?;
        let mut req = vec![1, u.len() as u8];
        req.extend_from_slice(u.as_bytes());
        req.push(p.len() as u8);
        req.extend_from_slice(p.as_bytes());
        s.write_all(&req).await?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await?;
        if r[1] != 0 {
            bail!("upstream socks {server} rejected our credentials");
        }
    }
    let mut req = vec![5, 1, 0];
    match &dest.host {
        Host::Ip(IpAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.octets());
        }
        Host::Ip(IpAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.octets());
        }
        Host::Domain(d) => {
            if d.len() > 255 {
                bail!("domain too long for SOCKS5");
            }
            req.push(3);
            req.push(d.len() as u8);
            req.extend_from_slice(d.as_bytes());
        }
    }
    req.extend_from_slice(&dest.port.to_be_bytes());
    s.write_all(&req).await?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    if h[1] != 0 {
        bail!("upstream socks {server}: connect failed (code {})", h[1]);
    }
    let skip = match h[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        t => bail!("upstream socks sent unknown address type {t}"),
    };
    let mut junk = vec![0u8; skip];
    s.read_exact(&mut junk).await?;
    Ok(s)
}
