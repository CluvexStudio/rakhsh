use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::config::{Config, DnsCfg};
use crate::engine::{Engine, Out};
use crate::entry::Pool;
use crate::route::{parse_cidr, Cidr, Dest, Host};

const RCODE_FORMERR: u8 = 1;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;

pub fn parse_question(pkt: &[u8]) -> Option<(String, u16, u16, usize)> {
    if pkt.len() < 12 || u16::from_be_bytes([pkt[4], pkt[5]]) != 1 {
        return None;
    }
    let (mut pos, mut name) = (12usize, String::new());
    loop {
        let len = *pkt.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let label = pkt.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
        if name.len() > 255 {
            return None;
        }
    }
    let t = pkt.get(pos..pos + 4)?;
    Some((
        name,
        u16::from_be_bytes([t[0], t[1]]),
        u16::from_be_bytes([t[2], t[3]]),
        pos + 4,
    ))
}

fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

fn skip_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let b = *pkt.get(pos)?;
        match b & 0xC0 {
            0 if b == 0 => return Some(pos + 1),
            0 => pos += 1 + b as usize,
            0xC0 => return Some(pos + 2),
            _ => return None,
        }
    }
}

struct Rr {
    answer: bool,
    typ: u16,
    ttl: u32,
    rdata: (usize, usize),
}

fn records(pkt: &[u8]) -> Option<Vec<Rr>> {
    if pkt.len() < 12 {
        return None;
    }
    let (qd, an, ns, ar) = (
        u16::from_be_bytes([pkt[4], pkt[5]]) as usize,
        u16::from_be_bytes([pkt[6], pkt[7]]) as usize,
        u16::from_be_bytes([pkt[8], pkt[9]]) as usize,
        u16::from_be_bytes([pkt[10], pkt[11]]) as usize,
    );
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(pkt, pos)? + 4;
    }
    let mut out = Vec::new();
    for i in 0..an + ns + ar {
        pos = skip_name(pkt, pos)?;
        let h = pkt.get(pos..pos + 10)?;
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        pos += 10;
        pkt.get(pos..pos + rdlen)?;
        out.push(Rr {
            answer: i < an,
            typ: u16::from_be_bytes([h[0], h[1]]),
            ttl: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
            rdata: (pos, pos + rdlen),
        });
        pos += rdlen;
    }
    Some(out)
}

pub fn answer_ips(pkt: &[u8]) -> Vec<IpAddr> {
    let mut v = Vec::new();
    for r in records(pkt).unwrap_or_default().iter().filter(|r| r.answer) {
        let d = &pkt[r.rdata.0..r.rdata.1];
        match (r.typ, d.len()) {
            (1, 4) => v.push(IpAddr::V4(Ipv4Addr::new(d[0], d[1], d[2], d[3]))),
            (28, 16) => v.push(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(d).unwrap()))),
            _ => {}
        }
    }
    v
}

fn min_ttl(pkt: &[u8]) -> Option<u32> {
    records(pkt)?
        .iter()
        .filter(|r| r.typ != 41)
        .map(|r| r.ttl)
        .min()
}

fn rcode(pkt: &[u8]) -> u8 {
    pkt.get(3).map_or(RCODE_SERVFAIL, |b| b & 0x0F)
}

fn truncated(pkt: &[u8]) -> bool {
    pkt.get(2).is_some_and(|b| b & 0x02 != 0)
}

fn set_id(pkt: &mut [u8], id: [u8; 2]) {
    if pkt.len() >= 2 {
        pkt[..2].copy_from_slice(&id);
    }
}

fn error_reply(q: &[u8], code: u8) -> Vec<u8> {
    let end = parse_question(q).map_or(12.min(q.len()), |(.., end)| end);
    let mut r = q[..end].to_vec();
    r.resize(end.max(12), 0);
    r[2] = 0x80 | (q.get(2).copied().unwrap_or(0) & 0x01);
    r[3] = 0x80 | code;
    r[6..12].fill(0);
    r
}

struct Cache {
    map: HashMap<(String, u16, u16), (Instant, Vec<u8>)>,
    cap: usize,
}

impl Cache {
    fn get(&self, key: &(String, u16, u16), now: Instant) -> Option<Vec<u8>> {
        self.map
            .get(key)
            .filter(|(exp, _)| *exp > now)
            .map(|(_, r)| r.clone())
    }

    fn put(&mut self, key: (String, u16, u16), resp: Vec<u8>, ttl: Duration, now: Instant) {
        if self.cap == 0 {
            return;
        }
        if self.map.len() >= self.cap {
            self.map.retain(|_, (exp, _)| *exp > now);
            if self.map.len() >= self.cap {
                self.map.clear();
            }
        }
        self.map.insert(key, (now + ttl, resp));
    }
}

fn parse_server(s: &str) -> Result<SocketAddr> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    let ip: IpAddr = s
        .trim_matches(|c| c == '[' || c == ']')
        .parse()
        .with_context(|| format!("bad DNS server {s:?}"))?;
    Ok(SocketAddr::new(ip, 53))
}

fn resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|r| {
            r.split_whitespace()
                .next()
                .and_then(|a| parse_server(a).ok())
        })
        .collect()
}

async fn udp_exchange(server: SocketAddr, q: &[u8], wait: Duration) -> Result<Vec<u8>> {
    let sock = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    sock.connect(server).await?;
    sock.send(q).await?;
    let mut buf = vec![0u8; 4096];
    tokio::time::timeout(wait, async {
        loop {
            let n = sock.recv(&mut buf).await?;
            if n >= 12 && buf[..2] == q[..2] {
                return Ok::<Vec<u8>, anyhow::Error>(buf[..n].to_vec());
            }
        }
    })
    .await
    .map_err(|_| anyhow!("{server}: no answer in {}s", wait.as_secs()))?
}

async fn tcp_on<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S, q: &[u8]) -> Result<Vec<u8>> {
    s.write_all(&(q.len() as u16).to_be_bytes()).await?;
    s.write_all(q).await?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await?;
    let mut r = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut r).await?;
    Ok(r)
}

enum Where {
    Local,
    Remote,
    Block,
}

pub struct Dns {
    engine: Arc<Engine>,
    allow: Vec<Cidr>,
    local: Vec<SocketAddr>,
    remote: Vec<SocketAddr>,
    wait: Duration,
    min_ttl: u32,
    max_ttl: u32,
    cache: Mutex<Cache>,
}

pub async fn spawn(cfg: &Config, engine: Arc<Engine>) -> Result<bool> {
    let Some(d) = &cfg.dns else { return Ok(false) };
    let listen: SocketAddr = d
        .listen
        .parse()
        .with_context(|| format!("[dns] listen {:?} must be ip:port", d.listen))?;
    let dns = Arc::new(Dns::new(d, engine, listen)?);
    let udp = Arc::new(
        UdpSocket::bind(listen)
            .await
            .with_context(|| format!("DNS UDP on {listen}"))?,
    );
    let tcp = TcpListener::bind(listen)
        .await
        .with_context(|| format!("DNS TCP on {listen}"))?;
    info!(
        "dns listening on {listen}: local {}, remote {} ({})",
        dns.local
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        dns.remote
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        if dns.engine.pool.is_some() {
            "through the tunnel"
        } else {
            "no tunnel here: asked directly"
        }
    );
    let busy = Arc::new(Semaphore::new(256));
    let (d1, u1) = (dns.clone(), udp.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = u1.recv_from(&mut buf).await else {
                continue;
            };
            if !d1.permits(&peer.ip()) {
                continue;
            }
            let Ok(permit) = busy.clone().acquire_owned().await else {
                return;
            };
            let (q, d, u) = (buf[..n].to_vec(), d1.clone(), u1.clone());
            tokio::spawn(async move {
                let _p = permit;
                if let Some(r) = d.handle(&q).await {
                    let _ = u.send_to(&r, peer).await;
                }
            });
        }
    });
    tokio::spawn(async move {
        loop {
            let Ok((mut s, peer)) = tcp.accept().await else {
                continue;
            };
            if !dns.permits(&peer.ip()) {
                continue;
            }
            let d = dns.clone();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    match tokio::time::timeout(Duration::from_secs(30), s.read_exact(&mut len))
                        .await
                    {
                        Ok(Ok(_)) => {}
                        _ => return,
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    let Some(r) = d.handle(&q).await else { return };
                    if s.write_all(&(r.len() as u16).to_be_bytes()).await.is_err()
                        || s.write_all(&r).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Ok(true)
}

impl Dns {
    fn new(c: &DnsCfg, engine: Arc<Engine>, listen: SocketAddr) -> Result<Dns> {
        let servers = |v: &[String]| {
            v.iter()
                .map(|s| parse_server(s))
                .collect::<Result<Vec<_>>>()
        };
        let mut local = servers(&c.local)?;
        if local.is_empty() {
            local = resolv_conf(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())
                .into_iter()
                .filter(|a| *a != listen && !(a.ip().is_loopback() && a.port() == listen.port()))
                .collect();
        }
        let mut remote = servers(&c.remote)?;
        if remote.is_empty() {
            remote = vec!["1.1.1.1:53".parse()?, "8.8.8.8:53".parse()?];
        }
        if local.is_empty() {
            bail!("[dns] has no local resolver: set `local = [\"…\"]` (this host's /etc/resolv.conf names none usable)");
        }
        let allow = c
            .allow
            .iter()
            .map(|a| {
                parse_cidr(a).ok_or_else(|| {
                    anyhow!("[dns] allow: bad network {a:?} (use e.g. 192.168.0.0/16)")
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if allow.is_empty() && !listen.ip().is_loopback() {
            warn!("dns on {listen} answers anyone who can reach it (an open resolver); set `allow = [\"<your clients' network>\"]` or listen on a private address");
        }
        Ok(Dns {
            engine,
            allow,
            local,
            remote,
            wait: Duration::from_secs(c.timeout.unwrap_or(3).max(1)),
            min_ttl: c.cache_min_ttl.unwrap_or(30),
            max_ttl: c.cache_max_ttl.unwrap_or(3600).max(1),
            cache: Mutex::new(Cache {
                map: HashMap::new(),
                cap: c.cache.unwrap_or(4096),
            }),
        })
    }

    fn permits(&self, ip: &IpAddr) -> bool {
        self.allow.is_empty() || self.allow.iter().any(|c| c.contains(ip))
    }

    async fn handle(&self, q: &[u8]) -> Option<Vec<u8>> {
        if q.len() < 2 {
            return None;
        }
        let id = [q[0], q[1]];
        let Some((name, qtype, qclass, _)) = parse_question(q) else {
            return Some(error_reply(q, RCODE_FORMERR));
        };
        let key = (name.clone(), qtype, qclass);
        if let Some(mut hit) = self.cache.lock().unwrap().get(&key, Instant::now()) {
            set_id(&mut hit, id);
            debug!("dns {name} {qtype}: cache");
            return Some(hit);
        }
        let (route, early) = self.decide(&name, qtype).await;
        let resp = match route {
            Where::Block => {
                debug!("dns {name}: blocked");
                return Some(error_reply(q, RCODE_NXDOMAIN));
            }
            Where::Local => match early {
                Some(r) => Ok(r),
                None => self.query_local(q).await,
            },
            Where::Remote => self.query_remote(q).await,
        };
        match resp {
            Ok(mut r) => {
                set_id(&mut r, id);
                let ttl = match rcode(&r) {
                    0 => min_ttl(&r).map(|t| t.clamp(self.min_ttl, self.max_ttl)),
                    RCODE_NXDOMAIN => Some(30),
                    _ => None,
                };
                if let Some(t) = ttl {
                    self.cache.lock().unwrap().put(
                        key,
                        r.clone(),
                        Duration::from_secs(u64::from(t)),
                        Instant::now(),
                    );
                }
                Some(r)
            }
            Err(e) => {
                warn!("dns {name}: {e:#}");
                Some(error_reply(q, RCODE_SERVFAIL))
            }
        }
    }

    async fn decide(&self, name: &str, qtype: u16) -> (Where, Option<Vec<u8>>) {
        let fetched: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let f2 = fetched.clone();
        let dest = Dest {
            host: Host::Domain(name.to_string()),
            port: 53,
        };
        let dec = self
            .engine
            .router
            .route_with("dns", &dest, |d, _| {
                let (f, this) = (f2.clone(), self);
                async move {
                    let probe = build_query(0x7261, &d, if qtype == 28 { 28 } else { 1 });
                    match this.query_local(&probe).await {
                        Ok(r) => {
                            let ips = answer_ips(&r);
                            *f.lock().unwrap() = Some(r);
                            ips
                        }
                        Err(_) => Vec::new(),
                    }
                }
            })
            .await;
        let route = match self.engine.outs.get(&dec.outbound) {
            Some(Out::Block) => Where::Block,
            Some(Out::Tunnel) | Some(Out::Socks { .. }) => Where::Remote,
            _ => Where::Local,
        };
        let early = fetched
            .lock()
            .unwrap()
            .take()
            .filter(|r| parse_question(r).is_some_and(|x| x.1 == qtype));
        (route, early)
    }

    async fn query_local(&self, q: &[u8]) -> Result<Vec<u8>> {
        let mut last = anyhow!("no local resolver");
        for &srv in &self.local {
            match udp_exchange(srv, q, self.wait).await {
                Ok(r) if truncated(&r) => match self.tcp_direct(srv, q).await {
                    Ok(full) => return Ok(full),
                    Err(_) => return Ok(r),
                },
                Ok(r) => return Ok(r),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn query_remote(&self, q: &[u8]) -> Result<Vec<u8>> {
        let mut last = anyhow!("no remote resolver");
        for &srv in &self.remote {
            let r = match &self.engine.pool {
                Some(pool) => tunnel_udp(pool, srv, q, self.wait).await,
                None => udp_exchange(srv, q, self.wait).await,
            };
            match r {
                Ok(r) if truncated(&r) => match self.tcp_remote(srv, q).await {
                    Ok(full) => return Ok(full),
                    Err(_) => return Ok(r),
                },
                Ok(r) => return Ok(r),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn tcp_direct(&self, srv: SocketAddr, q: &[u8]) -> Result<Vec<u8>> {
        let mut s = tokio::time::timeout(self.wait, TcpStream::connect(srv))
            .await
            .map_err(|_| anyhow!("{srv}: tcp connect timed out"))??;
        tokio::time::timeout(self.wait, tcp_on(&mut s, q))
            .await
            .map_err(|_| anyhow!("{srv}: tcp answer timed out"))?
    }

    async fn tcp_remote(&self, srv: SocketAddr, q: &[u8]) -> Result<Vec<u8>> {
        let Some(pool) = &self.engine.pool else {
            return self.tcp_direct(srv, q).await;
        };
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let (mine, theirs) = tokio::try_join!(TcpStream::connect(addr), async {
            l.accept().await.map(|x| x.0)
        })?;
        let ts = pool
            .open_tcp(&srv.to_string())
            .await
            .ok_or_else(|| anyhow!("no live lane"))?;
        tokio::spawn(async move { ts.relay(theirs, &[], None).await });
        let mut mine = mine;
        tokio::time::timeout(self.wait * 2, tcp_on(&mut mine, q))
            .await
            .map_err(|_| anyhow!("{srv}: tcp answer timed out (tunnel)"))?
    }
}

async fn tunnel_udp(pool: &Pool, srv: SocketAddr, q: &[u8], wait: Duration) -> Result<Vec<u8>> {
    let mut flow = pool
        .open_udp(&srv.to_string())
        .await
        .ok_or_else(|| anyhow!("no live lane"))?;
    flow.send(q).await;
    let r = tokio::time::timeout(wait, async {
        while let Some(b) = flow.rx.recv().await {
            if b.len() >= 12 && b[..2] == q[..2] {
                return Some(b.to_vec());
            }
        }
        None
    })
    .await;
    flow.close().await;
    match r {
        Ok(Some(b)) => Ok(b),
        Ok(None) => Err(anyhow!("{srv}: tunnel flow closed")),
        Err(_) => Err(anyhow!(
            "{srv}: no answer through the tunnel in {}s",
            wait.as_secs()
        )),
    }
}

#[cfg(test)]
#[path = "../tests/unit/dns.rs"]
mod tests;
