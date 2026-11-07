use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::Arc;
use std::task::{Context as TaskCtx, Poll};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use bytes::{Buf, BytesMut};

use crate::wire::{read_frame, write_frame};

#[async_trait]
pub trait FrameTx: Send {
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()>;
    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[async_trait]
pub trait FrameRx: Send {
    async fn recv(&mut self) -> io::Result<BytesMut>;
}

pub(crate) fn into_bytes_mut(v: Vec<u8>) -> BytesMut {
    bytes::Bytes::from(v)
        .try_into_mut()
        .unwrap_or_else(|b| BytesMut::from(&b[..]))
}

pub type BoxTx = Box<dyn FrameTx>;
pub type BoxRx = Box<dyn FrameRx>;

struct ByteTx<W> {
    w: W,
    pending: Vec<([u8; 2], Vec<u8>)>,
    bytes: usize,
}
struct ByteRx<R> {
    r: R,
    buf: BytesMut,
}
const IO_BUF: usize = 256 * 1024;

#[async_trait]
impl<W: AsyncWrite + Unpin + Send> FrameTx for ByteTx<W> {
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        if frame.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        self.bytes += 2 + frame.len();
        self.pending
            .push(((frame.len() as u16).to_be_bytes(), frame));
        if self.bytes >= IO_BUF || self.pending.len() >= 256 {
            self.flush().await?;
        }
        Ok(())
    }
    async fn flush(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        if self.pending.is_empty() {
            return Ok(());
        }
        let mut slices: Vec<std::io::IoSlice<'_>> = Vec::with_capacity(self.pending.len() * 2);
        for (prefix, body) in &self.pending {
            slices.push(std::io::IoSlice::new(prefix));
            slices.push(std::io::IoSlice::new(body));
        }
        let mut bufs: &mut [std::io::IoSlice<'_>] = &mut slices;
        while !bufs.is_empty() {
            let n = self.w.write_vectored(bufs).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            std::io::IoSlice::advance_slices(&mut bufs, n);
        }
        drop(slices);
        self.pending.clear();
        self.bytes = 0;
        self.w.flush().await
    }
}

#[async_trait]
impl<R: AsyncRead + Unpin + Send> FrameRx for ByteRx<R> {
    async fn recv(&mut self) -> io::Result<BytesMut> {
        use tokio::io::AsyncReadExt;
        loop {
            if self.buf.len() >= 2 {
                let n = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "zero-length frame",
                    ));
                }
                if self.buf.len() >= 2 + n {
                    self.buf.advance(2);
                    return Ok(self.buf.split_to(n));
                }
                self.buf.reserve(2 + n - self.buf.len());
            }
            if self.buf.capacity() - self.buf.len() < 4096 {
                self.buf.reserve(IO_BUF);
            }
            if self.r.read_buf(&mut self.buf).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof inside record",
                ));
            }
        }
    }
}

pub fn split_bytes<S>(s: S) -> (BoxTx, BoxRx)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (r, w) = tokio::io::split(s);
    (
        Box::new(ByteTx {
            w,
            pending: Vec::new(),
            bytes: 0,
        }),
        Box::new(ByteRx {
            r,
            buf: BytesMut::with_capacity(IO_BUF),
        }),
    )
}

struct RawTx<W>(W);
struct RawRx<R>(R);

#[async_trait]
impl<W: AsyncWrite + Unpin + Send> FrameTx for RawTx<W> {
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        write_frame(&mut self.0, &frame).await
    }
}

#[async_trait]
impl<R: AsyncRead + Unpin + Send> FrameRx for RawRx<R> {
    async fn recv(&mut self) -> io::Result<BytesMut> {
        read_frame(&mut self.0).await.map(into_bytes_mut)
    }
}

pub fn split_bytes_unbuffered<S>(s: S) -> (BoxTx, BoxRx)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (r, w) = tokio::io::split(s);
    (Box::new(RawTx(w)), Box::new(RawRx(r)))
}

struct WsTx<S>(futures_util::stream::SplitSink<WebSocketStream<S>, Message>);
struct WsRx<S>(futures_util::stream::SplitStream<WebSocketStream<S>>);

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> FrameTx for WsTx<S> {
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.0
            .feed(Message::Binary(frame.into()))
            .await
            .map_err(io::Error::other)
    }
    async fn flush(&mut self) -> io::Result<()> {
        self.0.flush().await.map_err(io::Error::other)
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> FrameRx for WsRx<S> {
    async fn recv(&mut self) -> io::Result<BytesMut> {
        loop {
            match self.0.next().await {
                Some(Ok(Message::Binary(b))) => {
                    return Ok(b.try_into_mut().unwrap_or_else(|b| BytesMut::from(&b[..])))
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(io::Error::other(e)),
                None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ws closed")),
            }
        }
    }
}

fn dials(cfg: &crate::config::Config) -> bool {
    cfg.role == cfg.dial.as_deref().unwrap_or("exit")
}

#[cfg(feature = "acme")]
fn server_tls(cfg: &crate::config::Config, sni: &str) -> Result<TlsAcceptor> {
    let Some(domain) = cfg.acme_domain.as_deref() else {
        return tls::acceptor(sni, &cfg.cert_path, &cfg.key_path);
    };
    if cfg.inspect_only || dials(cfg) {
        return tls::acceptor(domain, &None, &None);
    }
    if cfg.cert_path.is_some() || cfg.key_path.is_some() {
        bail!("set either acme_domain or cert_path/key_path, not both");
    }
    let acme = crate::acme::Acme::from_config(
        domain,
        &cfg.acme_email,
        &cfg.acme_dir,
        cfg.acme_port,
        cfg.acme_staging,
    )?;
    tls::acceptor_resolved(crate::acme::start(&acme)?)
}

#[cfg(not(feature = "acme"))]
fn server_tls(cfg: &crate::config::Config, sni: &str) -> Result<TlsAcceptor> {
    if cfg.acme_domain.is_some() {
        bail!("acme_domain needs the \"acme\" feature, which this build does not have");
    }
    tls::acceptor(sni, &cfg.cert_path, &cfg.key_path)
}

fn ws_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .read_buffer_size(40 * 1024)
        .write_buffer_size(64 * 1024)
}

fn split_ws<S>(ws: WebSocketStream<S>) -> (BoxTx, BoxRx)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = ws.split();
    (Box::new(WsTx(sink)), Box::new(WsRx(stream)))
}

mod camo {
    use super::*;
    use base64::prelude::{Engine, BASE64_STANDARD};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::Role;

    fn accept_key(key: &str) -> String {
        let mut data = key.as_bytes().to_vec();
        data.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let d = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
        BASE64_STANDARD.encode(d.as_ref())
    }

    fn decoy_page() -> String {
        "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n\
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style>\n\
</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is \
successfully installed and working. Further configuration is required.</p>\n\
<p>For online documentation and support please refer to\n<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\n\
Commercial support is available at\n<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n\
<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n"
            .to_string()
    }

    async fn serve_decoy<S>(mut s: S, status: &str)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let body = decoy_page();
        let now = httpdate_now();
        let resp = format!(
            "HTTP/1.1 {status}\r\nServer: nginx\r\nDate: {now}\r\nContent-Type: text/html; charset=UTF-8\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = s.write_all(resp.as_bytes()).await;
    }

    fn httpdate_now() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
        const MON: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let days = secs / 86400;
        let dow = DAYS[(days % 7) as usize];
        let (mut y, mut d) = (1970i64, days as i64);
        loop {
            let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
            let yl = if leap { 366 } else { 365 };
            if d < yl {
                break;
            }
            d -= yl;
            y += 1;
        }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let mlen = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut m = 0usize;
        while d >= mlen[m] {
            d -= mlen[m];
            m += 1;
        }
        let sod = secs % 86400;
        format!(
            "{dow}, {:02} {} {} {:02}:{:02}:{:02} GMT",
            d + 1,
            MON[m],
            y,
            sod / 3600,
            (sod % 3600) / 60,
            sod % 60
        )
    }

    pub async fn ws_accept<S>(
        mut s: S,
        ws_path: &str,
        cred: &Option<String>,
        decoy: bool,
    ) -> Result<Option<WebSocketStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 2048];
        loop {
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                return Ok(None);
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 32 * 1024 {
                break;
            }
        }
        let req = String::from_utf8_lossy(&buf);
        let lower = req.to_ascii_lowercase();
        let first = req.lines().next().unwrap_or("");
        let target = first.split_whitespace().nth(1).unwrap_or("");
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let is_ws = lower.contains("upgrade: websocket");
        let key = req.lines().find_map(|l| {
            let p = l.splitn(2, ':').collect::<Vec<_>>();
            if p.len() == 2 && p[0].trim().eq_ignore_ascii_case("sec-websocket-key") {
                Some(p[1].trim().to_string())
            } else {
                None
            }
        });
        let cred_ok = match cred {
            Some(c) => query.split('&').any(|kv| kv == format!("k={c}")),
            None => true,
        };
        if is_ws && path == ws_path && cred_ok {
            if let Some(k) = key {
                let resp = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Accept: {}\r\nServer: nginx\r\n\r\n",
                    accept_key(&k)
                );
                s.write_all(resp.as_bytes()).await?;
                return Ok(Some(
                    WebSocketStream::from_raw_socket(s, Role::Server, Some(ws_config())).await,
                ));
            }
        }
        if decoy {
            let status = if is_ws { "400 Bad Request" } else { "200 OK" };
            serve_decoy(s, status).await;
        }
        Ok(None)
    }
}

#[derive(Clone)]
pub struct Carrier(Arc<Inner>);

enum Inner {
    Stream {
        tls: bool,
        ws: bool,
        sni: String,
        ws_path: String,
        ws_credential: Option<String>,
        decoy: bool,
        edge_ip: Option<String>,
        tune: SockTune,
        acceptor: Option<TlsAcceptor>,
        connector: Option<TlsConnector>,
        frag: usize,
    },
    Quic {
        sni: String,
        server: quinn::ServerConfig,
        client_ep: quinn::Endpoint,
        mask_key: [u8; 32],
        mask: bool,
    },
    Kcp {
        config: tokio_kcp::KcpConfig,
    },
    Raw {
        kind: String,
        params: crate::raw::RawParams,
        spoof: crate::raw::SpoofOpts,
        spoof_peer: Option<Ipv4Addr>,
        fec: Option<(usize, usize)>,
        reliability: String,
        counter: Arc<AtomicU64>,
    },
    RamaQuic(Arc<crate::ramaquic::RamaQuic>),
}

impl Carrier {
    pub fn lanes_override(&self) -> Option<usize> {
        match &*self.0 {
            Inner::Raw { .. } => Some(crate::raw::RAW_LANES as usize),
            _ => None,
        }
    }

    pub fn from_cfg(cfg: &crate::config::Config) -> Result<Carrier> {
        let kind = cfg.carrier.as_deref().unwrap_or("tcp");
        quic::set_congestion(cfg.congestion.as_deref());
        quic::set_bind(cfg.bind.as_deref());
        let sni = cfg.sni.as_deref().unwrap_or("www.cloudflare.com");
        let ws_path = cfg.ws_path.as_deref().unwrap_or("/");
        let parse_ip =
            |o: &Option<String>| -> Option<Ipv4Addr> { o.as_deref().and_then(|s| s.parse().ok()) };
        let mut pool: Vec<Ipv4Addr> = Vec::new();
        for s in cfg.spoof_src_ip.iter().chain(cfg.spoof_src_pool.iter()) {
            for p in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                if let Ok(ip) = p.parse::<Ipv4Addr>() {
                    if !pool.contains(&ip) {
                        pool.push(ip);
                    }
                }
            }
        }
        let inner = match kind {
            "faketcp" | "icmp" | "spoof" | "l2tcp" => Inner::Raw {
                kind: kind.to_string(),
                params: crate::raw::RawParams::derive(&cfg.token),
                spoof: crate::raw::SpoofOpts {
                    pool,
                    sockbuf: cfg.spoof_sockbuf,
                    ttl_jitter: cfg.spoof_ttl_jitter.unwrap_or(false),
                    dscp_jitter: cfg.spoof_dscp_jitter.unwrap_or(false),
                    rotate_secs: cfg.spoof_rotate_secs.unwrap_or(0),
                    link_encrypt: cfg.link_encrypt.unwrap_or(true),
                    peer_src: cfg
                        .spoof_peer_src
                        .as_deref()
                        .unwrap_or("")
                        .split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect(),
                },
                spoof_peer: parse_ip(&cfg.spoof_peer_ip),
                fec: match (cfg.fec_data, cfg.fec_parity) {
                    (Some(d), Some(p)) if d > 0 && p > 0 => Some((d, p)),
                    _ => None,
                },
                reliability: cfg.reliability.clone().unwrap_or_else(|| "quic".into()),
                counter: Arc::new(AtomicU64::new(0)),
            },
            "tcp" | "tls" | "ws" | "wss" => {
                let tls = matches!(kind, "tls" | "wss");
                let ws = matches!(kind, "ws" | "wss");
                let fp = cfg.tls_fingerprint.as_deref().unwrap_or("chrome");
                let (acceptor, connector) = if tls {
                    (Some(server_tls(cfg, sni)?), Some(tls::connector(fp)?))
                } else {
                    (None, None)
                };
                let t = cfg.tuning();
                Inner::Stream {
                    tls,
                    ws,
                    sni: sni.to_string(),
                    ws_path: ws_path.to_string(),
                    ws_credential: cfg.ws_credential.clone(),
                    decoy: cfg.decoy.unwrap_or(ws),
                    edge_ip: cfg.edge_ip.clone(),
                    tune: SockTune {
                        rcvbuf: t.rcvbuf,
                        sndbuf: t.sndbuf,
                        keepalive: t.keepalive,
                    },
                    acceptor,
                    connector,
                    frag: cfg.tls_frag.unwrap_or(0),
                }
            }
            "quic" | "quic-quinn" => {
                let mask = cfg.quic_mask.unwrap_or(false);
                let version = cfg.quic_version.unwrap_or(0xff00_001d);
                let mask_key = blake3::derive_key("rakhsh-quic-mask-v1", cfg.token.as_bytes());
                let server = quic::server_config(sni)?;
                let client_ep = quic::client_endpoint(mask_key, mask, version)
                    .context("quic client endpoint")?;
                Inner::Quic {
                    sni: sni.to_string(),
                    server,
                    client_ep,
                    mask_key,
                    mask,
                }
            }
            "kcp" => Inner::Kcp {
                config: kcp::config(),
            },
            "quicv2" => Inner::RamaQuic(Arc::new(crate::ramaquic::RamaQuic::new(sni))),
            other => return Err(anyhow!("unknown carrier {other:?}")),
        };
        Ok(Carrier(Arc::new(inner)))
    }

    pub async fn dial(&self, addr: &str) -> Result<(BoxTx, BoxRx)> {
        match &*self.0 {
            Inner::Stream {
                tls,
                ws,
                sni,
                ws_path,
                ws_credential,
                edge_ip,
                tune,
                connector,
                frag,
                ..
            } => {
                let dial_to = edge_ip.clone().unwrap_or_else(|| addr.to_string());
                let tcp = TcpStream::connect(&dial_to)
                    .await
                    .with_context(|| format!("connecting to {dial_to}"))?;
                tcp.set_nodelay(true).ok();
                tune_tcp(&tcp, tune);
                let q = match ws_credential {
                    Some(c) => format!("?k={c}"),
                    None => String::new(),
                };
                let url = format!("ws://{sni}{ws_path}{q}");
                match (tls, ws) {
                    (false, false) => Ok(split_bytes(tcp)),
                    (true, false) => {
                        Ok(split_bytes(tls_connect(connector, sni, tcp, *frag).await?))
                    }
                    (false, true) => {
                        let (w, _) = tokio_tungstenite::client_async_with_config(
                            &url,
                            tcp,
                            Some(ws_config()),
                        )
                        .await?;
                        Ok(split_ws(w))
                    }
                    (true, true) => {
                        let s = tls_connect(connector, sni, tcp, *frag).await?;
                        let (w, _) =
                            tokio_tungstenite::client_async_with_config(&url, s, Some(ws_config()))
                                .await?;
                        Ok(split_ws(w))
                    }
                }
            }
            Inner::Quic { sni, client_ep, .. } => {
                let sa: SocketAddr = addr.parse().context("quic addr must be ip:port")?;
                let conn = client_ep.connect(sa, sni)?.await?;
                let (send, recv) = conn.open_bi().await?;
                Ok(split_bytes_unbuffered(tokio::io::join(recv, send)))
            }
            Inner::Kcp { config } => {
                let sa: SocketAddr = addr.parse().context("kcp addr must be ip:port")?;
                let s = tokio_kcp::KcpStream::connect(config, sa)
                    .await
                    .map_err(|e| anyhow!("kcp connect: {e}"))?;
                Ok(split_bytes_unbuffered(s))
            }
            Inner::Raw {
                kind,
                params,
                spoof,
                counter,
                fec,
                reliability,
                ..
            } => {
                let peer = raw_peer_ip(addr)?;
                let lane = counter.fetch_add(1, SeqCst);
                let dial = crate::raw::Dial {
                    kind,
                    params,
                    spoof,
                    fec: *fec,
                    reliability,
                };
                crate::raw::connect(dial, true, Some(peer), lane).await
            }
            Inner::RamaQuic(rq) => rq.dial(addr).await,
        }
    }

    pub async fn bind(&self, addr: &str) -> Result<Listener> {
        match &*self.0 {
            Inner::Stream {
                acceptor,
                ws,
                ws_path,
                ws_credential,
                decoy,
                tune,
                ..
            } => {
                let l = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("binding lane listener {addr}"))?;
                Ok(Listener::Stream {
                    l,
                    tls: acceptor.clone(),
                    ws: *ws,
                    ws_path: ws_path.clone(),
                    ws_credential: ws_credential.clone(),
                    decoy: *decoy,
                    tune: *tune,
                })
            }
            Inner::Quic {
                server,
                mask_key,
                mask,
                ..
            } => {
                let ep = quic::server_endpoint(server.clone(), addr, *mask_key, *mask)
                    .context("quic server")?;
                Ok(Listener::Quic(ep))
            }
            Inner::Kcp { config } => {
                let sa: SocketAddr = addr.parse().context("kcp addr must be ip:port")?;
                let l = tokio_kcp::KcpListener::bind(*config, sa)
                    .await
                    .map_err(|e| anyhow!("kcp bind: {e}"))?;
                Ok(Listener::Kcp(Mutex::new(l)))
            }
            Inner::Raw {
                kind,
                params,
                spoof,
                spoof_peer,
                fec,
                reliability,
                ..
            } => Ok(Listener::Raw {
                kind: kind.clone(),
                params: *params,
                spoof: spoof.clone(),
                spoof_peer: *spoof_peer,
                fec: *fec,
                reliability: reliability.clone(),
                counter: AtomicU64::new(0),
            }),
            Inner::RamaQuic(_) => Ok(Listener::RamaQuic(
                crate::ramaquic::server_endpoint(addr).await?,
            )),
        }
    }
}

fn raw_peer_ip(addr: &str) -> Result<Ipv4Addr> {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    host.parse()
        .with_context(|| format!("raw carrier needs an ipv4 peer, got {addr}"))
}

#[derive(Clone, Copy)]
pub(crate) struct SockTune {
    rcvbuf: Option<usize>,
    sndbuf: Option<usize>,
    keepalive: u64,
}

fn tune_tcp(tcp: &TcpStream, t: &SockTune) {
    use socket2::{SockRef, TcpKeepalive};
    let r = SockRef::from(tcp);
    let secs = t.keepalive.max(5);
    let ka = TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(secs))
        .with_interval(std::time::Duration::from_secs((secs / 3).max(1)));
    let _ = r.set_tcp_keepalive(&ka);
    if let Some(n) = t.rcvbuf {
        let _ = r.set_recv_buffer_size(n);
    }
    if let Some(n) = t.sndbuf {
        let _ = r.set_send_buffer_size(n);
    }
}

const FRAG_BUDGET: usize = 2048;

struct FragWriter<T> {
    inner: T,
    left: usize,
    piece: usize,
}

impl<T> FragWriter<T> {
    fn new(inner: T, piece: usize) -> Self {
        let left = if piece == 0 { 0 } else { FRAG_BUDGET };
        Self { inner, left, piece }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FragWriter<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FragWriter<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.left == 0 {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        let n = buf.len().min(self.piece).min(self.left);
        let r = Pin::new(&mut self.inner).poll_write(cx, &buf[..n]);
        if let Poll::Ready(Ok(w)) = &r {
            self.left -= w;
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        false
    }
}

async fn tls_connect(
    connector: &Option<TlsConnector>,
    sni: &str,
    tcp: TcpStream,
    frag: usize,
) -> Result<tokio_rustls::client::TlsStream<FragWriter<TcpStream>>> {
    let name = rustls_pki_types::ServerName::try_from(sni.to_string()).context("invalid sni")?;
    Ok(connector
        .as_ref()
        .unwrap()
        .connect(name, FragWriter::new(tcp, frag))
        .await?)
}

pub enum Listener {
    Stream {
        l: TcpListener,
        tls: Option<TlsAcceptor>,
        ws: bool,
        ws_path: String,
        ws_credential: Option<String>,
        decoy: bool,
        tune: SockTune,
    },
    Quic(quinn::Endpoint),
    Kcp(Mutex<tokio_kcp::KcpListener>),
    Raw {
        kind: String,
        params: crate::raw::RawParams,
        spoof: crate::raw::SpoofOpts,
        spoof_peer: Option<Ipv4Addr>,
        fec: Option<(usize, usize)>,
        reliability: String,
        counter: AtomicU64,
    },
    RamaQuic(rama::quic::Endpoint),
}

impl Listener {
    pub async fn accept(&self) -> Result<(BoxTx, BoxRx)> {
        match self {
            Listener::Stream {
                l,
                tls,
                ws,
                ws_path,
                ws_credential,
                decoy,
                tune,
            } => loop {
                let (tcp, _peer) = l.accept().await?;
                tcp.set_nodelay(true).ok();
                tune_tcp(&tcp, tune);
                match (tls, ws) {
                    (None, false) => return Ok(split_bytes(tcp)),
                    (Some(a), false) => return Ok(split_bytes(a.accept(tcp).await?)),
                    (None, true) => {
                        match camo::ws_accept(tcp, ws_path, ws_credential, *decoy).await {
                            Ok(Some(w)) => return Ok(split_ws(w)),
                            _ => continue,
                        }
                    }
                    (Some(a), true) => {
                        let s = match a.accept(tcp).await {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        match camo::ws_accept(s, ws_path, ws_credential, *decoy).await {
                            Ok(Some(w)) => return Ok(split_ws(w)),
                            _ => continue,
                        }
                    }
                }
            },
            Listener::Quic(ep) => {
                let incoming = ep
                    .accept()
                    .await
                    .ok_or_else(|| anyhow!("quic endpoint closed"))?;
                let conn = incoming.await?;
                let (send, recv) = conn.accept_bi().await?;
                Ok(split_bytes_unbuffered(tokio::io::join(recv, send)))
            }
            Listener::Kcp(l) => {
                let (s, _peer) = l
                    .lock()
                    .await
                    .accept()
                    .await
                    .map_err(|e| anyhow!("kcp accept: {e}"))?;
                Ok(split_bytes_unbuffered(s))
            }
            Listener::Raw {
                kind,
                params,
                spoof,
                spoof_peer,
                fec,
                reliability,
                counter,
            } => {
                let lane = counter.fetch_add(1, SeqCst);
                if lane >= crate::raw::RAW_LANES {
                    std::future::pending::<()>().await;
                }
                let dial = crate::raw::Dial {
                    kind,
                    params,
                    spoof,
                    fec: *fec,
                    reliability,
                };
                crate::raw::connect(dial, false, *spoof_peer, lane).await
            }
            Listener::RamaQuic(ep) => crate::ramaquic::accept(ep).await,
        }
    }
}

pub(crate) fn raw_quic_configs() -> Result<(quinn::ServerConfig, quinn::ClientConfig)> {
    let mut s = quic::server_config("rakhsh")?;
    let mut c = quic::client_config(1)?;
    s.transport_config(quic::transport_raw());
    c.transport_config(quic::transport_raw());
    Ok((s, c))
}

pub(crate) fn noverify_connector() -> TlsConnector {
    TlsConnector::from(Arc::new(tls::client_config_noverify()))
}

pub(crate) mod tls {
    use super::*;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

    pub fn provider() -> Arc<CryptoProvider> {
        static P: std::sync::OnceLock<Arc<CryptoProvider>> = std::sync::OnceLock::new();
        P.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
            .clone()
    }

    pub fn server_cert(
        sni: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let ck = rcgen::generate_simple_self_signed(vec![sni.to_string()])
            .context("generating self-signed cert")?;
        let cert: CertificateDer<'static> = ck.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
        Ok((vec![cert], key))
    }

    pub fn acceptor(
        sni: &str,
        cert_path: &Option<String>,
        key_path: &Option<String>,
    ) -> Result<TlsAcceptor> {
        let (certs, key) = match (cert_path, key_path) {
            (Some(c), Some(k)) => load_pem(c, k)?,
            _ => server_cert(sni)?,
        };
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .context("selecting TLS versions")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building server TLS config")?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(TlsAcceptor::from(Arc::new(cfg)))
    }

    pub fn acceptor_resolved(
        resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    ) -> Result<TlsAcceptor> {
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .context("selecting TLS versions")?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(TlsAcceptor::from(Arc::new(cfg)))
    }

    fn load_pem(
        cert_path: &str,
        key_path: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        use base64::prelude::{Engine, BASE64_STANDARD};
        fn blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
            let (begin, end) = (
                format!("-----BEGIN {label}-----"),
                format!("-----END {label}-----"),
            );
            let mut out = Vec::new();
            let mut rest = pem;
            while let Some(s) = rest.find(&begin) {
                let after = &rest[s + begin.len()..];
                let Some(e) = after.find(&end) else { break };
                let b64: String = after[..e].split_whitespace().collect();
                if let Ok(der) = BASE64_STANDARD.decode(b64.as_bytes()) {
                    out.push(der);
                }
                rest = &after[e + end.len()..];
            }
            out
        }
        let cert_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("reading cert {cert_path}"))?;
        let key_pem =
            std::fs::read_to_string(key_path).with_context(|| format!("reading key {key_path}"))?;
        let certs: Vec<CertificateDer<'static>> = blocks(&cert_pem, "CERTIFICATE")
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        if certs.is_empty() {
            bail!("no CERTIFICATE block in {cert_path}");
        }
        let key = if let Some(d) = blocks(&key_pem, "PRIVATE KEY").into_iter().next() {
            PrivateKeyDer::Pkcs8(d.into())
        } else if let Some(d) = blocks(&key_pem, "RSA PRIVATE KEY").into_iter().next() {
            PrivateKeyDer::Pkcs1(d.into())
        } else if let Some(d) = blocks(&key_pem, "EC PRIVATE KEY").into_iter().next() {
            PrivateKeyDer::Sec1(d.into())
        } else {
            bail!("no private key block in {key_path}");
        };
        Ok((certs, key))
    }

    pub fn connector(fingerprint: &str) -> Result<TlsConnector> {
        let mut cfg = client_config_noverify();
        if fingerprint != "rustls" {
            cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        Ok(TlsConnector::from(Arc::new(cfg)))
    }

    pub fn client_config_noverify() -> rustls::ClientConfig {
        let p = provider();
        rustls::ClientConfig::builder_with_provider(p.clone())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(p)))
            .with_no_client_auth()
    }

    #[derive(Debug)]
    pub struct NoVerify(pub Arc<CryptoProvider>);

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _e: &CertificateDer,
            _i: &[CertificateDer],
            _n: &ServerName,
            _o: &[u8],
            _t: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

pub(crate) const QUIC_STREAM_WINDOW: u32 = 16 * 1024 * 1024;
pub(crate) const QUIC_SEND_WINDOW: u64 = 64 * 1024 * 1024;

mod quic {
    use super::*;
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

    const ALPN: &[&[u8]] = &[b"h3"];

    static BIND: std::sync::OnceLock<String> = std::sync::OnceLock::new();

    pub fn set_bind(addr: Option<&str>) {
        if let Some(a) = addr {
            let with_port = if a.contains(':') {
                a.to_string()
            } else {
                format!("{a}:0")
            };
            let _ = BIND.set(with_port);
        }
    }

    fn local() -> &'static str {
        BIND.get().map(String::as_str).unwrap_or("0.0.0.0:0")
    }

    static CUBIC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    pub fn set_congestion(name: Option<&str>) {
        CUBIC.store(
            matches!(name.map(str::to_ascii_lowercase).as_deref(), Some("cubic")),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn transport() -> Arc<quinn::TransportConfig> {
        let mut tc = quinn::TransportConfig::default();
        if CUBIC.load(std::sync::atomic::Ordering::Relaxed) {
            tc.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        } else {
            tc.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        tc.stream_receive_window(quinn::VarInt::from_u32(QUIC_STREAM_WINDOW));
        tc.send_window(QUIC_SEND_WINDOW);
        tc.max_concurrent_bidi_streams(32u32.into());
        tc.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        tc.initial_mtu(1200);
        tc.min_mtu(1200);
        tc.mtu_discovery_config(None);
        Arc::new(tc)
    }

    pub fn transport_raw() -> Arc<quinn::TransportConfig> {
        let mut tc = quinn::TransportConfig::default();
        tc.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        tc.stream_receive_window(quinn::VarInt::from_u32(1024 * 1024));
        tc.send_window(2 * 1024 * 1024);
        tc.max_concurrent_bidi_streams(8u32.into());
        tc.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        tc.initial_mtu(1200);
        tc.min_mtu(1200);
        tc.mtu_discovery_config(None);
        Arc::new(tc)
    }

    pub fn client_endpoint(key: [u8; 32], mask: bool, version: u32) -> Result<quinn::Endpoint> {
        let mut ep = if mask {
            let obf = obf::bind(local(), key, true)?;
            quinn::Endpoint::new_with_abstract_socket(
                endpoint_config(version),
                None,
                obf,
                Arc::new(quinn::TokioRuntime),
            )?
        } else {
            quinn::Endpoint::new(
                endpoint_config(version),
                None,
                native_socket(local())?,
                Arc::new(quinn::TokioRuntime),
            )?
        };
        ep.set_default_client_config(client_config(version)?);
        Ok(ep)
    }

    fn native_socket(addr: &str) -> Result<std::net::UdpSocket> {
        const UDP_BUF: usize = 4 * 1024 * 1024;
        let sa: SocketAddr = addr.parse().context("quic address must be ip:port")?;
        let s = socket2::Socket::new(
            socket2::Domain::for_address(sa),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        let _ = s.set_recv_buffer_size(UDP_BUF);
        let _ = s.set_send_buffer_size(UDP_BUF);
        s.bind(&sa.into())?;
        s.set_nonblocking(true)?;
        Ok(s.into())
    }

    pub fn server_endpoint(
        cfg: quinn::ServerConfig,
        addr: &str,
        key: [u8; 32],
        mask: bool,
    ) -> Result<quinn::Endpoint> {
        if mask {
            let obf = obf::bind(addr, key, true)?;
            return Ok(quinn::Endpoint::new_with_abstract_socket(
                endpoint_config(1),
                Some(cfg),
                obf,
                Arc::new(quinn::TokioRuntime),
            )?);
        }
        Ok(quinn::Endpoint::new(
            endpoint_config(1),
            Some(cfg),
            native_socket(addr)?,
            Arc::new(quinn::TokioRuntime),
        )?)
    }

    fn endpoint_config(version: u32) -> quinn::EndpointConfig {
        let mut vers: Vec<u32> = vec![
            0x0000_0001,
            0xff00_001d,
            0xff00_001e,
            0xff00_001f,
            0xff00_0020,
            0xff00_0021,
            0xff00_0022,
        ];
        if !vers.contains(&version) {
            vers.insert(0, version);
        }
        let mut ec = quinn::EndpointConfig::default();
        ec.supported_versions(vers);
        ec
    }

    pub fn server_config(sni: &str) -> Result<quinn::ServerConfig> {
        let (certs, key) = super::tls::server_cert(sni)?;
        let mut crypto = rustls::ServerConfig::builder_with_provider(super::tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("quic server TLS version")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("quic server crypto")?;
        crypto.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
        let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(crypto).context("quic server config")?,
        ));
        cfg.transport_config(transport());
        Ok(cfg)
    }

    pub fn client_config(version: u32) -> Result<quinn::ClientConfig> {
        let p = super::tls::provider();
        let mut crypto = rustls::ClientConfig::builder_with_provider(p.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("quic client TLS version")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(super::tls::NoVerify(p)))
            .with_no_client_auth();
        crypto.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
        let mut cfg = quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).context("quic client config")?,
        ));
        cfg.transport_config(transport());
        cfg.version(version);
        Ok(cfg)
    }

    mod obf {
        use quinn::udp::{RecvMeta, Transmit};
        use quinn::{AsyncUdpSocket, UdpPoller};
        use std::io;
        use std::net::SocketAddr;
        use std::pin::Pin;
        use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
        use std::sync::Arc;
        use std::task::{ready, Context, Poll};

        #[derive(Debug)]
        pub struct ObfSocket {
            sock: tokio::net::UdpSocket,
            key: [u8; 32],
            ctr: AtomicU32,
            mask: bool,
        }

        pub fn bind(addr: &str, key: [u8; 32], mask: bool) -> io::Result<Arc<ObfSocket>> {
            let s = std::net::UdpSocket::bind(addr)?;
            s.set_nonblocking(true)?;
            let sock = socket2::SockRef::from(&s);
            let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
            Ok(Arc::new(ObfSocket {
                sock: tokio::net::UdpSocket::from_std(s)?,
                key,
                ctr: AtomicU32::new(0),
                mask,
            }))
        }

        fn keystream(key: &[u8; 32], salt: &[u8], n: usize) -> Vec<u8> {
            let mut h = blake3::Hasher::new_keyed(key);
            h.update(salt);
            let mut out = vec![0u8; n];
            h.finalize_xof().fill(&mut out);
            out
        }

        fn mask(key: &[u8; 32], salt: u32, data: &[u8]) -> Vec<u8> {
            let salt = salt.to_be_bytes();
            let ks = keystream(key, &salt, data.len());
            let mut v = Vec::with_capacity(4 + data.len());
            v.extend_from_slice(&salt);
            v.extend(data.iter().zip(ks).map(|(b, k)| b ^ k));
            v
        }

        fn unmask(key: &[u8; 32], wire: &[u8]) -> Vec<u8> {
            if wire.len() < 4 {
                return Vec::new();
            }
            let ks = keystream(key, &wire[0..4], wire.len() - 4);
            wire[4..].iter().zip(ks).map(|(b, k)| b ^ k).collect()
        }

        #[derive(Debug)]
        struct Poller(Arc<ObfSocket>);
        impl UdpPoller for Poller {
            fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
                self.0.sock.poll_send_ready(cx)
            }
        }

        impl AsyncUdpSocket for ObfSocket {
            fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
                Box::pin(Poller(self))
            }

            fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
                if !self.mask {
                    return self
                        .sock
                        .try_send_to(transmit.contents, transmit.destination)
                        .map(|_| ());
                }
                let salt = self.ctr.fetch_add(1, Relaxed);
                let masked = mask(&self.key, salt, transmit.contents);
                self.sock
                    .try_send_to(&masked, transmit.destination)
                    .map(|_| ())
            }

            fn poll_recv(
                &self,
                cx: &mut Context,
                bufs: &mut [std::io::IoSliceMut<'_>],
                meta: &mut [RecvMeta],
            ) -> Poll<io::Result<usize>> {
                let mut tmp = [0u8; 65535];
                loop {
                    ready!(self.sock.poll_recv_ready(cx))?;
                    match self.sock.try_recv_from(&mut tmp) {
                        Ok((n, addr)) => {
                            let data = if self.mask {
                                unmask(&self.key, &tmp[..n])
                            } else {
                                tmp[..n].to_vec()
                            };
                            if data.is_empty() {
                                continue;
                            }
                            let len = data.len().min(bufs[0].len());
                            bufs[0][..len].copy_from_slice(&data[..len]);
                            meta[0] = RecvMeta {
                                addr,
                                len,
                                stride: len,
                                ecn: None,
                                dst_ip: None,
                            };
                            return Poll::Ready(Ok(1));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
            }

            fn local_addr(&self) -> io::Result<SocketAddr> {
                self.sock.local_addr()
            }

            fn may_fragment(&self) -> bool {
                false
            }
        }
    }
}

mod kcp {
    pub fn config() -> tokio_kcp::KcpConfig {
        super::kcp_profile(1350, false)
    }
}

pub(crate) fn kcp_profile(mtu: usize, stream: bool) -> tokio_kcp::KcpConfig {
    tokio_kcp::KcpConfig {
        nodelay: tokio_kcp::KcpNoDelayConfig {
            nodelay: true,
            interval: 10,
            resend: 2,
            nc: true,
        },
        mtu,
        wnd_size: (1024, 1024),
        stream,
        ..Default::default()
    }
}

#[cfg(test)]
#[path = "../tests/unit/carrier_frag.rs"]
mod frag_tests;
