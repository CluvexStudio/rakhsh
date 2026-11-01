use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::carrier::{BoxRx, BoxTx};
use crate::config::{Config, Forward};
use crate::l3::L3;
use crate::limits::{Limiter, StreamMeter};
use crate::links;
use crate::noise::{Enc, Keys};
use crate::resume;
use crate::session::{
    deregister, register, run_stream, spawn_heartbeat, spawn_writer, Credits, LaneTasks, Session,
    Streams,
};
use crate::wire::{self, Frame, FLAG_UDP};

#[derive(Clone)]
pub(crate) struct Pool {
    lanes: Arc<Mutex<Vec<Session>>>,
    rr: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    limit: usize,
    pub(crate) limits: Arc<Limiter>,
    hub: Option<Arc<resume::Hub>>,
}

impl Pool {
    fn pick(&self) -> Option<Session> {
        let v = self.lanes.lock().unwrap();
        if v.is_empty() {
            return None;
        }
        let i = self.rr.fetch_add(1, SeqCst) % v.len();
        Some(v[i].clone())
    }
    fn remove(&self, lane_id: u64) {
        self.lanes.lock().unwrap().retain(|s| s.lane_id != lane_id);
    }
}

pub async fn run(cfg: Config) -> Result<()> {
    let keys = Keys::from_cfg(&cfg)?;
    keys.mode.announce();
    let metrics = crate::status::init(&cfg, "entry");
    tokio::spawn(crate::status::serve(crate::status::socket_path(&cfg)));
    let l3 = crate::l3::setup(&cfg)?;

    let pool = Pool {
        lanes: Arc::new(Mutex::new(Vec::new())),
        rr: Arc::new(AtomicUsize::new(0)),
        active: Arc::new(AtomicUsize::new(0)),
        limit: cfg.max_connections.unwrap_or(0),
        limits: Limiter::new(&cfg, true)?,
        hub: resume::from_cfg(&cfg, true),
    };
    metrics.bind_active(pool.active.clone());
    metrics.bind_limiter(&pool.limits);
    if let Some(h) = &pool.hub {
        metrics.bind_hub(h);
    }
    {
        let (st_tx, mut st_rx) =
            mpsc::channel::<tokio::sync::oneshot::Sender<crate::status::SpeedResult>>(4);
        metrics.bind_speedtest(st_tx);
        let pool2 = pool.clone();
        tokio::spawn(async move {
            while let Some(reply) = st_rx.recv().await {
                let down_mbit = pool2.speedtest(4).await;
                let up_mbit = pool2.speedtest_up(4).await;
                let _ = reply.send(crate::status::SpeedResult { down_mbit, up_mbit });
            }
        });
    }
    crate::stats::spawn_logger();
    let hb = cfg.tuning().heartbeat;

    crate::engine::spawn(&cfg, Some(pool.clone())).await?;
    init_dyn(&cfg, &pool);

    for fwd in cfg.forward.clone() {
        let pool = pool.clone();
        tokio::spawn(async move {
            let res = if fwd.udp {
                udp_forward_listener(fwd.clone(), pool).await
            } else {
                forward_listener(fwd.clone(), pool).await
            };
            if let Err(e) = res {
                warn!("forward {} stopped: {e:#}", fwd.listen);
            }
        });
    }

    let carrier = cfg.carrier.clone().unwrap_or_else(|| "tcp".into());
    let serve: links::Serve = {
        let (pool, l3) = (pool.clone(), l3.clone());
        Arc::new(move |lane_id, tx, rx, enc| {
            let (pool, l3, carrier) = (pool.clone(), l3.clone(), carrier.clone());
            Box::pin(async move {
                if let Some(m) = crate::status::get() {
                    m.lane_up(lane_id, &carrier);
                }
                let r = serve_entry_lane(tx, rx, enc, lane_id, &pool, &l3, hb).await;
                if let Some(m) = crate::status::get() {
                    m.lane_down(lane_id);
                }
                r
            })
        })
    };
    if links::dialing(&cfg) {
        links::dial_lanes(&cfg, keys, serve).await
    } else {
        links::listen(&cfg, keys, serve).await
    }
}

async fn serve_entry_lane(
    tx: BoxTx,
    mut rx: BoxRx,
    enc: Enc,
    lane_id: u64,
    pool: &Pool,
    l3: &Option<Arc<L3>>,
    hb: u64,
) -> Result<()> {
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(1024);
    if let Some(l3) = l3 {
        l3.add_lane(out_tx.clone());
    }
    let mut tasks = LaneTasks::default();
    tasks.add(spawn_writer(tx, enc.clone(), out_rx));
    if let Some(h) = spawn_heartbeat(out_tx.clone(), hb, lane_id) {
        tasks.add(h);
    }
    let dead = Duration::from_secs(hb.max(5).saturating_mul(3).max(if pool.hub.is_some() {
        15
    } else {
        30
    }));

    let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
    let credits: Credits = Arc::new(Mutex::new(HashMap::new()));
    pool.lanes.lock().unwrap().push(Session {
        lane_id,
        out_tx: out_tx.clone(),
        streams: streams.clone(),
        credits: credits.clone(),
        next_id: Arc::new(AtomicU32::new(1)),
    });
    let _cleanup = LaneCleanup {
        pool: pool.clone(),
        lane_id,
        streams: streams.clone(),
        credits: credits.clone(),
        _tasks: tasks,
    };
    if let Some(h) = &pool.hub {
        h.lane_up(lane_id, out_tx.clone());
    }

    loop {
        let frame = match tokio::time::timeout(dead, rx.recv()).await {
            Ok(Ok(f)) => f,
            Ok(Err(_)) => break,
            Err(_) => {
                warn!("lane {lane_id} dead ({}s silent)", dead.as_secs());
                break;
            }
        };
        let plain = match enc.open_bytes(frame) {
            Ok(p) => p,
            Err(_) => break,
        };
        if let Some(h) = &pool.hub {
            if plain.first().is_some_and(|t| *t >= resume::R_FIRST) {
                h.on_frame(lane_id, &plain).await;
                continue;
            }
        }
        match wire::parse(&plain) {
            Some(Frame::Data { id, data }) => {
                let s = streams.lock().unwrap().get(&id).cloned();
                if let Some(s) = s {
                    let _ = s.send(data);
                }
            }
            Some(Frame::Close { id }) => {
                streams.lock().unwrap().remove(&id);
            }
            Some(Frame::Fin { id }) => {
                let s = streams.lock().unwrap().get(&id).cloned();
                if let Some(s) = s {
                    let _ = s.send(Bytes::new());
                }
            }
            Some(Frame::Credit { id, n }) => {
                let c = credits.lock().unwrap().get(&id).cloned();
                if let Some(c) = c {
                    c.add_permits(n as usize);
                }
            }
            Some(Frame::L3 { pkt }) => {
                if let Some(l3) = l3 {
                    l3.write_pkt(&pkt).await;
                }
            }
            Some(Frame::Ping) => {
                let _ = out_tx.send(wire::pong()).await;
            }
            Some(Frame::Pong) => {
                if let Some(m) = crate::status::get() {
                    m.pong_recv(lane_id);
                }
            }
            Some(Frame::Sync { json }) => apply_sync(&json),
            _ => {}
        }
    }
    Ok(())
}

struct LaneCleanup {
    pool: Pool,
    lane_id: u64,
    streams: Streams,
    credits: Credits,
    _tasks: LaneTasks,
}

impl Drop for LaneCleanup {
    fn drop(&mut self) {
        self.pool.remove(self.lane_id);
        self.streams.lock().unwrap().clear();
        self.credits.lock().unwrap().clear();
        if let Some(h) = &self.pool.hub {
            h.lane_down(self.lane_id);
        }
    }
}

async fn forward_listener(fwd: Forward, pool: Pool) -> Result<()> {
    let l = TcpListener::bind(&fwd.listen)
        .await
        .with_context(|| format!("binding forward {}", fwd.listen))?;
    let meter = pool.limits.meter(
        &format!("forward {}", fwd.listen),
        &fwd.limits,
        pool.limits.global(),
    )?;
    info!("forwarding {} -> {}", fwd.listen, fwd.target);
    loop {
        let (user, peer) = l.accept().await?;
        if pool.limit > 0 && pool.active.load(SeqCst) >= pool.limit {
            continue;
        }
        let sm = match &meter {
            Some(m) => match m.open() {
                Some(s) => Some(Arc::new(s)),
                None => continue,
            },
            None => None,
        };
        if let Some(hub) = &pool.hub {
            let client = fwd.proxy_protocol.then(|| peer.to_string());
            let Some(s) = hub.open(&fwd.target, client.as_deref()).await else {
                continue;
            };
            pool.active.fetch_add(1, SeqCst);
            let active = pool.active.clone();
            tokio::spawn(async move {
                s.run(user, Bytes::new(), sm).await;
                active.fetch_sub(1, SeqCst);
            });
            continue;
        }
        let Some(sess) = pool.pick() else {
            continue;
        };
        let id = sess.next_id.fetch_add(1, SeqCst);
        let (rx, cred) = register(&sess.streams, &sess.credits, id);
        let open = if fwd.proxy_protocol {
            wire::open_pp(id, 0, &fwd.target, &peer.to_string())
        } else {
            wire::open(id, 0, &fwd.target)
        };
        if sess.out_tx.send(open).await.is_err() {
            deregister(&sess.streams, &sess.credits, id);
            continue;
        }
        pool.active.fetch_add(1, SeqCst);
        let active = pool.active.clone();
        let (out_tx, streams, credits) = (
            sess.out_tx.clone(),
            sess.streams.clone(),
            sess.credits.clone(),
        );
        tokio::spawn(async move {
            run_stream(
                user,
                id,
                out_tx,
                rx,
                crate::session::StreamCtx {
                    streams,
                    credits,
                    send_credit: cred,
                    meter: sm,
                },
            )
            .await;
            active.fetch_sub(1, SeqCst);
        });
    }
}

struct UdpFlow {
    id: u32,
    sess: Session,
    last: Instant,
}

async fn udp_forward_listener(fwd: Forward, pool: Pool) -> Result<()> {
    let sock = Arc::new(
        UdpSocket::bind(&fwd.listen)
            .await
            .with_context(|| format!("binding udp forward {}", fwd.listen))?,
    );
    info!("forwarding udp {} -> {}", fwd.listen, fwd.target);

    let flows: Arc<Mutex<HashMap<SocketAddr, UdpFlow>>> = Arc::new(Mutex::new(HashMap::new()));

    let sweeper = flows.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let now = Instant::now();
            sweeper.lock().unwrap().retain(|_, f| {
                if now.duration_since(f.last) > Duration::from_secs(60) {
                    let _ = f.sess.out_tx.try_send(wire::close(f.id));
                    deregister(&f.sess.streams, &f.sess.credits, f.id);
                    false
                } else {
                    true
                }
            });
        }
    });

    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        let existing = flows
            .lock()
            .unwrap()
            .get(&src)
            .map(|f| (f.id, f.sess.clone()));
        let (id, sess) = match existing {
            Some(x) => x,
            None => {
                let Some(sess) = pool.pick() else {
                    continue;
                };
                let id = sess.next_id.fetch_add(1, SeqCst);
                let (rx, _cred) = register(&sess.streams, &sess.credits, id);
                if sess
                    .out_tx
                    .send(wire::open(id, FLAG_UDP, &fwd.target))
                    .await
                    .is_err()
                {
                    deregister(&sess.streams, &sess.credits, id);
                    continue;
                }
                let s2 = sock.clone();
                let mut rx = rx;
                tokio::spawn(async move {
                    while let Some(b) = rx.recv().await {
                        let _ = s2.send_to(&b, src).await;
                    }
                });
                flows.lock().unwrap().insert(
                    src,
                    UdpFlow {
                        id,
                        sess: sess.clone(),
                        last: Instant::now(),
                    },
                );
                (id, sess)
            }
        };
        if sess.out_tx.send(wire::data(id, &buf[..n])).await.is_err() {
            flows.lock().unwrap().remove(&src);
            continue;
        }
        if let Some(f) = flows.lock().unwrap().get_mut(&src) {
            f.last = Instant::now();
        }
    }
}

type ActiveForward = (crate::xui::SyncFwd, tokio::task::JoinHandle<()>);

pub(crate) struct DynForwards {
    listen: String,
    allowed: Vec<(u16, u16)>,
    reserved: std::collections::HashSet<u16>,
    pool: Pool,
    active: Mutex<HashMap<(u16, bool), ActiveForward>>,
    last: Mutex<Vec<u8>>,
}

static DYN: std::sync::OnceLock<DynForwards> = std::sync::OnceLock::new();

fn parse_ports(list: &[String]) -> Vec<(u16, u16)> {
    let mut v = Vec::new();
    for p in list {
        let p = p.trim();
        let r = match p.split_once('-') {
            Some((a, b)) => (a.trim().parse().ok(), b.trim().parse().ok()),
            None => (p.parse().ok(), p.parse().ok()),
        };
        if let (Some(a), Some(b)) = r {
            v.push((a, b));
        }
    }
    v
}

fn init_dyn(cfg: &Config, pool: &Pool) {
    if !cfg.accept_sync.unwrap_or(false) {
        return;
    }
    let mut reserved = std::collections::HashSet::new();
    if let Some(p) = cfg
        .tunnel_listen
        .as_deref()
        .and_then(|a| a.rsplit(':').next())
        .and_then(|p| p.parse().ok())
    {
        reserved.insert(p);
    }
    for f in &cfg.forward {
        if let Some(p) = f.listen.rsplit(':').next().and_then(|p| p.parse().ok()) {
            reserved.insert(p);
        }
    }
    let allowed = if cfg.sync_ports.is_empty() {
        vec![(1024, 65535)]
    } else {
        parse_ports(&cfg.sync_ports)
    };
    info!("x-ui sync accepted: ports {:?}, reserved {:?}", allowed, {
        let mut r: Vec<_> = reserved.iter().copied().collect();
        r.sort();
        r
    });
    let _ = DYN.set(DynForwards {
        listen: cfg.sync_listen.clone().unwrap_or_else(|| "0.0.0.0".into()),
        allowed,
        reserved,
        pool: pool.clone(),
        active: Mutex::new(HashMap::new()),
        last: Mutex::new(Vec::new()),
    });
}

fn apply_sync(json: &[u8]) {
    let Some(d) = DYN.get() else { return };
    {
        let mut last = d.last.lock().unwrap();
        if *last == json {
            return;
        }
        *last = json.to_vec();
    }
    let Ok(set) = serde_json::from_slice::<Vec<crate::xui::SyncFwd>>(json) else {
        warn!("x-ui sync: ignoring a malformed forward set");
        return;
    };
    let mut want: HashMap<(u16, bool), crate::xui::SyncFwd> = HashMap::new();
    for f in set {
        if d.reserved.contains(&f.port)
            || !d
                .allowed
                .iter()
                .any(|(lo, hi)| (*lo..=*hi).contains(&f.port))
        {
            warn!(
                "x-ui sync: refusing forward on port {} (reserved or outside sync_ports)",
                f.port
            );
            continue;
        }
        want.insert((f.port, f.udp), f);
    }
    let mut active = d.active.lock().unwrap();
    active.retain(|k, (cur, h)| {
        let keep = want.get(k) == Some(cur);
        if !keep {
            h.abort();
            info!(
                "x-ui sync: closed forward {}{}",
                k.0,
                if k.1 { "/udp" } else { "" }
            );
        }
        keep
    });
    for (k, f) in want {
        if active.contains_key(&k) {
            continue;
        }
        let fwd = Forward {
            listen: format!("{}:{}", d.listen, f.port),
            target: f.target.clone(),
            udp: f.udp,
            proxy_protocol: f.proxy_protocol,
            limits: Default::default(),
        };
        info!(
            "x-ui sync: opening forward {} -> {} ({})",
            fwd.listen, fwd.target, f.label
        );
        let pool = d.pool.clone();
        let fcopy = fwd.clone();
        let h = tokio::spawn(async move {
            let res = if fcopy.udp {
                udp_forward_listener(fcopy.clone(), pool).await
            } else {
                forward_listener(fcopy.clone(), pool).await
            };
            if let Err(e) = res {
                warn!("x-ui sync: forward {} stopped: {e:#}", fcopy.listen);
            }
        });
        active.insert(k, (f, h));
    }
}

pub(crate) struct TunnelStream(Option<Opened>);

enum Opened {
    Plain {
        id: u32,
        sess: Session,
        rx: mpsc::UnboundedReceiver<bytes::Bytes>,
        cred: Arc<tokio::sync::Semaphore>,
        active: Arc<AtomicUsize>,
    },
    Resumable {
        stream: Arc<resume::RStream>,
        active: Arc<AtomicUsize>,
    },
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        match self.0.take() {
            Some(Opened::Plain {
                id, sess, active, ..
            }) => {
                deregister(&sess.streams, &sess.credits, id);
                let _ = sess.out_tx.try_send(wire::close(id));
                active.fetch_sub(1, SeqCst);
            }
            Some(Opened::Resumable { stream, active }) => {
                active.fetch_sub(1, SeqCst);
                tokio::spawn(async move { stream.abort(true).await });
            }
            None => {}
        }
    }
}

impl Pool {
    pub(crate) async fn open_tcp(&self, target: &str) -> Option<TunnelStream> {
        if self.limit > 0 && self.active.load(SeqCst) >= self.limit {
            return None;
        }
        if let Some(hub) = &self.hub {
            let stream = hub.open(target, None).await?;
            self.active.fetch_add(1, SeqCst);
            return Some(TunnelStream(Some(Opened::Resumable {
                stream,
                active: self.active.clone(),
            })));
        }
        let sess = self.pick()?;
        let id = sess.next_id.fetch_add(1, SeqCst);
        let (rx, cred) = register(&sess.streams, &sess.credits, id);
        if sess.out_tx.send(wire::open(id, 0, target)).await.is_err() {
            deregister(&sess.streams, &sess.credits, id);
            return None;
        }
        self.active.fetch_add(1, SeqCst);
        Some(TunnelStream(Some(Opened::Plain {
            id,
            sess,
            rx,
            cred,
            active: self.active.clone(),
        })))
    }

    pub(crate) async fn speedtest(&self, secs: u64) -> Option<f64> {
        let sess = self.pick()?;
        let id = sess.next_id.fetch_add(1, SeqCst);
        let (mut rx, _cred) = register(&sess.streams, &sess.credits, id);
        if sess
            .out_tx
            .send(wire::open(id, 0, "@speedtest"))
            .await
            .is_err()
        {
            deregister(&sess.streams, &sess.credits, id);
            return None;
        }
        let start = Instant::now();
        let deadline = start + Duration::from_secs(secs);
        let mut total: u64 = 0;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, rx.recv()).await {
                Ok(Some(b)) if !b.is_empty() => {
                    total += b.len() as u64;
                    let _ = sess.out_tx.send(wire::credit(id, b.len() as u32)).await;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let _ = sess.out_tx.send(wire::close(id)).await;
        deregister(&sess.streams, &sess.credits, id);
        let el = start.elapsed().as_secs_f64().max(0.01);
        Some(total as f64 * 8.0 / el / 1e6)
    }

    pub(crate) async fn speedtest_up(&self, secs: u64) -> Option<f64> {
        let sess = self.pick()?;
        let id = sess.next_id.fetch_add(1, SeqCst);
        let (rx, cred) = register(&sess.streams, &sess.credits, id);
        tokio::spawn(async move {
            let mut rx = rx;
            while rx.recv().await.is_some() {}
        });
        if sess
            .out_tx
            .send(wire::open(id, 0, "@speedtest-up"))
            .await
            .is_err()
        {
            deregister(&sess.streams, &sess.credits, id);
            return None;
        }
        let chunk = vec![0u8; wire::MAX_PAYLOAD];
        let start = Instant::now();
        let deadline = start + Duration::from_secs(secs);
        let mut total: u64 = 0;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, cred.acquire_many(chunk.len() as u32)).await {
                Ok(Ok(p)) => p.forget(),
                _ => break,
            }
            if sess.out_tx.send(wire::data(id, &chunk)).await.is_err() {
                break;
            }
            total += chunk.len() as u64;
        }
        let _ = sess.out_tx.send(wire::fin(id)).await;
        let _ = sess.out_tx.send(wire::close(id)).await;
        deregister(&sess.streams, &sess.credits, id);
        let el = start.elapsed().as_secs_f64().max(0.01);
        let drained = total.saturating_sub(crate::session::WINDOW as u64);
        Some(drained as f64 * 8.0 / el / 1e6)
    }
}

impl TunnelStream {
    pub(crate) async fn relay(
        mut self,
        user: tokio::net::TcpStream,
        early: &[u8],
        meter: Option<Arc<StreamMeter>>,
    ) {
        let Some(opened) = self.0.take() else { return };
        let (id, sess, rx, cred, active) = match opened {
            Opened::Plain {
                id,
                sess,
                rx,
                cred,
                active,
            } => (id, sess, rx, cred, active),
            Opened::Resumable { stream, active } => {
                stream.run(user, Bytes::copy_from_slice(early), meter).await;
                active.fetch_sub(1, SeqCst);
                return;
            }
        };
        let mut ok = true;
        for chunk in early.chunks(wire::MAX_PAYLOAD) {
            match cred.acquire_many(chunk.len() as u32).await {
                Ok(p) => p.forget(),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
            if sess.out_tx.send(wire::data(id, chunk)).await.is_err() {
                ok = false;
                break;
            }
        }
        if ok {
            run_stream(
                user,
                id,
                sess.out_tx.clone(),
                rx,
                crate::session::StreamCtx {
                    streams: sess.streams.clone(),
                    credits: sess.credits.clone(),
                    send_credit: cred,
                    meter,
                },
            )
            .await;
        } else {
            deregister(&sess.streams, &sess.credits, id);
        }
        active.fetch_sub(1, SeqCst);
    }
}

pub(crate) struct TunnelUdp {
    id: u32,
    sess: Session,
    pub rx: mpsc::UnboundedReceiver<bytes::Bytes>,
}

impl Pool {
    pub(crate) async fn open_udp(&self, target: &str) -> Option<TunnelUdp> {
        let sess = self.pick()?;
        let id = sess.next_id.fetch_add(1, SeqCst);
        let (rx, _cred) = register(&sess.streams, &sess.credits, id);
        if sess
            .out_tx
            .send(wire::open(id, FLAG_UDP, target))
            .await
            .is_err()
        {
            deregister(&sess.streams, &sess.credits, id);
            return None;
        }
        Some(TunnelUdp { id, sess, rx })
    }
}

impl TunnelUdp {
    pub(crate) async fn send(&self, datagram: &[u8]) -> bool {
        self.sess
            .out_tx
            .send(wire::data(self.id, datagram))
            .await
            .is_ok()
    }
    pub(crate) async fn close(&self) {
        let _ = self.sess.out_tx.send(wire::close(self.id)).await;
        deregister(&self.sess.streams, &self.sess.credits, self.id);
    }
}
