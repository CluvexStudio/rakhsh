use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Semaphore};
use tracing::{debug, info, warn};

use crate::limits::StreamMeter;
use crate::noise::TAG;
use crate::session::{write_all_chunks, WINDOW};
use crate::wire::{FLAG_PROXY, MAX_PAYLOAD};

pub const R_OPEN: u8 = 10;
pub const R_DATA: u8 = 11;
pub const R_ACK: u8 = 12;
pub const R_SYNC: u8 = 13;
pub const R_CLOSE: u8 = 14;
pub const R_FIRST: u8 = R_OPEN;

const F_REPLY: u8 = 1;
const F_FORCE: u8 = 2;

const UP_READ: usize = 64 * 1024;
const UP_HANDOFF: usize = 32 * 1024;
const DOWN_COALESCE: usize = 256 * 1024;
const TICK: Duration = Duration::from_secs(1);
const GAP_REQUEST_EVERY: Duration = Duration::from_millis(500);
const EXIT_ATTACH_DELAY: Duration = Duration::from_secs(1);
pub const DEFAULT_GRACE_SECS: u64 = 60;

#[derive(Debug)]
pub enum RFrame {
    Open {
        id: u64,
        client: Option<String>,
        target: String,
    },
    Data {
        id: u64,
        off: u64,
        payload: Bytes,
    },
    Ack {
        id: u64,
        consumed: u64,
    },
    Sync {
        id: u64,
        rx_off: u64,
        consumed: u64,
        reply: bool,
        force: bool,
    },
    Close {
        id: u64,
    },
}

impl RFrame {
    fn id(&self) -> u64 {
        match self {
            RFrame::Open { id, .. }
            | RFrame::Data { id, .. }
            | RFrame::Ack { id, .. }
            | RFrame::Sync { id, .. }
            | RFrame::Close { id } => *id,
        }
    }
}

fn head(t: u8, id: u64, extra: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + extra + TAG);
    v.push(t);
    v.extend_from_slice(&id.to_be_bytes());
    v
}

fn open_frame(id: u64, client: Option<&str>, target: &str) -> Vec<u8> {
    let mut v = head(R_OPEN, id, 3 + client.map_or(0, str::len) + target.len());
    v.push(if client.is_some() { FLAG_PROXY } else { 0 });
    let c = client.unwrap_or("");
    v.extend_from_slice(&(c.len() as u16).to_be_bytes());
    v.extend_from_slice(c.as_bytes());
    v.extend_from_slice(target.as_bytes());
    v
}

fn data_frame(id: u64, off: u64, payload: &[u8]) -> Vec<u8> {
    let mut v = head(R_DATA, id, 8 + payload.len());
    v.extend_from_slice(&off.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn ack_frame(id: u64, consumed: u64) -> Vec<u8> {
    let mut v = head(R_ACK, id, 8);
    v.extend_from_slice(&consumed.to_be_bytes());
    v
}

fn sync_frame(id: u64, rx_off: u64, consumed: u64, reply: bool, force: bool) -> Vec<u8> {
    let mut v = head(R_SYNC, id, 17);
    v.extend_from_slice(&rx_off.to_be_bytes());
    v.extend_from_slice(&consumed.to_be_bytes());
    v.push(if reply { F_REPLY } else { 0 } | if force { F_FORCE } else { 0 });
    v
}

fn close_frame(id: u64) -> Vec<u8> {
    head(R_CLOSE, id, 0)
}

pub fn parse(buf: &Bytes) -> Option<RFrame> {
    let p: &[u8] = buf;
    let t = *p.first()?;
    let id = u64::from_be_bytes(p.get(1..9)?.try_into().ok()?);
    let u64_at = |i: usize| {
        p.get(i..i + 8)
            .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
    };
    Some(match t {
        R_OPEN => {
            let flags = *p.get(9)?;
            let clen = u16::from_be_bytes(p.get(10..12)?.try_into().ok()?) as usize;
            let client = String::from_utf8(p.get(12..12 + clen)?.to_vec())
                .ok()
                .filter(|_| flags & FLAG_PROXY != 0);
            RFrame::Open {
                id,
                client,
                target: String::from_utf8(p.get(12 + clen..)?.to_vec()).ok()?,
            }
        }
        R_DATA => RFrame::Data {
            id,
            off: u64_at(9)?,
            payload: buf.slice(17..),
        },
        R_ACK => RFrame::Ack {
            id,
            consumed: u64_at(9)?,
        },
        R_SYNC => {
            let f = *p.get(25)?;
            RFrame::Sync {
                id,
                rx_off: u64_at(9)?,
                consumed: u64_at(17)?,
                reply: f & F_REPLY != 0,
                force: f & F_FORCE != 0,
            }
        }
        R_CLOSE => RFrame::Close { id },
        _ => return None,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub enum Chunk {
    Data(Bytes),
    Fin,
}

impl Chunk {
    fn len(&self) -> u64 {
        match self {
            Chunk::Data(b) => b.len() as u64,
            Chunk::Fin => 1,
        }
    }
}

#[derive(Default)]
pub struct Tx {
    pub off: u64,
    pub acked: u64,
    chunks: VecDeque<(u64, Chunk)>,
}

impl Tx {
    pub fn push(&mut self, c: Chunk) -> u64 {
        let off = self.off;
        self.off += c.len();
        self.chunks.push_back((off, c));
        off
    }

    pub fn ack(&mut self, consumed: u64) -> u64 {
        let consumed = consumed.min(self.off);
        if consumed <= self.acked {
            return 0;
        }
        let delta = consumed - self.acked;
        self.acked = consumed;
        while self
            .chunks
            .front()
            .is_some_and(|(off, c)| off + c.len() <= self.acked)
        {
            self.chunks.pop_front();
        }
        delta
    }

    pub fn resend(&self, from: u64) -> Vec<(u64, Chunk)> {
        self.chunks
            .iter()
            .filter(|(off, c)| off + c.len() > from)
            .map(|(off, c)| match c {
                Chunk::Data(b) if *off < from => {
                    (from, Chunk::Data(b.slice((from - off) as usize..)))
                }
                _ => (*off, c.clone()),
            })
            .collect()
    }

    #[cfg(test)]
    pub fn buffered(&self) -> usize {
        self.chunks.len()
    }
}

#[derive(Default)]
pub struct Rx {
    pub off: u64,
    pub consumed: u64,
}

#[derive(Debug, PartialEq)]
pub enum Take {
    Deliver(Bytes),
    Fin,
    Duplicate,
    Gap,
}

impl Rx {
    pub fn accept(&mut self, off: u64, payload: &Bytes) -> Take {
        let len = payload.len().max(1) as u64;
        if off > self.off {
            return Take::Gap;
        }
        if off + len <= self.off {
            return Take::Duplicate;
        }
        let skip = (self.off - off) as usize;
        self.off = off + len;
        if payload.is_empty() {
            Take::Fin
        } else {
            Take::Deliver(payload.slice(skip..))
        }
    }
}

enum Ev {
    Data(Bytes),
    Fin,
}

#[derive(Clone)]
struct LaneRef {
    id: u64,
    tx: mpsc::Sender<Vec<u8>>,
}

struct Link {
    lane: Option<LaneRef>,
    detached_at: Option<Instant>,
    synced: bool,
}

struct HubState {
    streams: HashMap<u64, Arc<RStream>>,
    lanes: Vec<LaneRef>,
    rr: usize,
    closed: HashMap<u64, Instant>,
}

impl HubState {
    fn pick(&mut self) -> Option<LaneRef> {
        if self.lanes.is_empty() {
            return None;
        }
        self.rr = self.rr.wrapping_add(1);
        Some(self.lanes[self.rr % self.lanes.len()].clone())
    }
}

pub fn from_cfg(cfg: &crate::config::Config, entry: bool) -> Option<Arc<Hub>> {
    if !cfg.resume {
        return None;
    }
    let grace = Duration::from_secs(cfg.resume_grace.unwrap_or(DEFAULT_GRACE_SECS).max(1));
    info!(
        "stream resumption on: TCP streams survive the loss of a lane (up to {}s without any lane)",
        grace.as_secs()
    );
    Some(Hub::new(entry, grace))
}

pub struct Hub {
    st: Mutex<HubState>,
    next_id: AtomicU64,
    entry: bool,
    grace: Duration,
    resent: AtomicU64,
}

fn random_u64() -> u64 {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 8];
    if SystemRandom::new().fill(&mut b).is_err() {
        return std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos() as u64);
    }
    u64::from_be_bytes(b)
}

impl Hub {
    pub fn new(entry: bool, grace: Duration) -> Arc<Hub> {
        let hub = Arc::new(Hub {
            st: Mutex::new(HubState {
                streams: HashMap::new(),
                lanes: Vec::new(),
                rr: 0,
                closed: HashMap::new(),
            }),
            next_id: AtomicU64::new(random_u64()),
            entry,
            grace,
            resent: AtomicU64::new(0),
        });
        let w = Arc::downgrade(&hub);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TICK).await;
                let Some(h) = w.upgrade() else { return };
                h.tick().await;
            }
        });
        hub
    }

    #[cfg(test)]
    pub fn streams(&self) -> usize {
        self.live_streams()
    }

    pub fn live_streams(&self) -> usize {
        self.st.lock().unwrap().streams.len()
    }

    pub fn resent(&self) -> u64 {
        self.resent.load(SeqCst)
    }

    async fn tick(self: &Arc<Self>) {
        let (todo, lane): (Vec<Arc<RStream>>, Option<LaneRef>) = {
            let mut st = self.st.lock().unwrap();
            st.closed
                .retain(|_, t| t.elapsed() < Duration::from_secs(10));
            let todo = st
                .streams
                .values()
                .filter(|s| s.needs_attention())
                .cloned()
                .collect();
            (todo, st.pick())
        };
        for s in todo {
            if s.finished_for().is_some_and(|t| t > self.grace) {
                s.abort(false).await;
            } else if s.detached_for().is_some_and(|t| t > self.grace) {
                warn!(
                    "stream {:x} gave up: no lane for {}s",
                    s.id,
                    self.grace.as_secs()
                );
                s.abort(true).await;
            } else if let (Some(_), Some(l)) = (s.detached_for(), lane.clone()) {
                s.spawn_attach(l);
            }
        }
    }

    pub fn lane_up(self: &Arc<Self>, lane: u64, tx: mpsc::Sender<Vec<u8>>) {
        let waiting: Vec<(Arc<RStream>, LaneRef)> = {
            let mut st = self.st.lock().unwrap();
            st.lanes.retain(|x| x.id != lane);
            st.lanes.push(LaneRef { id: lane, tx });
            let detached: Vec<Arc<RStream>> = st
                .streams
                .values()
                .filter(|s| s.detached_for().is_some())
                .cloned()
                .collect();
            detached
                .into_iter()
                .filter_map(|s| st.pick().map(|l| (s, l)))
                .collect()
        };
        if !waiting.is_empty() {
            info!("lane {lane} up: {} stream(s) resume", waiting.len());
        }
        for (s, l) in waiting {
            s.spawn_attach(l);
        }
    }

    pub fn lane_down(self: &Arc<Self>, lane: u64) {
        let (lost, other): (Vec<Arc<RStream>>, Option<LaneRef>) = {
            let mut st = self.st.lock().unwrap();
            st.lanes.retain(|x| x.id != lane);
            let lost = st
                .streams
                .values()
                .filter(|s| s.detach_if(lane))
                .cloned()
                .collect();
            (lost, st.pick())
        };
        if lost.is_empty() {
            return;
        }
        match other {
            Some(l) => {
                info!(
                    "lane {lane} down: {} stream(s) move to lane {}",
                    lost.len(),
                    l.id
                );
                for s in lost {
                    s.spawn_attach(l.clone());
                }
            }
            None => info!("lane {lane} down: {} stream(s) wait for a lane", lost.len()),
        }
    }

    fn remove(&self, id: u64) {
        self.st.lock().unwrap().streams.remove(&id);
    }

    fn new_stream(
        self: &Arc<Self>,
        id: u64,
        lane: Option<LaneRef>,
        open: Option<Vec<u8>>,
        confirmed: bool,
    ) -> Arc<RStream> {
        let (inbound, inbound_rx) = mpsc::unbounded_channel();
        let detached_at = if lane.is_none() {
            Some(Instant::now())
        } else {
            None
        };
        let s = Arc::new(RStream {
            id,
            hub: Arc::downgrade(self),
            entry: self.entry,
            link: Mutex::new(Link {
                lane,
                detached_at,
                synced: true,
            }),
            send_lock: tokio::sync::Mutex::new(()),
            tx: Mutex::new(Tx::default()),
            credit: Semaphore::new(WINDOW),
            rx: Mutex::new(Rx::default()),
            inbound,
            inbound_rx: Mutex::new(Some(inbound_rx)),
            open,
            confirmed: AtomicBool::new(confirmed),
            attaching: AtomicBool::new(false),
            fin_end: AtomicU64::new(0),
            rx_fin: AtomicBool::new(false),
            last_gap: Mutex::new(None),
            finished: Mutex::new(None),
            abort_tx: watch::channel(false).0,
        });
        self.st.lock().unwrap().streams.insert(id, s.clone());
        s
    }

    pub async fn open(
        self: &Arc<Self>,
        target: &str,
        client: Option<&str>,
    ) -> Option<Arc<RStream>> {
        let lane = self.st.lock().unwrap().pick()?;
        let id = self.next_id.fetch_add(1, SeqCst);
        let frame = open_frame(id, client, target);
        let s = self.new_stream(id, Some(lane), Some(frame.clone()), false);
        s.send_locked(frame).await;
        Some(s)
    }

    pub async fn on_frame(self: &Arc<Self>, lane: u64, plain: &Bytes) {
        let Some(f) = parse(plain) else { return };
        let stream = self.st.lock().unwrap().streams.get(&f.id()).cloned();
        match (f, stream) {
            (RFrame::Data { off, payload, .. }, Some(s)) => s.on_data(off, payload),
            (RFrame::Ack { consumed, .. }, Some(s)) => s.on_ack(consumed),
            (RFrame::Open { .. }, Some(s)) => {
                if let Some(l) = self.lane_ref(lane) {
                    tokio::spawn(async move { s.on_sync(Some(l), 0, 0, true, false).await });
                }
            }
            (RFrame::Open { id, client, target }, None) => {
                let lref = self.lane_ref(lane);
                if self.entry || lref.is_none() {
                    return;
                }
                let s = self.new_stream(id, lref, None, true);
                tokio::spawn(async move {
                    match TcpStream::connect(&target).await {
                        Ok(mut sock) => {
                            if let Some(c) = client.as_deref().and_then(|c| c.parse().ok()) {
                                if let Ok(dst) = sock.peer_addr() {
                                    let _ = sock.write_all(&crate::proxy::proxy_v2(c, dst)).await;
                                }
                            }
                            s.run(sock, Bytes::new(), None).await
                        }
                        Err(e) => {
                            warn!("dial {target} failed: {e}");
                            s.abort(true).await;
                        }
                    }
                });
            }
            (
                RFrame::Sync {
                    rx_off,
                    consumed,
                    reply,
                    force,
                    ..
                },
                Some(s),
            ) => {
                let lref = self.lane_ref(lane);
                tokio::spawn(async move { s.on_sync(lref, rx_off, consumed, reply, force).await });
            }
            (RFrame::Close { .. }, Some(s)) => s.abort(false).await,
            (RFrame::Close { .. }, None) => {}
            (f, None) => self.unknown(self.lane_ref(lane), f.id()),
        }
    }

    fn lane_ref(&self, lane: u64) -> Option<LaneRef> {
        self.st
            .lock()
            .unwrap()
            .lanes
            .iter()
            .find(|l| l.id == lane)
            .cloned()
    }

    fn unknown(&self, lane: Option<LaneRef>, id: u64) {
        let Some(l) = lane else { return };
        {
            let mut st = self.st.lock().unwrap();
            if st
                .closed
                .insert(id, Instant::now())
                .is_some_and(|t| t.elapsed() < Duration::from_secs(10))
            {
                return;
            }
        }
        tokio::spawn(async move {
            let _ = l.tx.send(close_frame(id)).await;
        });
    }
}

pub struct RStream {
    id: u64,
    hub: Weak<Hub>,
    entry: bool,
    link: Mutex<Link>,
    send_lock: tokio::sync::Mutex<()>,
    tx: Mutex<Tx>,
    credit: Semaphore,
    rx: Mutex<Rx>,
    inbound: mpsc::UnboundedSender<Ev>,
    inbound_rx: Mutex<Option<mpsc::UnboundedReceiver<Ev>>>,
    open: Option<Vec<u8>>,
    confirmed: AtomicBool,
    attaching: AtomicBool,
    fin_end: AtomicU64,
    rx_fin: AtomicBool,
    last_gap: Mutex<Option<Instant>>,
    finished: Mutex<Option<Instant>>,
    abort_tx: watch::Sender<bool>,
}

impl RStream {
    fn detached_for(&self) -> Option<Duration> {
        self.link.lock().unwrap().detached_at.map(|t| t.elapsed())
    }

    fn finished_for(&self) -> Option<Duration> {
        self.finished.lock().unwrap().map(|t| t.elapsed())
    }

    fn needs_attention(&self) -> bool {
        self.detached_for().is_some() || self.finished_for().is_some()
    }

    fn synced(&self) -> bool {
        self.link.lock().unwrap().synced
    }

    fn detach_if(&self, lane: u64) -> bool {
        let mut l = self.link.lock().unwrap();
        if l.lane.as_ref().is_some_and(|x| x.id == lane) {
            l.lane = None;
            l.detached_at = Some(Instant::now());
            l.synced = false;
            return true;
        }
        false
    }

    async fn emit(&self, frame: Vec<u8>) -> bool {
        use mpsc::error::TrySendError;
        let full = {
            let l = self.link.lock().unwrap();
            match l.lane.as_ref() {
                None => return false,
                Some(lane) => match lane.tx.try_send(frame) {
                    Ok(()) => return true,
                    Err(TrySendError::Closed(_)) => Err(lane.id),
                    Err(TrySendError::Full(f)) => Ok((lane.clone(), f)),
                },
            }
        };
        match full {
            Err(id) => {
                self.detach_if(id);
                false
            }
            Ok((lane, frame)) => {
                if lane.tx.send(frame).await.is_ok() {
                    return true;
                }
                self.detach_if(lane.id);
                false
            }
        }
    }

    async fn send_locked(&self, frame: Vec<u8>) -> bool {
        let _g = self.send_lock.lock().await;
        self.emit(frame).await
    }

    fn state(&self) -> (u64, u64) {
        let r = self.rx.lock().unwrap();
        (r.off, r.consumed)
    }

    async fn resend_locked(&self, from: u64) -> bool {
        let again = self.tx.lock().unwrap().resend(from);
        if !again.is_empty() {
            debug!(
                "stream {:x}: sending {} chunk(s) again from offset {from}",
                self.id,
                again.len()
            );
            if let Some(h) = self.hub.upgrade() {
                h.resent.fetch_add(again.len() as u64, SeqCst);
            }
        }
        for (off, c) in again {
            let ok = match &c {
                Chunk::Data(b) => self.emit(data_frame(self.id, off, b)).await,
                Chunk::Fin => self.emit(data_frame(self.id, off, &[])).await,
            };
            if !ok {
                return false;
            }
        }
        self.link.lock().unwrap().synced = true;
        true
    }

    fn spawn_attach(self: &Arc<Self>, lane: LaneRef) {
        if self.attaching.swap(true, SeqCst) {
            return;
        }
        let s = self.clone();
        tokio::spawn(async move {
            s.attach(lane).await;
            s.attaching.store(false, SeqCst);
        });
    }

    async fn attach(self: &Arc<Self>, lane: LaneRef) {
        if !self.entry {
            tokio::time::sleep(EXIT_ATTACH_DELAY).await;
            if self.link.lock().unwrap().lane.is_some() {
                return;
            }
        }
        let _g = self.send_lock.lock().await;
        {
            let mut l = self.link.lock().unwrap();
            if l.lane.is_some() {
                return;
            }
            l.lane = Some(lane);
            l.detached_at = None;
            l.synced = false;
        }
        if self.entry && !self.confirmed.load(SeqCst) {
            if let Some(open) = self.open.clone() {
                if self.emit(open).await {
                    self.resend_locked(0).await;
                }
            }
        } else {
            let (rx_off, consumed) = self.state();
            self.emit(sync_frame(self.id, rx_off, consumed, true, false))
                .await;
        }
    }

    async fn on_sync(
        self: &Arc<Self>,
        lane: Option<LaneRef>,
        peer_rx: u64,
        peer_consumed: u64,
        reply: bool,
        force: bool,
    ) {
        self.confirmed.store(true, SeqCst);
        self.on_ack(peer_consumed);
        let _g = self.send_lock.lock().await;
        if let Some(lane) = lane {
            let mut l = self.link.lock().unwrap();
            if l.lane.as_ref().map(|x| x.id) != Some(lane.id) {
                l.lane = Some(lane);
                l.detached_at = None;
                l.synced = false;
            }
        }
        let aligned = {
            let l = self.link.lock().unwrap();
            if l.lane.is_none() {
                return;
            }
            l.synced
        };
        if reply {
            let (rx_off, consumed) = self.state();
            if !self
                .emit(sync_frame(self.id, rx_off, consumed, false, false))
                .await
            {
                return;
            }
        }
        if force || !aligned {
            self.resend_locked(peer_rx).await;
        }
    }

    fn on_ack(&self, consumed: u64) {
        self.confirmed.store(true, SeqCst);
        let delta = self.tx.lock().unwrap().ack(consumed);
        if delta > 0 {
            self.credit.add_permits(delta as usize);
            self.check_done();
        }
    }

    fn on_data(self: &Arc<Self>, off: u64, payload: Bytes) {
        self.confirmed.store(true, SeqCst);
        let take = self.rx.lock().unwrap().accept(off, &payload);
        match take {
            Take::Deliver(b) => {
                let _ = self.inbound.send(Ev::Data(b));
            }
            Take::Fin => {
                self.rx_fin.store(true, SeqCst);
                let _ = self.inbound.send(Ev::Fin);
            }
            Take::Duplicate => {}
            Take::Gap => {
                let due = {
                    let mut g = self.last_gap.lock().unwrap();
                    let due = g.is_none_or(|t| t.elapsed() > GAP_REQUEST_EVERY);
                    if due {
                        *g = Some(Instant::now());
                    }
                    due
                };
                if due {
                    let s = self.clone();
                    tokio::spawn(async move {
                        let _g = s.send_lock.lock().await;
                        let (rx_off, consumed) = s.state();
                        s.emit(sync_frame(s.id, rx_off, consumed, true, true)).await;
                    });
                }
            }
        }
    }

    fn check_done(&self) {
        let fin_end = self.fin_end.load(SeqCst);
        if fin_end == 0 || !self.rx_fin.load(SeqCst) || self.tx.lock().unwrap().acked < fin_end {
            return;
        }
        let (off, consumed) = self.state();
        if consumed >= off {
            if let Some(h) = self.hub.upgrade() {
                h.remove(self.id);
            }
        }
    }

    pub async fn abort(&self, tell_peer: bool) {
        if self.abort_tx.send_replace(true) {
            return;
        }
        if let Some(h) = self.hub.upgrade() {
            h.remove(self.id);
        }
        if tell_peer {
            let lane = self.link.lock().unwrap().lane.clone();
            if let Some(l) = lane {
                let id = self.id;
                tokio::spawn(async move {
                    let _ = l.tx.send(close_frame(id)).await;
                });
            }
        }
    }

    async fn cancelled(&self) {
        let mut rx = self.abort_tx.subscribe();
        let _ = rx.wait_for(|v| *v).await;
    }

    pub async fn run(
        self: Arc<Self>,
        sock: TcpStream,
        early: Bytes,
        meter: Option<Arc<StreamMeter>>,
    ) {
        let _ = sock.set_nodelay(true);
        let (rd, wr) = sock.into_split();
        let mut up = tokio::spawn(self.clone().uplink(rd, early, meter.clone()));
        let mut down = tokio::spawn(self.clone().downlink(wr, meter));
        tokio::select! {
            _ = async { let _ = tokio::join!(&mut up, &mut down); } => {}
            _ = self.cancelled() => {
                up.abort();
                down.abort();
            }
        }
        *self.finished.lock().unwrap() = Some(Instant::now());
        self.check_done();
    }

    async fn send_read(&self, b: Bytes, meter: &Option<Arc<StreamMeter>>) -> bool {
        let n = b.len();
        if let Some(m) = meter {
            if !m.up(n).await {
                self.abort(true).await;
                return false;
            }
        }
        match self.credit.acquire_many(n as u32).await {
            Ok(p) => p.forget(),
            Err(_) => return false,
        }
        let _g = self.send_lock.lock().await;
        for i in (0..n).step_by(MAX_PAYLOAD) {
            let c = b.slice(i..(i + MAX_PAYLOAD).min(n));
            let off = self.tx.lock().unwrap().push(Chunk::Data(c.clone()));
            if self.synced() {
                self.emit(data_frame(self.id, off, &c)).await;
            }
        }
        true
    }

    async fn uplink(
        self: Arc<Self>,
        mut rd: OwnedReadHalf,
        early: Bytes,
        meter: Option<Arc<StreamMeter>>,
    ) {
        if !early.is_empty() && !self.send_read(early, &meter).await {
            return;
        }
        let mut buf = BytesMut::with_capacity(UP_READ);
        loop {
            if buf.capacity() < UP_READ {
                buf.reserve(UP_READ);
            }
            match rd.read_buf(&mut buf).await {
                Ok(0) => {
                    let _g = self.send_lock.lock().await;
                    let off = self.tx.lock().unwrap().push(Chunk::Fin);
                    self.fin_end.store(off + 1, SeqCst);
                    if self.synced() {
                        self.emit(data_frame(self.id, off, &[])).await;
                    }
                    return;
                }
                Err(_) => return self.abort(true).await,
                Ok(n) => {
                    let b = if n >= UP_HANDOFF {
                        buf.split().freeze()
                    } else {
                        let b = Bytes::copy_from_slice(&buf);
                        buf.clear();
                        b
                    };
                    if !self.send_read(b, &meter).await {
                        return;
                    }
                }
            }
        }
    }

    async fn downlink(self: Arc<Self>, mut wr: OwnedWriteHalf, meter: Option<Arc<StreamMeter>>) {
        let Some(mut rx) = self.inbound_rx.lock().unwrap().take() else {
            return;
        };
        let mut batch: Vec<Bytes> = Vec::new();
        loop {
            let Some(first) = rx.recv().await else {
                let _ = wr.shutdown().await;
                return;
            };
            batch.clear();
            let (mut total, mut fin) = (0usize, false);
            let mut ev = Some(first);
            while let Some(e) = ev.take() {
                match e {
                    Ev::Data(b) => {
                        total += b.len();
                        batch.push(b);
                    }
                    Ev::Fin => {
                        fin = true;
                        break;
                    }
                }
                if total < DOWN_COALESCE {
                    ev = rx.try_recv().ok();
                }
            }
            if total > 0 {
                if let Some(m) = &meter {
                    if !m.down(total).await {
                        return self.abort(true).await;
                    }
                }
                if write_all_chunks(&mut wr, &batch).await.is_err() {
                    return self.abort(true).await;
                }
            }
            let consumed = {
                let mut r = self.rx.lock().unwrap();
                r.consumed += total as u64 + u64::from(fin);
                r.consumed
            };
            self.send_locked(ack_frame(self.id, consumed)).await;
            if fin {
                let _ = wr.shutdown().await;
                self.check_done();
                return;
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/resume.rs"]
mod tests;
