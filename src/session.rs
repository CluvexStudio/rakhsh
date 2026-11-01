use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};

use crate::carrier::BoxTx;
use crate::limits::StreamMeter;
use crate::noise::Enc;
use crate::wire::{self, MAX_PAYLOAD};

pub const WINDOW: usize = 16 * 1024 * 1024;

const UP_READ: usize = 64 * 1024;
const DOWN_COALESCE: usize = 256 * 1024;

pub(crate) async fn write_all_chunks(
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    chunks: &[Bytes],
) -> std::io::Result<()> {
    if let [one] = chunks {
        return wr.write_all(one).await;
    }
    let mut slices: Vec<std::io::IoSlice<'_>> =
        chunks.iter().map(|c| std::io::IoSlice::new(c)).collect();
    let mut bufs: &mut [std::io::IoSlice<'_>] = &mut slices;
    while !bufs.is_empty() {
        let n = wr.write_vectored(bufs).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        std::io::IoSlice::advance_slices(&mut bufs, n);
    }
    Ok(())
}

pub type Streams = Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Bytes>>>>;
pub type Credits = Arc<Mutex<HashMap<u32, Arc<Semaphore>>>>;

#[derive(Clone)]
pub struct Session {
    pub lane_id: u64,
    pub out_tx: mpsc::Sender<Vec<u8>>,
    pub streams: Streams,
    pub credits: Credits,
    pub next_id: Arc<AtomicU32>,
}

pub fn register(
    streams: &Streams,
    credits: &Credits,
    id: u32,
) -> (mpsc::UnboundedReceiver<Bytes>, Arc<Semaphore>) {
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let cred = Arc::new(Semaphore::new(WINDOW));
    streams.lock().unwrap().insert(id, in_tx);
    credits.lock().unwrap().insert(id, cred.clone());
    (in_rx, cred)
}

pub fn deregister(streams: &Streams, credits: &Credits, id: u32) {
    streams.lock().unwrap().remove(&id);
    credits.lock().unwrap().remove(&id);
}

#[derive(Default)]
pub struct LaneTasks(Vec<tokio::task::AbortHandle>);

impl LaneTasks {
    pub fn add<T>(&mut self, h: tokio::task::JoinHandle<T>) {
        self.0.push(h.abort_handle());
    }
}

impl Drop for LaneTasks {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

pub fn spawn_heartbeat(
    out_tx: mpsc::Sender<Vec<u8>>,
    secs: u64,
    lane_id: u64,
) -> Option<tokio::task::JoinHandle<()>> {
    if secs == 0 {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs));
        tick.tick().await;
        loop {
            tick.tick().await;
            if out_tx.send(crate::wire::ping()).await.is_err() {
                break;
            }
            if let Some(m) = crate::status::get() {
                m.ping_sent(lane_id);
            }
        }
    }))
}

pub fn spawn_writer(
    mut tx: BoxTx,
    enc: Enc,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(mut plain) = rx.recv().await {
            enc.seal_in_place(&mut plain);
            if tx.send(plain).await.is_err() {
                break;
            }
            while let Ok(mut plain) = rx.try_recv() {
                enc.seal_in_place(&mut plain);
                if tx.send(plain).await.is_err() {
                    return;
                }
            }
            if tx.flush().await.is_err() {
                break;
            }
        }
    })
}

pub struct StreamCtx {
    pub streams: Streams,
    pub credits: Credits,
    pub send_credit: Arc<Semaphore>,
    pub meter: Option<Arc<StreamMeter>>,
}

pub async fn run_stream(
    sock: TcpStream,
    id: u32,
    out_tx: mpsc::Sender<Vec<u8>>,
    mut in_rx: mpsc::UnboundedReceiver<Bytes>,
    ctx: StreamCtx,
) {
    let StreamCtx {
        streams,
        credits,
        send_credit,
        meter,
    } = ctx;
    let _ = sock.set_nodelay(true);
    let (mut rd, mut wr) = sock.into_split();

    let up_tx = out_tx.clone();
    let up_meter = meter.clone();
    let mut uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; UP_READ];
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) => {
                    return up_tx.send(wire::fin(id)).await.is_ok();
                }
                Err(_) => return false,
                Ok(n) => n,
            };
            if let Some(m) = &up_meter {
                if !m.up(n).await {
                    return false;
                }
            }
            match send_credit.acquire_many(n as u32).await {
                Ok(p) => p.forget(),
                Err(_) => return false,
            }
            for chunk in buf[..n].chunks(MAX_PAYLOAD) {
                if up_tx.send(wire::data(id, chunk)).await.is_err() {
                    return false;
                }
            }
        }
    });

    let cr_tx = out_tx.clone();
    let mut downlink = tokio::spawn(async move {
        let mut batch: Vec<Bytes> = Vec::new();
        while let Some(first) = in_rx.recv().await {
            if first.is_empty() {
                let _ = wr.shutdown().await;
                return true;
            }
            let mut total = first.len();
            let mut fin = false;
            batch.clear();
            batch.push(first);
            while total < DOWN_COALESCE {
                match in_rx.try_recv() {
                    Ok(c) if c.is_empty() => {
                        fin = true;
                        break;
                    }
                    Ok(c) => {
                        total += c.len();
                        batch.push(c);
                    }
                    Err(_) => break,
                }
            }
            if let Some(m) = &meter {
                if !m.down(total).await {
                    return false;
                }
            }
            if write_all_chunks(&mut wr, &batch).await.is_err() {
                return false;
            }
            let _ = cr_tx.send(wire::credit(id, total as u32)).await;
            if fin {
                let _ = wr.shutdown().await;
                return true;
            }
        }
        let _ = wr.shutdown().await;
        false
    });

    let (mut up_done, mut down_done) = (false, false);
    while !(up_done && down_done) {
        tokio::select! {
            r = &mut uplink, if !up_done => {
                if r.unwrap_or(false) { up_done = true } else { break }
            }
            r = &mut downlink, if !down_done => {
                if r.unwrap_or(false) { down_done = true } else { break }
            }
        }
    }
    uplink.abort();
    downlink.abort();

    let _ = out_tx.send(wire::close(id)).await;
    deregister(&streams, &credits, id);
}

pub async fn run_udp_exit(
    target: String,
    id: u32,
    out_tx: mpsc::Sender<Vec<u8>>,
    mut in_rx: mpsc::UnboundedReceiver<Bytes>,
    streams: Streams,
    credits: Credits,
) {
    let us = match tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await {
        Ok(s) => s,
        Err(_) => {
            deregister(&streams, &credits, id);
            let _ = out_tx.send(wire::close(id)).await;
            return;
        }
    };
    if us.connect(&target).await.is_err() {
        deregister(&streams, &credits, id);
        let _ = out_tx.send(wire::close(id)).await;
        return;
    }
    let us = Arc::new(us);

    let up_us = us.clone();
    let up_tx = out_tx.clone();
    let mut uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok(n) = up_us.recv(&mut buf).await {
            if up_tx.send(wire::data(id, &buf[..n])).await.is_err() {
                break;
            }
        }
    });

    let mut downlink = tokio::spawn(async move {
        while let Some(b) = in_rx.recv().await {
            let _ = us.send(&b).await;
        }
    });

    tokio::select! {
        _ = &mut uplink => { downlink.abort(); }
        _ = &mut downlink => { uplink.abort(); }
    }

    let _ = out_tx.send(wire::close(id)).await;
    deregister(&streams, &credits, id);
}

#[cfg(test)]
#[path = "../tests/unit/session.rs"]
mod tests;
