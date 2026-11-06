use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::carrier::{BoxRx, BoxTx};
use crate::config::Config;
use crate::l3::L3;
use crate::links;
use crate::noise::{Enc, Keys};
use crate::resume;
use crate::session::{
    deregister, register, run_stream, run_udp_exit, spawn_heartbeat, spawn_writer, Credits,
    LaneTasks, Streams,
};
use crate::wire::{self, Frame, FLAG_UDP};

static SYNC_TX: std::sync::OnceLock<tokio::sync::watch::Sender<Option<Arc<Vec<u8>>>>> =
    std::sync::OnceLock::new();

fn spawn_xui_poller(cfg: &Config) {
    let (Some(panel), Some(token)) = (cfg.xui_panel.clone(), cfg.xui_token.clone()) else {
        return;
    };
    let host = cfg
        .xui_target_host
        .clone()
        .unwrap_or_else(|| "127.0.0.1".into());
    let pp = cfg.xui_proxy_protocol.unwrap_or(false);
    let every = Duration::from_secs(cfg.xui_interval.unwrap_or(10).max(2));
    let (tx, _rx) = tokio::sync::watch::channel(None);
    let _ = SYNC_TX.set(tx);
    info!(
        "live x-ui sync on: polling {panel} every {}s",
        every.as_secs()
    );
    tokio::spawn(async move {
        let mut last: Option<Vec<u8>> = None;
        loop {
            match crate::xui::fetch_forwards(&panel, &token, &host, pp).await {
                Ok((fwds, _skipped, _total)) => {
                    let json = serde_json::to_vec(&fwds).unwrap_or_default();
                    if last.as_deref() != Some(json.as_slice()) {
                        info!(
                            "x-ui: {} forward(s) in the panel -> pushing to the entry",
                            fwds.len()
                        );
                        if let Some(tx) = SYNC_TX.get() {
                            tx.send_replace(Some(Arc::new(json.clone())));
                        }
                        last = Some(json);
                    }
                }
                Err(e) => warn!("x-ui poll failed (keeping the last forward set): {e:#}"),
            }
            tokio::time::sleep(every).await;
        }
    });
}

pub async fn run(cfg: Config) -> Result<()> {
    let keys = Keys::from_cfg(&cfg)?;
    keys.mode.announce();
    let metrics = crate::status::init(&cfg, "exit");
    tokio::spawn(crate::status::serve(crate::status::socket_path(&cfg)));
    let stream_gauge = Arc::new(AtomicUsize::new(0));
    metrics.bind_active(stream_gauge.clone());
    let l3 = crate::l3::setup(&cfg)?;
    crate::stats::spawn_logger();
    spawn_xui_poller(&cfg);
    let hb = cfg.tuning().heartbeat;
    crate::engine::spawn(&cfg, None).await?;

    let hub = resume::from_cfg(&cfg, false);
    if let Some(h) = &hub {
        metrics.bind_hub(h);
    }
    let serve: links::Serve = {
        let (l3, hub) = (l3.clone(), hub.clone());
        Arc::new(move |lane_id, carrier, tx, rx, enc| {
            let (l3, hub, gauge) = (l3.clone(), hub.clone(), stream_gauge.clone());
            Box::pin(async move {
                if let Some(m) = crate::status::get() {
                    m.lane_up(lane_id, &carrier);
                }
                let ctx = ExitCtx {
                    enc,
                    l3: l3.clone(),
                    hub: hub.clone(),
                    hb,
                    stream_gauge: gauge,
                };
                let r = serve_exit_lane(tx, rx, lane_id, ctx).await;
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

struct ExitCtx {
    enc: Enc,
    l3: Option<Arc<L3>>,
    hub: Option<Arc<resume::Hub>>,
    hb: u64,
    stream_gauge: Arc<AtomicUsize>,
}

async fn serve_exit_lane(tx: BoxTx, mut rx: BoxRx, lane_id: u64, ctx: ExitCtx) -> Result<()> {
    let ExitCtx {
        enc,
        l3,
        hub,
        hb,
        stream_gauge,
    } = ctx;
    let (l3, hub) = (&l3, &hub);
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(1024);
    if let Some(l3) = l3 {
        l3.add_lane(out_tx.clone());
    }
    let mut tasks = LaneTasks::default();
    tasks.add(spawn_writer(tx, enc.clone(), out_rx));
    if let Some(h) = spawn_heartbeat(out_tx.clone(), hb, lane_id) {
        tasks.add(h);
    }
    if let Some(sync) = SYNC_TX.get() {
        let mut rx_set = sync.subscribe();
        let out = out_tx.clone();
        tasks.add(tokio::spawn(async move {
            loop {
                let cur = rx_set.borrow_and_update().clone();
                if let Some(json) = cur {
                    if out.send(wire::sync(&json)).await.is_err() {
                        break;
                    }
                }
                if rx_set.changed().await.is_err() {
                    break;
                }
            }
        }));
    }
    let dead =
        Duration::from_secs(
            hb.max(5)
                .saturating_mul(3)
                .max(if hub.is_some() { 15 } else { 30 }),
        );

    let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
    let credits: Credits = Arc::new(Mutex::new(HashMap::new()));
    let _cleanup = LaneCleanup {
        lane_id,
        hub: hub.clone(),
        streams: streams.clone(),
        credits: credits.clone(),
        _tasks: tasks,
    };
    if let Some(h) = hub {
        h.lane_up(lane_id, out_tx.clone());
    }

    loop {
        let frame = match tokio::time::timeout(dead, rx.recv()).await {
            Ok(Ok(f)) => f,
            Ok(Err(_)) => break,
            Err(_) => {
                warn!(
                    "lane {lane_id} dead ({}s silent), reconnecting",
                    dead.as_secs()
                );
                break;
            }
        };
        let plain = match enc.open_bytes(frame) {
            Ok(p) => p,
            Err(_) => break,
        };
        if let Some(h) = hub {
            if plain.first().is_some_and(|t| *t >= resume::R_FIRST) {
                h.on_frame(lane_id, &plain).await;
                continue;
            }
        }
        match wire::parse(&plain) {
            Some(Frame::Open {
                id,
                flags,
                target,
                client,
            }) => {
                let (rx, cred) = register(&streams, &credits, id);
                let out_tx = out_tx.clone();
                let streams2 = streams.clone();
                let credits2 = credits.clone();
                if target == "@speedtest" || target == "@speedtest-up" {
                    let up = target == "@speedtest-up";
                    let out = out_tx.clone();
                    let (s2, c2) = (streams.clone(), credits.clone());
                    tokio::spawn(async move {
                        if up {
                            let mut rx = rx;
                            while let Some(b) = rx.recv().await {
                                if !b.is_empty() {
                                    let _ = out.send(wire::credit(id, b.len() as u32)).await;
                                }
                            }
                        } else {
                            let mut drain = rx;
                            tokio::spawn(async move { while drain.recv().await.is_some() {} });
                            let chunk = vec![0u8; wire::MAX_PAYLOAD];
                            let end = std::time::Instant::now() + Duration::from_secs(6);
                            while std::time::Instant::now() < end {
                                match cred.acquire_many(chunk.len() as u32).await {
                                    Ok(p) => p.forget(),
                                    Err(_) => break,
                                }
                                if out.send(wire::data(id, &chunk)).await.is_err() {
                                    break;
                                }
                            }
                            let _ = out.send(wire::fin(id)).await;
                        }
                        deregister(&s2, &c2, id);
                    });
                    continue;
                }
                stream_gauge.fetch_add(1, Relaxed);
                let gauge = stream_gauge.clone();
                if flags & FLAG_UDP != 0 {
                    tokio::spawn(async move {
                        run_udp_exit(target, id, out_tx, rx, streams2, credits2).await;
                        gauge.fetch_sub(1, Relaxed);
                    });
                } else {
                    tokio::spawn(async move {
                        match TcpStream::connect(&target).await {
                            Ok(mut sock) => {
                                if let Some(c) = client.as_deref().and_then(|c| c.parse().ok()) {
                                    if let Ok(dst) = sock.peer_addr() {
                                        use tokio::io::AsyncWriteExt;
                                        let _ =
                                            sock.write_all(&crate::proxy::proxy_v2(c, dst)).await;
                                    }
                                }
                                run_stream(
                                    sock,
                                    id,
                                    out_tx,
                                    rx,
                                    crate::session::StreamCtx {
                                        streams: streams2,
                                        credits: credits2,
                                        send_credit: cred,
                                        meter: None,
                                    },
                                )
                                .await
                            }
                            Err(e) => {
                                warn!("dial {target} failed: {e}");
                                deregister(&streams2, &credits2, id);
                                let _ = out_tx.send(wire::close(id)).await;
                            }
                        }
                        gauge.fetch_sub(1, Relaxed);
                    });
                }
            }
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
            _ => {}
        }
    }
    Ok(())
}

struct LaneCleanup {
    lane_id: u64,
    hub: Option<Arc<resume::Hub>>,
    streams: Streams,
    credits: Credits,
    _tasks: LaneTasks,
}

impl Drop for LaneCleanup {
    fn drop(&mut self) {
        self.streams.lock().unwrap().clear();
        self.credits.lock().unwrap().clear();
        if let Some(h) = &self.hub {
            h.lane_down(self.lane_id);
        }
    }
}
