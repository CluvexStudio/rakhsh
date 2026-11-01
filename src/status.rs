use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::config::Config;

static METRICS: OnceLock<Arc<Metrics>> = OnceLock::new();

pub fn get() -> Option<&'static Arc<Metrics>> {
    METRICS.get()
}

pub const DEFAULT_SOCKET: &str = "/run/rakhsh.sock";

pub fn socket_path(cfg: &Config) -> String {
    cfg.control_socket
        .clone()
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string())
}

#[derive(Default)]
struct LaneInfo {
    label: String,
    up_since: Option<Instant>,
    rtt_ms: Option<f64>,
    jitter_ms: f64,
    pings: u64,
    pongs: u64,
    waiting: bool,
    last_ping: Option<Instant>,
}

impl LaneInfo {
    fn loss_pct(&self) -> f64 {
        if self.pings == 0 {
            0.0
        } else {
            (self.pings - self.pongs.min(self.pings)) as f64 * 100.0 / self.pings as f64
        }
    }
}

pub struct Metrics {
    start: Instant,
    pid: u32,
    host: String,
    role: String,
    carrier: String,
    encryption: String,
    resume: bool,
    target_lanes: usize,

    lanes_up: AtomicUsize,
    lanes_established: AtomicU64,
    peak_concurrent: AtomicUsize,

    peak_tx_bps: AtomicU64,
    peak_rx_bps: AtomicU64,

    active: Mutex<Option<Arc<AtomicUsize>>>,
    hub: Mutex<Option<Weak<crate::resume::Hub>>>,
    limiter: Mutex<Option<Arc<crate::limits::Limiter>>>,

    lanes: Mutex<BTreeMap<u64, LaneInfo>>,
    sample: Mutex<Sample>,
    cpu: Mutex<CpuSampler>,
    speedtest: Mutex<Option<mpsc::Sender<oneshot::Sender<SpeedResult>>>>,
}

#[derive(Default, Clone, Copy)]
struct Sample {
    tx_bps: u64,
    rx_bps: u64,
    cpu_pct: f64,
    sys_cpu_pct: f64,
    rss_kb: u64,
    sys_mem_total_kb: u64,
    sys_mem_avail_kb: u64,
    load1: f64,
    load5: f64,
    load15: f64,
}

pub fn init(cfg: &Config, role: &str) -> Arc<Metrics> {
    let m = Arc::new(Metrics {
        start: Instant::now(),
        pid: std::process::id(),
        host: hostname(),
        role: role.to_string(),
        carrier: cfg.carrier.clone().unwrap_or_else(|| "tcp".into()),
        encryption: cfg
            .crypto_mode()
            .map(|x| x.as_str().to_string())
            .unwrap_or_else(|_| "full".into()),
        resume: cfg.resume,
        target_lanes: cfg.lanes.unwrap_or(4),
        lanes_up: AtomicUsize::new(0),
        lanes_established: AtomicU64::new(0),
        peak_concurrent: AtomicUsize::new(0),
        peak_tx_bps: AtomicU64::new(0),
        peak_rx_bps: AtomicU64::new(0),
        active: Mutex::new(None),
        hub: Mutex::new(None),
        limiter: Mutex::new(None),
        lanes: Mutex::new(BTreeMap::new()),
        sample: Mutex::new(Sample::default()),
        cpu: Mutex::new(CpuSampler::default()),
        speedtest: Mutex::new(None),
    });
    let _ = METRICS.set(m.clone());
    let w = Arc::downgrade(&m);
    tokio::spawn(async move {
        let (mut last_tx, mut last_rx) = (
            crate::stats::TX.load(Relaxed),
            crate::stats::RX.load(Relaxed),
        );
        let mut last = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let Some(m) = w.upgrade() else { return };
            let dt = last.elapsed().as_secs_f64().max(1e-3);
            last = Instant::now();
            let (tx, rx) = (
                crate::stats::TX.load(Relaxed),
                crate::stats::RX.load(Relaxed),
            );
            let tx_bps = ((tx.wrapping_sub(last_tx)) as f64 * 8.0 / dt) as u64;
            let rx_bps = ((rx.wrapping_sub(last_rx)) as f64 * 8.0 / dt) as u64;
            last_tx = tx;
            last_rx = rx;
            m.peak_tx_bps.fetch_max(tx_bps, Relaxed);
            m.peak_rx_bps.fetch_max(rx_bps, Relaxed);
            let (cpu_pct, sys_cpu_pct) = m.cpu.lock().unwrap().tick(dt);
            let (rss_kb, _) = self_mem();
            let (mt, ma) = sys_mem();
            let (l1, l5, l15) = loadavg();
            *m.sample.lock().unwrap() = Sample {
                tx_bps,
                rx_bps,
                cpu_pct,
                sys_cpu_pct,
                rss_kb,
                sys_mem_total_kb: mt,
                sys_mem_avail_kb: ma,
                load1: l1,
                load5: l5,
                load15: l15,
            };
        }
    });
    m
}

impl Metrics {
    pub fn bind_active(&self, active: Arc<AtomicUsize>) {
        *self.active.lock().unwrap() = Some(active);
    }
    pub fn bind_hub(&self, hub: &Arc<crate::resume::Hub>) {
        *self.hub.lock().unwrap() = Some(Arc::downgrade(hub));
    }
    pub fn bind_limiter(&self, l: &Arc<crate::limits::Limiter>) {
        *self.limiter.lock().unwrap() = Some(l.clone());
    }
    pub fn bind_speedtest(&self, tx: mpsc::Sender<oneshot::Sender<SpeedResult>>) {
        *self.speedtest.lock().unwrap() = Some(tx);
    }

    pub async fn run_speedtest(&self) -> SpeedResult {
        let Some(tx) = self.speedtest.lock().unwrap().clone() else {
            return SpeedResult::default();
        };
        let (reply, rx) = oneshot::channel();
        if tx.send(reply).await.is_err() {
            return SpeedResult::default();
        }
        tokio::time::timeout(Duration::from_secs(20), rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or_default()
    }

    pub fn lane_up(&self, id: u64, label: &str) {
        let up = self.lanes_up.fetch_add(1, Relaxed) + 1;
        self.lanes_established.fetch_add(1, Relaxed);
        self.peak_concurrent.fetch_max(up, Relaxed);
        self.lanes.lock().unwrap().insert(
            id,
            LaneInfo {
                label: label.to_string(),
                up_since: Some(Instant::now()),
                ..Default::default()
            },
        );
    }

    pub fn lane_down(&self, id: u64) {
        self.lanes_up.fetch_sub(1, Relaxed);
        self.lanes.lock().unwrap().remove(&id);
    }

    pub fn ping_sent(&self, id: u64) {
        if let Some(l) = self.lanes.lock().unwrap().get_mut(&id) {
            l.pings += 1;
            l.waiting = true;
            l.last_ping = Some(Instant::now());
        }
    }

    pub fn pong_recv(&self, id: u64) {
        let mut g = self.lanes.lock().unwrap();
        let Some(l) = g.get_mut(&id) else { return };
        let Some(t) = l.last_ping.take() else { return };
        if !l.waiting {
            return;
        }
        l.waiting = false;
        l.pongs += 1;
        let rtt = t.elapsed().as_secs_f64() * 1000.0;
        match l.rtt_ms {
            None => {
                l.rtt_ms = Some(rtt);
                l.jitter_ms = 0.0;
            }
            Some(prev) => {
                let delta = (rtt - prev).abs();
                l.jitter_ms = 0.875 * l.jitter_ms + 0.125 * delta;
                l.rtt_ms = Some(0.875 * prev + 0.125 * rtt);
            }
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let s = *self.sample.lock().unwrap();
        let established = self.lanes_established.load(Relaxed);
        let peak = self.peak_concurrent.load(Relaxed) as u64;
        let streams = self
            .active
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| a.load(Relaxed))
            .unwrap_or(0);
        let resume_stats = self
            .hub
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade)
            .map(|h| ResumeStats {
                streams: h.live_streams(),
                resent_chunks: h.resent(),
            });
        let quotas = self
            .limiter
            .lock()
            .unwrap()
            .as_ref()
            .map(|l| l.usage().into_iter().map(QuotaUsage::from).collect())
            .unwrap_or_default();
        let links = self
            .lanes
            .lock()
            .unwrap()
            .iter()
            .map(|(id, l)| LinkSnap {
                id: *id,
                label: l.label.clone(),
                up_secs: l.up_since.map(|t| t.elapsed().as_secs()).unwrap_or(0),
                rtt_ms: l.rtt_ms.map(round1),
                jitter_ms: round1(l.jitter_ms),
                loss_pct: round1(l.loss_pct()),
            })
            .collect();
        let exit = self.role == "exit";
        let (down_bps, up_bps) = if exit {
            (s.tx_bps, s.rx_bps)
        } else {
            (s.rx_bps, s.tx_bps)
        };
        let (pt, pr) = (
            self.peak_tx_bps.load(Relaxed),
            self.peak_rx_bps.load(Relaxed),
        );
        let (peak_down, peak_up) = if exit { (pt, pr) } else { (pr, pt) };
        let (tt, rt) = (
            crate::stats::TX.load(Relaxed),
            crate::stats::RX.load(Relaxed),
        );
        let (down_total, up_total) = if exit { (tt, rt) } else { (rt, tt) };
        Snapshot {
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: self.pid,
            host: self.host.clone(),
            role: self.role.clone(),
            carrier: self.carrier.clone(),
            encryption: self.encryption.clone(),
            resume: self.resume,
            uptime_secs: self.start.elapsed().as_secs(),
            target_lanes: self.target_lanes,
            lanes_up: self.lanes_up.load(Relaxed),
            lanes_established: established,
            reconnects: established.saturating_sub(peak),
            streams,
            tx_bps: up_bps,
            rx_bps: down_bps,
            peak_tx_bps: peak_up,
            peak_rx_bps: peak_down,
            tx_total: up_total,
            rx_total: down_total,
            cpu_pct: round1(s.cpu_pct),
            rss_mb: round1(s.rss_kb as f64 / 1024.0),
            sys_cpu_pct: round1(s.sys_cpu_pct),
            sys_mem_pct: if s.sys_mem_total_kb == 0 {
                0.0
            } else {
                round1(
                    (s.sys_mem_total_kb - s.sys_mem_avail_kb) as f64 * 100.0
                        / s.sys_mem_total_kb as f64,
                )
            },
            load: [round2(s.load1), round2(s.load5), round2(s.load15)],
            resume_stats,
            quotas,
            links,
            ts: now_unix(),
        }
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}
fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Snapshot {
    pub version: String,
    pub pid: u32,
    pub host: String,
    pub role: String,
    pub carrier: String,
    pub encryption: String,
    pub resume: bool,
    pub uptime_secs: u64,
    pub target_lanes: usize,
    pub lanes_up: usize,
    pub lanes_established: u64,
    pub reconnects: u64,
    pub streams: usize,
    pub tx_bps: u64,
    pub rx_bps: u64,
    pub peak_tx_bps: u64,
    pub peak_rx_bps: u64,
    pub tx_total: u64,
    pub rx_total: u64,
    pub cpu_pct: f64,
    pub rss_mb: f64,
    pub sys_cpu_pct: f64,
    pub sys_mem_pct: f64,
    pub load: [f64; 3],
    pub resume_stats: Option<ResumeStats>,
    pub quotas: Vec<QuotaUsage>,
    pub links: Vec<LinkSnap>,
    pub ts: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ResumeStats {
    pub streams: usize,
    pub resent_chunks: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct QuotaUsage {
    pub scope: String,
    pub used: u64,
    pub limit: u64,
    pub pct: f64,
    pub resets: String,
}

impl From<crate::limits::QuotaUsage> for QuotaUsage {
    fn from(q: crate::limits::QuotaUsage) -> Self {
        QuotaUsage {
            scope: q.scope,
            used: q.used,
            limit: q.limit,
            pct: round1(q.pct),
            resets: q.resets,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LinkSnap {
    pub id: u64,
    pub label: String,
    pub up_secs: u64,
    pub rtt_ms: Option<f64>,
    pub jitter_ms: f64,
    pub loss_pct: f64,
}

#[derive(Serialize, Deserialize, Clone, Copy, Default)]
pub struct SpeedResult {
    pub down_mbit: Option<f64>,
    pub up_mbit: Option<f64>,
}

pub async fn serve(path: String) {
    let _ = std::fs::remove_file(&path);
    if let Some(dir) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let listener = match tokio::net::UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            warn!("control socket {path}: {e} (status/panel disabled; set control_socket to a writable path)");
            return;
        }
    };
    debug!("control socket on {path}");
    loop {
        let Ok((mut conn, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut cmd = [0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut cmd))
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(0);
            let verb = std::str::from_utf8(&cmd[..n]).unwrap_or("").trim();
            let out = if verb == "speedtest" {
                let r = match get() {
                    Some(m) => m.run_speedtest().await,
                    None => SpeedResult::default(),
                };
                serde_json::to_vec(
                    &serde_json::json!({ "down_mbit": r.down_mbit, "up_mbit": r.up_mbit }),
                )
                .unwrap_or_else(|_| b"{}".to_vec())
            } else {
                match get().map(|m| m.snapshot()) {
                    Some(s) => serde_json::to_vec(&s).unwrap_or_else(|_| b"{}".to_vec()),
                    None => b"{\"error\":\"not running\"}".to_vec(),
                }
            };
            let _ = conn.write_all(&out).await;
            let _ = conn.write_all(b"\n").await;
            let _ = conn.shutdown().await;
        });
    }
}

pub async fn query_speedtest(path: &str) -> anyhow::Result<SpeedResult> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut conn = tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| anyhow::anyhow!("cannot reach the daemon on {path}: {e}"))?;
    conn.write_all(b"speedtest\n").await?;
    conn.shutdown().await.ok();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(25), conn.read_to_end(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("speed test timed out"))??;
    let v: serde_json::Value = serde_json::from_slice(&buf)?;
    Ok(SpeedResult {
        down_mbit: v.get("down_mbit").and_then(serde_json::Value::as_f64),
        up_mbit: v.get("up_mbit").and_then(serde_json::Value::as_f64),
    })
}

pub async fn query(path: &str) -> anyhow::Result<Snapshot> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut conn = tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| anyhow::anyhow!("cannot reach the daemon on {path}: {e} (is it running? is control_socket set to match?)"))?;
    conn.write_all(b"status\n").await?;
    conn.shutdown().await.ok();
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "node".into())
}

fn self_mem() -> (u64, u64) {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let rss = field_kb(&s, "VmRSS:");
    (rss, 0)
}

fn sys_mem() -> (u64, u64) {
    let s = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    (field_kb(&s, "MemTotal:"), field_kb(&s, "MemAvailable:"))
}

fn field_kb(s: &str, key: &str) -> u64 {
    s.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn loadavg() -> (f64, f64, f64) {
    let s = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let mut it = s.split_whitespace();
    let p = |x: Option<&str>| x.and_then(|v| v.parse().ok()).unwrap_or(0.0);
    (p(it.next()), p(it.next()), p(it.next()))
}

#[derive(Default)]
struct CpuSampler {
    last_self: u64,
    last_total: u64,
    last_idle: u64,
    clk: u64,
}

impl CpuSampler {
    fn tick(&mut self, dt: f64) -> (f64, f64) {
        if self.clk == 0 {
            self.clk = clk_tck();
        }
        let proc_pct = {
            let now = self_cpu_ticks();
            let d = now.saturating_sub(self.last_self);
            self.last_self = now;
            if self.last_self == d {
                0.0
            } else {
                d as f64 / self.clk as f64 / dt * 100.0
            }
        };
        let sys_pct = {
            let (total, idle) = sys_cpu_jiffies();
            let dtot = total.saturating_sub(self.last_total);
            let didle = idle.saturating_sub(self.last_idle);
            let first = self.last_total == 0;
            self.last_total = total;
            self.last_idle = idle;
            if first || dtot == 0 {
                0.0
            } else {
                (dtot - didle) as f64 * 100.0 / dtot as f64
            }
        };
        (proc_pct.max(0.0), sys_pct.clamp(0.0, 100.0))
    }
}

fn clk_tck() -> u64 {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 {
        v as u64
    } else {
        100
    }
}

fn self_cpu_ticks() -> u64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after = s.rsplit_once(')').map(|(_, r)| r).unwrap_or(&s);
    let f: Vec<&str> = after.split_whitespace().collect();
    let u: u64 = f.get(11).and_then(|v| v.parse().ok()).unwrap_or(0);
    let st: u64 = f.get(12).and_then(|v| v.parse().ok()).unwrap_or(0);
    u + st
}

fn sys_cpu_jiffies() -> (u64, u64) {
    let s = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    parse_stat_cpu(&s)
}

fn parse_stat_cpu(s: &str) -> (u64, u64) {
    let Some(line) = s.lines().find(|l| l.starts_with("cpu ")) else {
        return (0, 0);
    };
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    let total: u64 = v.iter().sum();
    let idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
    (total, idle)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mbit(bps: u64) -> String {
    format!("{:.1} Mbit/s", bps as f64 / 1e6)
}

fn bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}

fn dur(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else {
        format!("{m}m {s}s")
    }
}

pub fn print_table(s: &Snapshot) {
    let row = |k: &str, v: String| println!("  {k:<16}{v}");
    println!("rakhsh {} — {} ({})", s.version, s.host, s.role);
    row("uptime", dur(s.uptime_secs));
    row(
        "carrier",
        format!(
            "{}, encryption {}{}",
            s.carrier,
            s.encryption,
            if s.resume { ", resume on" } else { "" }
        ),
    );
    row(
        "lanes",
        format!(
            "{} up, {} established, {} reconnect(s)",
            s.lanes_up, s.lanes_established, s.reconnects
        ),
    );
    row("streams", s.streams.to_string());
    row(
        "download",
        format!("{} (peak {})", mbit(s.rx_bps), mbit(s.peak_rx_bps)),
    );
    row(
        "upload",
        format!("{} (peak {})", mbit(s.tx_bps), mbit(s.peak_tx_bps)),
    );
    row(
        "transferred",
        format!("{} down, {} up", bytes(s.rx_total), bytes(s.tx_total)),
    );
    row(
        "cpu",
        format!("{:.1}% process, {:.1}% system", s.cpu_pct, s.sys_cpu_pct),
    );
    row(
        "memory",
        format!(
            "{:.1} MiB rss, {:.1}% system, load {:.2}",
            s.rss_mb, s.sys_mem_pct, s.load[0]
        ),
    );
    if let Some(r) = &s.resume_stats {
        row(
            "resume",
            format!(
                "{} live stream(s), {} chunk(s) resent",
                r.streams, r.resent_chunks
            ),
        );
    }
    for q in &s.quotas {
        row(
            "quota",
            format!(
                "{}: {} / {} ({:.1}%), resets {}",
                q.scope,
                bytes(q.used),
                bytes(q.limit),
                q.pct,
                q.resets
            ),
        );
    }
    if !s.links.is_empty() {
        println!("  links");
        for l in &s.links {
            let rtt = l
                .rtt_ms
                .map(|r| format!("{r:.1} ms",))
                .unwrap_or_else(|| "—".into());
            println!(
                "    #{:<4}{:<10} up {:<8} rtt {rtt}  jitter {:.1} ms  loss {:.1}%",
                l.id,
                l.label,
                dur(l.up_secs),
                l.jitter_ms,
                l.loss_pct
            );
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/status.rs"]
mod tests;
