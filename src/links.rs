use anyhow::{anyhow, bail, Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::carrier::{BoxRx, BoxTx, Carrier};
use crate::config::Config;
use crate::noise::{Enc, Keys};

pub type Serve = Arc<
    dyn Fn(u64, BoxTx, BoxRx, Enc) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

const STAGGER: Duration = Duration::from_millis(1200);
const PENALTY_BASE: Duration = Duration::from_secs(3);
const PENALTY_MAX: Duration = Duration::from_secs(60);
const FLAP: Duration = Duration::from_secs(15);
const RETRY: Duration = Duration::from_secs(3);
const QUICK_RETRY: Duration = Duration::from_millis(250);

pub struct Point {
    pub kind: String,
    pub carrier: Carrier,
    pub addr: String,
    pub peer: [u8; 32],
    pub peer_name: String,
}

impl Point {
    pub fn label(&self) -> String {
        if self.peer_name == "peer" {
            format!("{} {}", self.kind, self.addr)
        } else {
            format!("{} {} ({})", self.kind, self.addr, self.peer_name)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Failover,
    Spread,
}

impl Policy {
    pub fn parse(s: Option<&str>) -> Result<Policy> {
        match s.map(str::trim) {
            None | Some("failover") => Ok(Policy::Failover),
            Some("spread") => Ok(Policy::Spread),
            Some(other) => {
                bail!("link_policy must be \"failover\" or \"spread\" (got \"{other}\")")
            }
        }
    }
}

pub fn dialing(cfg: &Config) -> bool {
    (cfg.role == "entry") == (cfg.dial.as_deref() == Some("entry"))
}

pub fn points(cfg: &Config, primary: &str, dialing: bool) -> Result<Vec<Point>> {
    let base = Carrier::from_cfg(cfg)?;
    let kind = cfg.carrier.as_deref().unwrap_or("tcp").to_string();
    let admitted = cfg.peer_keys()?;
    let first = &admitted[0];
    let mut v = Vec::new();
    if !cfg.peer_public.is_empty() || !dialing {
        v.push(Point {
            kind: kind.clone(),
            carrier: base.clone(),
            addr: primary.to_string(),
            peer: first.key,
            peer_name: if dialing {
                first.name.clone()
            } else {
                "peer".into()
            },
        });
    }
    if dialing {
        for a in &cfg.backup_connect {
            v.push(Point {
                kind: kind.clone(),
                carrier: base.clone(),
                addr: a.clone(),
                peer: first.key,
                peer_name: first.name.clone(),
            });
        }
        for pk in admitted
            .iter()
            .skip(usize::from(!cfg.peer_public.is_empty()))
        {
            let Some(addr) = &pk.connect else { continue };
            v.push(Point {
                kind: kind.clone(),
                carrier: base.clone(),
                addr: addr.clone(),
                peer: pk.key,
                peer_name: pk.name.clone(),
            });
        }
    }
    for l in &cfg.link {
        let carrier = Carrier::from_cfg(&cfg.with_link(l))
            .with_context(|| format!("[[link]] {} {}", l.carrier, l.addr))?;
        v.push(Point {
            kind: l.carrier.clone(),
            carrier,
            addr: l.addr.clone(),
            peer: first.key,
            peer_name: first.name.clone(),
        });
    }
    if v.is_empty() {
        bail!("nothing to dial: give the peer a connect address");
    }
    Ok(v)
}

struct Settings {
    policy: Policy,
    timeout: Duration,
    probe: Option<Duration>,
}

fn settings(cfg: &Config) -> Result<Settings> {
    Ok(Settings {
        policy: Policy::parse(cfg.link_policy.as_deref())?,
        timeout: Duration::from_secs(cfg.link_timeout.unwrap_or(10).max(2)),
        probe: match cfg.link_probe.unwrap_or(30) {
            0 => None,
            n => Some(Duration::from_secs(n)),
        },
    })
}

fn primary_addr(cfg: &Config) -> Result<String> {
    if dialing(cfg) {
        cfg.tunnel_connect
            .clone()
            .or_else(|| cfg.peers.iter().find_map(|p| p.connect.clone()))
            .context("this side dials lanes: it needs tunnel_connect or a [[peer]] with connect")
    } else {
        cfg.tunnel_listen
            .clone()
            .context("this side accepts lanes: it needs tunnel_listen")
    }
}

pub fn describe(cfg: &Config) -> Result<Vec<String>> {
    let s = settings(cfg)?;
    let dial = dialing(cfg);
    let pts = points(cfg, &primary_addr(cfg)?, dial)?;
    let mut out = vec![format!(
        "{} {} link(s), policy {:?}, attempt timeout {}s, check for a better link every {}",
        if dial { "dials" } else { "listens on" },
        pts.len(),
        s.policy,
        s.timeout.as_secs(),
        s.probe
            .map(|p| format!("{}s", p.as_secs()))
            .unwrap_or_else(|| "never".into())
    )];
    for (i, p) in pts.iter().enumerate() {
        out.push(format!("  {}. {}", i + 1, p.label()));
    }
    let admitted = cfg.peer_keys()?;
    if admitted.len() > 1 {
        let names: Vec<&str> = admitted.iter().map(|p| p.name.as_str()).collect();
        out.push(format!(
            "  admits {} peer identities: {}",
            admitted.len(),
            names.join(", ")
        ));
    }
    Ok(out)
}

pub async fn listen(cfg: &Config, keys: Keys, serve: Serve) -> Result<()> {
    let s = settings(cfg)?;
    let pts = points(cfg, &primary_addr(cfg)?, false)?;
    let ids = Arc::new(AtomicU64::new(1));
    let mut tasks = Vec::new();
    for p in pts {
        let listener = p
            .carrier
            .bind(&p.addr)
            .await
            .with_context(|| format!("listening on {}", p.label()))?;
        info!("listening for lanes on {}", p.label());
        let (serve, ids, label, timeout) = (serve.clone(), ids.clone(), p.label(), s.timeout);
        let keys = keys.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let (mut tx, mut rx) = match listener.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        warn!("accept lane on {label} failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let lane_id = ids.fetch_add(1, SeqCst);
                let (serve, label, keys) = (serve.clone(), label.clone(), keys.clone());
                tokio::spawn(async move {
                    let (enc, admitted) = match tokio::time::timeout(
                        timeout,
                        keys.accept(&mut *tx, &mut *rx),
                    )
                    .await
                    {
                        Ok(Ok(pair)) => pair,
                        Ok(Err(e)) => return warn!("lane {lane_id} on {label} refused: {e:#}"),
                        Err(_) => {
                            return warn!(
                                "lane {lane_id} on {label}: no handshake within {}s",
                                timeout.as_secs()
                            )
                        }
                    };
                    info!(
                        "lane {lane_id} authenticated via {label} as {}",
                        keys.admitted_name(admitted)
                    );
                    if let Err(e) = serve(lane_id, tx, rx, enc).await {
                        warn!("lane {lane_id} ended: {e:#}");
                    }
                });
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Health {
    fail: u32,
    until: Instant,
}

struct Established {
    tx: BoxTx,
    rx: BoxRx,
    enc: Enc,
    idx: usize,
}

pub struct Dialer {
    points: Vec<Point>,
    health: Mutex<Vec<Health>>,
    keys: Keys,
    policy: Policy,
    timeout: Duration,
    probe: Option<Duration>,
}

fn penalty(fail: u32) -> Duration {
    (PENALTY_BASE * 2u32.pow(fail.saturating_sub(1).min(5))).min(PENALTY_MAX)
}

impl Dialer {
    fn new(cfg: &Config, keys: Keys) -> Result<Dialer> {
        let s = settings(cfg)?;
        let points = points(cfg, &primary_addr(cfg)?, true)?;
        let now = Instant::now();
        Ok(Dialer {
            health: Mutex::new(vec![
                Health {
                    fail: 0,
                    until: now
                };
                points.len()
            ]),
            points,
            keys,
            policy: s.policy,
            timeout: s.timeout,
            probe: s.probe,
        })
    }

    fn order(&self, lane: usize) -> Vec<usize> {
        let n = self.points.len();
        let shift = if self.policy == Policy::Spread {
            lane % n
        } else {
            0
        };
        (0..n).map(|k| (k + shift) % n).collect()
    }

    fn penalized(&self, i: usize) -> bool {
        self.health.lock().unwrap()[i].until > Instant::now()
    }

    fn failed(&self, i: usize) {
        let mut h = self.health.lock().unwrap();
        h[i].fail = h[i].fail.saturating_add(1);
        h[i].until = Instant::now() + penalty(h[i].fail);
    }

    fn proved(&self, i: usize) {
        let mut h = self.health.lock().unwrap();
        h[i] = Health {
            fail: 0,
            until: Instant::now(),
        };
    }

    fn ended(&self, i: usize, lived: Duration) {
        if lived >= FLAP {
            self.proved(i)
        } else {
            self.failed(i)
        }
    }

    async fn attempt(&self, i: usize) -> Result<Established> {
        let p = &self.points[i];
        let work = async {
            let (mut tx, mut rx) = p.carrier.dial(&p.addr).await?;
            let enc = self.keys.connect_to(&p.peer, &mut *tx, &mut *rx).await?;
            Ok::<Established, anyhow::Error>(Established {
                tx,
                rx,
                enc,
                idx: i,
            })
        };
        match tokio::time::timeout(self.timeout, work).await {
            Ok(r) => r,
            Err(_) => Err(anyhow!("no answer within {}s", self.timeout.as_secs())),
        }
    }

    fn start(
        &self,
        i: usize,
    ) -> Pin<Box<dyn Future<Output = (usize, Result<Established>)> + Send + '_>> {
        Box::pin(async move { (i, self.attempt(i).await) })
    }

    async fn connect(&self, order: &[usize]) -> Result<Established> {
        let mut cands: Vec<usize> = order
            .iter()
            .copied()
            .filter(|&i| !self.penalized(i))
            .collect();
        if cands.is_empty() {
            cands = order.to_vec();
        }
        let mut running = FuturesUnordered::new();
        let mut next = 0usize;
        loop {
            if running.is_empty() {
                if next >= cands.len() {
                    return Err(anyhow!("every link failed"));
                }
                running.push(self.start(cands[next]));
                next += 1;
            }
            tokio::select! {
                Some((i, res)) = running.next() => match res {
                    Ok(est) => return Ok(est),
                    Err(e) => {
                        warn!("link {} failed: {e:#}", self.points[i].label());
                        self.failed(i);
                    }
                },
                _ = tokio::time::sleep(STAGGER), if next < cands.len() => {
                    running.push(self.start(cands[next]));
                    next += 1;
                }
            }
        }
    }

    async fn better(&self, order: &[usize], pos: usize, lane: usize) -> Established {
        let every = self.probe.unwrap_or(Duration::from_secs(30));
        tokio::time::sleep(every + every.mul_f64((lane % 8) as f64 / 8.0)).await;
        loop {
            for &i in &order[..pos] {
                match self.attempt(i).await {
                    Ok(est) => return est,
                    Err(_) => self.failed(i),
                }
            }
            tokio::time::sleep(every).await;
        }
    }
}

enum Outcome {
    Ended(Result<()>),
    Moved(Established),
}

pub async fn dial_lanes(cfg: &Config, keys: Keys, serve: Serve) -> Result<()> {
    let d = Arc::new(Dialer::new(cfg, keys)?);
    let lanes = d.points[0]
        .carrier
        .lanes_override()
        .unwrap_or_else(|| cfg.lanes.unwrap_or(4).max(1));
    info!(
        "opening {lanes} lane(s) over {} link(s): {}",
        d.points.len(),
        d.points
            .iter()
            .map(Point::label)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut handles = Vec::new();
    for lane in 0..lanes {
        let (d, serve) = (d.clone(), serve.clone());
        handles.push(tokio::spawn(async move {
            let lane_id = lane as u64 + 1;
            let order = d.order(lane);
            loop {
                let mut est = match d.connect(&order).await {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("lane {lane_id}: no link works ({e:#})");
                        tokio::time::sleep(RETRY).await;
                        continue;
                    }
                };
                let mut lived: Duration;
                loop {
                    let idx = est.idx;
                    let pos = order.iter().position(|&i| i == idx).unwrap_or(0);
                    info!("lane {lane_id} up via {}", d.points[idx].label());
                    let started = Instant::now();
                    let outcome = {
                        let fut = serve(lane_id, est.tx, est.rx, est.enc);
                        tokio::pin!(fut);
                        tokio::select! {
                            r = &mut fut => Outcome::Ended(r),
                            better = d.better(&order, pos, lane), if pos > 0 && d.probe.is_some() => Outcome::Moved(better),
                        }
                    };
                    lived = started.elapsed();
                    d.ended(idx, lived);
                    match outcome {
                        Outcome::Moved(better) => {
                            info!("lane {lane_id} moving up to {}", d.points[better.idx].label());
                            est = better;
                        }
                        Outcome::Ended(r) => {
                            if let Err(e) = r {
                                warn!("lane {lane_id} ended on {}: {e:#}", d.points[idx].label());
                            }
                            break;
                        }
                    }
                }
                tokio::time::sleep(if lived >= FLAP { QUICK_RETRY } else { RETRY }).await;
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/links.rs"]
mod tests;
