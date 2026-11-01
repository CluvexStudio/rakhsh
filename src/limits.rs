use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::config::{Config, Limits};

pub fn parse_rate(s: &str) -> Result<f64> {
    let t = s.trim();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: f64 = num
        .parse()
        .with_context(|| format!("bad rate {s:?}: no number"))?;
    let unit = unit.trim();
    let unit = unit
        .strip_suffix("/s")
        .or_else(|| unit.strip_suffix("ps"))
        .unwrap_or(unit);
    let (factor, rest) = match unit.chars().next() {
        Some(c @ ('k' | 'K' | 'm' | 'M' | 'g' | 'G')) => (
            match c.to_ascii_lowercase() {
                'k' => 1e3,
                'm' => 1e6,
                _ => 1e9,
            },
            &unit[1..],
        ),
        _ => (1.0, unit),
    };
    let bytes = match rest {
        "bit" | "Bit" | "b" => n * factor / 8.0,
        "B" => n * factor,
        _ => bail!("bad rate {s:?}: use e.g. 20Mbit, 1.5Gbit/s or 5MB/s"),
    };
    if bytes < 1.0 {
        bail!("rate {s:?} is below 1 byte per second");
    }
    Ok(bytes)
}

pub fn parse_size(s: &str) -> Result<u64> {
    let t = s.trim();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: f64 = num
        .parse()
        .with_context(|| format!("bad size {s:?}: no number"))?;
    let unit = unit.trim().to_ascii_lowercase();
    let mult: f64 = match unit.as_str() {
        "" | "b" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        "kib" => 1024.0,
        "mib" => 1024.0 * 1024.0,
        "gib" => 1024.0 * 1024.0 * 1024.0,
        "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => bail!("bad size {s:?}: use e.g. 500GB, 1.5TB or 10GiB"),
    };
    Ok((n * mult) as u64)
}

pub fn human(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let (mut v, mut i) = (bytes as f64, 0);
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.2} {}", U[i])
    }
}

pub struct Rate {
    per_sec: f64,
    burst: Duration,
    next: Mutex<Instant>,
}

impl Rate {
    pub fn new(bytes_per_sec: f64) -> Rate {
        Rate {
            per_sec: bytes_per_sec.max(1.0),
            burst: Duration::from_millis(100),
            next: Mutex::new(Instant::now()),
        }
    }

    pub async fn take(&self, n: usize) {
        let wait = {
            let mut next = self.next.lock().unwrap();
            let now = Instant::now();
            let start = (*next).max(now.checked_sub(self.burst).unwrap_or(now));
            *next = start + Duration::from_secs_f64(n as f64 / self.per_sec);
            (*next)
                .checked_sub(self.burst)
                .unwrap_or(*next)
                .saturating_duration_since(now)
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Period {
    Day,
    Week,
    Month,
    Never,
}

impl Period {
    pub fn parse(s: Option<&str>) -> Result<Period> {
        match s.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            None | Some("month") => Ok(Period::Month),
            Some("day") => Ok(Period::Day),
            Some("week") => Ok(Period::Week),
            Some("never") | Some("total") => Ok(Period::Never),
            Some(o) => bail!("quota_period must be day, week, month or never (got {o:?})"),
        }
    }

    pub fn bounds(self, now: i64) -> (i64, i64) {
        let days = now.div_euclid(86_400);
        match self {
            Period::Day => (days * 86_400, (days + 1) * 86_400),
            Period::Week => {
                let monday = days - (days + 3).rem_euclid(7);
                (monday * 86_400, (monday + 7) * 86_400)
            }
            Period::Month => {
                let (y, m, _) = civil_from_days(days);
                let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
                (
                    days_from_civil(y, m, 1) * 86_400,
                    days_from_civil(ny, nm, 1) * 86_400,
                )
            }
            Period::Never => (0, i64::MAX),
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn date(unix: i64) -> String {
    if unix == i64::MAX {
        return "never".into();
    }
    let (y, m, d) = civil_from_days(unix.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02} UTC")
}

#[derive(Serialize, Deserialize, Clone, Copy, Default)]
struct Saved {
    start: i64,
    used: u64,
}

pub struct Quota {
    pub scope: String,
    limit: u64,
    period: Period,
    used: AtomicU64,
    bounds: Mutex<(i64, i64)>,
    dirty: AtomicBool,
    warned: Mutex<[bool; 2]>,
}

impl Quota {
    fn new(scope: &str, limit: u64, period: Period, now: i64) -> Quota {
        Quota {
            scope: scope.to_string(),
            limit,
            period,
            used: AtomicU64::new(0),
            bounds: Mutex::new(period.bounds(now)),
            dirty: AtomicBool::new(false),
            warned: Mutex::new([false; 2]),
        }
    }

    fn roll_at(&self, now: i64) {
        let mut b = self.bounds.lock().unwrap();
        if now >= b.1 {
            *b = self.period.bounds(now);
            self.used.store(0, Relaxed);
            *self.warned.lock().unwrap() = [false; 2];
            self.dirty.store(true, Relaxed);
            info!(
                "quota {}: new period, usage reset (next reset {})",
                self.scope,
                date(b.1)
            );
        }
    }

    pub fn add(&self, n: u64) {
        self.used.fetch_add(n, Relaxed);
        self.dirty.store(true, Relaxed);
    }

    pub fn exceeded(&self) -> bool {
        self.roll_at(now_unix());
        self.used.load(Relaxed) >= self.limit
    }

    pub fn used(&self) -> u64 {
        self.used.load(Relaxed)
    }

    fn saved(&self) -> Saved {
        Saved {
            start: self.bounds.lock().unwrap().0,
            used: self.used(),
        }
    }

    fn restore(&self, s: Saved) {
        if s.start == self.bounds.lock().unwrap().0 {
            self.used.store(s.used, Relaxed);
        }
    }

    pub fn usage(&self) -> QuotaUsage {
        let used = self.used();
        let pct = if self.limit == 0 {
            0.0
        } else {
            used as f64 * 100.0 / self.limit as f64
        };
        QuotaUsage {
            scope: self.scope.clone(),
            used,
            limit: self.limit,
            pct,
            resets: date(self.bounds.lock().unwrap().1),
        }
    }

    pub fn line(&self) -> String {
        let used = self.used();
        let pct = if self.limit == 0 {
            0.0
        } else {
            used as f64 * 100.0 / self.limit as f64
        };
        let reset = self.bounds.lock().unwrap().1;
        format!(
            "{}: {} of {} ({pct:.1}%), resets {}",
            self.scope,
            human(used),
            human(self.limit),
            date(reset)
        )
    }

    fn watch(&self) {
        let pct = self.used() as f64 * 100.0 / self.limit.max(1) as f64;
        let mut w = self.warned.lock().unwrap();
        if pct >= 100.0 && !w[1] {
            w[1] = true;
            warn!(
                "quota {} used up: new connections are refused until {}",
                self.scope,
                date(self.bounds.lock().unwrap().1)
            );
        } else if pct >= 80.0 && !w[0] {
            w[0] = true;
            warn!("quota {} — {pct:.0}% used", self.scope);
        }
    }
}

pub struct Meter {
    up: Option<Rate>,
    down: Option<Rate>,
    per_stream: Option<f64>,
    quota: Option<Arc<Quota>>,
    parent: Option<Arc<Meter>>,
}

pub struct StreamMeter {
    meter: Arc<Meter>,
    up: Option<Rate>,
    down: Option<Rate>,
}

impl Meter {
    fn chain(&self) -> impl Iterator<Item = &Meter> {
        let mut cur: Option<&Meter> = Some(self);
        std::iter::from_fn(move || {
            let m = cur?;
            cur = m.parent.as_deref();
            Some(m)
        })
    }

    pub fn open(self: &Arc<Self>) -> Option<StreamMeter> {
        if self
            .chain()
            .any(|m| m.quota.as_ref().is_some_and(|q| q.exceeded()))
        {
            return None;
        }
        let per = self.chain().find_map(|m| m.per_stream);
        Some(StreamMeter {
            meter: self.clone(),
            up: per.map(Rate::new),
            down: per.map(Rate::new),
        })
    }
}

impl StreamMeter {
    pub async fn up(&self, n: usize) -> bool {
        self.pass(true, n).await
    }

    pub async fn down(&self, n: usize) -> bool {
        self.pass(false, n).await
    }

    async fn pass(&self, up: bool, n: usize) -> bool {
        if self
            .meter
            .chain()
            .any(|m| m.quota.as_ref().is_some_and(|q| q.exceeded()))
        {
            return false;
        }
        for m in self.meter.chain() {
            if let Some(q) = &m.quota {
                q.add(n as u64);
            }
            if let Some(r) = if up { &m.up } else { &m.down } {
                r.take(n).await;
            }
        }
        if let Some(r) = if up { &self.up } else { &self.down } {
            r.take(n).await;
        }
        true
    }
}

pub struct Limiter {
    global: Mutex<Option<Arc<Meter>>>,
    quotas: Mutex<Vec<Arc<Quota>>>,
    path: PathBuf,
}

#[derive(Serialize, Deserialize, Default)]
struct StateFile {
    scopes: BTreeMap<String, Saved>,
}

fn read_state(path: &Path) -> StateFile {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

impl Limiter {
    pub fn new(cfg: &Config, run: bool) -> Result<Arc<Limiter>> {
        let path = cfg
            .quota_state
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let dir = cfg
                    .source
                    .as_deref()
                    .and_then(Path::parent)
                    .filter(|p| !p.as_os_str().is_empty());
                dir.map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("rakhsh-quota.json")
            });
        let l = Arc::new(Limiter {
            global: Mutex::new(None),
            quotas: Mutex::new(Vec::new()),
            path,
        });
        let global = l.meter("global", &cfg.limits, None)?;
        *l.global.lock().unwrap() = global;
        l.restore();
        if run {
            tokio::spawn(l.clone().saver());
        }
        Ok(l)
    }

    pub fn global(&self) -> Option<Arc<Meter>> {
        self.global.lock().unwrap().clone()
    }

    fn restore(&self) {
        let state = read_state(&self.path);
        for q in self.quotas.lock().unwrap().iter() {
            if let Some(s) = state.scopes.get(&q.scope) {
                q.restore(*s);
            }
        }
    }

    pub fn meter(
        &self,
        scope: &str,
        lim: &Limits,
        parent: Option<Arc<Meter>>,
    ) -> Result<Option<Arc<Meter>>> {
        let rate = |s: &Option<String>| s.as_deref().map(parse_rate).transpose();
        let both = rate(&lim.limit).with_context(|| format!("{scope}: limit"))?;
        let up = rate(&lim.limit_up)
            .with_context(|| format!("{scope}: limit_up"))?
            .or(both);
        let down = rate(&lim.limit_down)
            .with_context(|| format!("{scope}: limit_down"))?
            .or(both);
        let per_stream =
            rate(&lim.limit_per_stream).with_context(|| format!("{scope}: limit_per_stream"))?;
        let quota = match lim.quota.as_deref() {
            Some(q) => {
                let period = Period::parse(lim.quota_period.as_deref())?;
                let q = Arc::new(Quota::new(
                    scope,
                    parse_size(q).with_context(|| format!("{scope}: quota"))?,
                    period,
                    now_unix(),
                ));
                if let Some(s) = read_state(&self.path).scopes.get(scope) {
                    q.restore(*s);
                }
                self.quotas.lock().unwrap().push(q.clone());
                Some(q)
            }
            None => None,
        };
        if up.is_none() && down.is_none() && per_stream.is_none() && quota.is_none() {
            return Ok(parent);
        }
        Ok(Some(Arc::new(Meter {
            up: up.map(Rate::new),
            down: down.map(Rate::new),
            per_stream,
            quota,
            parent,
        })))
    }

    pub fn declare(&self, cfg: &Config) -> Result<()> {
        for f in &cfg.forward {
            self.meter(&format!("forward {}", f.listen), &f.limits, self.global())?;
        }
        for i in &cfg.inbound {
            let tag = i.tag.clone().unwrap_or_else(|| i.listen.clone());
            self.meter(&format!("inbound {tag}"), &i.limits, self.global())?;
        }
        Ok(())
    }

    pub fn report(&self) -> Vec<String> {
        self.quotas
            .lock()
            .unwrap()
            .iter()
            .map(|q| q.line())
            .collect()
    }

    pub fn usage(&self) -> Vec<QuotaUsage> {
        self.quotas
            .lock()
            .unwrap()
            .iter()
            .map(|q| q.usage())
            .collect()
    }

    pub fn reset(&self) -> Result<()> {
        for q in self.quotas.lock().unwrap().iter() {
            q.used.store(0, Relaxed);
        }
        self.save()
    }

    fn save(&self) -> Result<()> {
        let st = StateFile {
            scopes: self
                .quotas
                .lock()
                .unwrap()
                .iter()
                .map(|q| (q.scope.clone(), q.saved()))
                .collect(),
        };
        if let Some(dir) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).ok();
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&st)?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("replacing {}", self.path.display()))
    }

    async fn saver(self: Arc<Self>) {
        let mut last = mtime(&self.path);
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if mtime(&self.path) != last {
                let state = read_state(&self.path);
                for q in self.quotas.lock().unwrap().iter() {
                    if let Some(s) = state.scopes.get(&q.scope) {
                        q.used.store(
                            if s.start == q.saved().start {
                                s.used
                            } else {
                                0
                            },
                            Relaxed,
                        );
                    }
                }
            }
            let now = now_unix();
            let mut dirty = false;
            for q in self.quotas.lock().unwrap().iter() {
                q.roll_at(now);
                q.watch();
                dirty |= q.dirty.swap(false, Relaxed);
            }
            if dirty {
                if let Err(e) = self.save() {
                    warn!("quota: {e:#}");
                }
            }
            last = mtime(&self.path);
        }
    }
}

fn describe_one(scope: &str, l: &Limits) -> Option<String> {
    let mut parts = Vec::new();
    match (&l.limit, &l.limit_up, &l.limit_down) {
        (Some(x), None, None) => parts.push(format!("speed {x} per direction")),
        (a, b, c) => {
            if let Some(x) = b.as_ref().or(a.as_ref()) {
                parts.push(format!("up {x}"));
            }
            if let Some(x) = c.as_ref().or(a.as_ref()) {
                parts.push(format!("down {x}"));
            }
        }
    }
    if let Some(x) = &l.limit_per_stream {
        parts.push(format!("{x} per connection"));
    }
    if let Some(q) = &l.quota {
        parts.push(format!(
            "quota {q} per {}",
            l.quota_period.as_deref().unwrap_or("month")
        ));
    }
    (!parts.is_empty()).then(|| format!("{scope}: {}", parts.join(", ")))
}

pub fn describe(cfg: &Config) -> Result<Vec<String>> {
    Limiter::new(cfg, false)?.declare(cfg)?;
    let mut out: Vec<String> = describe_one("global", &cfg.limits).into_iter().collect();
    out.extend(
        cfg.forward
            .iter()
            .filter_map(|f| describe_one(&format!("forward {}", f.listen), &f.limits)),
    );
    out.extend(cfg.inbound.iter().filter_map(|i| {
        describe_one(
            &format!(
                "inbound {}",
                i.tag.clone().unwrap_or_else(|| i.listen.clone())
            ),
            &i.limits,
        )
    }));
    Ok(out)
}

#[derive(Clone)]
pub struct QuotaUsage {
    pub scope: String,
    pub used: u64,
    pub limit: u64,
    pub pct: f64,
    pub resets: String,
}

#[cfg(test)]
#[path = "../tests/unit/limits.rs"]
mod tests;
