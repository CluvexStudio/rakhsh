use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use tracing::{info, warn};

use crate::config::Route;

#[derive(Debug, Clone, PartialEq)]
pub enum Host {
    Domain(String),
    Ip(IpAddr),
}

impl Host {
    pub fn parse(s: &str) -> Host {
        match s.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(s.to_ascii_lowercase()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Dest {
    pub host: Host,
    pub port: u16,
}

impl Dest {
    pub fn target(&self) -> String {
        match &self.host {
            Host::Domain(d) => format!("{d}:{}", self.port),
            Host::Ip(IpAddr::V4(a)) => format!("{a}:{}", self.port),
            Host::Ip(IpAddr::V6(a)) => format!("[{a}]:{}", self.port),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Cidr {
    V4(u32, u32),
    V6(u128, u128),
}

pub(crate) fn parse_cidr(s: &str) -> Option<Cidr> {
    let (ip, len) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => {
            let len: u32 = match len {
                Some(l) => l.parse().ok()?,
                None => 32,
            };
            if len > 32 {
                return None;
            }
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            Some(Cidr::V4(u32::from(a) & mask, mask))
        }
        IpAddr::V6(a) => {
            let len: u32 = match len {
                Some(l) => l.parse().ok()?,
                None => 128,
            };
            if len > 128 {
                return None;
            }
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            Some(Cidr::V6(u128::from(a) & mask, mask))
        }
    }
}

impl Cidr {
    pub(crate) fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4(n, m), IpAddr::V4(a)) => u32::from(*a) & m == *n,
            (Cidr::V6(n, m), IpAddr::V6(a)) => u128::from(*a) & m == *n,
            _ => false,
        }
    }
}

#[derive(Default)]
struct DestMatch {
    exact: HashSet<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    cidr: Vec<Cidr>,
}

fn norm_suffix(s: &str) -> String {
    s.trim().trim_start_matches('.').to_ascii_lowercase()
}

impl DestMatch {
    fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.suffix.is_empty()
            && self.keyword.is_empty()
            && self.cidr.is_empty()
    }

    fn domain_hit(&self, d: &str) -> bool {
        if self.exact.contains(d) {
            return true;
        }
        for s in &self.suffix {
            if d == s
                || (d.len() > s.len()
                    && d.ends_with(s.as_str())
                    && d.as_bytes()[d.len() - s.len() - 1] == b'.')
            {
                return true;
            }
        }
        self.keyword.iter().any(|k| d.contains(k.as_str()))
    }

    fn ip_hit(&self, ip: &IpAddr) -> bool {
        self.cidr.iter().any(|c| c.contains(ip))
    }

    fn add_line(&mut self, raw: &str) {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            return;
        }
        if let Some(v) = line.strip_prefix("domain:") {
            self.exact.insert(v.trim().to_ascii_lowercase());
        } else if let Some(v) = line.strip_prefix("suffix:") {
            self.suffix.push(norm_suffix(v));
        } else if let Some(v) = line.strip_prefix("keyword:") {
            self.keyword.push(v.trim().to_ascii_lowercase());
        } else if let Some(v) = line.strip_prefix("cidr:") {
            if let Some(c) = parse_cidr(v.trim()) {
                self.cidr.push(c);
            }
        } else if let Some(c) = parse_cidr(line) {
            self.cidr.push(c);
        } else {
            self.suffix.push(norm_suffix(line));
        }
    }
}

struct CRule {
    outbound: String,
    inbound: Vec<String>,
    ports: Vec<(u16, u16)>,
    dest: DestMatch,
}

pub struct Router {
    rules: Vec<CRule>,
    pub fallback: String,
    resolve: bool,
}

pub struct Decision {
    pub outbound: String,
    pub resolved: Vec<IpAddr>,
}

fn parse_port(s: &str) -> Result<(u16, u16)> {
    let s = s.trim();
    match s.split_once('-') {
        Some((a, b)) => Ok((a.trim().parse()?, b.trim().parse()?)),
        None => {
            let p: u16 = s.parse()?;
            Ok((p, p))
        }
    }
}

impl Router {
    pub fn compile(route: &Route, tags: &[String], default_final: &str) -> Result<Router> {
        let fallback = route
            .fallback
            .clone()
            .unwrap_or_else(|| default_final.to_string());
        if !tags.contains(&fallback) {
            bail!("route.final {fallback:?} is not a defined outbound (have {tags:?})");
        }
        let mut rules = Vec::new();
        for (i, r) in route.rule.iter().enumerate() {
            if !tags.contains(&r.outbound) {
                bail!(
                    "route.rule #{} points at unknown outbound {:?} (have {tags:?})",
                    i + 1,
                    r.outbound
                );
            }
            let mut dest = DestMatch::default();
            for d in &r.domain {
                dest.exact.insert(d.trim().to_ascii_lowercase());
            }
            for s in &r.domain_suffix {
                dest.suffix.push(norm_suffix(s));
            }
            for k in &r.domain_keyword {
                dest.keyword.push(k.trim().to_ascii_lowercase());
            }
            for c in &r.ip_cidr {
                dest.cidr.push(
                    parse_cidr(c)
                        .with_context(|| format!("route.rule #{}: bad ip_cidr {c:?}", i + 1))?,
                );
            }
            if let Some(path) = &r.rule_file {
                match std::fs::read_to_string(path) {
                    Ok(text) => {
                        let before = dest.exact.len()
                            + dest.suffix.len()
                            + dest.keyword.len()
                            + dest.cidr.len();
                        for l in text.lines() {
                            dest.add_line(l);
                        }
                        let after = dest.exact.len()
                            + dest.suffix.len()
                            + dest.keyword.len()
                            + dest.cidr.len();
                        info!("rule_file {path}: loaded {} entries", after - before);
                    }
                    Err(e) => warn!(
                        "rule_file {path} not loaded ({e}); rule uses its inline matchers only"
                    ),
                }
            }
            let ports = r
                .port
                .iter()
                .map(|p| {
                    parse_port(p).with_context(|| format!("route.rule #{}: bad port {p:?}", i + 1))
                })
                .collect::<Result<Vec<_>>>()?;
            rules.push(CRule {
                outbound: r.outbound.clone(),
                inbound: r.inbound.clone(),
                ports,
                dest,
            });
        }
        Ok(Router {
            rules,
            fallback,
            resolve: route.resolve.unwrap_or(true),
        })
    }

    pub async fn route(&self, inbound: &str, dest: &Dest) -> Decision {
        self.route_with(inbound, dest, |d, p| async move { resolve(&d, p).await })
            .await
    }

    pub async fn route_with<F, Fut>(&self, inbound: &str, dest: &Dest, mut resolver: F) -> Decision
    where
        F: FnMut(String, u16) -> Fut,
        Fut: std::future::Future<Output = Vec<IpAddr>>,
    {
        let mut resolved: Option<Vec<IpAddr>> = None;
        for rule in &self.rules {
            if !rule.inbound.is_empty() && !rule.inbound.iter().any(|t| t == inbound) {
                continue;
            }
            if !rule.ports.is_empty()
                && !rule
                    .ports
                    .iter()
                    .any(|(lo, hi)| (*lo..=*hi).contains(&dest.port))
            {
                continue;
            }
            let hit = if rule.dest.is_empty() {
                true
            } else {
                match &dest.host {
                    Host::Ip(ip) => rule.dest.ip_hit(ip),
                    Host::Domain(d) => {
                        if rule.dest.domain_hit(d) {
                            true
                        } else if self.resolve && !rule.dest.cidr.is_empty() {
                            if resolved.is_none() {
                                resolved = Some(resolver(d.clone(), dest.port).await);
                            }
                            resolved
                                .as_ref()
                                .is_some_and(|ips| ips.iter().any(|ip| rule.dest.ip_hit(ip)))
                        } else {
                            false
                        }
                    }
                }
            };
            if hit {
                return Decision {
                    outbound: rule.outbound.clone(),
                    resolved: resolved.unwrap_or_default(),
                };
            }
        }
        Decision {
            outbound: self.fallback.clone(),
            resolved: resolved.unwrap_or_default(),
        }
    }
}

async fn resolve(host: &str, port: u16) -> Vec<IpAddr> {
    match tokio::time::timeout(
        Duration::from_millis(1500),
        tokio::net::lookup_host((host, port)),
    )
    .await
    {
        Ok(Ok(it)) => it.map(|sa| sa.ip()).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
#[path = "../tests/unit/route.rs"]
mod tests;
