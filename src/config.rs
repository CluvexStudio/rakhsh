use anyhow::{bail, Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub role: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub static_secret: String,
    #[serde(default)]
    pub peer_public: String,
    pub tunnel_listen: Option<String>,
    pub tunnel_connect: Option<String>,
    pub carrier: Option<String>,
    pub sni: Option<String>,
    pub ws_path: Option<String>,
    pub dial: Option<String>,
    pub lanes: Option<usize>,
    pub peer_ip: Option<String>,
    pub max_connections: Option<usize>,
    pub l3_addr: Option<String>,
    pub l3_mtu: Option<u16>,
    pub quic_mask: Option<bool>,
    pub quic_version: Option<u32>,
    pub bind: Option<String>,
    pub congestion: Option<String>,
    pub fec_data: Option<usize>,
    pub fec_parity: Option<usize>,
    pub reliability: Option<String>,
    pub spoof_src_ip: Option<String>,
    pub spoof_peer_ip: Option<String>,
    pub spoof_src_pool: Option<String>,
    pub spoof_sockbuf: Option<usize>,
    pub spoof_ttl_jitter: Option<bool>,
    pub spoof_dscp_jitter: Option<bool>,
    pub spoof_rotate_secs: Option<u64>,
    pub link_encrypt: Option<bool>,
    pub spoof_peer_src: Option<String>,

    pub ws_credential: Option<String>,
    pub decoy: Option<bool>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,

    pub tls_fingerprint: Option<String>,
    pub tls_frag: Option<usize>,
    pub pace_burst: Option<usize>,
    pub pace_gap_us: Option<u64>,
    pub pace_pps: Option<usize>,
    pub pace_auto: Option<bool>,

    pub edge_ip: Option<String>,

    #[serde(default)]
    pub backup_connect: Vec<String>,

    #[serde(default, rename = "peer")]
    pub peers: Vec<Peer>,

    #[serde(flatten)]
    pub limits: Limits,
    pub quota_state: Option<String>,
    #[serde(skip)]
    pub source: Option<std::path::PathBuf>,

    pub dns: Option<DnsCfg>,

    #[serde(default)]
    pub link: Vec<Link>,
    pub link_policy: Option<String>,
    pub link_timeout: Option<u64>,
    pub link_probe: Option<u64>,

    pub heartbeat: Option<u64>,
    pub keepalive: Option<u64>,

    pub mss_clamp: Option<u16>,

    pub encryption: Option<String>,

    #[serde(default)]
    pub resume: bool,
    pub resume_grace: Option<u64>,

    pub control_socket: Option<String>,

    pub preset: Option<String>,
    pub so_rcvbuf: Option<usize>,
    pub so_sndbuf: Option<usize>,

    pub l3_gre: Option<bool>,
    pub gre_key: Option<u32>,
    pub l3_auto_mtu: Option<bool>,
    pub l3_qdisc: Option<String>,
    pub l3_txqueuelen: Option<u32>,
    pub l3_paths: Option<usize>,

    #[serde(default)]
    pub forward: Vec<Forward>,

    #[serde(default)]
    pub inbound: Vec<Inbound>,
    #[serde(default)]
    pub outbound: Vec<Outbound>,
    #[serde(default)]
    pub route: Route,
    pub access_log: Option<bool>,

    pub xui_panel: Option<String>,
    pub xui_token: Option<String>,
    pub xui_interval: Option<u64>,
    pub xui_target_host: Option<String>,
    pub xui_proxy_protocol: Option<bool>,
    pub accept_sync: Option<bool>,
    #[serde(default)]
    pub sync_ports: Vec<String>,
    pub sync_listen: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Inbound {
    pub tag: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    pub listen: String,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(flatten)]
    pub limits: Limits,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Outbound {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub server: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Route {
    #[serde(rename = "final")]
    pub fallback: Option<String>,
    pub resolve: Option<bool>,
    #[serde(default)]
    pub rule: Vec<Rule>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rule {
    pub outbound: String,
    #[serde(default)]
    pub inbound: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub port: Vec<String>,
    pub rule_file: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Limits {
    pub limit: Option<String>,
    pub limit_up: Option<String>,
    pub limit_down: Option<String>,
    pub limit_per_stream: Option<String>,
    pub quota: Option<String>,
    pub quota_period: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Forward {
    pub listen: String,
    pub target: String,
    #[serde(default)]
    pub udp: bool,
    #[serde(flatten)]
    pub limits: Limits,
    #[serde(default)]
    pub proxy_protocol: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsCfg {
    pub listen: String,
    #[serde(default)]
    pub local: Vec<String>,
    #[serde(default)]
    pub remote: Vec<String>,
    pub cache: Option<usize>,
    pub cache_min_ttl: Option<u32>,
    pub cache_max_ttl: Option<u32>,
    pub timeout: Option<u64>,
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub name: Option<String>,
    pub public: String,
    pub connect: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeerKey {
    pub name: String,
    pub key: [u8; 32],
    pub connect: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub carrier: String,
    pub addr: String,
    pub sni: Option<String>,
    pub ws_path: Option<String>,
    pub ws_credential: Option<String>,
    pub decoy: Option<bool>,
    pub edge_ip: Option<String>,
    pub tls_fingerprint: Option<String>,
    pub tls_frag: Option<usize>,
    pub pace_burst: Option<usize>,
    pub pace_gap_us: Option<u64>,
    pub pace_pps: Option<usize>,
    pub pace_auto: Option<bool>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub quic_mask: Option<bool>,
    pub quic_version: Option<u32>,
    pub reliability: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Config = toml::from_str(&text).context("parsing config TOML")?;
        cfg.source = Some(path.to_path_buf());
        match cfg.role.as_str() {
            "entry" | "exit" => {
                if cfg.token.is_empty()
                    || cfg.static_secret.is_empty()
                    || (cfg.peer_public.is_empty() && cfg.peers.is_empty())
                {
                    bail!(
                        "role {:?} needs token, static_secret and either peer_public or at least \
                         one [[peer]] (run `rakhsh init`)",
                        cfg.role
                    );
                }
            }
            "node" => {}
            other => bail!("role must be \"entry\", \"exit\" or \"node\", got {other:?}"),
        }
        Ok(cfg)
    }

    pub fn with_link(&self, l: &Link) -> Config {
        let mut c = self.clone();
        c.link.clear();
        c.carrier = Some(l.carrier.clone());
        macro_rules! over {
            ($($f:ident),*) => { $( if l.$f.is_some() { c.$f = l.$f.clone(); } )* };
        }
        over!(
            sni,
            ws_path,
            ws_credential,
            decoy,
            edge_ip,
            tls_fingerprint,
            tls_frag,
            pace_burst,
            pace_gap_us,
            pace_pps,
            pace_auto,
            cert_path,
            key_path,
            quic_mask,
            quic_version,
            reliability
        );
        c
    }

    pub fn crypto_mode(&self) -> Result<crate::noise::Mode> {
        match self.encryption.as_deref() {
            None => Ok(crate::noise::Mode::Full),
            Some(s) => crate::noise::Mode::parse(s),
        }
    }

    pub fn secret_key(&self) -> Result<[u8; 32]> {
        decode32(&self.static_secret).context("static_secret")
    }

    pub fn peer_key(&self) -> Result<[u8; 32]> {
        decode32(&self.peer_public).context("peer_public")
    }

    pub fn peer_keys(&self) -> Result<Vec<PeerKey>> {
        let mut out = Vec::with_capacity(1 + self.peers.len());
        if !self.peer_public.is_empty() {
            out.push(PeerKey {
                name: "peer".into(),
                key: self.peer_key()?,
                connect: self.tunnel_connect.clone(),
            });
        }
        for (i, p) in self.peers.iter().enumerate() {
            let name = p.name.clone().unwrap_or_else(|| format!("peer{}", i + 1));
            let key = decode32(&p.public).with_context(|| format!("[[peer]] {name}: public"))?;
            if out.iter().any(|k| k.key == key) {
                bail!("[[peer]] {name} repeats a public key already listed");
            }
            out.push(PeerKey {
                name,
                key,
                connect: p.connect.clone(),
            });
        }
        if out.is_empty() {
            bail!("no peer identity: set peer_public or at least one [[peer]]");
        }
        Ok(out)
    }

    pub fn tuning(&self) -> Tuning {
        let (hb, ka) = match self.preset.as_deref().unwrap_or("balance") {
            "turbo" => (8, 20),
            "aggressive" => (5, 15),
            "throughput" => (15, 30),
            _ => (10, 30),
        };
        Tuning {
            heartbeat: self.heartbeat.unwrap_or(hb),
            keepalive: self.keepalive.unwrap_or(ka),
            rcvbuf: self.so_rcvbuf,
            sndbuf: self.so_sndbuf,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    pub heartbeat: u64,
    pub keepalive: u64,
    pub rcvbuf: Option<usize>,
    pub sndbuf: Option<usize>,
}

pub fn decode32(s: &str) -> Result<[u8; 32]> {
    let raw = BASE64_STANDARD.decode(s.trim()).context("base64 decode")?;
    if raw.len() != 32 {
        bail!("expected 32 bytes, got {}", raw.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}
