use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::config::Config;

pub const DEFAULT_PORT: u16 = 1194;

const OPCODE: usize = 1;
const PEER_ID: usize = 3;
const PACKET_ID: usize = 4;
const EPOCH_ID: usize = 8;
const AEAD_TAG: usize = 16;
const AES_IV: usize = 16;
const AES_BLOCK: usize = 16;
const ETH_HDR: usize = 14;
const IPV4_TCP: usize = 40;
const COMPRESS_BYTE: usize = 1;
const CONTROL_DEFAULT: usize = 1250;

const GRE_CARRIED: usize = 1427;
const L2_CARRIED: usize = 1405;
const UDP_CARRIED: usize = 1437;
const TCP_CARRIED: usize = 1365;
const SESSION_CARRIED: usize = 1380;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Device {
    Tun,
    Tap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Crypto {
    Aead,
    CbcSha1,
    CbcSha256,
    CbcSha512,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenVpn {
    #[serde(default = "default_proto")]
    pub proto: Proto,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_device")]
    pub device: Device,
    #[serde(default = "default_crypto")]
    pub crypto: Crypto,
    pub server: Option<String>,
    #[serde(default)]
    pub compress: bool,
    #[serde(default = "default_peer_id")]
    pub peer_id: bool,
    pub overhead: Option<usize>,
    pub listen: Option<String>,
    #[serde(default = "default_epoch")]
    pub epoch: bool,
}

fn default_proto() -> Proto {
    Proto::Udp
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_device() -> Device {
    Device::Tun
}

fn default_crypto() -> Crypto {
    Crypto::Aead
}

fn default_peer_id() -> bool {
    true
}

fn default_epoch() -> bool {
    true
}

impl Default for OpenVpn {
    fn default() -> OpenVpn {
        OpenVpn {
            proto: default_proto(),
            port: default_port(),
            device: default_device(),
            crypto: default_crypto(),
            server: None,
            compress: false,
            peer_id: default_peer_id(),
            overhead: None,
            listen: None,
            epoch: default_epoch(),
        }
    }
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
        }
    }

    pub fn parse(s: &str) -> Result<Proto> {
        match s {
            "udp" | "udp4" | "udp6" => Ok(Proto::Udp),
            "tcp" | "tcp4" | "tcp6" | "tcp-server" | "tcp-client" => Ok(Proto::Tcp),
            other => bail!("openvpn proto {other:?}: expected \"udp\" or \"tcp\""),
        }
    }

    pub fn client_directive(self) -> &'static str {
        match self {
            Proto::Udp => "proto udp",
            Proto::Tcp => "proto tcp-client",
        }
    }

    pub fn server_directive(self) -> &'static str {
        match self {
            Proto::Udp => "proto udp",
            Proto::Tcp => "proto tcp-server",
        }
    }
}

impl Device {
    pub fn as_str(self) -> &'static str {
        match self {
            Device::Tun => "tun",
            Device::Tap => "tap",
        }
    }

    pub fn parse(s: &str) -> Result<Device> {
        match s {
            "tun" => Ok(Device::Tun),
            "tap" => Ok(Device::Tap),
            other => bail!("openvpn device {other:?}: expected \"tun\" or \"tap\""),
        }
    }

    fn framing(self) -> usize {
        match self {
            Device::Tun => 0,
            Device::Tap => ETH_HDR,
        }
    }
}

impl Crypto {
    pub fn as_str(self) -> &'static str {
        match self {
            Crypto::Aead => "aead",
            Crypto::CbcSha1 => "cbc-sha1",
            Crypto::CbcSha256 => "cbc-sha256",
            Crypto::CbcSha512 => "cbc-sha512",
        }
    }

    pub fn parse(s: &str) -> Result<Crypto> {
        match s {
            "aead" | "gcm" | "aes-gcm" | "chacha20-poly1305" => Ok(Crypto::Aead),
            "cbc-sha1" | "cbc" => Ok(Crypto::CbcSha1),
            "cbc-sha256" => Ok(Crypto::CbcSha256),
            "cbc-sha512" => Ok(Crypto::CbcSha512),
            other => bail!(
                "openvpn crypto {other:?}: expected \"aead\", \"cbc-sha1\", \"cbc-sha256\" or \
                 \"cbc-sha512\""
            ),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Crypto::Aead => "AES-GCM or ChaCha20-Poly1305",
            Crypto::CbcSha1 => "AES-CBC with HMAC-SHA1",
            Crypto::CbcSha256 => "AES-CBC with HMAC-SHA256",
            Crypto::CbcSha512 => "AES-CBC with HMAC-SHA512",
        }
    }

    fn per_packet(self, epoch: bool) -> usize {
        match self {
            Crypto::Aead if epoch => EPOCH_ID + AEAD_TAG,
            Crypto::Aead => PACKET_ID + AEAD_TAG,
            Crypto::CbcSha1 => 20 + AES_IV + PACKET_ID + AES_BLOCK,
            Crypto::CbcSha256 => 32 + AES_IV + PACKET_ID + AES_BLOCK,
            Crypto::CbcSha512 => 64 + AES_IV + PACKET_ID + AES_BLOCK,
        }
    }

    fn aead(self) -> bool {
        matches!(self, Crypto::Aead)
    }
}

impl OpenVpn {
    pub fn overhead_bytes(&self) -> usize {
        if let Some(n) = self.overhead {
            return n;
        }
        OPCODE
            + if self.peer_id { PEER_ID } else { 0 }
            + self.crypto.per_packet(self.epoch && self.crypto.aead())
            + self.device.framing()
            + if self.compress { COMPRESS_BYTE } else { 0 }
    }

    pub fn listen_addr(&self) -> String {
        self.listen
            .clone()
            .unwrap_or_else(|| format!("0.0.0.0:{}", self.port))
    }

    pub fn server_addr(&self) -> String {
        self.server
            .clone()
            .unwrap_or_else(|| format!("127.0.0.1:{}", self.port))
    }

    pub fn parse_spec(spec: &str) -> Result<OpenVpn> {
        let mut ov = OpenVpn::default();
        let (head, rest) = spec.split_once('/').unwrap_or((spec, ""));
        let (head, overhead) = match head.split_once('+') {
            Some((h, n)) => (
                h,
                Some(
                    n.parse::<usize>()
                        .with_context(|| format!("openvpn overhead {n:?} is not a byte count"))?,
                ),
            ),
            None => (head, None),
        };
        ov.overhead = overhead;

        let head = head.trim();
        if !head.is_empty() {
            match head.split_once(':') {
                Some((p, port)) => {
                    ov.proto = Proto::parse(p)?;
                    ov.port = port
                        .parse()
                        .with_context(|| format!("openvpn port {port:?} is not a port number"))?;
                }
                None => match head.parse::<u16>() {
                    Ok(port) => ov.port = port,
                    Err(_) => ov.proto = Proto::parse(head)?,
                },
            }
        }

        for opt in rest.split('/').filter(|s| !s.is_empty()) {
            match opt {
                "tun" | "tap" => ov.device = Device::parse(opt)?,
                "compress" | "comp" => ov.compress = true,
                "no-peer-id" => ov.peer_id = false,
                "no-epoch" => ov.epoch = false,
                other => ov.crypto = Crypto::parse(other)?,
            }
        }
        Ok(ov)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub proto: Proto,
    pub device: Device,
    pub carried: Option<usize>,
    pub overhead: usize,
    pub tun_mtu: Option<usize>,
    pub listen: String,
    pub server: String,
    pub carrier: String,
    pub datagram: bool,
}

impl Plan {
    pub fn mss(&self) -> Option<usize> {
        self.tun_mtu.map(|m| m.saturating_sub(IPV4_TCP))
    }
}

pub fn carried_payload(carrier: &str) -> Option<usize> {
    match carrier {
        "shabdiz-gre" => Some(GRE_CARRIED),
        "shabdiz-l2" => Some(L2_CARRIED),
        "shabdiz-udp" => Some(UDP_CARRIED),
        "shabdiz-tcp" => Some(TCP_CARRIED),
        _ => None,
    }
}

pub fn plan(cfg: &Config, ov: &OpenVpn) -> Plan {
    let carrier = cfg.carrier.clone().unwrap_or_else(|| "tcp".to_string());
    let datagram = carried_payload(&carrier).is_some();
    let carried = match ov.proto {
        Proto::Tcp => None,
        Proto::Udp => Some(carried_payload(&carrier).unwrap_or(SESSION_CARRIED)),
    };
    let overhead = ov.overhead_bytes();
    Plan {
        proto: ov.proto,
        device: ov.device,
        carried,
        overhead,
        tun_mtu: carried.map(|c| c.saturating_sub(overhead)),
        listen: ov.listen_addr(),
        server: ov.server_addr(),
        carrier,
        datagram,
    }
}

pub fn forward_toml(ov: &OpenVpn) -> String {
    let mut s = format!(
        "\n[[forward]]\nlisten = \"{}\"\ntarget = \"{}\"\n",
        ov.listen_addr(),
        ov.server_addr()
    );
    if ov.proto == Proto::Udp {
        s.push_str("udp = true\n");
    }
    s
}

pub fn config_toml(ov: &OpenVpn) -> String {
    let mut s = format!(
        "\n[openvpn]\nproto = \"{}\"\nport = {}\ndevice = \"{}\"\ncrypto = \"{}\"\nserver = \"{}\"\n",
        ov.proto.as_str(),
        ov.port,
        ov.device.as_str(),
        ov.crypto.as_str(),
        ov.server_addr()
    );
    if ov.compress {
        s.push_str("compress = true\n");
    }
    if !ov.peer_id {
        s.push_str("peer_id = false\n");
    }
    if !ov.epoch {
        s.push_str("epoch = false\n");
    }
    if let Some(n) = ov.overhead {
        s.push_str(&format!("overhead = {n}\n"));
    }
    s
}

pub fn validate(cfg: &Config) -> Result<()> {
    let Some(ov) = &cfg.openvpn else {
        return Ok(());
    };
    ov.listen_addr()
        .parse::<std::net::SocketAddr>()
        .with_context(|| {
            format!(
                "[openvpn] listen = {:?} is not an address:port",
                ov.listen_addr()
            )
        })?;
    let server = ov.server_addr();
    let (host, port) = server
        .rsplit_once(':')
        .with_context(|| format!("[openvpn] server = {server:?} needs a host:port"))?;
    if host.is_empty() || port.parse::<u16>().is_err() {
        bail!("[openvpn] server = {server:?} needs a host:port");
    }
    if cfg.role == "node" {
        bail!("[openvpn] needs a tunnel: role is \"node\", which has no peer to carry it");
    }
    let want_udp = ov.proto == Proto::Udp;
    let found = cfg
        .forward
        .iter()
        .find(|f| f.listen == ov.listen_addr() && f.udp == want_udp);
    if found.is_none() {
        bail!(
            "[openvpn] proto = \"{}\" needs a matching [[forward]]: listen = \"{}\", target = \
             \"{}\"{}",
            ov.proto.as_str(),
            ov.listen_addr(),
            ov.server_addr(),
            if want_udp { ", udp = true" } else { "" }
        );
    }
    Ok(())
}

pub fn describe(cfg: &Config) -> Vec<String> {
    let Some(ov) = &cfg.openvpn else {
        return Vec::new();
    };
    let p = plan(cfg, ov);
    let mut out = vec![format!(
        "openvpn: {} on {} -> {}, device {}, {}",
        p.proto.as_str(),
        p.listen,
        p.server,
        p.device.as_str(),
        ov.crypto.label()
    )];

    match (p.proto, p.carried, p.tun_mtu) {
        (Proto::Udp, Some(carried), Some(tun_mtu)) => {
            out.push(format!(
                "  this tunnel carries a udp payload of {carried} bytes; openvpn adds {} per \
                 packet, so set tun-mtu {tun_mtu} on both openvpn ends",
                p.overhead
            ));
            if let Some(mss) = p.mss() {
                out.push(format!(
                    "  and mssfix {tun_mtu} mtu (openvpn 2.6+), which announces an mss of {mss}"
                ));
            }
            out.push(format!(
                "  and max-packet-size {carried}, which bounds openvpn's control channel too — \
                 without it a path under {CONTROL_DEFAULT} bytes never finishes its handshake"
            ));
            if !p.datagram {
                out.push(format!(
                    "  WARNING: carrier {:?} is a reliable carrier. A udp payload inside it is \
                     ordered and retransmitted, which is the opposite of what openvpn wants — use \
                     a shabdiz-* carrier for proto udp",
                    p.carrier
                ));
            }
            out.push(
                "  run `rakhsh openvpn -c <config>` for the directives to paste into both \
                 openvpn configs"
                    .to_string(),
            );
        }
        (Proto::Tcp, _, _) => {
            out.push(
                "  openvpn over tcp needs no mtu arithmetic: its segments adapt. It is a plain \
                 stream forward"
                    .to_string(),
            );
            if p.datagram {
                out.push(format!(
                    "  WARNING: carrier {:?} carries datagrams, and proto = \"tcp\" asks for a \
                     stream forward. Use proto = \"udp\", or pick a stream carrier",
                    p.carrier
                ));
            } else {
                out.push(
                    "  note: this is tcp inside tcp. It works, and it is slower to recover from \
                     loss than proto = \"udp\" on a shabdiz-* carrier"
                        .to_string(),
                );
            }
        }
        _ => {}
    }
    out
}

pub fn directives(cfg: &Config) -> Result<String> {
    let Some(ov) = &cfg.openvpn else {
        bail!("this config has no [openvpn] section");
    };
    let p = plan(cfg, ov);
    let mut s = String::new();

    s.push_str("# ─── openvpn server, on the host the exit forwards to ───\n");
    s.push_str(&format!("{}\n", p.proto.server_directive()));
    s.push_str(&format!("port {}\n", ov.port));
    s.push_str(&format!("dev {}\n", p.device.as_str()));
    if let (Some(mtu), Some(carried)) = (p.tun_mtu, p.carried) {
        s.push_str(&format!("tun-mtu {mtu}\n"));
        s.push_str(&format!("mssfix {mtu} mtu\n"));
        s.push_str(&format!("max-packet-size {carried}\n"));
    }
    s.push('\n');

    s.push_str("# ─── openvpn client ───\n");
    s.push_str("client\n");
    s.push_str(&format!("{}\n", p.proto.client_directive()));
    let (host, port) = p.listen.rsplit_once(':').unwrap_or((&p.listen, "1194"));
    let host = if host == "0.0.0.0" || host == "[::]" {
        "<the entry's public address>"
    } else {
        host
    };
    s.push_str(&format!("remote {host} {port}\n"));
    s.push_str(&format!("dev {}\n", p.device.as_str()));
    if let (Some(mtu), Some(carried)) = (p.tun_mtu, p.carried) {
        s.push_str(&format!("tun-mtu {mtu}\n"));
        s.push_str(&format!("mssfix {mtu} mtu\n"));
        s.push_str(&format!("max-packet-size {carried}\n"));
    }
    s.push('\n');

    if let (Some(carried), Some(mtu)) = (p.carried, p.tun_mtu) {
        s.push_str(&format!(
            "# this tunnel carries a udp payload of {carried} bytes.\n\
             # openvpn adds {} per packet for {}, device {}, so tun-mtu is {mtu}.\n\
             # max-packet-size bounds the control channel as well: openvpn defaults it to\n\
             # {CONTROL_DEFAULT}, and on a path that carries less the tls handshake never\n\
             # finishes, with nothing in the log to say why.\n\
             # on openvpn 2.5 and older, replace `mssfix {mtu} mtu` with `fragment {mtu}`\n\
             # and `max-packet-size {carried}` with `link-mtu {carried}`.\n\
             # verify it: ping -M do -s {} <the other end inside the tunnel>\n",
            p.overhead,
            ov.crypto.label(),
            p.device.as_str(),
            mtu.saturating_sub(28)
        ));
    }
    Ok(s)
}

#[cfg(test)]
#[path = "../tests/unit/openvpn.rs"]
mod tests;
