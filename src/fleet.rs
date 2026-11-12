use anyhow::{bail, Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};

use crate::noise;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dial {
    Exit,
    Entry,
}

impl Dial {
    pub fn parse(s: &str) -> Result<Dial> {
        match s.trim() {
            "exit" => Ok(Dial::Exit),
            "entry" => Ok(Dial::Entry),
            other => bail!("dial must be \"exit\" or \"entry\" (got {other:?})"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Dial::Exit => "exit",
            Dial::Entry => "entry",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Host {
    pub name: String,
    pub addr: String,
}

impl Host {
    pub fn parse(s: &str, default_port: u16) -> Result<Host> {
        let (name, addr) = s
            .split_once('=')
            .with_context(|| format!("expected name=address, got {s:?}"))?;
        let name = name.trim();
        let addr = addr.trim();
        if name.is_empty() || addr.is_empty() {
            bail!("expected name=address, got {s:?}");
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            bail!("node name {name:?} may use letters, digits, - and _ only");
        }
        let addr = if addr.contains(':') {
            addr.to_string()
        } else {
            format!("{addr}:{default_port}")
        };
        Ok(Host {
            name: name.to_string(),
            addr,
        })
    }

    fn host(&self) -> &str {
        self.addr
            .rsplit_once(':')
            .map(|x| x.0)
            .unwrap_or(&self.addr)
    }

    fn port(&self) -> Option<u16> {
        self.addr.rsplit_once(':').and_then(|x| x.1.parse().ok())
    }
}

pub struct Spec {
    pub exits: Vec<Host>,
    pub entries: Vec<Host>,
    pub carrier: String,
    pub sni: String,
    pub dial: Dial,
    pub lanes: usize,
    pub port: u16,
    pub proxy: Option<String>,
    pub forwards: Vec<String>,
}

#[derive(Debug)]
pub struct Node {
    pub name: String,
    pub role: &'static str,
    pub addr: String,
    pub config: String,
}

struct Identity {
    name: String,
    addr: String,
    private: String,
    public: String,
}

fn identities(hosts: &[Host]) -> Result<Vec<Identity>> {
    hosts
        .iter()
        .map(|h| {
            let (private, public) = noise::generate_keypair()?;
            Ok(Identity {
                name: h.name.clone(),
                addr: h.addr.clone(),
                private: BASE64_STANDARD.encode(private),
                public: BASE64_STANDARD.encode(public),
            })
        })
        .collect()
}

pub fn plan(spec: &Spec) -> Result<Vec<Node>> {
    if spec.exits.is_empty() || spec.entries.is_empty() {
        bail!("a fleet needs at least one exit and one entry");
    }
    if spec.carrier.starts_with("shabdiz-") {
        bail!(
            "carrier {:?} carries one datagram tunnel between one pair of hosts: it reads neither \
             the [[peer]] identities a fleet is built from nor `lanes`, and it needs a peer_ip a \
             fleet cannot choose. Generate each tunnel on its own with `rakhsh init --carrier {} \
             --peer-ip <far end> --forward <listen>=<target>/udp`.",
            spec.carrier,
            spec.carrier
        );
    }
    let mut names: Vec<&str> = spec
        .exits
        .iter()
        .chain(spec.entries.iter())
        .map(|h| h.name.as_str())
        .collect();
    names.sort_unstable();
    if let Some(w) = names.windows(2).find(|w| w[0] == w[1]) {
        bail!("two nodes are both called {:?}", w[0]);
    }

    let mut token = [0u8; 32];
    crate::cli::getrandom(&mut token);
    let token = BASE64_STANDARD.encode(token);

    let exits = identities(&spec.exits)?;
    let entries = identities(&spec.entries)?;
    let tls = matches!(spec.carrier.as_str(), "tls" | "ws" | "wss");

    let mut out = Vec::with_capacity(exits.len() + entries.len());
    for e in &exits {
        out.push(Node {
            name: e.name.clone(),
            role: "exit",
            addr: e.addr.clone(),
            config: render(spec, &token, "exit", e, &entries, tls),
        });
    }
    for e in &entries {
        out.push(Node {
            name: e.name.clone(),
            role: "entry",
            addr: e.addr.clone(),
            config: render(spec, &token, "entry", e, &exits, tls),
        });
    }
    Ok(out)
}

fn render(
    spec: &Spec,
    token: &str,
    role: &str,
    me: &Identity,
    others: &[Identity],
    tls: bool,
) -> String {
    let dials = (role == "entry") == (spec.dial == Dial::Entry);
    let mut s = String::new();
    s.push_str(&format!("role = \"{role}\"\n"));
    s.push_str(&format!("token = \"{token}\"\n"));
    s.push_str(&format!("static_secret = \"{}\"\n", me.private));
    s.push_str(&format!("carrier = \"{}\"\n", spec.carrier));
    if tls {
        s.push_str(&format!("sni = \"{}\"\n", spec.sni));
    }
    s.push_str(&format!("dial = \"{}\"\n", spec.dial.as_str()));
    s.push_str(&format!("lanes = {}\n", spec.lanes));
    if !dials {
        let port = Host {
            name: me.name.clone(),
            addr: me.addr.clone(),
        }
        .port()
        .unwrap_or(spec.port);
        let v6 = me.addr.trim().starts_with('[') || me.addr.contains("::");
        let any = if v6 { "[::]" } else { "0.0.0.0" };
        s.push_str(&format!("tunnel_listen = \"{any}:{port}\"\n"));
    }
    s.push_str(&format!(
        "control_socket = \"/run/rakhsh-{}.sock\"\n",
        me.name
    ));

    for o in others {
        s.push_str(&format!(
            "\n[[peer]]\nname = \"{}\"\npublic = \"{}\"\n",
            o.name, o.public
        ));
        if dials {
            s.push_str(&format!("connect = \"{}\"\n", o.addr));
        }
    }

    for f in &spec.forwards {
        if let Some((listen, target)) = f.split_once('=') {
            let (target, udp) = match target.strip_suffix("/udp") {
                Some(t) => (t, true),
                None => (target, false),
            };
            s.push_str(&format!(
                "\n[[forward]]\nlisten = \"{listen}\"\ntarget = \"{target}\"\n"
            ));
            if udp {
                s.push_str("udp = true\n");
            }
        }
    }

    if role == "entry" {
        if let Some(p) = &spec.proxy {
            s.push_str(&crate::cli::proxy_block(Some(p), false, true));
        }
    }
    s
}

pub fn control_config(nodes: &[Node], listen: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!("listen = \"{listen}\"\n"));
    for n in nodes {
        let host = Host {
            name: n.name.clone(),
            addr: n.addr.clone(),
        };
        s.push_str(&format!(
            "\n[[node]]\nname = \"{}\"\nssh = \"root@{}\"\nsocket = \"/run/rakhsh-{}.sock\"\n\
             unit = \"rakhsh-{}\"\nconfig_path = \"/etc/rakhsh-{}.toml\"\n",
            n.name,
            host.host(),
            n.name,
            n.name,
            n.name
        ));
    }
    s
}

pub fn summary(spec: &Spec, nodes: &[Node]) -> Vec<String> {
    let exits: Vec<&str> = nodes
        .iter()
        .filter(|n| n.role == "exit")
        .map(|n| n.name.as_str())
        .collect();
    let entries: Vec<&str> = nodes
        .iter()
        .filter(|n| n.role == "entry")
        .map(|n| n.name.as_str())
        .collect();
    let (dialer, listener) = match spec.dial {
        Dial::Exit => ("exits dial", "entries listen"),
        Dial::Entry => ("entries dial", "exits listen"),
    };
    vec![
        format!(
            "{} exit(s): {} | {} entry(s): {}",
            exits.len(),
            exits.join(", "),
            entries.len(),
            entries.join(", ")
        ),
        format!("carrier {}, {dialer}, {listener}", spec.carrier),
        "every exit admits every entry and the other way round, so losing one node leaves the rest \
         connected"
            .to_string(),
    ]
}

#[cfg(test)]
#[path = "../tests/unit/fleet.rs"]
mod tests;
