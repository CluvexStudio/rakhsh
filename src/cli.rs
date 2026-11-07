use crate::{
    config, dgram, doctor, engine, entry, exit, fleet, l3, limits, links, noise, openvpn, raw,
    resume, status, xui,
};
use anyhow::{bail, Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "rakhsh",
    version,
    about = "A fast, authenticated tunnel between two servers."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args)]
pub struct FleetArgs {
    #[arg(long = "exit", required = true)]
    exits: Vec<String>,
    #[arg(long = "entry", required = true)]
    entries: Vec<String>,
    #[arg(long, default_value = "wss")]
    carrier: String,
    #[arg(long, default_value = "www.cloudflare.com")]
    sni: String,
    #[arg(long, default_value = "exit")]
    dial: String,
    #[arg(long, default_value_t = 4)]
    lanes: usize,
    #[arg(long, default_value_t = 7000)]
    port: u16,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long = "forward")]
    forwards: Vec<String>,
    #[arg(long, default_value = "0.0.0.0:8443")]
    control_listen: String,
    #[arg(long, short)]
    out: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct InitArgs {
    #[arg(long)]
    tunnel_addr: String,
    #[arg(long = "forward")]
    forwards: Vec<String>,
    #[arg(long, default_value = "tcp")]
    carrier: String,
    #[arg(long, default_value = "www.cloudflare.com")]
    sni: String,
    #[arg(long, default_value_t = false)]
    direct: bool,
    #[arg(long, default_value_t = 4)]
    lanes: usize,
    #[arg(long = "link")]
    links: Vec<String>,
    #[arg(long)]
    link_policy: Option<String>,
    #[arg(long, default_value = "full")]
    encryption: String,
    #[arg(long, default_value_t = false)]
    resume: bool,
    #[arg(long)]
    resume_grace: Option<u64>,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long)]
    dns: Option<String>,
    #[arg(long, default_value_t = false)]
    split_iran: bool,
    #[arg(long)]
    openvpn: Option<String>,
    #[arg(long)]
    peer_ip: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
    Keygen,
    Init(InitArgs),
    Fleet(FleetArgs),
    InitNode {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
    },
    Rules {
        #[arg(default_value = "iran")]
        which: String,
        #[arg(short, long, default_value = "/etc/rakhsh/iran.txt")]
        output: PathBuf,
    },
    XuiSync {
        #[arg(long)]
        panel: String,
        #[arg(long)]
        token: String,
        #[arg(long, default_value = "0.0.0.0")]
        iran_listen: String,
        #[arg(long, default_value = "127.0.0.1")]
        target_host: String,
        #[arg(long, default_value_t = false)]
        proxy_protocol: bool,
    },
    SpoofTest {
        #[command(subcommand)]
        side: SpoofSide,
    },
    Check {
        #[arg(short, long)]
        config: PathBuf,
    },
    Openvpn {
        #[arg(short, long)]
        config: PathBuf,
    },
    Doctor {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long, default_value_t = false)]
        serve: bool,
        #[arg(long)]
        peer: Option<String>,
        #[arg(long, default_value_t = doctor::PORT)]
        port: u16,
        #[arg(long, default_value_t = 8)]
        seconds: u64,
        #[arg(long = "carrier")]
        carriers: Vec<String>,
        #[arg(long, default_value_t = false)]
        protocols: bool,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    Quota {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long, default_value_t = false)]
        reset: bool,
    },
    Status {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Speedtest {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        socket: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Install {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long, default_value = "rakhsh")]
        name: String,
    },
    Uninstall {
        #[arg(long, default_value = "rakhsh")]
        name: String,
    },
    Optimize {
        #[arg(long, default_value_t = true)]
        persist: bool,
    },
}

#[derive(Subcommand)]
enum SpoofSide {
    Recv {
        #[arg(long, default_value_t = 45000)]
        port: u16,
        #[arg(long, default_value_t = 40)]
        seconds: u64,
        #[arg(long, default_value_t = 5)]
        probes: u16,
        #[arg(long, default_value_t = 20.0)]
        threshold: f64,
        #[arg(long, default_value = "rakhsh")]
        token: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    Send {
        #[arg(long)]
        to: String,
        #[arg(long, default_value_t = 45000)]
        port: u16,
        #[arg(long, default_value_t = 5)]
        probes: u16,
        #[arg(long, default_value = "rakhsh")]
        token: String,
        #[arg(long)]
        interface: Option<String>,
        candidates: String,
    },
}

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("rakhsh=info")),
        )
        .init();

    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => {
            let (private, public) = noise::generate_keypair()?;
            println!("# static_secret for this host:");
            println!("static_secret = \"{}\"", BASE64_STANDARD.encode(&private));
            println!("# public key to pin as peer_public on the OTHER host:");
            println!("public = \"{}\"", BASE64_STANDARD.encode(&public));
        }
        Cmd::Init(args) => init(&args)?,
        Cmd::Fleet(args) => fleet(&args)?,
        Cmd::XuiSync {
            panel,
            token,
            iran_listen,
            target_host,
            proxy_protocol,
        } => {
            xui::sync(&panel, &token, &iran_listen, &target_host, proxy_protocol).await?;
        }
        Cmd::SpoofTest { side } => match side {
            SpoofSide::Recv {
                port,
                seconds,
                probes,
                threshold,
                token,
                out,
            } => raw::spoof_test_recv(port, seconds, probes, threshold, &token, out.as_deref())?,
            SpoofSide::Send {
                to,
                port,
                probes,
                token,
                interface,
                candidates,
            } => {
                let to: std::net::Ipv4Addr = to.parse().context("--to must be an IPv4 address")?;
                let list = raw::parse_candidates(&candidates)?;
                raw::spoof_test_send(to, port, &list, probes, &token, interface.as_deref())?
            }
        },
        Cmd::Quota { config, reset } => {
            let cfg = config::Config::load(&config)?;
            let l = limits::Limiter::new(&cfg, false)?;
            l.declare(&cfg)?;
            let lines = l.report();
            if lines.is_empty() {
                println!("no quota configured in {}", config.display());
            }
            for line in &lines {
                println!("{line}");
            }
            if reset && !lines.is_empty() {
                l.reset()?;
                println!("counters zeroed (a running rakhsh picks it up within a few seconds)");
            }
        }
        Cmd::Check { config } => {
            let cfg = config::Config::load(&config)?;
            entry::validate(&cfg)?;
            if cfg.role == "node" {
                println!("role node — a proxy and router on this host, with no tunnel peer");
            } else {
                println!(
                    "role {}, carrier {}",
                    cfg.role,
                    cfg.carrier.as_deref().unwrap_or("tcp")
                );
            }
            if matches!(
                cfg.carrier.as_deref(),
                Some("faketcp" | "l2tcp" | "icmp" | "spoof")
            ) {
                let (a, b) = raw::lane_ports(&cfg.token);
                let dialer = cfg.dial.as_deref().unwrap_or("exit");
                println!(
                    "  crafted-TCP ports: {dialer} sends from {a} to {b} (derived from the token — \
                     both ends compute the same pair, and it is what to filter a capture on)"
                );
                println!(
                    "  reliability: {}{} — the other end must match",
                    cfg.reliability.as_deref().unwrap_or("quic"),
                    if cfg.reliability.is_none() {
                        " (default)"
                    } else {
                        ""
                    }
                );
                if cfg.lanes.is_some_and(|l| l != raw::RAW_LANES as usize) {
                    println!(
                        "  note: lanes = {} is ignored — a raw carrier always runs {} lane. Each \
                         lane would be its own crafted-TCP port pair over the same bottleneck, so \
                         extra lanes cost CPU without adding throughput; FEC is the lever instead. \
                         Set lanes = {} so the config says what it does.",
                        cfg.lanes.unwrap_or(0),
                        raw::RAW_LANES,
                        raw::RAW_LANES
                    );
                }
                if let Some(n) = cfg.spoof_sockbuf {
                    println!(
                        "  WARNING: spoof_sockbuf = {n} — on a CPU-bound entry a big socket buffer \
                         measured slower, not faster (upload fell from 11 to 1.5 Mbit/s as the \
                         queue grew). Leave it unset unless you have measured otherwise."
                    );
                }
            }
            for f in &cfg.forward {
                f.listen.parse::<std::net::SocketAddr>().with_context(|| {
                    format!(
                        "[[forward]] listen = {:?} is not an address:port (one entry needs a \
                         listen and a target, as in listen = \"0.0.0.0:443\", target = \
                         \"127.0.0.1:8443\")",
                        f.listen
                    )
                })?;
                let (host, port) = f.target.rsplit_once(':').with_context(|| {
                    format!("[[forward]] target = {:?} needs a host:port", f.target)
                })?;
                if host.is_empty() || port.parse::<u16>().is_err() {
                    anyhow::bail!("[[forward]] target = {:?} needs a host:port", f.target);
                }
                println!(
                    "forward {} {} -> {}",
                    if f.udp { "udp" } else { "tcp" },
                    f.listen,
                    f.target
                );
            }
            if cfg.xui_panel.is_some() && cfg.role != "exit" {
                println!(
                    "  note: xui_panel is read by the exit, which polls the panel and pushes the \
                     port list across. On a {} it does nothing.",
                    cfg.role
                );
            }
            if cfg.accept_sync.unwrap_or(false) && cfg.role != "entry" {
                println!(
                    "  note: accept_sync is read by the entry, which opens the ports the exit \
                     pushes. On a {} it does nothing.",
                    cfg.role
                );
            }
            openvpn::validate(&cfg)?;
            for line in openvpn::describe(&cfg) {
                println!("{line}");
            }
            for line in limits::describe(&cfg)? {
                println!("limits — {line}");
            }
            let mode = cfg.crypto_mode()?;
            println!("data protection: {} — {}", mode.as_str(), mode.summary());
            if dgram::selected(&cfg) {
                for line in dgram::describe(&cfg) {
                    println!("{line}");
                }
                dgram::validate(&cfg)?;
            } else if cfg.role == "entry" || cfg.role == "exit" {
                for line in links::describe(&cfg)? {
                    println!("{line}");
                }
            }
            if cfg.mss_clamp.is_some() && cfg.l3_addr.is_none() {
                println!(
                    "  note: mss_clamp is read in layer-3 mode only, so without l3_addr it has \
                     no effect"
                );
            }
            for line in l3::describe(&cfg)? {
                println!("{line}");
            }
            if mode != noise::Mode::Full {
                println!("  (the other end must set encryption = \"{}\" too, or the lanes will not connect)", mode.as_str());
            }
            if cfg.resume {
                println!(
                    "stream resumption: on — TCP streams survive the loss of a lane (up to {}s without any lane)",
                    cfg.resume_grace.unwrap_or(resume::DEFAULT_GRACE_SECS)
                );
                println!(
                    "  (the other end must set resume = true too, or the lanes will not connect)"
                );
            }
            if cfg.inbound.is_empty() && cfg.dns.is_none() {
                println!("core: no [[inbound]] — plain tunnel config");
            } else {
                println!("core: {}", engine::validate(&cfg)?);
            }
            println!("config OK");
        }
        Cmd::Openvpn { config } => {
            let cfg = config::Config::load(&config)?;
            openvpn::validate(&cfg)?;
            print!("{}", openvpn::directives(&cfg)?);
        }
        Cmd::Doctor {
            config,
            serve,
            peer,
            port,
            seconds,
            carriers,
            protocols,
            out,
        } => {
            tidy_on_signal();
            let _tidy = Tidy;
            let cfg = config::Config::load(&config)?;
            match (serve, peer.as_deref()) {
                (true, None) => doctor::serve(&cfg, port).await?,
                (false, Some(peer)) => {
                    let (host, control) = doctor::parse_peer(peer, port)?;
                    let plan = doctor::Plan::new(&carriers, seconds, protocols)?;
                    println!(
                        "measuring {} carrier(s) against {host}, up to {}s each — about {}s in all",
                        plan.carriers.len(),
                        seconds,
                        plan.budget().as_secs()
                    );
                    let needs = plan.privileged();
                    if !needs.is_empty() {
                        println!(
                            "  note: {} forge their own packets, so both ends need CAP_NET_RAW",
                            needs.join(", ")
                        );
                    }
                    println!("{}", doctor::HEADER);
                    let report = doctor::run(&cfg, &host, control, plan).await?;
                    let good = report.ordered();
                    println!();
                    if good.is_empty() {
                        println!("nothing held on this path");
                    } else {
                        println!(
                            "{} of {} carrier(s) held; fastest was {} at {:.1} Mbit/s",
                            good.len(),
                            report.verdicts.len(),
                            good[0].carrier,
                            good[0].mbit
                        );
                    }
                    let text = report.config(&host, control, links::dialing(&cfg));
                    match out {
                        Some(path) => {
                            write_private(&path, &text)?;
                            println!("wrote {} — the links in measured order", path.display());
                        }
                        None => {
                            println!();
                            print!("{text}");
                        }
                    }
                }
                (true, Some(_)) => {
                    bail!("--serve waits for a peer; --peer drives the tests. Pick one")
                }
                (false, None) => bail!(
                    "give --serve on one host and --peer <that host> on the other, \
                     each with its half of a config pair from `rakhsh init`"
                ),
            }
        }
        Cmd::Status {
            config,
            socket,
            json,
        } => {
            let path = socket
                .or_else(|| {
                    config
                        .as_ref()
                        .and_then(|c| config::Config::load(c).ok())
                        .and_then(|c| c.control_socket)
                })
                .unwrap_or_else(|| status::DEFAULT_SOCKET.to_string());
            let snap = status::query(&path).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snap)?);
            } else {
                status::print_table(&snap);
            }
        }
        Cmd::Speedtest {
            config,
            socket,
            json,
        } => {
            let path = socket
                .or_else(|| {
                    config
                        .as_ref()
                        .and_then(|c| config::Config::load(c).ok())
                        .and_then(|c| c.control_socket)
                })
                .unwrap_or_else(|| status::DEFAULT_SOCKET.to_string());
            let r = status::query_speedtest(&path).await?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "down_mbit": r.down_mbit, "up_mbit": r.up_mbit })
                );
            } else if r.down_mbit.is_none() && r.up_mbit.is_none() {
                println!("speed test unavailable (needs the entry role and a live lane)");
            } else {
                if let Some(m) = r.down_mbit {
                    println!("in-tunnel download: {m:.0} Mbit/s");
                }
                if let Some(m) = r.up_mbit {
                    println!("in-tunnel upload:   {m:.0} Mbit/s");
                }
            }
        }
        Cmd::InitNode { listen } => init_node(&listen),
        Cmd::Rules { which, output } => build_rules(&which, &output)?,
        Cmd::Install { config, name } => install_service(&config, &name)?,
        Cmd::Uninstall { name } => uninstall_service(&name)?,
        Cmd::Optimize { persist } => optimize(persist)?,
        Cmd::Run { config } => {
            tidy_on_signal();
            let cfg = config::Config::load(&config)?;
            if dgram::selected(&cfg) {
                return dgram::run(cfg).await;
            }
            match cfg.role.as_str() {
                "entry" => entry::run(cfg).await?,
                "exit" => exit::run(cfg).await?,
                "node" => engine::run_node(cfg).await?,
                other => anyhow::bail!("unknown role {other:?}"),
            }
        }
    }
    Ok(())
}

fn fleet(args: &FleetArgs) -> Result<()> {
    let spec = fleet::Spec {
        exits: args
            .exits
            .iter()
            .map(|h| fleet::Host::parse(h, args.port))
            .collect::<Result<_>>()?,
        entries: args
            .entries
            .iter()
            .map(|h| fleet::Host::parse(h, args.port))
            .collect::<Result<_>>()?,
        carrier: args.carrier.clone(),
        sni: args.sni.clone(),
        dial: fleet::Dial::parse(&args.dial)?,
        lanes: args.lanes,
        port: args.port,
        proxy: args.proxy.clone(),
        forwards: args.forwards.clone(),
    };
    let nodes = fleet::plan(&spec)?;
    let control = fleet::control_config(&nodes, &args.control_listen);

    for line in fleet::summary(&spec, &nodes) {
        println!("# {line}");
    }
    match &args.out {
        Some(dir) => {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            for n in &nodes {
                let path = dir.join(format!("{}.toml", n.name));
                write_private(&path, &n.config)?;
                println!("{}  ({} {})", path.display(), n.role, n.addr);
            }
            let path = dir.join("control.toml");
            write_private(&path, &control)?;
            println!("{}  (the managing host)", path.display());
            println!("#");
            println!("# copy each file to its own host as /etc/rakhsh-<name>.toml, then");
            println!("#   rakhsh install -c /etc/rakhsh-<name>.toml --name rakhsh-<name>");
            println!("# and run rakhsh-control with control.toml on the managing host.");
        }
        None => {
            for n in &nodes {
                println!(
                    "\n########## {}.toml  ({} {}) ##########",
                    n.name, n.role, n.addr
                );
                print!("{}", n.config);
            }
            println!("\n########## control.toml  (the managing host) ##########");
            print!("{control}");
        }
    }
    Ok(())
}

fn write_private(path: &std::path::Path, text: &str) -> Result<()> {
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn init(args: &InitArgs) -> Result<()> {
    let InitArgs {
        tunnel_addr,
        forwards,
        carrier,
        sni,
        direct,
        lanes,
        links,
        link_policy,
        encryption,
        resume,
        resume_grace,
        proxy,
        dns,
        split_iran,
        openvpn: ovpn,
        peer_ip: far_ip,
    } = args;
    let far_ip = far_ip.as_deref();
    let ovpn = match ovpn.as_deref() {
        Some(spec) => Some(openvpn::OpenVpn::parse_spec(spec)?),
        None => None,
    };
    let (direct, lanes, resume, split_iran) = (*direct, *lanes, *resume, *split_iran);
    let (resume_grace, link_policy) = (*resume_grace, link_policy.as_deref());
    let (proxy, dns) = (proxy.as_deref(), dns.as_deref());
    let (tunnel_addr, carrier, sni, encryption) = (
        tunnel_addr.as_str(),
        carrier.as_str(),
        sni.as_str(),
        encryption.as_str(),
    );
    let (forwards, links) = (forwards.as_slice(), links.as_slice());
    let mode = noise::Mode::parse(encryption)?;
    if let Some(p) = link_policy {
        links::Policy::parse(Some(p))?;
    }
    let (e_priv, e_pub) = noise::generate_keypair()?;
    let (x_priv, x_pub) = noise::generate_keypair()?;
    let mut token = [0u8; 32];
    getrandom(&mut token);
    let token = BASE64_STANDARD.encode(token);
    let b64 = |b: &[u8]| BASE64_STANDARD.encode(b);

    let port = tunnel_addr.rsplit(':').next().unwrap_or("7000");
    let bind = format!("0.0.0.0:{port}");
    let tls = matches!(carrier, "tls" | "ws" | "wss");
    let urlsafe = |n: usize| {
        let mut b = vec![0u8; n];
        getrandom(&mut b);
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(b)
    };
    let ws_path = format!("/{}", urlsafe(6));
    let ws_cred = urlsafe(16);

    let mut fwd_toml = String::new();
    for f in forwards {
        let mut spec = f.as_str();
        let (mut udp, mut pp) = (false, false);
        loop {
            if let Some(s) = spec.strip_suffix("/udp") {
                spec = s;
                udp = true;
            } else if let Some(s) = spec.strip_suffix("/pp") {
                spec = s;
                pp = true;
            } else {
                break;
            }
        }
        let (l, t) = spec.split_once('=').with_context(|| {
            format!(
                "--forward {f:?} needs listen=target, as in 0.0.0.0:443=127.0.0.1:8443 \
                 (add /udp for a datagram forward, /pp for PROXY protocol)"
            )
        })?;
        l.parse::<std::net::SocketAddr>()
            .with_context(|| format!("--forward {f:?}: {l:?} is not an address:port"))?;
        fwd_toml.push_str(&format!(
            "\n[[forward]]\nlisten = \"{l}\"\ntarget = \"{t}\"\n"
        ));
        if udp {
            fwd_toml.push_str("udp = true\n");
        }
        if pp {
            fwd_toml.push_str("proxy_protocol = true\n");
        }
    }

    let mut ovpn_toml = String::new();
    if let Some(ov) = &ovpn {
        fwd_toml.push_str(&openvpn::forward_toml(ov));
        ovpn_toml.push_str(&openvpn::config_toml(ov));
    }

    let common = |extra: &str| -> String {
        let mut s = format!("carrier = \"{carrier}\"\n");
        if tls {
            s.push_str(&format!("sni = \"{sni}\"\n"));
        }
        if matches!(carrier, "ws" | "wss") {
            s.push_str(&format!("ws_path = \"{ws_path}\"\n"));
            s.push_str(&format!("ws_credential = \"{ws_cred}\"\n"));
        }
        if direct {
            s.push_str("dial = \"entry\"\n");
        }
        if mode != noise::Mode::Full {
            s.push_str(&format!(
                "# {}\nencryption = \"{}\"\n",
                mode.summary(),
                mode.as_str()
            ));
        }
        if resume {
            s.push_str("# TCP streams survive the loss of a lane (see RESUME.md)\nresume = true\n");
            if let Some(g) = resume_grace {
                s.push_str(&format!("resume_grace = {g}\n"));
            }
        }
        if let Some(p) = link_policy {
            s.push_str(&format!("link_policy = \"{p}\"\n"));
        }
        s.push_str(extra);
        s
    };

    let (host, tunnel_port) = tunnel_addr
        .rsplit_once(':')
        .unwrap_or((tunnel_addr, "7000"));
    let (mut entry_links, mut exit_links) = (String::new(), String::new());
    let proto = |k: &str| {
        if matches!(k, "quic" | "quicv2" | "kcp") {
            "udp"
        } else {
            "tcp"
        }
    };
    let mut used: Vec<(&str, String)> = vec![(proto(carrier), tunnel_port.to_string())];
    for spec in links {
        let (kind, port) = spec.split_once(':').unwrap_or((spec.as_str(), tunnel_port));
        if !matches!(
            kind,
            "tcp" | "tls" | "ws" | "wss" | "quic" | "quicv2" | "kcp"
        ) {
            bail!("--link {spec}: carrier must be tcp, tls, ws, wss, quic, quicv2 or kcp (raw carriers: write the [[link]] by hand)");
        }
        if used.contains(&(proto(kind), port.to_string())) {
            bail!("--link {spec}: {} port {port} is already used by another carrier of this tunnel; give this one its own port, e.g. --link {kind}:{}",
                proto(kind).to_uppercase(), port.parse::<u16>().map_or(7001, |p| p.saturating_add(1)));
        }
        used.push((proto(kind), port.to_string()));
        let mut extra = String::new();
        if matches!(kind, "tls" | "ws" | "wss" | "quic" | "quicv2") {
            extra.push_str(&format!("sni = \"{sni}\"\n"));
        }
        if matches!(kind, "ws" | "wss") {
            extra.push_str(&format!(
                "ws_path = \"/{}\"\nws_credential = \"{}\"\n",
                rand_token(6),
                rand_token(16)
            ));
        }
        let table =
            |addr: String| format!("\n[[link]]\ncarrier = \"{kind}\"\naddr = \"{addr}\"\n{extra}");
        let (listen_addr, dial_addr) = (format!("0.0.0.0:{port}"), format!("{host}:{port}"));
        if direct {
            entry_links.push_str(&table(dial_addr));
            exit_links.push_str(&table(listen_addr));
        } else {
            entry_links.push_str(&table(listen_addr));
            exit_links.push_str(&table(dial_addr));
        }
    }

    let datagram = carrier.starts_with("shabdiz-");
    let raw_peer = matches!(
        carrier,
        "faketcp" | "l2tcp" | "icmp" | "spoof" | "shabdiz-gre" | "shabdiz-esp" | "shabdiz-l2"
    );
    let (dials_peer_ip, listens_peer_ip) = if raw_peer {
        let listens = match far_ip {
            Some(ip) => format!("peer_ip = \"{ip}\"\n"),
            None => format!(
                "# This carrier forges its own packets, so it has no socket to learn the far \
                 end's\n# address from. Set peer_ip to the {} public address, or pass \
                 --peer-ip to\n# `rakhsh init` to have it written here.\n# \
                 peer_ip = \"203.0.113.9\"\n",
                if direct { "entry's" } else { "exit's" }
            ),
        };
        (format!("peer_ip = \"{host}\"\n"), listens)
    } else {
        (String::new(), String::new())
    };
    let lane_line = if datagram {
        String::new()
    } else if matches!(carrier, "faketcp" | "l2tcp" | "icmp" | "spoof") {
        format!("lanes = {}\n", raw::RAW_LANES)
    } else {
        format!("lanes = {lanes}\n")
    };
    let (entry_link, exit_link) = if direct {
        (
            format!("tunnel_connect = \"{tunnel_addr}\"\n{lane_line}{dials_peer_ip}"),
            format!("tunnel_listen = \"{bind}\"\n{listens_peer_ip}"),
        )
    } else {
        (
            format!("tunnel_listen = \"{bind}\"\n{listens_peer_ip}"),
            format!("tunnel_connect = \"{tunnel_addr}\"\n{lane_line}{dials_peer_ip}"),
        )
    };

    println!("########## entry.toml  (run on the Iran server) ##########");
    println!("role = \"entry\"");
    println!("token = \"{token}\"");
    println!("static_secret = \"{}\"", b64(&e_priv));
    println!("peer_public = \"{}\"", b64(&x_pub));
    print!("{}", common(&entry_link));
    print!("{fwd_toml}");
    print!("{ovpn_toml}");
    if proxy.is_some() || dns.is_some() {
        print!("{}", proxy_block(proxy, split_iran, true));
    }
    if let Some(listen) = dns {
        let open = !(listen.starts_with("127.")
            || listen.starts_with("localhost")
            || listen.starts_with("[::1]"));
        print!("\n[dns]\nlisten = \"{listen}\"\n# Resolvers asked directly from this host (default: /etc/resolv.conf); remote ones (default 1.1.1.1, 8.8.8.8) are asked through the tunnel.\n# local = [\"…\"]\n# remote = [\"1.1.1.1\"]\n");
        if open {
            print!("# Anyone who can reach this address could use it as an open resolver: list your clients' networks.\n# allow = [\"203.0.113.0/24\"]\n");
        }
    }
    print!("{entry_links}");
    println!("\n########## exit.toml  (run on the foreign server) ##########");
    println!("role = \"exit\"");
    println!("token = \"{token}\"");
    println!("static_secret = \"{}\"", b64(&x_priv));
    println!("peer_public = \"{}\"", b64(&e_pub));
    print!("{}", common(&exit_link));
    if datagram {
        print!("{fwd_toml}");
        print!("{ovpn_toml}");
    }
    print!("{exit_links}");
    Ok(())
}

fn rand_token(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom(&mut b);
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(b)
}

pub(crate) fn proxy_block(listen: Option<&str>, split_iran: bool, with_tunnel: bool) -> String {
    let mut s = String::new();
    if let Some(listen) = listen {
        let loopback = listen.starts_with("127.")
            || listen.starts_with("localhost")
            || listen.starts_with("[::1]");
        s.push_str("\n[[inbound]]\ntag = \"proxy\"\ntype = \"mixed\"\n");
        s.push_str(&format!("listen = \"{listen}\"\n"));
        if !loopback {
            s.push_str(&format!(
                "username = \"rk\"\npassword = \"{}\"\n",
                rand_token(12)
            ));
        }
    }
    if with_tunnel {
        s.push_str("\n[[outbound]]\ntag = \"tunnel\"\ntype = \"tunnel\"\n");
    }
    s.push_str("\n[[outbound]]\ntag = \"direct\"\ntype = \"direct\"\n");
    s.push_str("\n[[outbound]]\ntag = \"block\"\ntype = \"block\"\n");
    s.push_str(&format!(
        "\n[route]\nfinal = \"{}\"\n",
        if with_tunnel { "tunnel" } else { "direct" }
    ));
    if split_iran && with_tunnel {
        s.push_str(
            "\n# Iranian sites go direct from this server; everything else rides the tunnel.\n\
# Build the full IP list with:  rakhsh rules iran\n\
[[route.rule]]\noutbound = \"direct\"\ndomain_suffix = [\".ir\"]\nrule_file = \"/etc/rakhsh/iran.txt\"\n",
        );
    }
    s
}

fn tidy() {
    raw::cleanup();
    shabdiz::carrier::l2::cleanup();
}

struct Tidy;

impl Drop for Tidy {
    fn drop(&mut self) {
        tidy();
    }
}

fn tidy_on_signal() {
    tokio::spawn(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        tidy();
        std::process::exit(0);
    });
}

fn init_node(listen: &str) {
    println!("# rakhsh standalone node — SOCKS5+HTTP proxy, direct out, no tunnel peer");
    println!("role = \"node\"");
    println!("control_socket = \"/run/rakhsh-node.sock\"");
    print!("{}", proxy_block(Some(listen), false, false));
}

fn build_rules(which: &str, output: &std::path::Path) -> Result<()> {
    if which != "iran" {
        anyhow::bail!("unknown rule set {which:?} (only \"iran\")");
    }
    const URL: &str = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest";
    println!("downloading {URL} …");
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "120", URL])
        .output()
        .context("running curl (is it installed?)")?;
    if !out.status.success() {
        anyhow::bail!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = vec![
        "# Iranian destinations (direct). Generated by `rakhsh rules iran`.".to_string(),
        "suffix:ir".to_string(),
        "suffix:xn--mgba3a4f16a".to_string(),
    ];
    let (mut v4, mut v6) = (0usize, 0usize);
    for l in text.lines() {
        let f: Vec<&str> = l.split('|').collect();
        if f.len() < 7 || f[1] != "IR" || !matches!(f[6], "allocated" | "assigned") {
            continue;
        }
        match f[2] {
            "ipv4" => {
                let (Ok(start), Ok(count)) =
                    (f[3].parse::<std::net::Ipv4Addr>(), f[4].parse::<u64>())
                else {
                    continue;
                };
                let mut cur = u32::from(start) as u64;
                let mut left = count;
                while left > 0 {
                    let align = if cur == 0 {
                        1u64 << 32
                    } else {
                        1u64 << cur.trailing_zeros().min(32)
                    };
                    let mut size = align.min(left);
                    size = 1u64 << (63 - size.leading_zeros());
                    lines.push(format!(
                        "cidr:{}/{}",
                        std::net::Ipv4Addr::from(cur as u32),
                        32 - size.trailing_zeros()
                    ));
                    cur += size;
                    left -= size;
                    v4 += 1;
                }
            }
            "ipv6" if f[3].parse::<std::net::Ipv6Addr>().is_ok() && f[4].parse::<u8>().is_ok() => {
                lines.push(format!("cidr:{}/{}", f[3], f[4]));
                v6 += 1;
            }
            _ => {}
        }
    }
    if v4 + v6 == 0 {
        anyhow::bail!("no Iranian allocations found in the registry file");
    }
    if let Some(dir) = output.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(output, lines.join("\n") + "\n")
        .with_context(|| format!("writing {}", output.display()))?;
    println!(
        "wrote {} ({} IPv4 blocks, {} IPv6 blocks)",
        output.display(),
        v4,
        v6
    );
    Ok(())
}

fn install_service(config: &std::path::Path, name: &str) -> Result<()> {
    use std::process::Command;
    let exe = std::env::current_exe().context("finding current executable")?;
    let cfg_abs = std::fs::canonicalize(config)
        .with_context(|| format!("resolving config path {}", config.display()))?;
    let unit_path = format!("/etc/systemd/system/{name}.service");
    let unit = format!(
        "[Unit]\n\
Description=rakhsh tunnel ({name})\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={exe} run -c {cfg}\n\
Restart=always\n\
RestartSec=2\n\
LimitNOFILE=1048576\n\
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n",
        exe = exe.display(),
        cfg = cfg_abs.display(),
    );
    std::fs::write(&unit_path, unit).with_context(|| format!("writing {unit_path} (need root)"))?;
    Command::new("systemctl").arg("daemon-reload").status().ok();
    let st = Command::new("systemctl")
        .args(["enable", "--now", &format!("{name}.service")])
        .status()
        .context("systemctl enable --now")?;
    if st.success() {
        println!("installed and started {name}.service ({unit_path})");
    } else {
        anyhow::bail!("systemctl enable --now {name}.service failed");
    }
    Ok(())
}

fn uninstall_service(name: &str) -> Result<()> {
    use std::process::Command;
    let svc = format!("{name}.service");
    Command::new("systemctl")
        .args(["disable", "--now", &svc])
        .status()
        .ok();
    let unit_path = format!("/etc/systemd/system/{name}.service");
    let _ = std::fs::remove_file(&unit_path);
    Command::new("systemctl").arg("daemon-reload").status().ok();
    println!("removed {svc}");
    Ok(())
}

fn optimize(persist: bool) -> Result<()> {
    use std::process::Command;
    let settings: &[(&str, &str)] = &[
        ("net.core.default_qdisc", "fq"),
        ("net.ipv4.tcp_congestion_control", "bbr"),
        ("net.core.rmem_max", "16777216"),
        ("net.core.wmem_max", "16777216"),
        ("net.ipv4.tcp_rmem", "4096 262144 16777216"),
        ("net.ipv4.tcp_wmem", "4096 262144 16777216"),
        ("net.core.netdev_max_backlog", "16384"),
        ("net.ipv4.tcp_mtu_probing", "1"),
        ("net.ipv4.tcp_fastopen", "3"),
    ];
    let mut applied = 0;
    for (k, v) in settings {
        if Command::new("sysctl")
            .arg("-w")
            .arg(format!("{k}={v}"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            applied += 1;
        }
    }
    if persist {
        let body: String = settings
            .iter()
            .map(|(k, v)| format!("{k} = {v}\n"))
            .collect();
        let _ = std::fs::write("/etc/sysctl.d/99-rakhsh.conf", body);
    }
    println!(
        "applied {applied}/{} kernel tunables (bbr+fq, buffers, backlog){}",
        settings.len(),
        if persist {
            "; persisted to /etc/sysctl.d/99-rakhsh.conf"
        } else {
            ""
        }
    );
    Ok(())
}

pub(crate) fn getrandom(buf: &mut [u8]) {
    if let Ok((priv_bytes, _)) = noise::generate_keypair() {
        let n = buf.len().min(priv_bytes.len());
        buf[..n].copy_from_slice(&priv_bytes[..n]);
    }
}
