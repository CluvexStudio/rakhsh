use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Inbound {
    pub port: u16,
    pub protocol: String,
    pub network: String,
    pub remark: String,
    pub listen: String,
    pub enable: bool,
    pub tcp: bool,
    pub udp: bool,
}

struct Url {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(u: &str) -> Result<Url> {
    let (https, rest) = if let Some(r) = u.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = u.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("panel URL must start with http:// or https://");
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].trim_end_matches('/').to_string()),
        None => (rest, String::new()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().context("bad panel port")?),
        None => (authority.to_string(), if https { 443 } else { 80 }),
    };
    Ok(Url {
        https,
        host,
        port,
        path,
    })
}

fn networks(protocol: &str, network: &str) -> (bool, bool) {
    match protocol {
        "wireguard" | "amneziawg" | "tuic" | "hysteria" | "hysteria2" => (false, true),
        "shadowsocks" | "dokodemo-door" => (true, true),
        _ => match network {
            "kcp" | "mkcp" | "quic" => (false, true),
            _ => (true, false),
        },
    }
}

fn parse_inbounds(body: &str) -> Result<Vec<Inbound>> {
    let v: serde_json::Value = serde_json::from_str(body).context("panel did not return JSON")?;
    if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
        bail!(
            "panel API error: {}",
            v.get("msg").and_then(|m| m.as_str()).unwrap_or("unknown")
        );
    }
    let arr = v.get("obj").and_then(|o| o.as_array()).ok_or_else(|| {
        anyhow!("unexpected API shape (no obj[] — wrong token scope or base path?)")
    })?;
    let mut out = Vec::new();
    for it in arr {
        let port = match it.get("port").and_then(|p| p.as_u64()) {
            Some(p) if p > 0 && p < 65536 => p as u16,
            _ => continue,
        };
        let protocol = it
            .get("protocol")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        let enable = it.get("enable").and_then(|e| e.as_bool()).unwrap_or(true);
        let listen = it
            .get("listen")
            .and_then(|l| l.as_str())
            .unwrap_or("")
            .to_string();
        let remark = it
            .get("remark")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        let ss = it
            .get("streamSettings")
            .or_else(|| it.get("stream_settings"));
        let network = match ss {
            Some(serde_json::Value::String(s)) => serde_json::from_str::<serde_json::Value>(s)
                .ok()
                .and_then(|j| j.get("network").and_then(|n| n.as_str()).map(String::from))
                .unwrap_or_default(),
            Some(serde_json::Value::Object(_)) => ss
                .and_then(|j| j.get("network"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string(),
            _ => String::new(),
        };
        let (tcp, udp) = networks(&protocol, &network);
        out.push(Inbound {
            port,
            protocol,
            network,
            remark,
            listen,
            enable,
            tcp,
            udp,
        });
    }
    Ok(out)
}

async fn http_get(url: &Url, token: &str) -> Result<String> {
    let endpoint = format!("{}/panel/api/inbounds/list", url.path);
    let req = format!(
        "GET {endpoint} HTTP/1.1\r\nHost: {}:{}\r\nAuthorization: Bearer {token}\r\n\
Accept: application/json\r\nUser-Agent: rakhsh\r\nConnection: close\r\n\r\n",
        url.host, url.port
    );
    let tcp = TcpStream::connect((url.host.as_str(), url.port))
        .await
        .with_context(|| format!("connecting to panel {}:{}", url.host, url.port))?;
    let raw = if url.https {
        let name = rustls_pki_types::ServerName::try_from(url.host.clone())
            .unwrap_or(rustls_pki_types::ServerName::try_from("localhost").unwrap());
        let mut s = crate::carrier::noverify_connector()
            .connect(name, tcp)
            .await
            .context("panel TLS")?;
        s.write_all(req.as_bytes()).await?;
        read_all_lenient(&mut s).await
    } else {
        let mut s = tcp;
        s.write_all(req.as_bytes()).await?;
        read_all_lenient(&mut s).await
    };
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response from panel"))?;
    let status = head.lines().next().unwrap_or("");
    if status.contains(" 401") || status.contains(" 403") {
        bail!(
            "panel refused the token ({}) — check the token and its scope (need node-sync/admin)",
            status.trim()
        );
    }
    if !status.contains(" 200") {
        bail!("panel returned: {}", status.trim());
    }
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        Ok(dechunk(body))
    } else {
        Ok(body.to_string())
    }
}

async fn read_all_lenient<R: tokio::io::AsyncRead + Unpin>(s: &mut R) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match s.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    buf
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size_line, after)) = rest.split_once("\r\n") {
        let size =
            usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0").trim(), 16)
                .unwrap_or(0);
        if size == 0 {
            break;
        }
        if after.len() < size {
            out.push_str(after);
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..].strip_prefix("\r\n").unwrap_or(&after[size..]);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SyncFwd {
    pub port: u16,
    pub udp: bool,
    pub proxy_protocol: bool,
    pub target: String,
    pub label: String,
}

pub async fn fetch_forwards(
    panel: &str,
    token: &str,
    target_host: &str,
    proxy_protocol: bool,
) -> Result<(Vec<SyncFwd>, Vec<String>, usize)> {
    let url = parse_url(panel)?;
    let body = http_get(&url, token).await?;
    let inbounds = parse_inbounds(&body)?;
    let total = inbounds.len();
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for ib in &inbounds {
        let why = if !ib.enable {
            Some("disabled")
        } else if matches!(ib.listen.as_str(), "127.0.0.1" | "::1" | "localhost") {
            Some("loopback-only")
        } else {
            None
        };
        if let Some(w) = why {
            skipped.push(format!("{}:{} ({}) — {w}", ib.port, ib.protocol, ib.remark));
            continue;
        }
        let label = format!(
            "{} {}{}",
            ib.protocol,
            ib.remark,
            if ib.network.is_empty() {
                String::new()
            } else {
                format!(" ({})", ib.network)
            }
        );
        let target = format!("{target_host}:{}", ib.port);
        if ib.tcp {
            out.push(SyncFwd {
                port: ib.port,
                udp: false,
                proxy_protocol,
                target: target.clone(),
                label: label.clone(),
            });
        }
        if ib.udp {
            out.push(SyncFwd {
                port: ib.port,
                udp: true,
                proxy_protocol: false,
                target: target.clone(),
                label: label.clone(),
            });
        }
    }
    Ok((out, skipped, total))
}

pub async fn sync(
    panel: &str,
    token: &str,
    iran_listen: &str,
    target_host: &str,
    proxy_protocol: bool,
) -> Result<()> {
    let (fwds, skipped, total) = fetch_forwards(panel, token, target_host, proxy_protocol).await?;
    if total == 0 {
        bail!("panel returned no inbounds (empty list, or the token cannot read them)");
    }
    println!("# rakhsh forwards for {total} panel inbound(s) -> {target_host}");
    println!("# paste these into the Iran entry config, then restart rakhsh.");
    for f in &fwds {
        println!(
            "\n[[forward]]  # {}\nlisten = \"{iran_listen}:{}\"\ntarget = \"{}\"",
            f.label, f.port, f.target
        );
        if f.udp {
            println!("udp = true");
        } else if f.proxy_protocol {
            println!("proxy_protocol = true");
        }
    }
    eprintln!(
        "\n# {} forward(s) generated; {} inbound(s) skipped.",
        fwds.len(),
        skipped.len()
    );
    for s in &skipped {
        eprintln!("#   skip {s}");
    }
    Ok(())
}
