use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::timeout;

use crate::Node;

pub async fn fetch_node(n: Node) -> Value {
    let first = try_fetch(&n).await;
    let result = match first {
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            try_fetch(&n).await
        }
        ok => ok,
    };
    match result {
        Ok(mut v) => {
            if let Some(o) = v.as_object_mut() {
                o.insert("name".into(), json!(n.name));
                o.insert("offline".into(), json!(false));
            }
            v
        }
        Err(e) => {
            tracing::debug!("node {}: {e:#}", n.name);
            offline(&n.name)
        }
    }
}

async fn try_fetch(n: &Node) -> anyhow::Result<Value> {
    let raw = match &n.ssh {
        Some(_) => {
            let cmd = n
                .status_cmd
                .clone()
                .unwrap_or_else(|| format!("rakhsh status --socket {} --json", n.socket));
            run_checked(n, &cmd, Duration::from_secs(10)).await?
        }
        None => {
            let mut c = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::UnixStream::connect(&n.socket),
            )
            .await??;
            c.write_all(b"status\n").await?;
            c.shutdown().await.ok();
            let mut buf = Vec::new();
            c.read_to_end(&mut buf).await?;
            buf
        }
    };
    Ok(serde_json::from_slice(&raw)?)
}

fn offline(name: &str) -> Value {
    json!({
        "name": name, "offline": true, "role": "—", "host": "—", "version": "—", "pid": "—",
        "carrier": "—", "encryption": "—", "resume": false,
        "uptime_secs": 0, "target_lanes": 0, "lanes_up": 0, "lanes_established": 0, "reconnects": 0, "streams": 0,
        "rx_bps": 0, "tx_bps": 0, "peak_rx_bps": 0, "peak_tx_bps": 0, "rx_total": 0, "tx_total": 0,
        "cpu_pct": 0, "rss_mb": 0, "sys_cpu_pct": 0, "sys_mem_pct": 0, "load": [0, 0, 0],
        "resume_stats": null, "quotas": [], "links": []
    })
}

pub async fn fetch_logs(n: &Node, lines: usize) -> anyhow::Result<Vec<Value>> {
    let unit = n.unit.clone().unwrap_or_else(|| "rakhsh".into());
    let cmd = format!("journalctl -u {unit} -n {lines} --no-pager -o short-iso 2>&1 || true");
    let out = run(n, &cmd, Duration::from_secs(12)).await?;
    Ok(String::from_utf8_lossy(&out)
        .lines()
        .filter_map(parse_log)
        .collect())
}

pub async fn run_action(n: &Node, action: &str) -> anyhow::Result<()> {
    if !matches!(action, "restart" | "stop" | "start") {
        anyhow::bail!("unsupported action");
    }
    let unit = n.unit.clone().unwrap_or_else(|| "rakhsh".into());
    let out = run_checked(
        n,
        &format!("systemctl {action} {unit}"),
        Duration::from_secs(20),
    )
    .await?;
    let _ = out;
    Ok(())
}

async fn run(n: &Node, cmd: &str, t: Duration) -> anyhow::Result<Vec<u8>> {
    let out = spawn(n, cmd, t).await?;
    Ok(out.stdout)
}

async fn run_checked(n: &Node, cmd: &str, t: Duration) -> anyhow::Result<Vec<u8>> {
    let out = spawn(n, cmd, t).await?;
    if !out.status.success() {
        anyhow::bail!(
            "{}",
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .lines()
                .next()
                .unwrap_or("command failed")
        );
    }
    Ok(out.stdout)
}

async fn spawn(n: &Node, cmd: &str, t: Duration) -> anyhow::Result<std::process::Output> {
    let fut = match &n.ssh {
        Some(ssh) => {
            let mut c = Command::new("ssh");
            c.args([
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=8",
                "-o",
                "StrictHostKeyChecking=accept-new",
            ]);
            if let Some(key) = &n.ssh_key {
                c.args(["-i", key]);
            }
            c.args([ssh, cmd]);
            c.output()
        }
        None => Command::new("sh").args(["-c", cmd]).output(),
    };
    Ok(timeout(t, fut).await??)
}

fn strip_ansi(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            while let Some(&n) = it.peek() {
                it.next();
                if n == 'm' {
                    break;
                }
            }
        } else {
            o.push(c);
        }
    }
    o
}

fn parse_log(line: &str) -> Option<Value> {
    let clean = strip_ansi(line);
    let clean = clean.trim_end();
    if clean.is_empty() {
        return None;
    }
    let level = if clean.contains("ERROR") {
        "err"
    } else if clean.contains("WARN") {
        "warn"
    } else {
        "info"
    };
    let ts = if clean.len() >= 19 && clean.as_bytes().get(10) == Some(&b'T') {
        clean[11..19].to_string()
    } else {
        String::new()
    };
    let mut rest = clean
        .split_once("]: ")
        .map(|x| x.1)
        .unwrap_or(clean)
        .trim_start();
    if let Some((first, tail)) = rest.split_once(char::is_whitespace) {
        if first.len() >= 19 && first.contains('T') {
            rest = tail.trim_start();
        }
    }
    for lv in ["INFO ", "WARN ", "ERROR ", "DEBUG ", "TRACE "] {
        if let Some(r) = rest.strip_prefix(lv) {
            rest = r;
            break;
        }
    }
    Some(json!({"ts": ts, "level": level, "msg": rest}))
}

pub async fn node_speedtest(n: &Node) -> anyhow::Result<(Option<f64>, Option<f64>)> {
    let cmd = format!("rakhsh speedtest --socket {} --json", n.socket);
    let out = run(n, &cmd, Duration::from_secs(30)).await?;
    let v: Value =
        serde_json::from_slice(&out).map_err(|_| anyhow::anyhow!("bad speedtest output"))?;
    Ok((
        v.get("down_mbit").and_then(Value::as_f64),
        v.get("up_mbit").and_then(Value::as_f64),
    ))
}

pub async fn fetch_config(n: &Node) -> anyhow::Result<String> {
    let path = n
        .config_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("no config_path set"))?;
    let out = run_checked(n, &format!("cat {path}"), Duration::from_secs(10)).await?;
    Ok(String::from_utf8_lossy(&out).to_string())
}
