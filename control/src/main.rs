use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::Query;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{info, warn};

mod bot;
mod fetch;

const PANEL: &str = include_str!("../assets/panel.html");
const MANIFEST: &str = r##"{"name":"rakhsh Control Center","short_name":"rakhsh","start_url":"/","display":"standalone","background_color":"#0d0f14","theme_color":"#0d0f14","icons":[]}"##;
const SAMPLE: &str = include_str!("../control.sample.toml");

#[derive(Parser)]
#[command(
    name = "rakhsh-control",
    version,
    about = "rakhsh Control Center (web panel over a fleet)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Serve {
        #[arg(short, long, default_value = "control.toml")]
        config: String,
    },
    Init {
        #[arg(short, long, default_value = "control.toml")]
        config: String,
    },
}

#[derive(Deserialize, Clone)]
struct Config {
    #[serde(default = "d_listen")]
    listen: String,
    #[serde(default)]
    password: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    refresh: Option<u64>,
    #[serde(default)]
    node: Vec<Node>,
    telegram: Option<Telegram>,
}

#[derive(Deserialize, Clone)]
pub struct Telegram {
    pub token: String,
    pub chat: i64,
    #[serde(default = "d_loss")]
    pub loss_pct: f64,
    #[serde(default = "d_cpu")]
    pub cpu_pct: f64,
    #[serde(default = "d_quota")]
    pub quota_pct: f64,
}
fn d_loss() -> f64 {
    5.0
}
fn d_cpu() -> f64 {
    92.0
}
fn d_quota() -> f64 {
    95.0
}

fn d_listen() -> String {
    "0.0.0.0:8443".into()
}

#[derive(Deserialize, Clone)]
pub struct Node {
    pub name: String,
    pub ssh: Option<String>,
    #[serde(default = "d_sock")]
    pub socket: String,
    pub status_cmd: Option<String>,
    pub unit: Option<String>,
    pub config_path: Option<String>,
    pub restart_at: Option<String>,
    pub ssh_key: Option<String>,
}

fn d_sock() -> String {
    "/run/rakhsh.sock".into()
}

struct AppState {
    cfg: Config,
    tokens: Mutex<HashSet<String>>,
    latest: RwLock<Vec<Value>>,
}
type Shared = Arc<AppState>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Init { config } => {
            if std::path::Path::new(&config).exists() {
                anyhow::bail!("{config} already exists");
            }
            std::fs::write(&config, SAMPLE).with_context(|| format!("writing {config}"))?;
            println!("wrote {config} — edit it, then: rakhsh-control serve -c {config}");
            Ok(())
        }
        Cmd::Serve { config } => serve(&config).await,
    }
}

async fn serve(path: &str) -> Result<()> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let cfg: Config = toml::from_str(&text).with_context(|| format!("parsing {path}"))?;
    if cfg.node.is_empty() {
        warn!("no [[node]] in {path}: the panel will be empty");
    }
    if cfg.password.is_empty() {
        warn!(
            "no password set: the panel is open to anyone who can reach {}",
            cfg.listen
        );
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let tls = load_tls(&cfg).await?;
    let addr: SocketAddr = cfg
        .listen
        .parse()
        .with_context(|| format!("listen address {:?}", cfg.listen))?;
    let refresh = cfg.refresh.unwrap_or(2).max(1);

    let state: Shared = Arc::new(AppState {
        cfg,
        tokens: Mutex::new(HashSet::new()),
        latest: RwLock::new(Vec::new()),
    });
    let n_nodes = state.cfg.node.len();

    tokio::spawn(refresh_loop(state.clone(), refresh));
    bot::spawn(&state.cfg, state.clone());
    if state.cfg.node.iter().any(|n| n.restart_at.is_some()) {
        tokio::spawn(scheduler(state.clone()));
    }

    let app = Router::new()
        .route("/", get(panel))
        .route("/manifest.webmanifest", get(manifest))
        .route("/api/login", post(login))
        .route("/api/status", get(status))
        .route("/api/logs", get(logs))
        .route("/api/action", post(action))
        .route("/api/speedtest", post(speedtest))
        .route("/api/backup", get(backup))
        .with_state(state);

    info!("control center on https://{addr} ({n_nodes} node(s), refresh {refresh}s)");
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn refresh_loop(state: Shared, every: u64) {
    loop {
        let nodes = state.cfg.node.clone();
        let results =
            futures_util::future::join_all(nodes.into_iter().map(fetch::fetch_node)).await;
        let up = results
            .iter()
            .filter(|v| v.get("offline").and_then(Value::as_bool) == Some(false))
            .count();
        tracing::debug!("fleet refreshed: {up}/{} node(s) up", results.len());
        *state.latest.write().unwrap() = results;
        tokio::time::sleep(Duration::from_secs(every)).await;
    }
}

async fn load_tls(cfg: &Config) -> Result<RustlsConfig> {
    if let (Some(c), Some(k)) = (&cfg.tls_cert, &cfg.tls_key) {
        return RustlsConfig::from_pem_file(c, k)
            .await
            .with_context(|| "loading tls_cert / tls_key");
    }
    let host = cfg
        .listen
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or("localhost");
    let san = if host.is_empty() || host == "0.0.0.0" {
        "localhost".to_string()
    } else {
        host.to_string()
    };
    let ck = rcgen::generate_simple_self_signed(vec![san, "localhost".into()])
        .context("self-signed cert")?;
    let cert = ck.cert.pem().into_bytes();
    let key = ck.signing_key.serialize_pem().into_bytes();
    info!("using a self-signed certificate (set tls_cert / tls_key to use your own)");
    RustlsConfig::from_pem(cert, key)
        .await
        .context("building the self-signed TLS config")
}

async fn panel() -> Html<&'static str> {
    Html(PANEL)
}

async fn manifest() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/manifest+json")],
        MANIFEST,
    )
}

#[derive(Deserialize)]
struct LoginReq {
    password: String,
}

async fn login(
    State(s): State<Shared>,
    Json(r): Json<LoginReq>,
) -> Result<Json<Value>, StatusCode> {
    if s.cfg.password.is_empty() || r.password == s.cfg.password {
        let token = rand_hex();
        s.tokens.lock().unwrap().insert(token.clone());
        Ok(Json(json!({ "token": token })))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn status(State(s): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, StatusCode> {
    if !authed(&s, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(json!(*s.latest.read().unwrap())))
}

fn authed(s: &Shared, h: &HeaderMap) -> bool {
    if s.cfg.password.is_empty() {
        return true;
    }
    let token = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    token
        .map(|t| s.tokens.lock().unwrap().contains(t))
        .unwrap_or(false)
}

#[derive(Deserialize)]
struct LogQ {
    node: String,
}

async fn logs(
    State(s): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<LogQ>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !authed(&s, &headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    let node = s
        .cfg
        .node
        .iter()
        .find(|n| n.name == q.node)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "no such node".into()))?;
    match fetch::fetch_logs(&node, 160).await {
        Ok(lines) => Ok(Json(json!({ "lines": lines }))),
        Err(e) => Err((StatusCode::BAD_GATEWAY, format!("{e:#}"))),
    }
}

#[derive(Deserialize)]
struct ActionReq {
    node: String,
    action: String,
}

async fn action(
    State(s): State<Shared>,
    headers: HeaderMap,
    Json(r): Json<ActionReq>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !authed(&s, &headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    let node = s
        .cfg
        .node
        .iter()
        .find(|n| n.name == r.node)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "no such node".into()))?;
    tracing::info!("action: {} {}", r.action, node.name);
    match fetch::run_action(&node, &r.action).await {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(e) => Err((StatusCode::BAD_GATEWAY, format!("{e:#}"))),
    }
}

#[derive(Deserialize)]
struct NodeReq {
    node: String,
}

async fn speedtest(
    State(s): State<Shared>,
    headers: HeaderMap,
    Json(r): Json<NodeReq>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !authed(&s, &headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    let entry = s
        .latest
        .read()
        .unwrap()
        .iter()
        .find(|n| n["role"].as_str() == Some("entry") && n["offline"].as_bool() != Some(true))
        .and_then(|n| n["name"].as_str().map(str::to_string));
    let target = entry.unwrap_or_else(|| r.node.clone());
    let node = s
        .cfg
        .node
        .iter()
        .find(|n| n.name == target)
        .cloned()
        .ok_or((
            StatusCode::NOT_FOUND,
            "no entry node to run the test".into(),
        ))?;
    match fetch::node_speedtest(&node).await {
        Ok((down, up)) => Ok(Json(
            json!({ "down_mbit": down, "up_mbit": up, "via": node.name }),
        )),
        Err(e) => Err((StatusCode::BAD_GATEWAY, format!("{e:#}"))),
    }
}

async fn backup(
    State(s): State<Shared>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !authed(&s, &headers) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    let mut out = serde_json::Map::new();
    out.insert("taken_at".into(), json!(now_rfc3339().await));
    let mut nodes = serde_json::Map::new();
    for n in &s.cfg.node {
        let v = match fetch::fetch_config(n).await {
            Ok(c) => json!({ "config": c }),
            Err(e) => json!({ "error": format!("{e:#}") }),
        };
        nodes.insert(n.name.clone(), v);
    }
    out.insert("nodes".into(), Value::Object(nodes));
    let body = serde_json::to_vec_pretty(&Value::Object(out)).unwrap_or_default();
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"rakhsh-backup.json\"".to_string(),
            ),
        ],
        body,
    ))
}

async fn now_rfc3339() -> String {
    tokio::process::Command::new("date")
        .arg("-Is")
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

async fn scheduler(state: Shared) {
    use std::collections::HashMap;
    let mut fired: HashMap<String, String> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(25)).await;
        let now = tokio::process::Command::new("date")
            .arg("+%Y-%m-%d %H:%M")
            .output()
            .await
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        if now.len() < 16 {
            continue;
        }
        let (day, hm) = (now[..10].to_string(), now[11..16].to_string());
        for node in &state.cfg.node {
            if node.restart_at.as_deref() == Some(hm.as_str())
                && fired.get(&node.name) != Some(&day)
            {
                fired.insert(node.name.clone(), day.clone());
                info!("scheduled restart: {}", node.name);
                let n = node.clone();
                tokio::spawn(async move {
                    if let Err(e) = fetch::run_action(&n, "restart").await {
                        warn!("scheduled restart {}: {e:#}", n.name);
                    }
                });
            }
        }
    }
}

fn rand_hex() -> String {
    let mut b = [0u8; 16];
    use std::io::Read;
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(1);
        b[..16].copy_from_slice(&t.to_be_bytes());
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}
