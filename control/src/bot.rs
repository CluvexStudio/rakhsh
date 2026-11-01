use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use teloxide::payloads::EditMessageTextSetters;
use teloxide::prelude::*;
use teloxide::types::{InlineKeyboardButton, InlineKeyboardMarkup, MessageId, ParseMode};

use crate::{fetch, Shared, Telegram};

const SPIN: [&str; 4] = ["◐", "◓", "◑", "◒"];
const LIVE_TICKS: u64 = 20;
const LIVE_EVERY: Duration = Duration::from_secs(3);

pub fn spawn(cfg: &crate::Config, state: Shared) {
    let Some(tg) = cfg.telegram.clone() else {
        return;
    };
    if tg.token.is_empty() {
        return;
    }
    let bot = Bot::new(tg.token.clone());
    tracing::info!("telegram bot on (alerts → chat {})", tg.chat);

    tokio::spawn(alerts(bot.clone(), state.clone(), tg));

    let live = Arc::new(AtomicU64::new(0));
    tokio::spawn(async move {
        let handler = dptree::entry()
            .branch(Update::filter_message().endpoint(on_message))
            .branch(Update::filter_callback_query().endpoint(on_callback));
        Dispatcher::builder(bot, handler)
            .dependencies(dptree::deps![state, live])
            .enable_ctrlc_handler()
            .build()
            .dispatch()
            .await;
    });
}

fn allowed(state: &Shared, chat_id: i64) -> bool {
    state.cfg.telegram.as_ref().map(|t| t.chat) == Some(chat_id)
}

async fn on_message(
    bot: Bot,
    msg: Message,
    state: Shared,
    live: Arc<AtomicU64>,
) -> ResponseResult<()> {
    if !allowed(&state, msg.chat.id.0) {
        return Ok(());
    }
    let text = msg.text().unwrap_or("").trim();
    let cmd = text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_start_matches('/')
        .to_lowercase();
    let cmd = cmd.split('@').next().unwrap_or("");

    let gen = live.fetch_add(1, Ordering::SeqCst) + 1;

    match cmd {
        "status" => {
            let (t, kb) = status_view(&state, 0, true);
            let sent = bot
                .send_message(msg.chat.id, t)
                .parse_mode(ParseMode::Html)
                .reply_markup(kb)
                .await?;
            spawn_live(
                bot,
                msg.chat.id,
                sent.id,
                state,
                live,
                gen,
                LiveMode::Status,
            );
        }
        "nodes" => {
            let (t, kb) = nodes_view(&state);
            bot.send_message(msg.chat.id, t)
                .parse_mode(ParseMode::Html)
                .reply_markup(kb)
                .await?;
        }
        "help" => {
            let (t, kb) = help_view();
            bot.send_message(msg.chat.id, t)
                .parse_mode(ParseMode::Html)
                .reply_markup(kb)
                .await?;
        }
        _ => {
            let (t, kb) = home_view(&state);
            bot.send_message(msg.chat.id, t)
                .parse_mode(ParseMode::Html)
                .reply_markup(kb)
                .await?;
        }
    }
    Ok(())
}

async fn on_callback(
    bot: Bot,
    q: CallbackQuery,
    state: Shared,
    live: Arc<AtomicU64>,
) -> ResponseResult<()> {
    bot.answer_callback_query(q.id.clone()).await.ok();
    let Some(msg) = q.regular_message() else {
        return Ok(());
    };
    let chat = msg.chat.id;
    let mid = msg.id;
    if !allowed(&state, chat.0) {
        return Ok(());
    }
    let data = q.data.clone().unwrap_or_default();
    let gen = live.fetch_add(1, Ordering::SeqCst) + 1;

    let (verb, arg) = match data.split_once(':') {
        Some((v, a)) => (v, a),
        None => (data.as_str(), ""),
    };

    match verb {
        "home" => {
            let (t, kb) = home_view(&state);
            edit(&bot, chat, mid, t, kb).await;
        }
        "help" => {
            let (t, kb) = help_view();
            edit(&bot, chat, mid, t, kb).await;
        }
        "status" => {
            let (t, kb) = status_view(&state, 0, true);
            edit(&bot, chat, mid, t, kb).await;
            spawn_live(bot, chat, mid, state, live, gen, LiveMode::Status);
        }
        "status_off" => {
            let (t, kb) = status_view(&state, 0, false);
            edit(&bot, chat, mid, t, kb).await;
        }
        "nodes" => {
            let (t, kb) = nodes_view(&state);
            edit(&bot, chat, mid, t, kb).await;
        }
        "node" => {
            let (t, kb) = node_view(&state, arg);
            edit(&bot, chat, mid, t, kb).await;
        }
        "speed" => {
            edit(
                &bot,
                chat,
                mid,
                "⏳ <b>in-tunnel speed test…</b>\n<i>flooding the tunnel both ways (~8s)</i>"
                    .into(),
                back_only_kb(),
            )
            .await;
            let t = speed_text(&state).await;
            edit(&bot, chat, mid, t, speed_kb()).await;
        }
        "logs" => {
            let (t, kb) = logs_view(&state, arg, 0, true).await;
            edit(&bot, chat, mid, t, kb).await;
            spawn_live(
                bot,
                chat,
                mid,
                state,
                live,
                gen,
                LiveMode::Logs(arg.to_string()),
            );
        }
        "logs_off" => {
            let (t, kb) = logs_view(&state, arg, 0, false).await;
            edit(&bot, chat, mid, t, kb).await;
        }
        "ask" => {
            let name = arg.strip_prefix("restart:").unwrap_or(arg);
            let kb = InlineKeyboardMarkup::new(vec![vec![
                btn("✅ Yes, restart", &format!("do:restart:{name}")),
                btn("✖ Cancel", &format!("node:{name}")),
            ]]);
            edit(
                &bot,
                chat,
                mid,
                format!(
                    "⚠️ <b>Restart {}?</b>\nThe tunnel on this node drops for a few seconds.",
                    html_escape(name)
                ),
                kb,
            )
            .await;
        }
        "do" => {
            let name = arg.strip_prefix("restart:").unwrap_or(arg).to_string();
            edit(
                &bot,
                chat,
                mid,
                format!("↻ restarting <b>{}</b>…", html_escape(&name)),
                back_only_kb(),
            )
            .await;
            let t = match state.cfg.node.iter().find(|n| n.name == name).cloned() {
                Some(node) => match fetch::run_action(&node, "restart").await {
                    Ok(_) => format!("✅ restart sent to <b>{}</b>.", html_escape(&name)),
                    Err(e) => format!(
                        "❌ restart of <b>{}</b> failed: {}",
                        html_escape(&name),
                        html_escape(&e.to_string())
                    ),
                },
                None => format!("no node named <code>{}</code>", html_escape(&name)),
            };
            let kb = InlineKeyboardMarkup::new(vec![vec![
                btn("⬅ Node", &format!("node:{name}")),
                btn("🏠 Home", "home"),
            ]]);
            edit(&bot, chat, mid, t, kb).await;
        }
        _ => {
            let (t, kb) = home_view(&state);
            edit(&bot, chat, mid, t, kb).await;
        }
    }
    Ok(())
}

async fn edit(bot: &Bot, chat: ChatId, mid: MessageId, text: String, kb: InlineKeyboardMarkup) {
    let _ = bot
        .edit_message_text(chat, mid, text)
        .parse_mode(ParseMode::Html)
        .reply_markup(kb)
        .await;
}

enum LiveMode {
    Status,
    Logs(String),
}

fn spawn_live(
    bot: Bot,
    chat: ChatId,
    mid: MessageId,
    state: Shared,
    live: Arc<AtomicU64>,
    gen: u64,
    mode: LiveMode,
) {
    tokio::spawn(async move {
        for tick in 1..=LIVE_TICKS {
            tokio::time::sleep(LIVE_EVERY).await;
            if live.load(Ordering::SeqCst) != gen {
                return;
            }
            let (t, kb) = match &mode {
                LiveMode::Status => status_view(&state, tick, true),
                LiveMode::Logs(name) => logs_view(&state, name, tick, true).await,
            };
            edit(&bot, chat, mid, t, kb).await;
        }
        if live.load(Ordering::SeqCst) == gen {
            let (t, kb) = match &mode {
                LiveMode::Status => status_view(&state, 0, false),
                LiveMode::Logs(name) => logs_view(&state, name, 0, false).await,
            };
            edit(&bot, chat, mid, t, kb).await;
        }
    });
}

fn btn(text: &str, data: &str) -> InlineKeyboardButton {
    InlineKeyboardButton::callback(text.to_string(), data.to_string())
}

fn home_view(state: &Shared) -> (String, InlineKeyboardMarkup) {
    let nodes = snap(state);
    let up = nodes
        .iter()
        .filter(|n| n["offline"].as_bool() != Some(true))
        .count();
    let text = format!(
        "🛰 <b>rakhsh Control Center</b>\n<i>fleet console</i>\n\n<b>{up}/{}</b> node(s) online\nPick a section:",
        nodes.len()
    );
    let kb = InlineKeyboardMarkup::new(vec![
        vec![btn("📊 Status", "status")],
        vec![btn("🖧 Nodes", "nodes"), btn("⚡ Speed test", "speed:")],
        vec![btn("🔄 Refresh", "home"), btn("❔ Help", "help")],
    ]);
    (text, kb)
}

fn help_view() -> (String, InlineKeyboardMarkup) {
    let text = "<b>rakhsh Control Center</b>\n\nTap the buttons to get around, or use:\n\
        • /status — live fleet status\n• /nodes — the node list\n• /start — the home menu\n\n\
        From a node you can run an in-tunnel <b>speed test</b> (↓ and ↑), watch <b>live logs</b>, and <b>restart</b> it."
        .to_string();
    let kb = InlineKeyboardMarkup::new(vec![vec![btn("🏠 Home", "home")]]);
    (text, kb)
}

fn status_view(state: &Shared, tick: u64, live: bool) -> (String, InlineKeyboardMarkup) {
    let head = if live {
        format!(
            "📊 <b>Fleet status</b>  {} <i>live</i>",
            SPIN[(tick % 4) as usize]
        )
    } else {
        "📊 <b>Fleet status</b>".to_string()
    };
    let text = format!(
        "{head}\n{}\n\n<i>updated {} UTC</i>",
        fleet_summary(state),
        clock()
    );
    let toggle = if live {
        btn("⏸ Stop live", "status_off")
    } else {
        btn("▶ Live", "status")
    };
    let kb = InlineKeyboardMarkup::new(vec![
        vec![btn("🔄 Refresh", "status"), toggle],
        vec![btn("🖧 Nodes", "nodes"), btn("🏠 Home", "home")],
    ]);
    (text, kb)
}

fn nodes_view(state: &Shared) -> (String, InlineKeyboardMarkup) {
    let nodes = snap(state);
    let tg = state.cfg.telegram.as_ref();
    let mut rows: Vec<Vec<InlineKeyboardButton>> = vec![];
    for n in &nodes {
        let name = n["name"].as_str().unwrap_or("?");
        let role = n["role"].as_str().unwrap_or("?");
        rows.push(vec![btn(
            &format!("{} {name} · {role}", dot(n, tg)),
            &format!("node:{name}"),
        )]);
    }
    rows.push(vec![btn("📊 Status", "status"), btn("🏠 Home", "home")]);
    (
        "🖧 <b>Nodes</b>\n<i>pick one for detail, speed test & logs</i>".to_string(),
        InlineKeyboardMarkup::new(rows),
    )
}

fn node_view(state: &Shared, name: &str) -> (String, InlineKeyboardMarkup) {
    let text = node_detail(state, name);
    let kb = InlineKeyboardMarkup::new(vec![
        vec![
            btn("⚡ Speed test", "speed:"),
            btn("📜 Logs", &format!("logs:{name}")),
        ],
        vec![btn("↻ Restart", &format!("ask:restart:{name}"))],
        vec![btn("🖧 Nodes", "nodes"), btn("🏠 Home", "home")],
    ]);
    (text, kb)
}

async fn logs_view(
    state: &Shared,
    name: &str,
    tick: u64,
    live: bool,
) -> (String, InlineKeyboardMarkup) {
    let head = if live {
        format!(
            "📜 <b>{} logs</b>  {} <i>live</i>",
            html_escape(name),
            SPIN[(tick % 4) as usize]
        )
    } else {
        format!("📜 <b>{} logs</b>", html_escape(name))
    };
    let body = match state.cfg.node.iter().find(|n| n.name == name).cloned() {
        Some(node) => match fetch::fetch_logs(&node, 60).await {
            Ok(lines) => {
                let tail: Vec<String> = lines
                    .iter()
                    .rev()
                    .take(14)
                    .rev()
                    .map(|l| {
                        format!(
                            "{} {} {}",
                            l["ts"].as_str().unwrap_or(""),
                            l["level"].as_str().unwrap_or("").to_uppercase(),
                            l["msg"].as_str().unwrap_or("")
                        )
                    })
                    .collect();
                if tail.is_empty() {
                    "no recent log lines".to_string()
                } else {
                    format!("<pre>{}</pre>", html_escape(&tail.join("\n")))
                }
            }
            Err(e) => format!("could not read logs: {}", html_escape(&e.to_string())),
        },
        None => format!("no node named <code>{}</code>", html_escape(name)),
    };
    let toggle = if live {
        btn("⏸ Stop live", &format!("logs_off:{name}"))
    } else {
        btn("▶ Live", &format!("logs:{name}"))
    };
    let kb = InlineKeyboardMarkup::new(vec![
        vec![btn("🔄 Refresh", &format!("logs:{name}")), toggle],
        vec![
            btn("⬅ Node", &format!("node:{name}")),
            btn("🏠 Home", "home"),
        ],
    ]);
    (
        format!("{head}\n{body}\n\n<i>updated {} UTC</i>", clock()),
        kb,
    )
}

fn speed_kb() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new(vec![vec![
        btn("🔁 Again", "speed:"),
        btn("🖧 Nodes", "nodes"),
        btn("🏠 Home", "home"),
    ]])
}
fn back_only_kb() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new(vec![vec![btn("🏠 Home", "home")]])
}

async fn speed_text(state: &Shared) -> String {
    let Some(node) = pick_entry(state) else {
        return "⚡ <b>Speed test</b>\nno online entry node to drive the test.".into();
    };
    match fetch::node_speedtest(&node).await {
        Ok((None, None)) => {
            "⚡ <b>Speed test</b>\nunavailable — needs an entry node with a live lane.".into()
        }
        Ok((down, up)) => format!(
            "⚡ <b>in-tunnel speed test</b>\n↓ <b>{}</b> · ↑ <b>{}</b> Mbit/s\n<i>via {}</i>",
            down.map(|m| format!("{m:.0}"))
                .unwrap_or_else(|| "—".into()),
            up.map(|m| format!("{m:.0}")).unwrap_or_else(|| "—".into()),
            html_escape(&node.name),
        ),
        Err(e) => format!(
            "⚡ <b>Speed test</b>\nfailed: {}",
            html_escape(&e.to_string())
        ),
    }
}

fn pick_entry(state: &Shared) -> Option<crate::Node> {
    let nodes = snap(state);
    let name = nodes
        .iter()
        .find(|n| n["role"].as_str() == Some("entry") && n["offline"].as_bool() != Some(true))
        .and_then(|n| n["name"].as_str().map(str::to_string))?;
    state.cfg.node.iter().find(|n| n.name == name).cloned()
}

fn clock() -> String {
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

fn snap(state: &Shared) -> Vec<Value> {
    state.latest.read().unwrap().clone()
}
fn find(nodes: &[Value], name: &str) -> Option<Value> {
    nodes
        .iter()
        .find(|n| n["name"].as_str() == Some(name))
        .cloned()
}
fn mbit(bps: f64) -> String {
    if bps >= 1e9 {
        format!("{:.2} Gb/s", bps / 1e9)
    } else {
        format!("{:.0} Mb/s", bps / 1e6)
    }
}
fn f(n: &Value, k: &str) -> f64 {
    n[k].as_f64().unwrap_or(0.0)
}
fn worst_loss(n: &Value) -> f64 {
    n["links"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|l| l["loss_pct"].as_f64())
                .fold(0.0, f64::max)
        })
        .unwrap_or(0.0)
}
fn dot(n: &Value, tg: Option<&Telegram>) -> &'static str {
    if n["offline"].as_bool() == Some(true) {
        return "🔴";
    }
    let (l, c) = (
        tg.map(|t| t.loss_pct).unwrap_or(5.0),
        tg.map(|t| t.cpu_pct).unwrap_or(92.0),
    );
    if worst_loss(n) >= l || f(n, "sys_cpu_pct") >= c {
        "🟠"
    } else {
        "🟢"
    }
}

fn fleet_summary(state: &Shared) -> String {
    let nodes = snap(state);
    if nodes.is_empty() {
        return "No nodes configured.".into();
    }
    let tg = state.cfg.telegram.as_ref();
    let mut s = String::new();
    for n in &nodes {
        let name = n["name"].as_str().unwrap_or("?");
        if n["offline"].as_bool() == Some(true) {
            s += &format!("\n{} <b>{name}</b> — offline", dot(n, tg));
            continue;
        }
        s += &format!(
            "\n{} <b>{name}</b> ({}) · ↓{} ↑{} · {} lanes · {} streams",
            dot(n, tg),
            n["role"].as_str().unwrap_or("?"),
            mbit(f(n, "rx_bps")),
            mbit(f(n, "tx_bps")),
            n["lanes_up"].as_u64().unwrap_or(0),
            n["streams"].as_u64().unwrap_or(0),
        );
    }
    s
}

fn node_detail(state: &Shared, name: &str) -> String {
    let nodes = snap(state);
    let Some(n) = find(&nodes, name) else {
        return format!("no node named <code>{}</code>", html_escape(name));
    };
    if n["offline"].as_bool() == Some(true) {
        return format!("🔴 <b>{}</b> is offline.", html_escape(name));
    }
    let uptime = f(&n, "uptime_secs") as u64;
    format!(
        "🟢 <b>{name}</b> ({role}) @ <code>{host}</code>\n\
         ↓ <b>{rx}</b> (peak {prx})\n↑ <b>{tx}</b> (peak {ptx})\n\
         lanes {lu}/{lt} · {rc} reconnects · {st} streams\n\
         CPU {cpu:.0}% · mem {mem:.0}% · load {load:.2}\n\
         carrier {carrier}, {enc}{resume} · up {up}",
        name = html_escape(name),
        role = n["role"].as_str().unwrap_or("?"),
        host = html_escape(n["host"].as_str().unwrap_or("?")),
        rx = mbit(f(&n, "rx_bps")),
        prx = mbit(f(&n, "peak_rx_bps")),
        tx = mbit(f(&n, "tx_bps")),
        ptx = mbit(f(&n, "peak_tx_bps")),
        lu = n["lanes_up"].as_u64().unwrap_or(0),
        lt = n["target_lanes"].as_u64().unwrap_or(0),
        rc = n["reconnects"].as_u64().unwrap_or(0),
        st = n["streams"].as_u64().unwrap_or(0),
        cpu = f(&n, "sys_cpu_pct"),
        mem = f(&n, "sys_mem_pct"),
        load = n["load"][0].as_f64().unwrap_or(0.0),
        carrier = n["carrier"].as_str().unwrap_or("?"),
        enc = n["encryption"].as_str().unwrap_or("?"),
        resume = if n["resume"].as_bool() == Some(true) {
            ", resume"
        } else {
            ""
        },
        up = dur(uptime),
    )
}

fn dur(s: u64) -> String {
    let (d, h, m) = (s / 86400, s / 3600 % 24, s / 60 % 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else {
        format!("{h}h {m}m")
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub const CONFIRM_ROUNDS: u8 = 2;

#[derive(Default)]
pub struct Confirm {
    announced: HashMap<String, &'static str>,
    pending: HashMap<String, (&'static str, u8)>,
}

impl Confirm {
    pub fn observe(&mut self, name: &str, bucket: &'static str) -> bool {
        let announced = self.announced.get(name).copied().unwrap_or("ok");
        if bucket == announced {
            self.pending.remove(name);
            return false;
        }
        let seen = match self.pending.get(name) {
            Some((pending, rounds)) if *pending == bucket => rounds + 1,
            _ => 1,
        };
        if seen < CONFIRM_ROUNDS {
            self.pending.insert(name.to_string(), (bucket, seen));
            return false;
        }
        self.pending.remove(name);
        self.announced.insert(name.to_string(), bucket);
        true
    }
}

async fn alerts(bot: Bot, state: Shared, tg: Telegram) {
    let mut confirm = Confirm::default();
    tokio::time::sleep(Duration::from_secs(8)).await;
    let alert_kb = InlineKeyboardMarkup::new(vec![vec![
        btn("📊 Status", "status"),
        btn("🖧 Nodes", "nodes"),
    ]]);
    loop {
        let nodes = snap(&state);
        for n in &nodes {
            let name = n["name"].as_str().unwrap_or("?").to_string();
            let (bucket, msg) = assess(n, &tg);
            if confirm.observe(&name, bucket) {
                let _ = bot
                    .send_message(ChatId(tg.chat), msg)
                    .parse_mode(ParseMode::Html)
                    .reply_markup(alert_kb.clone())
                    .await;
            }
        }
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
}

#[cfg(test)]
#[path = "../tests/unit/confirm.rs"]
mod confirm_tests;

fn assess(n: &Value, tg: &Telegram) -> (&'static str, String) {
    let name = n["name"].as_str().unwrap_or("?");
    if n["offline"].as_bool() == Some(true) {
        return (
            "down",
            format!("🔴 <b>{name}</b> is OFFLINE — the control center cannot reach it."),
        );
    }
    let quota = n["quotas"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|q| q["pct"].as_f64())
                .fold(0.0, f64::max)
        })
        .unwrap_or(0.0);
    if quota >= tg.quota_pct {
        return (
            "quota",
            format!("🟠 <b>{name}</b> quota at {quota:.0}% — new connections may be refused."),
        );
    }
    let loss = worst_loss(n);
    if loss >= tg.loss_pct {
        return (
            "loss",
            format!("🟠 <b>{name}</b> packet loss {loss:.1}% on a lane."),
        );
    }
    let cpu = f(n, "sys_cpu_pct");
    if cpu >= tg.cpu_pct {
        return (
            "cpu",
            format!("🟠 <b>{name}</b> CPU {cpu:.0}% — the node is saturated."),
        );
    }
    ("ok", format!("🟢 <b>{name}</b> recovered — healthy again."))
}
