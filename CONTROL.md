# Control Center: web panel, Telegram bot, fleet

`rakhsh-control` is a **separate binary** that watches and manages a fleet of `rakhsh` nodes from one place —
a web panel, a Telegram bot, live monitoring, in-tunnel speed tests, config backups and scheduled restarts. It is
deliberately kept out of the tunnel binary so the data path stays lean: the daemon gains only a tiny local Unix
socket; all the heavy web dependencies live only here.

```
            ┌──────────────── rakhsh-control (one host) ─────────────────┐
  browser → │  HTTPS panel  ·  Telegram bot  ·  alerts  ·  scheduler       │
            └───────┬───────────────────────────────┬─────────────────────┘
          local Unix socket                   SSH (status / logs / actions)
                    │                               │
              ┌─────▼─────┐                   ┌──────▼──────┐
              │  rakhsh   │                   │   rakhsh    │   … more nodes
              │  (local)  │                   │  (remote)   │
              └───────────┘                   └─────────────┘
```

## The daemon side

Every `rakhsh` daemon (entry/exit/node) serves a **local Unix control socket** — no new network port, so its
attack surface does not grow. Default `/run/rakhsh.sock`; override with `control_socket` in the config.

```
rakhsh status                 # a live table: lanes, rtt/jitter/loss, throughput, cpu/mem, resume, quota
rakhsh status --json          # the same as JSON (what the control center reads)
rakhsh speedtest              # measure download throughput through the live tunnel (entry only)
```

The control center reads a node either by its **local socket** (a node on the same host) or by running
`rakhsh status --json` / `rakhsh speedtest` **over SSH** (a remote node). Logs come from `journalctl`, and the
Restart/Stop/Start actions run `systemctl`, both over the same SSH — so the daemon itself exposes nothing but the
read-only local socket.

## Setup

```
rakhsh-control init -c control.toml     # writes a sample
rakhsh-control serve -c control.toml    # the panel on https://<listen>
```

```toml
listen = "0.0.0.0:8443"
password = "a-strong-password"      # panel login; empty = no auth (only behind a trusted network)
# tls_cert = "/etc/rakhsh/panel.crt" # your own PEM cert + key; omit for a self-signed pair
# tls_key  = "/etc/rakhsh/panel.key"
refresh = 2                          # seconds between fleet refreshes

[[node]]
name = "this-host"
socket = "/run/rakhsh.sock"          # a node on THIS host: just its socket

[[node]]
name = "asia-entry"
ssh = "root@203.0.113.9"             # a remote node: reached with rakhsh/journalctl/systemctl over SSH
ssh_key = "/etc/rakhsh/control_key"  # SSH identity (-i), if not your default key
socket = "/run/rakhsh.sock"
unit = "rakhsh"                      # systemd unit for Logs + Restart/Stop/Start
config_path = "/root/rakhsh.toml"    # for config backups
restart_at = "04:30"                 # optional: daily local time to auto-restart this node

[telegram]                           # optional
token = "123456:ABC-DEF..."          # from @BotFather
chat = 123456789                     # your chat id (from @userinfobot); the bot obeys only this chat
loss_pct = 5                         # alert thresholds
cpu_pct = 92
quota_pct = 95
```

## The panel

Six live sections (left nav), refreshed every `refresh` seconds:

- **Overview** — per-node KPIs (download/upload with sparklines, streams, lanes), a throughput chart with a
  hover tooltip, radial CPU/memory gauges, a lanes preview and node details. A **Speed test** button runs an
  in-tunnel measurement.
- **Lanes** — aggregate stats and the full lane table (carrier, up-time, RTT, jitter, loss, health), plus a
  per-lane round-trip-time bar chart.
- **Traffic** — the throughput chart, totals and peaks, and a **fleet comparison** (every node's current
  download/upload side by side) with quota bars.
- **Security** — the data-protection posture of each node (`full` = AES-256-GCM, or `none` = plaintext, flagged),
  resume state, and how rakhsh secures the wire.
- **Logs** — a live terminal view of each node's `journalctl`, colour-coded by level, auto-refreshing.
- **Settings** — the fleet with **Restart / Stop / Start** buttons per node (confirmed, then run over SSH),
  a **Backup configs** button (downloads every node's config), and control-center info.

The panel is one self-contained page with the fonts embedded, so it renders fully **offline** — important for a
tool used during an internet shutdown.

## Telegram bot

With `[telegram]` set, the bot answers (only in the configured chat):

- `/status` — a fleet summary
- `/nodes` — the node list
- `/node <name>` — full details for one node
- `/logs <name>` — recent warnings for a node
- `/speedtest <name>` — an in-tunnel speed test
- `/help`

And it sends **alerts** on its own when a node goes offline, a lane's loss or the system CPU crosses the
threshold, or a quota is nearly full — and once more when it recovers (debounced, not repeated).

## Backup & scheduled restart

- **Backup**: the panel's *Backup configs* button (and `GET /api/backup`) collects every node's config file (from
  its `config_path`, over SSH) into one JSON you download. Restore by putting the file back and restarting the
  service.
- **Scheduled restart**: a node with `restart_at = "HH:MM"` is restarted daily at that local time by the control
  center.

## Security of the control center itself

- The **daemon** exposes only a local Unix socket (read-only status + a speed-test trigger). No network port is
  added to the tunnel.
- The **control center** is the thing with power: the panel password gates the API, and the SSH keys it holds can
  manage the nodes. Put it on a trusted host, give it a strong password, use a real certificate if you can, and
  **firewall the panel port to your own address** — a fleet-control panel on an open port is a target.

## Build

The panel is a **React + Vite + Tailwind (shadcn-style) + Recharts** app in `control/panel-ui/`, bundled by
`vite-plugin-singlefile` into one self-contained `dist/index.html` (JS, CSS and fonts all inlined, so it renders
fully offline). That file is copied to `control/assets/panel.html` and embedded into the binary with `include_str!`.

```
cd control/panel-ui && npm install && npm run build      # → dist/index.html
cp control/panel-ui/dist/index.html control/assets/panel.html

cargo build -p rakhsh-control                                  # local
cargo zigbuild --release --target x86_64-unknown-linux-musl -p rakhsh-control   # static, for deployment
```
