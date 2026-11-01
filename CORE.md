# rakhsh core

rakhsh started as a tunnel between two servers. It is now a small **network
core**: the tunnel is one building block, and the same binary can also be a
proxy, a router, or both at once. Nothing about the tunnel changed — it is just
one *outbound* among several, and the core is off unless a config asks for it.

```
   inbounds                    router                      outbounds
 ┌───────────────┐       ┌──────────────────┐        ┌─────────────────────┐
 │ socks5        │       │ domain / suffix  │        │ direct   this host  │
 │ http (CONNECT)│ ────► │ keyword / CIDR   │ ─────► │ tunnel   rakhsh     │
 │ mixed (auto)  │       │ port / inbound   │        │          lanes→peer │
 │ forward  tun  │       │ rule files (geo) │        │ block               │
 └───────────────┘       └──────────────────┘        │ socks    chain      │
                                                     └─────────────────────┘
```

* **Inbound** – where traffic enters: `socks` (SOCKS5 + auth), `http`
  (CONNECT and plain), `mixed` (both on one port, auto-detected), plus the
  existing `[[forward]]` ports and L3 TUN.
* **Router** – picks an outbound per connection. Rules are tried in order, the
  first match wins, else `final`. Destination matchers (`domain`,
  `domain_suffix`, `domain_keyword`, `ip_cidr`, `rule_file`) are OR'd inside a
  rule; `port` and `inbound` are extra constraints.
* **Outbound** – where it goes: `direct` (dial from this host), `tunnel`
  (the rakhsh lanes to the peer, entry role), `block`, `socks` (chain).

## Roles

| role  | what it is |
|-------|------------|
| entry | holds the tunnel lanes; may also run proxy inbounds with `direct`/`tunnel`/`block`/`socks` outbounds |
| exit  | answers the entry's streams; may also run proxy inbounds (`direct`/`block`/`socks`) |
| node  | standalone core, no tunnel peer — a plain proxy/router (`direct`/`block`/`socks`) |

## The headline use: Iranian split routing

Run a proxy on the Iran entry. Iranian destinations go **direct** from the
Iran server (fast, no border crossing); everything else rides the **tunnel** to
the foreign exit. The destination list comes from the RIPE NCC registry:

```
rakhsh rules iran                      # writes /etc/rakhsh/iran.txt (≈2000 IPv4 + 575 IPv6 blocks + .ir)
rakhsh init --tunnel-addr IP:7000 --carrier wss \
            --proxy 0.0.0.0:1080 --split-iran      # login is generated for non-loopback
rakhsh check -c entry.toml             # validate without starting
```

A domain is matched by name first; only if a CIDR rule needs it is it resolved
locally and compared against the list (`resolve = false` disables that, so no
DNS ever leaks). Foreign domains are sent through the tunnel **by name**, so
they are resolved abroad.

## Config

```toml
[[inbound]]
tag = "proxy"
type = "mixed"                 # socks | http | mixed
listen = "127.0.0.1:1080"      # non-loopback without a login logs a warning
# username = "u"  password = "p"

[[outbound]]  tag = "tunnel"  type = "tunnel"
[[outbound]]  tag = "direct"  type = "direct"
[[outbound]]  tag = "block"   type = "block"
# [[outbound]] tag = "up" type = "socks" server = "10.0.0.2:1080" username = ".." password = ".."

[route]
final = "tunnel"
# resolve = false
[[route.rule]]
outbound = "direct"
domain_suffix = [".ir"]
rule_file = "/etc/rakhsh/iran.txt"       # lines: domain:x  suffix:x  keyword:x  cidr:a.b.c.d/n  (bare = auto)
[[route.rule]]
outbound = "block"
port = ["25", "6881-6889"]
```

Old configs (no `[[inbound]]`) behave exactly as before.

## UDP through the proxy (SOCKS5 UDP ASSOCIATE)

The socks (and `mixed`) inbound answers UDP ASSOCIATE (RFC 1928). The router sees
each datagram's destination like a TCP connect: `tunnel` opens one UDP flow per
destination to the exit (domain destinations are resolved *there*, so DNS does not
leak), `direct` uses a local UDP socket, `block` drops. The relay port is bound on
the interface the client reached, accepts datagrams only from the client's own IP,
and lives exactly as long as the TCP control connection (idle > ~10 min also ends it).
Verified on the real Iran ⇄ Hetzner link: DNS to 1.1.1.1 by address and by name,
datagrams up to 8000 bytes byte-exact, 8 parallel associations, foreign-source
datagrams ignored. `socks` (chained) outbounds do not carry UDP.

## What it does *not* do yet (honest list)

* DNS: the built-in resolver is `DNS.md`; no fake-IP, DoH or DoT yet.
* Outbound **groups** (selector, latency-test, failover) — `backup_connect`
  covers tunnel-address failover only.
* Transparent proxy (Linux TPROXY/redirect) inbound.
* A control API / panel.

## Where it can go

The pieces compose, so the next steps are additive:

1. **DNS** – a DoH/DoT resolver and rule-driven DNS (resolve Iranian names
   locally, foreign ones abroad); UDP itself is done (above).
2. **Outbound groups** – `urltest` (pick the lowest-latency exit), `selector`, failover between
   outbounds. (Failover between *carriers* of the tunnel itself is done: `LINKS.md`.)
3. **Multi-hop & mesh** – chain `entry → relay → exit`; with node identities
   (already Noise keys) a mesh where each node routes to the best peer.
4. **Transparent mode** – TPROXY/redirect inbound so whole machines or a LAN
   use the core with no per-app proxy settings.
5. **Control plane** – JSON API + live stats (the `check`/`status` seeds are
   there), the base for a panel, subscriptions and share links.
