# Links: several carriers, one tunnel

One carrier is one point of failure. The Iran filter has treated QUIC v2 as 0 Mbit/s in one hour and as
900 Mbit/s the next; a port gets blocked, a CDN edge dies. With **links** the two ends are configured with
several carriers at once and the tunnel moves between them by itself, no restart, no editing.

A *link* is a (carrier, address) pair. The top-level `carrier` with `tunnel_listen` / `tunnel_connect` is the
primary link, `backup_connect` adds more addresses on the same carrier, and every `[[link]]` adds another
carrier on its own address. Order is preference.

```toml
# entry (accepts lanes)                      # exit (dials lanes)
carrier = "wss"                              carrier = "wss"
tunnel_listen = "0.0.0.0:443"                tunnel_connect = "203.0.113.9:443"
ws_path = "/x7Kq2m"                          ws_path = "/x7Kq2m"
ws_credential = "…"                          ws_credential = "…"

[[link]]                                     [[link]]
carrier = "quicv2"                           carrier = "quicv2"
addr = "0.0.0.0:443"     # UDP: same port    addr = "203.0.113.9:443"
                         # number is fine
[[link]]                                     [[link]]
carrier = "kcp"                              carrier = "kcp"
addr = "0.0.0.0:7001"                        addr = "203.0.113.9:7001"
```

`addr` is where this side **binds** if it accepts lanes and where it **connects** if it dials, so the two
configs differ only in the addresses (and in direct mode, `dial = "entry"`, the roles swap). Generate both at once:

```
rakhsh init --tunnel-addr 203.0.113.9:443 --carrier wss --link quicv2 --link kcp:7001
rakhsh check -c entry.toml        # lists the links, in order
```

## What it does

- **Accepting side:** listens on every link at once. Lanes from any of them join the same pool, so a user
  connection can ride whichever lanes are up.
- **Dialing side, racing.** A lane tries the links best first but does not wait for a dead one: if a link has not
  produced an *authenticated* lane within 1.2 s, the next is started in parallel and the first to finish the
  handshake wins. A blocked carrier costs about a second, not its timeout. (Loopback test: a black-holed primary,
  lanes up on the fallback in 1.3 s with a 4 s timeout.)
- **Dialing side, penalties.** A link that fails is skipped for 3 s, then 6, 12 ... up to 60 s, shared by all lanes,
  so a dead carrier costs one timeout once, not one per lane per retry. A link whose lanes keep dying within 15 s of
  coming up counts as failing too (a carrier that handshakes and is then cut must not look healthy).
- **Failback.** A lane that fell back keeps checking, every `link_probe` seconds (staggered across lanes), whether a
  better link answers a full handshake again, and moves up to it when one does. The moved lane's streams are reset
  once (they would have been disturbed by the outage anyway); the rest of the pool is untouched.
- **Bounded handshakes.** Every attempt, on either side, has a deadline (`link_timeout`), so a peer or scanner that
  connects and says nothing no longer holds a task open.

## Settings

| key | default | |
|---|---|---|
| `link_policy` | `"failover"` | `"failover"`: every lane prefers the first link that works. `"spread"`: lane *n* prefers link *n mod links*, so bandwidth and risk are spread across the carriers; each lane still falls back and moves back up. |
| `link_timeout` | `10` | seconds one attempt (dial + handshake) may take |
| `link_probe` | `30` | seconds between checks for a better link while on a fallback; `0` = never move back |

A `[[link]]` may override `sni`, `ws_path`, `ws_credential`, `decoy`, `edge_ip`, `tls_fingerprint`, `cert_path`,
`key_path`, `quic_mask`, `quic_version` and `reliability`; everything else is inherited from the top level, which is
also where raw carriers (`faketcp`, `l2tcp`, `icmp`, `spoof`) take their `spoof_*` settings. `lanes` is the total
number of lanes, not per link. `encryption` applies to the whole tunnel.

## Verified

Loopback (`fallback_test.py`-style: entry on tcp + quicv2, the primary reached through a forwarder that can be
switched off): primary up -> all lanes on it; primary blocked -> lanes on quicv2 in 3 s, data intact; primary back ->
lanes moved up in 2.4 s, data intact; primary black-holed at start -> lanes up on the fallback in 1.3 s (attempt
timeout 4 s), data intact. Real Iran ⇄ Hetzner link, wss primary black-holed with tcp and quicv2 as fallbacks: lanes
up on tcp 1.35 s after start, 8-stream download over the fallback 814 Mbit/s; with the primary reachable the lanes
come up on wss in 0.3-0.6 s.

## Honest limits

- Both ends must list the same links; the listening side has to listen on each one (a firewall rule per port).
- Failback replaces a lane, so streams on that lane are reset once, unless `resume = true` (`RESUME.md`), in which case
  they move to another lane and go on. `link_probe = 0` trades the move for staying put.
- A losing attempt that had already reached the peer shows up there as a lane that authenticates and ends at once.
- **A link is "up" when it authenticates and stays up, not when it is fast.** A carrier that the network throttles but
  does not block (the Iran filter did this to QUIC v2: handshake fine, data at 1-10 Mbit/s) still counts as up, so put
  the carrier you trust most first. Quality-aware selection is not built.
- A dialing process that is killed abruptly leaves its QUIC lanes alive on the accepting side until the 30 s dead-peer
  timer (a killed TCP lane is noticed at once). Restart the accepting side too, or wait, before judging a restart.
- Which carrier works is the network's decision: links make the tunnel survive a blocked carrier, they do not
  make a blocked carrier work.

## Logs

```
INFO opening 4 lane(s) over 3 link(s): wss 203.0.113.9:443, quicv2 203.0.113.9:443, kcp 203.0.113.9:7001
INFO lane 1 up via wss 203.0.113.9:443
WARN link wss 203.0.113.9:443 failed: no answer within 10s
INFO lane 2 up via quicv2 203.0.113.9:443
INFO lane 2 moving up to wss 203.0.113.9:443
INFO lane 1 authenticated via wss 0.0.0.0:443          (accepting side)
```
