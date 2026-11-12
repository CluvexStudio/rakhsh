# Shabdiz, as Rakhsh uses it

The protocol lives in its own repository, <https://github.com/CluvexStudio/shabdiz>,
and knows nothing about Rakhsh. Its design, its wire format and the measurements
behind both are in that repository's README. This file is only about the seam.

Rakhsh's own session is reliable, ordered and credit-flow-controlled, which is
right for TCP streams and wrong for a payload that already has a transport of
its own. On the Iran route it turned 29% path loss into over 120 ms of ping and
jitter, because every lost packet cost a round trip of head-of-line blocking for
everything behind it. For a UDP payload (a VPN, QUIC, DNS, voice, a game) the
`shabdiz-*` carriers skip all of it: one client datagram becomes one protocol
datagram, and loss stays the payload's business, as it already was.

## Selecting it

A `shabdiz-*` carrier replaces the session rather than feeding it, so none of
the lane and stream machinery applies. `src/dgram.rs` takes over the whole run.

```toml
role = "entry"
carrier = "shabdiz-gre"       # or shabdiz-gre6, shabdiz-l2, shabdiz-udp, shabdiz-tcp
tunnel_listen = "0.0.0.0:7030"
peer_ip = "203.0.113.9"       # gre and l2: the peer's address, needed on both ends
# dial = "exit" is the default, and on a filtered path it is not optional

[[forward]]
listen = "0.0.0.0:37024"
target = "127.0.0.1:37021"
udp = true
```

One UDP forward per tunnel; give a second forward its own config. `rakhsh check`
prints the carrier, which end opens the flow, the crafted-TCP port pair the
token derives, and what it will carry.

## Which carrier

| | needs | survives a UDP block | crosses NAT | notes |
|---|---|---|---|---|
| `shabdiz-gre` | root, a public address at each end | **yes** | no | **the one to use between two servers.** Measured on the Iran route at 213 Mbit/s outbound with 0.29% loss, 100 Mbit/s inbound with 1.4%, about 7× `l2` |
| `shabdiz-gre6` | root, a public **IPv6** address at each end | **yes** | no | the same bridged frame on IPv6 next-header 47. Worth a try where the v4 path drops protocol 47, since filters are often written for v4 only; the extra 20 bytes of header leave a 1407-byte payload instead of 1427 |
| `shabdiz-l2` | root, a real NIC | **yes** | no | 32 Mbit/s at 0.5-8% out on the same route. Nothing for a filter to track, and it works where protocol 47 does not |
| `shabdiz-udp` | nothing | no | yes | measured **150× slower** than `l2` on this route, at 84% loss. The carrier for a client's own hop, not for the border |
| `shabdiz-tcp` | nothing | **yes** | yes | works anywhere; the carrier is ordered, so a loss holds up what is behind it |

Both raw carriers need `peer_ip` on *both* ends, they have no socket to learn
the far end's address from. Either end may open a `gre` flow; `l2` must be
exit-dialled.

## What it reports

`src/dgram.rs` logs the session's own view every 15 s while traffic moves:
datagrams and bytes each way, ring drops, loss in both directions (from counter
gaps, exactly), round trip and jitter. That log is where every tuning decision
on this route came from, read it before changing anything.
