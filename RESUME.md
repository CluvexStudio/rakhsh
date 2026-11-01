# Resume: streams survive a dead lane

A lane is one connection between the two ends. When it dies — a filter resets it, a NAT forgets it, the carrier
is cut, a better link takes over (see `LINKS.md`) — every TCP connection that rode on it dies with it: the
download breaks, the SSH session drops, the user sees a reset. With `resume = true` they do not. The streams that
were on the lane move to another one and go on **exactly where they stopped**; the user's own TCP connection never
notices, apart from a short pause.

```toml
# both ends — it is part of the handshake, so a mismatch just fails to connect
resume = true
resume_grace = 60      # seconds a stream waits without any lane before it is given up (default 60)
```

```
rakhsh init --tunnel-addr IP:7000 --carrier tcp --resume          # both generated configs get it
rakhsh check -c entry.toml                                        # "stream resumption: on …"
```

## What it covers

- TCP streams: `[[forward]]` ports, and the proxy core's `tunnel` outbound (SOCKS5/HTTP through the tunnel, DNS
  over TCP through the tunnel).
- Not UDP flows (a datagram that was in flight on the dead lane is lost, as on any network) and not the L3 TUN mode.
- Not a connection that the *target* resets: if the backend closes or resets, the stream ends, as it should.
- Not a restart of either process: the streams live in memory. After a restart the other end learns the stream is
  gone (`CLOSE`) and ends it.

## How it works

Every byte of a stream has an **offset**. A frame carries its offset, so the receiver takes exactly the next
byte, drops anything it already has and ignores anything that skips ahead. That makes every frame safe to send
twice and safe to deliver on a different lane than its predecessors.

- **The sender keeps what is not confirmed.** Data stays in a retransmit buffer until the peer says it has written
  it to its socket. A half-close (FIN) is one extra unit in the sequence, so it is repeated and confirmed like data.
- **Acknowledgements are cumulative** ("I have written the first N units to my socket"). They free the buffer and
  are also the flow-control credit (the same 16 MB window as without `resume`), so a lost ack is repaired by the next.
- **When a stream loses its lane** it moves to another live lane at once, or waits for the next one to come up. It
  then sends `SYNC` — "I have received up to X, written Y" — the peer answers with its own state and sends again from
  X. Until that exchange is done a stream only buffers; it never sends ahead of what the peer knows. The entry
  announces immediately, the exit after a second if the entry stayed silent (so the common case, both ends noticing
  together, costs one round trip and no duplicate traffic).
- **A stream whose opening was lost** with the lane is opened again, with everything buffered so far.
- **Gaps repair themselves**: a frame that skips ahead (possible when a stream changes lane while the old one still
  delivers) makes the receiver ask for a resend from where it is. At most one such request per 0.5 s per stream.
- **Giving up**: a stream that has had no lane for `resume_grace` seconds is closed on both ends; a stream the peer
  no longer knows is closed with a `CLOSE`.

The frames are ordinary lane records (AES-256-GCM in `encryption = "full"`), so they are authenticated like
everything else; `resume` is bound into the handshake transcript, which is why both ends must agree.

## How long is the pause?

| what happens | pause |
|---|---|
| one of several lanes dies | one round trip (its streams move to a live lane) |
| the only lane dies (reset / closed connection), it had been up ≥ 15 s | ~0.25 s to re-dial + handshake + one round trip — **0.45 s measured on loopback; ~1 s on the real 80 ms link** (4 lanes, all reset at once) |
| the only lane dies, it was young (< 15 s: a flapping link) | 3 s re-dial pause, then the same |
| the lane is silently dead (no reset, packets vanish) | until the heartbeat notices: `3 × heartbeat`, at least 15 s with `resume` (30 s without). `heartbeat = 5` gives 15 s |

(The re-dial pause itself is new: a lane that had been healthy for 15 s or more is reconnected after 0.25 s instead
of 3 s, with or without `resume`. Young lanes keep the 3 s, so a peer that flaps is not hammered.)

## What it costs

- **Memory.** Each stream may hold up to one 16 MB window of unacknowledged data per direction (the same bound the
  receiving end already had). It is only held while the data is in flight; an idle or fast-draining stream holds
  almost nothing. During a long outage every busy stream fills its window and then pushes back on its user
  (TCP backpressure), so the worst case is `streams × 16 MB × 2` — `resume_grace` bounds how long it lasts.
- **CPU and speed.** Every byte is also written to a buffer that stays alive until it is acknowledged, which
  doubles the memory traffic of the data in flight; the bookkeeping itself is small. Measured on the real Iran ⇄
  Hetzner link, both ends 2-vCPU and CPU-bound (tight ABAB, 6 rounds, 8 streams): download 1874 → 1916 Mbit/s
  (level), upload 2655 → 2260 (−15%, lower in every round). On a link that is not CPU-bound there is nothing to lose.
  With `resume` off the data path is unchanged (a controlled A/B against the build before this feature: 0.98 / 0.99).

## Tests

- 13 unit tests (12 in `resume.rs`, one in `noise.rs` for the handshake binding): the offset logic (`Tx`/`Rx`: duplicates, overlap, gaps, FIN, resend from any point), the frame
  codec, and the whole protocol between two in-process hubs joined by lanes that get killed — one lane lost,
  several lost and replaced, a lane that dies on one end only (so old frames arrive after new ones), a stream
  that gives up after the grace period, both ends forgetting a stream the user hung up, and an OPEN that was lost
  with the lane. `RESUME_CHAOS_SEEDS=200 cargo test chaos` runs the randomised one for as many seeds as you like
  (120 seeds pass).
- `scripts/resume_test.py BINARY` (about a minute): the real binary, with a proxy between exit and entry that
  kills every lane connection.
  - **A** six streams of 12 MB echoed in both directions, lanes cut twice mid-transfer: every stream intact
    (sha256 of what was sent equals what came back).
  - **D** one unpaced 64 MB stream (four times the window), four cuts in quick succession: intact.
  - **E** lanes that have lived 16 s are cut once: longest stall 0.45 s.
  - **F** the lanes start on the fallback carrier, the primary comes back mid-transfer and the lanes move up to it
    while four streams are running: all intact.
  - **B** the same cut *without* `resume`: every stream breaks — the control that proves the test cuts the lanes.
  - **C** no lane for longer than `resume_grace`: the stream is closed after 3.1 s, and the tunnel works again as
    soon as a lane returns.
- On the real Iran ⇄ Hetzner link: iperf3 with 4 download streams, every lane connection reset mid-run
  (`iptables … REJECT --reject-with tcp-reset` for 0.2 s). With `resume`: all streams and iperf3's control connection
  survive, one second at 31.5 Mbit/s, then back at 1150 Mbit/s, run completed (1.88 GB). Without it: `iperf3: error -
  control socket has closed unexpectedly`, 0 Mbit/s from the reset on. Details in `BENCH.md`.
- The integrity matrix (`scripts/integrity_test.py`) passes with `resume = true` on all seven carriers
  (tcp, tls, ws, wss, quic, quicv2, kcp), in `full` and `none`.

## Honest limits

- Detection is the lane's own: a connection that is reset is noticed at once, one that silently drops packets only
  when the heartbeat runs out (see the table). Lower `heartbeat` if that matters more than a few spurious
  reconnects — with `resume` a false alarm costs a pause, not the user's connection.
- `resume` hides the loss of *lanes*. If both ends are cut off from each other for longer than `resume_grace`,
  the streams end.
- In `encryption = "none"` the records have no integrity after the first (see `SECURITY.md`); resume adds nothing
  to that and takes nothing away.
