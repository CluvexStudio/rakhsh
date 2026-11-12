# Security

## Reporting a vulnerability

Please don't open a public issue for a security problem. Report it privately through the
**Security** tab of this repository ("Report a vulnerability"), or message us on Telegram at
https://t.me/CluvexStudio.

Tell us what you found, how to reproduce it and which version you tested. We'll get back to you
as soon as we can, and we're happy to credit you in the fix.

## Supported versions

Security fixes go into the latest release.

## Security model and the `encryption` setting

Rakhsh protects a tunnel in two stages, and you choose how much of the second stage you want.

1. **The handshake, always on, identical in both modes.** Each lane starts with a Noise
   `IKpsk2` handshake (`Noise_IKpsk2_25519_AESGCM_BLAKE2s`): both ends pin the other's static
   public key and mix in a pre-shared key derived from `token`. A peer without the right keys *and*
   the token cannot complete it, so nobody but your two servers can open a lane. The dial target
   (where the exit connects to) travels inside the session, never in the clear.
2. **The records, what happens to your bytes afterwards.** This is the `encryption` setting:

| `encryption` | Peers authenticated | The path can read the data | The path can alter / inject / replay | CPU |
|---|---|---|---|---|
| **`"full"`** (default) | yes | **no** (AES-256-GCM | **no**) detected, the lane is dropped | AES-256-GCM on every byte |
| **`"none"`** | yes (handshake only) | yes | **yes**, nothing protects the records after the handshake | none |

`"none"` leaves the records in the clear once the handshake is done. It exists for payloads that are
already encrypted end to end, where a second layer buys nothing. **The default stays `"full"`.**

### Choosing

- **Use `full`** unless you have a reason not to. It is the only mode in which the path learns nothing
  about the payload and cannot tamper with it, including through a CDN.
- **Use `none`** only when two things are both true: the payload is already encrypted end to end, so
  encrypting it again is wasted CPU, **and** you accept what an attacker *on* the path can do, read
  whatever is not already encrypted, and forge the tunnel's own control frames, which means asking your
  exit to open a stream to a target of their choosing, or closing and hijacking streams. A censor that
  merely watches sees only the already-encrypted payload.

Things that do not change with the mode:

- On `tls`, `wss`, `quic` and `quicv2` the carrier's own TLS/QUIC still hides the bytes from a
  *passive* observer, but it does not authenticate the server (self-signed certificate) unless you
  configure a real one, so reason about `none` as if an active attacker could sit on the path.
- Behind a CDN the TLS ends at the CDN: with `none` **the CDN can read your data**. Use `full`.
- Traffic analysis (record sizes, timing) is visible in both modes.

### Setting it

Both ends must use the same value; the mode is bound into the handshake transcript, so a mismatch
simply fails to connect (the accepting side logs: *both ends need the same token, keys and
`encryption` setting*). There is nothing to negotiate, hence nothing to downgrade.

```toml
encryption = "none"          # omit for "full"
```

```
rakhsh init --tunnel-addr IP:7000 --carrier tcp --encryption none     # writes it into both configs
rakhsh check -c entry.toml                                            # prints the mode; warns when not full
```

The installer asks the same question when you create a tunnel, and Rakhsh logs a warning at start-up
whenever the mode is not `full`.

### Why a replayed handshake cannot open a plaintext lane

A passive attacker can record the first handshake message and replay it to your entry. In `full` mode
that gains nothing: without the session keys no record they send will authenticate. In `none` mode there
is no per-record check left to rely on, so the lane adds one more step:

- **record 0 of every direction is always full AEAD**, and
- the dialing side's record 0 is a **key confirmation** (the handshake hash, sealed with the session
  keys). The accepting side serves nothing on the lane until it verifies it.

Whoever replays a recorded handshake cannot derive the keys, so they cannot produce that record, and
the lane never opens. (Unit-tested: `a_replayed_handshake_never_opens_a_plaintext_lane`.) After the
confirmation, `none` records are not protected, that is the mode.

### Stream resumption (`resume = true`)

Resumption adds no new trust and no new key material. Its frames are ordinary lane records (AES-256-GCM in
`full`; in `none` they have no integrity after record 0, like everything else in that mode), and `resume` is bound
into the handshake transcript the same way the mode is, so two ends configured differently never connect.

It also does not let a peer make the other end hold more than it already could: a stream's unacknowledged data is
capped by the same 16 MB window, offsets are checked (a frame that skips ahead is ignored, a repeated one is
dropped, an acknowledgement beyond what was sent is clamped), stream ids start at a random 64-bit value so a
restarted process cannot be confused with its earlier self, and a stream that stays without a lane is dropped after
`resume_grace`. See `RESUME.md`.

### What it buys

Measured on the real Iran ⇄ Germany link, both ends 2-vCPU and CPU-bound (`BENCH.md`, "Encryption
upload over 11 rounds, inside the noise) and is worth +8% to +12% over `full`; on wss, where the data would otherwise be
