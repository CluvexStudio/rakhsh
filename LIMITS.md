# Bandwidth limits and traffic quotas

Cap how fast a forward or proxy may go, and how much traffic it may use per day / week / month. Both are
enforced at the entry (the side users connect to) on every TCP stream that crosses the tunnel.

```toml
limit = "200Mbit"            # whole process, per direction
quota = "2TB"                # whole process, up + down together
quota_period = "month"       # day | week | month (default) | never; UTC calendar, weeks start on Monday
# quota_state = "/var/lib/rakhsh/quota.json"   # default: rakhsh-quota.json next to the config

[[forward]]
listen = "0.0.0.0:443"
target = "127.0.0.1:2096"
limit = "50Mbit"             # this forward only
limit_per_stream = "10Mbit"  # each single connection
quota = "500GB"              # this forward's own allowance (the process-wide one counts too)
quota_period = "week"

[[inbound]]                  # a proxy inbound takes the same keys
tag = "proxy"
type = "mixed"
listen = "0.0.0.0:1080"
limit_up = "20Mbit"
limit_down = "100Mbit"
```

| key | meaning |
|---|---|
| `limit` | speed cap, **per direction** (`limit_up` / `limit_down` set one direction separately) |
| `limit_per_stream` | speed cap per direction for each single connection |
| `quota` | total bytes (both directions) per period |
| `quota_period` | `day`, `week`, `month` (default), `never` (a lifetime allowance) |

Rates: `20Mbit`, `20 Mbit/s`, `1.5Gbps`, `800kbit` (a lower-case `b` is bits) or `5MB/s` (an upper-case `B` is bytes);
decimal prefixes. Sizes: `500GB`, `1.5TB` (decimal), `10GiB` (binary), or bare bytes.

## How it behaves

- **Scopes stack.** A forward or inbound is held to its own limits *and* to the process-wide ones, so a forward
  can be given 50 Mbit inside a 200 Mbit total.
- **Speed limits throttle by back-pressure**: the entry simply stops reading from the user, so TCP slows the
  sender down, nothing is dropped. The long-run rate is exact; a connection may burst 100 ms worth after idling.
- **Quota exhausted:** new connections are refused at once (a forward drops them, a proxy answers "not allowed"),
  and running ones end at their next chunk. When the period rolls over the counter restarts at zero by itself.
- **Usage survives restarts.** It is saved every 5 s (and only counted for the period it belongs to). Look at it with
  `rakhsh quota -c entry.toml`; zero it with `rakhsh quota -c entry.toml --reset` — a running rakhsh picks the new
  file up within seconds. rakhsh logs when a quota reaches 80% and 100%.
- `rakhsh check` lists every scope's limits and rejects a malformed value.

## Honest limits

- Counted and enforced at the entry only, for TCP streams through the tunnel. UDP forwards and SOCKS5 UDP, and the
  proxy core's `direct` / `socks` outbounds (traffic that never enters the tunnel), are not metered.
- Granularity is one chunk (up to 256 KB), so a quota can be overshot by that much per active stream; a crash loses
  up to 5 s of counting.
- The quota counts payload bytes, not tunnel overhead (framing and encryption add roughly 0.1%).
