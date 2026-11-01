# Built-in DNS

A small caching DNS server whose upstream depends on the *name*. Behind a filter that poisons or blocks foreign
names, and for sites that give a better answer to a local resolver, that is exactly what plain DNS cannot do:

- names the router sends **direct** (with `--split-iran`: `.ir` and the Iranian list) are asked of a **local** resolver
  — fast, and the CDN node nearest the user;
- names the router sends to the **tunnel** are asked of a resolver **abroad, through the tunnel** — nothing leaks to the
  local network and nothing can poison it;
- names the router sends to **block** get NXDOMAIN.

```toml
[dns]
listen = "127.0.0.1:5353"            # UDP and TCP; "0.0.0.0:53" to serve a network (then set `allow`)
local  = ["178.22.122.100"]          # asked directly from this host (default: /etc/resolv.conf, minus this server)
remote = ["1.1.1.1", "8.8.8.8"]      # asked through the tunnel (default shown); asked directly where there is no tunnel
allow  = ["203.0.113.0/24"]          # clients allowed to ask (default: anyone who can reach `listen`)
cache = 4096                         # entries; 0 turns the cache off
cache_min_ttl = 30                   # TTLs are clamped to [min, max] seconds
cache_max_ttl = 3600
timeout = 3                          # seconds per upstream before trying the next

# The same rules that route connections route names (see CORE.md):
[route]
final = "tunnel"
resolve = true
[[route.rule]]
outbound = "direct"
domain_suffix = [".ir"]
rule_file = "/etc/rakhsh/iran.txt"   # `rakhsh rules iran`: the Iranian address ranges
[[route.rule]]
outbound = "block"
domain = ["ads.example.com"]
```

`rakhsh init --tunnel-addr IP:443 --carrier wss --dns 127.0.0.1:5353 --split-iran` writes all of this.

## How a name is decided

Rules are tried in order, first match wins, like for connections. A rule that lists **domains** matches on the name. A
rule that lists **address ranges** (the Iranian list) needs an address, so the name is asked of the local resolver
first: if the answer lands in the listed ranges the local answer is used as it is, otherwise the question goes abroad.
So an Iranian shop on a `.com` name still resolves locally, and a foreign name never leaves through a local resolver
unless a rule says so. No rule matches → the `final` outbound.

## Details

- Queries are forwarded as raw packets (EDNS options, DNSSEC records and so on pass through); only the header, the
  first question and answer TTLs are read. A truncated UDP answer is retried over TCP — through the tunnel for remote names.
- The cache honours the smallest TTL of an answer, clamped to `cache_min_ttl`…`cache_max_ttl`; NXDOMAIN is kept 30 s;
  SERVFAIL is never cached. A cached answer is returned as it was received (TTLs are not counted down).
- Every upstream failing gives SERVFAIL; a malformed query gets FORMERR.
- Listening on a non-loopback address without `allow` makes an open resolver, and rakhsh warns.
- Don't point this host's own `/etc/resolv.conf` at rakhsh's DNS *and* list no `local` servers: the default `local`
  list skips this server, but an empty list then has nothing to ask.

## Honest limits

- No DNS-over-HTTPS / TLS upstreams (the tunnel already encrypts the remote leg; the local leg is plain DNS), no
  DNSSEC validation, no fake-IP mode, no EDNS client-subnet handling.
- A name that falls through to a range rule costs one extra local lookup (an A, or an AAAA for AAAA questions).
- The proxy core's own name handling is unchanged: foreign names given to SOCKS/HTTP are sent through the tunnel by
  name and resolved abroad anyway; this DNS server is for devices and apps that use it as their resolver.

## Verified

`scripts/dns_test.py` (loopback, two mock resolvers): `.ir` answered locally; a name whose local answer is in the
listed range stays local; any other name is answered by the resolver abroad through the tunnel; a repeat is served
from the cache with the client's own id; a blocked name gets NXDOMAIN; DNS over TCP; a truncated UDP answer is
retried over TCP through the tunnel; other record types pass through.
