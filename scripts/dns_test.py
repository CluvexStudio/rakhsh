#!/usr/bin/env python3
# Loopback test of the built-in DNS (~15 s).
#   dns_test.py BINARY
# Two mock resolvers stand in for "this side's resolver" (local) and "the resolver abroad" (remote, reached through the
# tunnel; the exit dials it). The router: *.ir -> direct, 10.1.1.0/24 -> direct (after a local lookup), blocked.example ->
# block, everything else -> tunnel.
import asyncio, os, socket, struct, subprocess, sys, tempfile, threading, time

bin_ = sys.argv[1]
TOK = "y5vi1yDXCE3pHH+QxG2rYLIm+GymyTQNHsZvQgTY+d0="
E_SEC = "XYy/JIqEm5D7gIaPT7TKhfFLQRbzOQVai2Uob5XBI9Q="; E_PEER = "gB9DNAluC10n35eTNAmiViQ7TpgF6GGGLflaevE/dHM="
X_SEC = "F3pB1tEoWjqv3efHYXh5FVIP7Rdn7AWolFcumq6JK2I="; X_PEER = "XbcC/IxQ4MHEUijmoE4Av7ImvTEeA9v6yBrYS6mKdHo="
LOCAL, REMOTE, DNS, TUN = 5391, 5392, 15354, 7061
ok = True
seen = {"local": [], "remote": []}


def say(name, passed, extra=""):
    global ok
    ok &= passed
    print(f"  {'PASS' if passed else 'FAIL'}  {name} {extra}", flush=True)


def qname(pkt):
    i, labels = 12, []
    while pkt[i]:
        labels.append(pkt[i + 1:i + 1 + pkt[i]].decode()); i += 1 + pkt[i]
    return ".".join(labels), struct.unpack("!H", pkt[i + 1:i + 3])[0], i + 5


def answer(q, ip, ttl=120, truncate=False):
    name, qtype, end = qname(q)
    r = bytearray(q[:end])
    r[2] = 0x81 | (0x02 if truncate else 0); r[3] = 0x80
    if truncate or qtype != 1:
        return bytes(r)
    r[6:8] = b"\x00\x01"
    return bytes(r) + b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!I", ttl) + b"\x00\x04" + socket.inet_aton(ip)


def local_ip(name):
    return "10.1.1.1" if name.endswith(".ir") else "10.1.1.2" if name.startswith("irhost.") else "203.0.113.9"


def mock(port, kind):
    def reply(q, udp):
        name, qtype, _ = qname(q)
        seen[kind].append((name, "udp" if udp else "tcp"))
        if kind == "local":
            return answer(q, local_ip(name))
        if name == "big.example" and udp:
            return answer(q, "", truncate=True)               # force the TCP retry
        return answer(q, "20.2.2.9" if name == "big.example" else "20.2.2.2")

    class U(asyncio.DatagramProtocol):
        def connection_made(self, t): self.t = t
        def datagram_received(self, d, a): self.t.sendto(reply(d, True), a)

    async def tcp(r, w):
        try:
            while True:
                n = struct.unpack("!H", await r.readexactly(2))[0]
                resp = reply(await r.readexactly(n), False)
                w.write(struct.pack("!H", len(resp)) + resp); await w.drain()
        except asyncio.IncompleteReadError:
            pass
        w.close()

    async def go():
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(U, local_addr=("127.0.0.1", port))
        await asyncio.start_server(tcp, "127.0.0.1", port)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(go())
    loop.run_forever()


for port, kind in ((LOCAL, "local"), (REMOTE, "remote")):
    threading.Thread(target=mock, args=(port, kind), daemon=True).start()
time.sleep(0.3)

tmp = tempfile.mkdtemp(prefix="rkdns-")
open(f"{tmp}/e.toml", "w").write(f'''role = "entry"
token = "{TOK}"
static_secret = "{E_SEC}"
peer_public = "{E_PEER}"
carrier = "tcp"
tunnel_listen = "127.0.0.1:{TUN}"

[dns]
listen = "127.0.0.1:{DNS}"
local = ["127.0.0.1:{LOCAL}"]
remote = ["127.0.0.1:{REMOTE}"]

[[outbound]]
tag = "tunnel"
type = "tunnel"
[[outbound]]
tag = "direct"
type = "direct"
[[outbound]]
tag = "block"
type = "block"

[route]
final = "tunnel"
resolve = true
[[route.rule]]
outbound = "direct"
domain_suffix = [".ir"]
[[route.rule]]
outbound = "block"
domain = ["blocked.example"]
[[route.rule]]
outbound = "direct"
ip_cidr = ["10.1.1.0/24"]
''')
open(f"{tmp}/x.toml", "w").write(f'''role = "exit"
token = "{TOK}"
static_secret = "{X_SEC}"
peer_public = "{X_PEER}"
carrier = "tcp"
tunnel_connect = "127.0.0.1:{TUN}"
lanes = 2
''')


def query(name, qtype=1, tcp=False, qid=0x1234):
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for lab in name.split("."):
        q += bytes([len(lab)]) + lab.encode()
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    if tcp:
        s = socket.create_connection(("127.0.0.1", DNS), timeout=6)
        s.sendall(struct.pack("!H", len(q)) + q)
        n = struct.unpack("!H", s.recv(2))[0]
        r = b""
        while len(r) < n:
            r += s.recv(n - len(r))
        s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(6)
        s.sendto(q, ("127.0.0.1", DNS))
        r = s.recv(4096)
    rc = r[3] & 15
    ips = []
    if r[6:8] != b"\x00\x00":
        end = qname(r)[2]
        i = end + 2 + 8 + 2
        ips.append(socket.inet_ntoa(r[i:i + 4]))
    return r, rc, ips


procs = []
try:
    out = subprocess.run([bin_, "check", "-c", f"{tmp}/e.toml"], capture_output=True, text=True).stdout
    say("check mentions the dns server", f"dns on 127.0.0.1:{DNS}" in out)
    procs.append(subprocess.Popen([bin_, "run", "-c", f"{tmp}/e.toml"], stdout=open(f"{tmp}/e.log", "w"), stderr=subprocess.STDOUT))
    time.sleep(0.8)
    procs.append(subprocess.Popen([bin_, "run", "-c", f"{tmp}/x.toml"], stdout=open(f"{tmp}/x.log", "w"), stderr=subprocess.STDOUT))
    time.sleep(1.5)

    r, rc, ips = query("shop.ir")
    say("1. *.ir is answered by the local resolver", ips == ["10.1.1.1"] and ("shop.ir", "udp") in seen["local"] and not seen["remote"], f"({ips})")
    r, rc, ips = query("irhost.example.com")
    say("2. a name whose local answer is in the listed range stays local", ips == ["10.1.1.2"] and not seen["remote"], f"({ips})")
    r, rc, ips = query("example.org", qid=0xBEEF)
    say("3. any other name is asked abroad through the tunnel", ips == ["20.2.2.2"] and ("example.org", "udp") in seen["remote"], f"({ips})")
    say("3b. the reply carries the client's own id", r[:2] == b"\xbe\xef")
    n_remote = len(seen["remote"])
    r, rc, ips = query("example.org", qid=0x0042)
    say("4. a repeat is served from the cache", ips == ["20.2.2.2"] and len(seen["remote"]) == n_remote and r[:2] == b"\x00\x42")
    r, rc, ips = query("blocked.example")
    say("5. a blocked name gets NXDOMAIN", rc == 3 and not ips)
    r, rc, ips = query("example.net", tcp=True)
    say("6. DNS over TCP works", ips == ["20.2.2.2"], f"({ips})")
    r, rc, ips = query("big.example")
    say("7. a truncated UDP answer is retried over TCP through the tunnel", ips == ["20.2.2.9"] and ("big.example", "tcp") in seen["remote"], f"({ips})")
    r, rc, ips = query("example.org", qtype=28)
    say("8. other record types pass through", rc == 0 and not ips)
finally:
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(5)
        except Exception:
            p.kill()
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
