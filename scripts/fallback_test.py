#!/usr/bin/env python3
# Loopback test of carrier links: fallback, failback and racing. ~40 s.
#   fallback_test.py BINARY
# Entry listens on a tcp link (reached through a TCP forwarder we can switch off = "the carrier gets blocked") and on a
# quicv2 link. The exit's primary link is tcp, its [[link]] is quicv2.
#   1. both up        -> lanes use the primary (tcp); data intact
#   2. block the primary (forwarder down) -> lanes fall back to quicv2; data intact
#   3. unblock        -> lanes move back up to tcp on their own; data intact
#   4. blackhole the primary at start (connect hangs) -> racing brings the lanes up on quicv2 within ~2-4 s, not after the timeout
import asyncio, hashlib, os, random, re, socket, subprocess, sys, tempfile, threading, time

bin_ = sys.argv[1]
TOK = "y5vi1yDXCE3pHH+QxG2rYLIm+GymyTQNHsZvQgTY+d0="
E_SEC = "XYy/JIqEm5D7gIaPT7TKhfFLQRbzOQVai2Uob5XBI9Q="; E_PEER = "gB9DNAluC10n35eTNAmiViQ7TpgF6GGGLflaevE/dHM="
X_SEC = "F3pB1tEoWjqv3efHYXh5FVIP7Rdn7AWolFcumq6JK2I="; X_PEER = "XbcC/IxQ4MHEUijmoE4Av7ImvTEeA9v6yBrYS6mKdHo="
BACK, P_TCP, P_QUIC, FWD, EXPOSE = 5351, 7041, 7042, 7043, 15651
tmp = tempfile.mkdtemp(prefix="rklink-")
ok = True
procs = []


def say(phase, passed, extra=""):
    global ok
    ok &= passed
    print(f"  {'PASS' if passed else 'FAIL'}  {phase} {extra}", flush=True)


open(f"{tmp}/e.toml", "w").write(f'''role = "entry"
token = "{TOK}"
static_secret = "{E_SEC}"
peer_public = "{E_PEER}"
carrier = "tcp"
tunnel_listen = "127.0.0.1:{P_TCP}"
[[link]]
carrier = "quicv2"
addr = "127.0.0.1:{P_QUIC}"
[[forward]]
listen = "127.0.0.1:{EXPOSE}"
target = "127.0.0.1:{BACK}"
''')


def exit_cfg(primary):
    return f'''role = "exit"
token = "{TOK}"
static_secret = "{X_SEC}"
peer_public = "{X_PEER}"
carrier = "tcp"
tunnel_connect = "{primary}"
lanes = 3
link_probe = 3
link_timeout = 4
[[link]]
carrier = "quicv2"
addr = "127.0.0.1:{P_QUIC}"
'''


# ---- a backend that echoes ------------------------------------------------------------------------
def backend():
    async def handle(r, w):
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
        w.close()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(asyncio.start_server(handle, "127.0.0.1", BACK))
    loop.run_forever()


threading.Thread(target=backend, daemon=True).start()


# ---- a TCP forwarder that can be switched off (the "blocked carrier") ---------------------------
class Forwarder:
    def __init__(self):
        self.loop = None
        self.server = None
        self.conns = []

    def start(self):
        ready = threading.Event()

        def run():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            async def pipe(r, w):
                try:
                    while True:
                        d = await r.read(65536)
                        if not d:
                            break
                        w.write(d)
                        await w.drain()
                except Exception:
                    pass
                finally:
                    w.close()

            async def handle(r, w):
                try:
                    ur, uw = await asyncio.open_connection("127.0.0.1", P_TCP)
                except Exception:
                    w.close()
                    return
                self.conns += [w, uw]
                await asyncio.gather(pipe(r, uw), pipe(ur, w))

            async def go():
                self.server = await asyncio.start_server(handle, "127.0.0.1", FWD)
                ready.set()

            self.loop.run_until_complete(go())
            self.loop.run_forever()

        threading.Thread(target=run, daemon=True).start()
        ready.wait(5)

    def stop(self):
        async def kill():
            self.server.close()
            for c in self.conns:
                c.close()
            self.conns.clear()
            await asyncio.sleep(0.2)

        asyncio.run_coroutine_threadsafe(kill(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)


def start(cfg_path, log):
    p = subprocess.Popen([bin_, "run", "-c", cfg_path], stdout=open(log, "w"), stderr=subprocess.STDOUT)
    procs.append(p)
    return p


def logtext(path):
    return re.sub(r"\x1b\[[0-9;]*m", "", open(path).read())


def wait_for(path, pattern, secs, count=1, since=0):
    t0 = time.time()
    while time.time() - t0 < secs:
        m = re.findall(pattern, logtext(path)[since:])
        if len(m) >= count:
            return m, time.time() - t0
        time.sleep(0.1)
    return [], secs


def transfer(label):
    """3 concurrent echo streams of 2 MB through the tunnel, sha256-checked."""
    res = []

    def one(i):
        data = random.Random(i + int(time.time())).randbytes(2 * 1024 * 1024)
        s = socket.create_connection(("127.0.0.1", EXPOSE), timeout=20)
        got = bytearray()

        def rd():
            while True:
                d = s.recv(1 << 18)
                if not d:
                    return
                got.extend(d)

        t = threading.Thread(target=rd)
        t.start()
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        t.join(30)
        s.close()
        res.append(hashlib.sha256(got).digest() == hashlib.sha256(data).digest())

    ths = [threading.Thread(target=one, args=(i,)) for i in range(3)]
    [t.start() for t in ths]
    [t.join(40) for t in ths]
    say(f"{label}: 3 x 2 MB echo intact", len(res) == 3 and all(res))


try:
    print("check output:")
    out = subprocess.run([bin_, "check", "-c", f"{tmp}/e.toml"], capture_output=True, text=True).stdout
    print("   " + out.replace("\n", "\n   "))
    say("check lists both links", "tcp 127.0.0.1" in out and "quicv2 127.0.0.1" in out)

    fwd = Forwarder(); fwd.start()
    open(f"{tmp}/x.toml", "w").write(exit_cfg(f"127.0.0.1:{FWD}"))
    start(f"{tmp}/e.toml", f"{tmp}/e.log"); time.sleep(0.8)
    xp = start(f"{tmp}/x.toml", f"{tmp}/x.log")

    print("phase 1: both links up")
    m, t = wait_for(f"{tmp}/x.log", r"lane \d+ up via tcp", 12, count=3)
    say("1. all 3 lanes on the primary (tcp)", len(m) >= 3, f"({t:.1f}s)")
    transfer("1")

    print("phase 2: primary blocked")
    mark = len(logtext(f"{tmp}/x.log"))
    fwd.stop()
    m, t = wait_for(f"{tmp}/x.log", r"lane \d+ up via quicv2", 20, count=3, since=mark)
    say("2. lanes fell back to quicv2", len(m) >= 3, f"({t:.1f}s)")
    transfer("2")

    print("phase 3: primary unblocked")
    mark = len(logtext(f"{tmp}/x.log"))
    fwd = Forwarder(); fwd.start()
    m, t = wait_for(f"{tmp}/x.log", r"lane \d+ moving up to tcp", 30, count=3, since=mark)
    say("3. lanes moved back up to tcp", len(m) >= 3, f"({t:.1f}s)")
    time.sleep(1.0)
    transfer("3")

    print("phase 4: primary black-holed (connects hang) — racing")
    xp.terminate(); xp.wait(5); fwd.stop(); time.sleep(0.5)
    open(f"{tmp}/x.toml", "w").write(exit_cfg("10.255.255.1:7043"))
    t0 = time.time()
    start(f"{tmp}/x.toml", f"{tmp}/x2.log")
    m, t = wait_for(f"{tmp}/x2.log", r"lane \d+ up via quicv2", 15, count=3)
    say("4. lanes up on quicv2 despite a hanging primary", len(m) >= 3, f"({t:.1f}s; the attempt timeout is 4s, the stagger 1.2s)")
    say("4. raced, did not wait for the timeout", t < 3.9)
    transfer("4")
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
