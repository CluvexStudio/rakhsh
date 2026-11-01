#!/usr/bin/env python3
# Loopback test of bandwidth limits and quotas (~30 s).
#   limits_test.py BINARY
#   A  forward with `limit = "8Mbit"`           -> 1 MB takes ~1 s (an unlimited forward takes well under that)
#   B  forward with `limit_per_stream = "4Mbit"`-> two parallel 500 KB downloads each take ~1 s (the cap is per connection)
#   C  forward with `quota = "1500KB"`          -> the second 1 MB download is cut near the allowance, then connections are refused
#   D  `rakhsh quota` shows the saved usage; `--reset` lets traffic through again within a few seconds
import asyncio, os, re, socket, subprocess, sys, tempfile, threading, time

bin_ = sys.argv[1]
TOK = "y5vi1yDXCE3pHH+QxG2rYLIm+GymyTQNHsZvQgTY+d0="
E_SEC = "XYy/JIqEm5D7gIaPT7TKhfFLQRbzOQVai2Uob5XBI9Q="; E_PEER = "gB9DNAluC10n35eTNAmiViQ7TpgF6GGGLflaevE/dHM="
X_SEC = "F3pB1tEoWjqv3efHYXh5FVIP7Rdn7AWolFcumq6JK2I="; X_PEER = "XbcC/IxQ4MHEUijmoE4Av7ImvTEeA9v6yBrYS6mKdHo="
BACK, TUN = 5361, 7051
F_RATE, F_QUOTA, F_STREAM, F_FREE = 15671, 15672, 15673, 15674
tmp = tempfile.mkdtemp(prefix="rklim-")
ok = True


def say(name, passed, extra=""):
    global ok
    ok &= passed
    print(f"  {'PASS' if passed else 'FAIL'}  {name} {extra}", flush=True)


open(f"{tmp}/e.toml", "w").write(f'''role = "entry"
token = "{TOK}"
static_secret = "{E_SEC}"
peer_public = "{E_PEER}"
carrier = "tcp"
tunnel_listen = "127.0.0.1:{TUN}"
quota_state = "{tmp}/quota.json"
[[forward]]
listen = "127.0.0.1:{F_RATE}"
target = "127.0.0.1:{BACK}"
limit = "8Mbit"
[[forward]]
listen = "127.0.0.1:{F_QUOTA}"
target = "127.0.0.1:{BACK}"
quota = "1500KB"
[[forward]]
listen = "127.0.0.1:{F_STREAM}"
target = "127.0.0.1:{BACK}"
limit_per_stream = "4Mbit"
[[forward]]
listen = "127.0.0.1:{F_FREE}"
target = "127.0.0.1:{BACK}"
''')
open(f"{tmp}/x.toml", "w").write(f'''role = "exit"
token = "{TOK}"
static_secret = "{X_SEC}"
peer_public = "{X_PEER}"
carrier = "tcp"
tunnel_connect = "127.0.0.1:{TUN}"
lanes = 2
''')


def backend():
    async def handle(r, w):
        n = int.from_bytes(await r.readexactly(4), "big")
        w.write(b"x" * n)
        await w.drain()
        w.close()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(asyncio.start_server(handle, "127.0.0.1", BACK))
    loop.run_forever()


threading.Thread(target=backend, daemon=True).start()


def download(port, n, timeout=20):
    """Ask the backend for n bytes through a forward; return (bytes received, seconds)."""
    t = time.time()
    got = 0
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.sendall(n.to_bytes(4, "big"))
        while True:
            d = s.recv(1 << 16)
            if not d:
                break
            got += len(d)
        s.close()
    except OSError:
        pass
    return got, time.time() - t


def cli(*args):
    return subprocess.run([bin_, *args], capture_output=True, text=True).stdout


procs = []
try:
    out = cli("check", "-c", f"{tmp}/e.toml")
    print("check:\n   " + "\n   ".join(l for l in out.splitlines() if l.startswith("limits")))
    say("check lists the limits", "forward 127.0.0.1:15671: speed 8Mbit per direction" in out and "quota 1500KB per month" in out)

    procs.append(subprocess.Popen([bin_, "run", "-c", f"{tmp}/e.toml"], stdout=open(f"{tmp}/e.log", "w"), stderr=subprocess.STDOUT))
    time.sleep(0.8)
    procs.append(subprocess.Popen([bin_, "run", "-c", f"{tmp}/x.toml"], stdout=open(f"{tmp}/x.log", "w"), stderr=subprocess.STDOUT))
    for _ in range(50):                                   # wait for a lane
        if download(F_FREE, 10, 3)[0] == 10:
            break
        time.sleep(0.2)

    print("A: speed limit")
    free = download(F_FREE, 1_000_000)
    lim = download(F_RATE, 1_000_000)
    say("A1 unlimited forward is fast", free[0] == 1_000_000 and free[1] < 0.6, f"({free[1]:.2f}s)")
    say("A2 limit = 8Mbit: 1 MB takes ~1 s", lim[0] == 1_000_000 and 0.7 < lim[1] < 1.6, f"({lim[1]:.2f}s, 8 Mbit/s = 1 MB/s)")

    print("B: per-connection limit")
    res = []
    ths = [threading.Thread(target=lambda: res.append(download(F_STREAM, 500_000))) for _ in range(2)]
    [t.start() for t in ths]; [t.join(20) for t in ths]
    say("B1 two parallel streams each get the cap", len(res) == 2 and all(g == 500_000 and 0.7 < t < 1.7 for g, t in res),
        "(" + ", ".join(f"{t:.2f}s" for _, t in res) + "; 4 Mbit/s = 0.5 MB/s each)")

    print("C: quota (1500 KB)")
    a = download(F_QUOTA, 1_000_000)
    b = download(F_QUOTA, 1_000_000)
    c = download(F_QUOTA, 1_000_000)
    say("C1 first download inside the allowance", a[0] == 1_000_000, f"({a[0]} bytes)")
    say("C2 second one is cut near the allowance", 300_000 < b[0] < 900_000, f"({b[0]} bytes of 1000000)")
    say("C3 afterwards connections are refused", c[0] == 0, f"({c[0]} bytes)")

    print("D: `rakhsh quota` and --reset")
    time.sleep(6)                                         # the daemon saves its counters every 5 s
    out = cli("quota", "-c", f"{tmp}/e.toml")
    print("   " + out.strip().replace("\n", "\n   "))
    m = re.search(r"forward 127\.0\.0\.1:15672: .*\(([\d.]+)%\)", out)
    say("D1 usage is saved and reported", bool(m) and float(m.group(1)) >= 99.0)
    cli("quota", "-c", f"{tmp}/e.toml", "--reset")
    back = (0, 0)
    for _ in range(40):                                   # the daemon notices the new file within ~5 s
        back = download(F_QUOTA, 1_000_000)
        if back[0] == 1_000_000:
            break
        time.sleep(0.5)
    say("D2 after --reset traffic flows again", back[0] == 1_000_000)
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
