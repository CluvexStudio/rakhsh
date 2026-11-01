#!/usr/bin/env python3
# Data-integrity test through a local rakhsh entry+exit pair for one carrier.
#   integrity_test.py BINARY CARRIER [STREAMS=6] [MB=16] [ENV=V,ENV=V] [EXTRA_TOML_LINE]
# Per stream (all concurrent): (a) ECHO — client sends MB of deterministic pseudo-random data in random-sized
# writes, half-closes (SHUT_WR) and must read the identical bytes back; (b) DOWNLOAD — server streams MB then
# closes, client must read the identical bytes. Verifies ordering, framing, credit/coalescing and half-close.
import asyncio, hashlib, os, random, socket, subprocess, sys, tempfile, threading, time

bin_, carrier = sys.argv[1], sys.argv[2]
streams = int(sys.argv[3]) if len(sys.argv) > 3 else 6
mb = int(sys.argv[4]) if len(sys.argv) > 4 else 16
env = dict(os.environ)
if len(sys.argv) > 5 and sys.argv[5]:
    for kv in sys.argv[5].split(","):
        k, v = kv.split("="); env[k] = v

extra = (sys.argv[6] + "\n") if len(sys.argv) > 6 and sys.argv[6] else ""
N = mb * 1024 * 1024
TOK = "y5vi1yDXCE3pHH+QxG2rYLIm+GymyTQNHsZvQgTY+d0="
E_SEC = "XYy/JIqEm5D7gIaPT7TKhfFLQRbzOQVai2Uob5XBI9Q="; E_PEER = "gB9DNAluC10n35eTNAmiViQ7TpgF6GGGLflaevE/dHM="
X_SEC = "F3pB1tEoWjqv3efHYXh5FVIP7Rdn7AWolFcumq6JK2I="; X_PEER = "XbcC/IxQ4MHEUijmoE4Av7ImvTEeA9v6yBrYS6mKdHo="
BACK, TUN, EXPOSE = 5311, 7031, 15631
sni = 'sni = "www.bing.com"\n' if carrier in ("tls", "wss") else ""
tmp = tempfile.mkdtemp(prefix="rkint-")
open(f"{tmp}/e.toml", "w").write(f'''role = "entry"
token = "{TOK}"
static_secret = "{E_SEC}"
peer_public = "{E_PEER}"
carrier = "{carrier}"
{sni}{extra}tunnel_listen = "127.0.0.1:{TUN}"
[[forward]]
listen = "127.0.0.1:{EXPOSE}"
target = "127.0.0.1:{BACK}"
''')
open(f"{tmp}/x.toml", "w").write(f'''role = "exit"
token = "{TOK}"
static_secret = "{X_SEC}"
peer_public = "{X_PEER}"
carrier = "{carrier}"
{sni}{extra}tunnel_connect = "127.0.0.1:{TUN}"
lanes = 4
''')


def payload(seed, n):
    return random.Random(seed).randbytes(n)


async def handle(r, w):
    mode = await r.readexactly(1)
    if mode == b"E":                      # echo until the client half-closes
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
    else:                                 # download: seed follows, stream N bytes then close
        seed = int.from_bytes(await r.readexactly(4), "big")
        data = payload(seed, N)
        for i in range(0, N, 65536):
            w.write(data[i:i + 65536])
            await w.drain()
    w.close()


def server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    srv = loop.run_until_complete(asyncio.start_server(handle, "127.0.0.1", BACK))
    loop.run_forever()


threading.Thread(target=server, daemon=True).start()
time.sleep(0.3)
procs = []
ok = True
try:
    procs.append(subprocess.Popen([bin_, "run", "-c", f"{tmp}/e.toml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env))
    time.sleep(0.8)
    procs.append(subprocess.Popen([bin_, "run", "-c", f"{tmp}/x.toml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env))
    # wait for a lane to come up: retry the first connect
    t0 = time.time()
    while True:
        try:
            s = socket.create_connection(("127.0.0.1", EXPOSE), timeout=3)
            s.sendall(b"E"); s.shutdown(socket.SHUT_WR)
            s.settimeout(6)
            if s.recv(1) == b"":
                s.close(); break
        except OSError:
            pass
        if time.time() - t0 > 40:
            print("FAIL lanes never came up"); sys.exit(2)
        time.sleep(0.5)

    results = {}

    def echo(i):
        data = payload(1000 + i, N)
        s = socket.create_connection(("127.0.0.1", EXPOSE), timeout=60)
        s.sendall(b"E")
        got = bytearray()

        def reader():
            while True:
                d = s.recv(1 << 18)
                if not d:
                    return
                got.extend(d)

        th = threading.Thread(target=reader); th.start()
        rnd = random.Random(i); pos = 0
        while pos < N:
            k = rnd.choice([1, 7, 100, 1500, 16384, 70000, 200000]); s.sendall(data[pos:pos + k]); pos += k
        s.shutdown(socket.SHUT_WR)
        th.join(120)
        s.close()
        results[("echo", i)] = (hashlib.sha256(got).hexdigest() == hashlib.sha256(data).hexdigest(), len(got))

    def download(i):
        seed = 5000 + i
        want = hashlib.sha256(payload(seed, N)).hexdigest()
        s = socket.create_connection(("127.0.0.1", EXPOSE), timeout=60)
        s.sendall(b"D" + seed.to_bytes(4, "big"))
        h = hashlib.sha256(); n = 0
        while True:
            d = s.recv(1 << 18)
            if not d:
                break
            h.update(d); n += len(d)
        s.close()
        results[("down", i)] = (h.hexdigest() == want, n)

    t = time.time()
    ths = [threading.Thread(target=echo, args=(i,)) for i in range(streams)] + [threading.Thread(target=download, args=(i,)) for i in range(streams)]
    [x.start() for x in ths]; [x.join(180) for x in ths]
    dt = time.time() - t
    bad = [k for k, (good, n) in results.items() if not good]
    short = [k for k in [(m, i) for m in ("echo", "down") for i in range(streams)] if k not in results]
    ok = not bad and not short
    total = 2 * streams * N * 2 / 1e6  # echo moves 2N per stream, download N ... approx MB moved
    print(f"{'PASS' if ok else 'FAIL'} carrier={carrier} streams={streams}x2 {mb}MB each, {dt:.1f}s"
          + (f" bad={bad}" if bad else "") + (f" missing={short}" if short else ""))
finally:
    for p in procs:
        p.terminate()
    for p in procs:
        try: p.wait(timeout=5)
        except Exception: p.kill()
sys.exit(0 if ok else 1)
