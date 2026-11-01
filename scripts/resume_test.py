#!/usr/bin/env python3
# Loopback test of stream resumption (~1 min).
#   resume_test.py BINARY
# The exit reaches the entry through a proxy this script can sever. Several streams carry an echo of random data in
# both directions (half-close at the end); in the middle of the transfer the proxy kills every lane connection, twice.
#   A  resume = true on both ends: every stream must still finish, every byte intact (sha256 of what was sent == what came back)
#   B  the same without resume: the streams must break (proves the test really cuts the lanes)
#   C  with resume, but no lane comes back for longer than resume_grace: the streams are closed, and the tunnel works again after
#   D  one unpaced stream four times the 16 MB window, cut four times in quick succession (acks, credit and the retransmit buffer under load)
#   E  lanes that have been up for a while are cut once: the streams stall for well under two seconds (a healthy lane is re-dialed at once)
#   F  failback during a transfer: the lanes start on the fallback carrier (quicv2), the primary comes back, the lanes
#      move up to it while the streams are running — and the streams survive the move
import asyncio, hashlib, os, re, socket, subprocess, sys, tempfile, threading, time

bin_ = sys.argv[1]
TOK = "y5vi1yDXCE3pHH+QxG2rYLIm+GymyTQNHsZvQgTY+d0="
E_SEC = "XYy/JIqEm5D7gIaPT7TKhfFLQRbzOQVai2Uob5XBI9Q="; E_PEER = "gB9DNAluC10n35eTNAmiViQ7TpgF6GGGLflaevE/dHM="
X_SEC = "F3pB1tEoWjqv3efHYXh5FVIP7Rdn7AWolFcumq6JK2I="; X_PEER = "XbcC/IxQ4MHEUijmoE4Av7ImvTEeA9v6yBrYS6mKdHo="
BACK, TUN, CUT, FWD, P_QUIC = 5381, 7081, 7082, 15691, 7084
STREAMS, MB, PACE = 6, 12, 0.012          # 6 streams x 12 MB, ~64 KB every 12 ms each (~5 MB/s per stream, ~2.5 s)
tmp = tempfile.mkdtemp(prefix="rkres-")
ok = True


def say(name, passed, extra=""):
    global ok
    ok &= passed
    print(f"  {'PASS' if passed else 'FAIL'}  {name} {extra}", flush=True)


def config(role, resume, grace, links=False):
    common = f'token = "{TOK}"\ncarrier = "tcp"\n'
    if resume:
        common += f"resume = true\nresume_grace = {grace}\n"
    quic = f'[[link]]\ncarrier = "quicv2"\naddr = "127.0.0.1:{P_QUIC}"\n' if links else ""
    if role == "entry":
        return f'''role = "entry"
{common}static_secret = "{E_SEC}"
peer_public = "{E_PEER}"
tunnel_listen = "127.0.0.1:{TUN}"
{quic}[[forward]]
listen = "127.0.0.1:{FWD}"
target = "127.0.0.1:{BACK}"
'''
    return f'''role = "exit"
{common}static_secret = "{X_SEC}"
peer_public = "{X_PEER}"
tunnel_connect = "127.0.0.1:{CUT}"
lanes = 2
{"link_probe = 2" + chr(10) if links else ""}{quic}'''


class Loop:
    """An asyncio loop in its own thread, for the helpers around the system under test."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=lambda: (asyncio.set_event_loop(self.loop), self.loop.run_forever()), daemon=True).start()

    def run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)


async def echo(r, w):
    try:
        while True:
            d = await r.read(1 << 16)
            if not d:
                break
            w.write(d)
            await w.drain()
        if w.can_write_eof():
            w.write_eof()
    except Exception:
        pass
    finally:
        w.close()


class Cutter:
    """A TCP proxy between the exit and the entry that can kill every connection at once, or refuse new ones."""

    def __init__(self, helper):
        self.pairs, self.blocked, self.loop = set(), False, helper.loop
        helper.run(asyncio.start_server(self.handle, "127.0.0.1", CUT))

    async def handle(self, r, w):
        if self.blocked:
            w.transport.abort()
            return
        try:
            tr, tw = await asyncio.open_connection("127.0.0.1", TUN)
        except OSError:
            w.transport.abort()
            return
        pair = (w, tw)
        self.pairs.add(pair)

        async def pipe(src, dst):
            try:
                while True:
                    d = await src.read(1 << 16)
                    if not d:
                        break
                    dst.write(d)
                    await dst.drain()
            except Exception:
                pass
            finally:
                dst.close()

        await asyncio.gather(pipe(r, tw), pipe(tr, w))
        self.pairs.discard(pair)

    def sever(self):
        def go():
            for a, b in list(self.pairs):
                a.transport.abort()
                b.transport.abort()
        self.loop.call_soon_threadsafe(go)


helper = Loop()
helper.run(asyncio.start_server(echo, "127.0.0.1", BACK))
cutter = Cutter(helper)


def start(resume, grace=30, links=False):
    """Fresh entry and exit; returns (procs, entry log path, exit log path)."""
    d = tempfile.mkdtemp(dir=tmp)
    for role in ("entry", "exit"):
        open(f"{d}/{role}.toml", "w").write(config(role, resume, grace, links))
    procs = []
    procs.append(subprocess.Popen([bin_, "run", "-c", f"{d}/entry.toml"], stdout=open(f"{d}/entry.log", "w"), stderr=subprocess.STDOUT))
    time.sleep(0.6)
    procs.append(subprocess.Popen([bin_, "run", "-c", f"{d}/exit.toml"], stdout=open(f"{d}/exit.log", "w"), stderr=subprocess.STDOUT))
    return procs, f"{d}/entry.log", f"{d}/exit.log"


def stop(procs):
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(5)
        except Exception:
            p.kill()


def lane_ready(timeout=20):
    """A short echo through the tunnel works."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", FWD), timeout=2)
            s.settimeout(2)
            s.sendall(b"ping")
            if s.recv(4) == b"ping":
                s.close()
                return True
            s.close()
        except OSError:
            pass
        time.sleep(0.3)
    return False


async def one_stream(i, progress, mb=MB, pace=PACE):
    """mb megabytes of random data out, the echo back, half-close at the end. Returns True if every byte came back intact."""
    sent, got = hashlib.sha256(), hashlib.sha256()
    total = mb << 20
    progress[i] = [0, 0, 0.0]                    # sent, received, longest silence of the echo
    last = time.time()
    try:
        r, w = await asyncio.open_connection("127.0.0.1", FWD)

        async def send():
            n = 0
            while n < total:
                piece = os.urandom(min(65536, total - n))
                sent.update(piece)
                w.write(piece)
                await w.drain()
                n += len(piece)
                progress[i][0] = n
                await asyncio.sleep(pace)
            w.write_eof()

        async def recv():
            nonlocal last
            while True:
                d = await r.read(1 << 16)
                if not d:
                    break
                got.update(d)
                progress[i][1] += len(d)
                now = time.time()
                progress[i][2] = max(progress[i][2], now - last)
                last = now

        await asyncio.wait_for(asyncio.gather(send(), recv()), 90)
    except Exception:
        return False
    return progress[i][1] == total and got.hexdigest() == sent.hexdigest()


async def transfer(cuts, streams=STREAMS, mb=MB, pace=PACE):
    """All streams at once; the lane connections are severed at the given times (seconds after the start)."""
    progress = {}
    tasks = [asyncio.create_task(one_stream(i, progress, mb, pace)) for i in range(streams)]
    seen = []
    t0 = time.time()
    for at in cuts:
        await asyncio.sleep(max(0, at - (time.time() - t0)))
        seen.append(sum(p[0] for p in progress.values()) / (streams * (mb << 20)))
        cutter.sever()
    res = await asyncio.gather(*tasks)
    stall = max((p[2] for p in progress.values()), default=0)
    return res, seen, time.time() - t0, stall


def log_lines(path, pattern):
    return [m for m in (re.search(pattern, l) for l in open(path, errors="replace")) if m]


procs = []
try:
    print("A: resume = true, both ends; the lanes are cut twice during the transfer")
    procs, elog, xlog = start(True)
    say("A0 the tunnel comes up", lane_ready())
    res, seen, secs, stall = asyncio.run(transfer([0.8, 2.2]))
    print(f"   cut at {', '.join(f'{s:.0%}' for s in seen)} of the data sent; {sum(res)}/{len(res)} streams intact; {secs:.1f}s")
    say("A1 the cuts landed in the middle of the transfer", all(0.03 < s < 0.9 for s in seen), f"({', '.join(f'{s:.0%}' for s in seen)})")
    say("A2 every stream finished with every byte intact", all(res), f"({sum(res)}/{len(res)})")
    moved = [int(m.group(1)) for m in log_lines(elog, r"lane \d+ down: (\d+) stream")] + [int(m.group(1)) for m in log_lines(xlog, r"lane \d+ down: (\d+) stream")]
    say("A3 the logs show streams that lost their lane and resumed", sum(moved) > 0 and bool(log_lines(elog, r"stream\(s\) resume|move to lane")), f"({sum(moved)} stream-moves logged)")
    stop(procs)

    print("D: one unpaced 64 MB stream, four cuts in quick succession")
    procs, elog, xlog = start(True)
    say("D0 the tunnel comes up", lane_ready())
    res, seen, secs, stall = asyncio.run(transfer([0.5, 1.3, 2.1, 2.9], streams=1, mb=64, pace=0))
    print(f"   cut at {', '.join(f'{s:.0%}' for s in seen)} of the data sent; {sum(res)}/{len(res)} streams intact; {secs:.1f}s")
    say("D1 the stream finished with every byte intact", all(res), f"(64 MB, {secs:.1f}s)")
    stop(procs)

    print("E: lanes that have been up for 16 s are cut once")
    procs, elog, xlog = start(True)
    say("E0 the tunnel comes up", lane_ready())
    time.sleep(16)                                          # a lane that lived this long is proven healthy: re-dialed at once
    res, seen, secs, stall = asyncio.run(transfer([0.5], streams=4, mb=6))
    say("E1 every stream finished with every byte intact", all(res), f"({sum(res)}/{len(res)})")
    say("E2 the longest stall was well under two seconds", stall < 2.0, f"({stall:.2f}s)")
    stop(procs)

    print("F: failback during a transfer (lanes start on quicv2, the primary tcp comes back mid-transfer)")
    cutter.blocked = True
    procs, elog, xlog = start(True, links=True)
    say("F0 the lanes come up on the fallback carrier", lane_ready(25))

    async def failback_case():
        progress = {}
        tasks = [asyncio.create_task(one_stream(i, progress, 24, PACE)) for i in range(4)]
        await asyncio.sleep(1.0)
        cutter.blocked = False                              # the primary is reachable again; the lanes probe every 2 s
        return await asyncio.gather(*tasks)

    res = asyncio.run(failback_case())
    moved = log_lines(xlog, r"moving up to")
    say("F1 the lanes moved up to the primary while the streams were running", len(moved) > 0, f"({len(moved)} lane moves logged)")
    say("F2 every stream finished with every byte intact", all(res), f"({sum(res)}/{len(res)})")
    stop(procs)
    cutter.blocked = False

    print("B: the same without resume (control)")
    procs, elog, xlog = start(False)
    say("B0 the tunnel comes up", lane_ready())
    res, seen, secs, stall = asyncio.run(transfer([0.8]))
    say("B1 without resume the cut breaks the streams", not any(res), f"({sum(res)}/{len(res)} survived; they must not)")
    stop(procs)

    print("C: resume_grace = 3, no lane for longer than that")
    procs, elog, xlog = start(True, grace=3)
    say("C0 the tunnel comes up", lane_ready())

    async def grace_case():
        r, w = await asyncio.open_connection("127.0.0.1", FWD)
        w.write(b"hello")
        await w.drain()
        assert await asyncio.wait_for(r.readexactly(5), 5) == b"hello"
        cutter.blocked = True
        cutter.sever()
        t = time.time()
        try:
            await asyncio.wait_for(r.read(), 20)               # the stream is given up: EOF or reset
            closed = True
        except (ConnectionError, OSError):
            closed = True
        except asyncio.TimeoutError:
            closed = False
        return closed, time.time() - t

    closed, waited = asyncio.run(grace_case())
    say("C1 the stream is closed once the grace period has passed", closed and 2 < waited < 15, f"({waited:.1f}s)")
    cutter.blocked = False
    say("C2 the tunnel works again when a lane comes back", lane_ready(40))
    stop(procs)
finally:
    stop(procs)
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
