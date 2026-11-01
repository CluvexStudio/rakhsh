use super::*;
use tokio::net::TcpListener;

fn digest(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}

fn b(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

#[test]
fn frames_round_trip() {
    let o = Bytes::from(open_frame(7, Some("1.2.3.4:5"), "example.org:443"));
    match parse(&o).unwrap() {
        RFrame::Open { id, client, target } => {
            assert_eq!(
                (id, client.as_deref(), target.as_str()),
                (7, Some("1.2.3.4:5"), "example.org:443")
            )
        }
        f => panic!("{f:?}"),
    }
    match parse(&Bytes::from(open_frame(8, None, "x:1"))).unwrap() {
        RFrame::Open { client, .. } => assert!(client.is_none()),
        f => panic!("{f:?}"),
    }
    match parse(&Bytes::from(data_frame(u64::MAX - 3, 1 << 40, b"hello"))).unwrap() {
        RFrame::Data { id, off, payload } => assert_eq!(
            (id, off, &payload[..]),
            (u64::MAX - 3, 1 << 40, &b"hello"[..])
        ),
        f => panic!("{f:?}"),
    }
    match parse(&Bytes::from(sync_frame(9, 100, 90, true, false))).unwrap() {
        RFrame::Sync {
            id,
            rx_off,
            consumed,
            reply,
            force,
        } => {
            assert_eq!(
                (id, rx_off, consumed, reply, force),
                (9, 100, 90, true, false)
            )
        }
        f => panic!("{f:?}"),
    }
    assert!(matches!(
        parse(&Bytes::from(sync_frame(9, 1, 1, false, true))),
        Some(RFrame::Sync {
            reply: false,
            force: true,
            ..
        })
    ));
    assert!(matches!(
        parse(&Bytes::from(ack_frame(1, 5))),
        Some(RFrame::Ack { id: 1, consumed: 5 })
    ));
    assert!(matches!(
        parse(&Bytes::from(close_frame(2))),
        Some(RFrame::Close { id: 2 })
    ));
    assert!(
        parse(&Bytes::from_static(&[R_DATA, 0, 0, 0])).is_none(),
        "a cut frame is rejected"
    );
    assert!(
        parse(&Bytes::from_static(&[1, 0, 0, 0, 0, 0, 0, 0, 1])).is_none(),
        "a plain frame type is not ours"
    );
}

#[test]
fn frames_leave_room_for_the_record_tag() {
    for f in [
        open_frame(1, None, "a:1"),
        data_frame(1, 0, &[0; 100]),
        ack_frame(1, 5),
        sync_frame(1, 0, 0, true, true),
        close_frame(1),
    ] {
        assert!(
            f.capacity() >= f.len() + TAG,
            "sealing in place must not reallocate"
        );
    }
}

#[test]
fn the_receiver_takes_each_byte_once_whatever_arrives() {
    let mut rx = Rx::default();
    assert_eq!(rx.accept(0, &b("hello")), Take::Deliver(b("hello")));
    assert_eq!(
        rx.accept(0, &b("hello")),
        Take::Duplicate,
        "a repeat is ignored"
    );
    assert_eq!(
        rx.accept(8, &b("late")),
        Take::Gap,
        "something is missing before this"
    );
    assert_eq!(
        rx.accept(3, &b("loworld")),
        Take::Deliver(b("world")),
        "an overlapping retransmission contributes only its new tail"
    );
    assert_eq!(rx.off, 10);
    assert_eq!(
        rx.accept(10, &Bytes::new()),
        Take::Fin,
        "an empty frame is the FIN unit"
    );
    assert_eq!(rx.accept(10, &Bytes::new()), Take::Duplicate);
    assert_eq!(rx.off, 11);
}

#[test]
fn the_sender_keeps_what_is_unacked_and_resends_from_any_point() {
    let mut tx = Tx::default();
    assert_eq!(tx.push(Chunk::Data(b("aaaa"))), 0);
    assert_eq!(tx.push(Chunk::Data(b("bbbb"))), 4);
    assert_eq!(tx.push(Chunk::Fin), 8);
    assert_eq!(tx.off, 9);
    assert_eq!(
        tx.resend(0),
        vec![
            (0, Chunk::Data(b("aaaa"))),
            (4, Chunk::Data(b("bbbb"))),
            (8, Chunk::Fin)
        ]
    );
    assert_eq!(
        tx.resend(6),
        vec![(6, Chunk::Data(b("bb"))), (8, Chunk::Fin)]
    );
    assert_eq!(tx.resend(9), vec![]);
    assert_eq!(tx.ack(4), 4);
    assert_eq!(tx.buffered(), 2);
    assert_eq!(tx.ack(4), 0, "a repeated ack changes nothing");
    assert_eq!(tx.ack(2), 0, "an older ack changes nothing");
    assert_eq!(tx.ack(6), 2);
    assert_eq!(tx.buffered(), 2, "half-acknowledged chunk is kept whole");
    assert_eq!(
        tx.ack(1000),
        3,
        "an ack past the end is clamped to what was sent"
    );
    assert_eq!(tx.buffered(), 0);
}

#[test]
fn a_resync_after_loss_rebuilds_the_stream_exactly() {
    let mut tx = Tx::default();
    let chunks: Vec<Bytes> = (0..5).map(|i| Bytes::from(vec![b'a' + i; 100])).collect();
    for c in &chunks {
        tx.push(Chunk::Data(c.clone()));
    }
    let mut rx = Rx::default();
    let mut out = Vec::new();
    for (i, c) in chunks.iter().enumerate().take(3) {
        let part = if i == 2 { c.slice(..50) } else { c.clone() };
        if let Take::Deliver(d) = rx.accept((i * 100) as u64, &part) {
            out.extend_from_slice(&d);
        }
    }
    tx.ack(rx.off);
    for (off, c) in tx.resend(rx.off) {
        let Chunk::Data(d) = c else { unreachable!() };
        if let Take::Deliver(d) = rx.accept(off, &d) {
            out.extend_from_slice(&d);
        }
    }
    let want: Vec<u8> = chunks.iter().flat_map(|c| c.to_vec()).collect();
    assert_eq!(out, want, "every byte exactly once, in order");
}

struct Wire {
    entry: Arc<Hub>,
    exit: Arc<Hub>,
    next: u64,
    pumps: HashMap<u64, Vec<tokio::task::AbortHandle>>,
    pace: Duration,
}

impl Wire {
    fn new(grace: Duration, pace: Duration) -> Wire {
        Wire {
            entry: Hub::new(true, grace),
            exit: Hub::new(false, grace),
            next: 0,
            pumps: HashMap::new(),
            pace,
        }
    }

    fn lane(&mut self) -> u64 {
        self.next += 1;
        let id = self.next;
        let (e_tx, mut e_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (x_tx, mut x_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (exit, entry, pace) = (self.exit.clone(), self.entry.clone(), self.pace);
        let h1 = tokio::spawn(async move {
            while let Some(f) = e_rx.recv().await {
                tokio::time::sleep(pace).await;
                exit.on_frame(id, &Bytes::from(f)).await;
            }
        });
        let h2 = tokio::spawn(async move {
            while let Some(f) = x_rx.recv().await {
                tokio::time::sleep(pace).await;
                entry.on_frame(id, &Bytes::from(f)).await;
            }
        });
        self.pumps
            .insert(id, vec![h1.abort_handle(), h2.abort_handle()]);
        self.entry.lane_up(id, e_tx);
        self.exit.lane_up(id, x_tx);
        id
    }

    fn kill(&mut self, id: u64) {
        for h in self.pumps.remove(&id).unwrap_or_default() {
            h.abort();
        }
        self.entry.lane_down(id);
        self.exit.lane_down(id);
    }
}

async fn echo_server() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

async fn user_through(wire: &Wire, target: &str) -> tokio::net::TcpStream {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let user = tokio::net::TcpStream::connect(l.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = l.accept().await.unwrap();
    let s = wire.entry.open(target, None).await.expect("a lane is up");
    tokio::spawn(s.run(accepted, Bytes::new(), None));
    user
}

async fn echo_through(user: tokio::net::TcpStream, data: Vec<u8>) -> Vec<u8> {
    let (mut rd, mut wr) = user.into_split();
    let writer = tokio::spawn(async move {
        for piece in data.chunks(64 * 1024) {
            wr.write_all(piece).await.unwrap();
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        wr.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), rd.read_to_end(&mut got))
        .await
        .expect("the echo ended")
        .unwrap();
    writer.await.unwrap();
    got
}

fn payload(n: usize) -> Vec<u8> {
    (0..n as u64)
        .map(|i| (i.wrapping_mul(2654435761) >> 7) as u8)
        .collect()
}

#[tokio::test]
async fn a_stream_survives_the_loss_of_its_only_lane() {
    let mut wire = Wire::new(Duration::from_secs(30), Duration::from_micros(300));
    let target = echo_server().await;
    let first = wire.lane();
    let user = user_through(&wire, &target).await;
    let data = payload(6 * 1024 * 1024);
    let want = digest(&data);
    let t = tokio::spawn(echo_through(user, data));
    tokio::time::sleep(Duration::from_millis(60)).await;
    wire.kill(first);
    assert_eq!(
        wire.entry.streams(),
        1,
        "the stream is kept while it has no lane"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    wire.lane();
    let got = t.await.unwrap();
    assert_eq!(got.len(), 6 * 1024 * 1024);
    assert_eq!(digest(&got), want, "every byte, once, in order");
    assert!(
        wire.entry.resent() + wire.exit.resent() > 0,
        "the kill must have cost something to repair, or the test proves nothing"
    );
}

#[tokio::test]
async fn a_stream_moves_to_another_live_lane_at_once() {
    let mut wire = Wire::new(Duration::from_secs(30), Duration::from_micros(300));
    let target = echo_server().await;
    let (a, b_) = (wire.lane(), wire.lane());
    let user = user_through(&wire, &target).await;
    let data = payload(4 * 1024 * 1024);
    let want = digest(&data);
    let t = tokio::spawn(echo_through(user, data));
    tokio::time::sleep(Duration::from_millis(40)).await;
    wire.kill(a);
    tokio::time::sleep(Duration::from_millis(40)).await;
    wire.kill(b_);
    tokio::time::sleep(Duration::from_millis(100)).await;
    wire.lane();
    let got = t.await.unwrap();
    assert_eq!(digest(&got), want);
    assert!(
        wire.entry.resent() + wire.exit.resent() > 0,
        "the kills must have cost something to repair"
    );
}

#[tokio::test]
async fn many_streams_and_repeated_lane_losses() {
    let mut wire = Wire::new(Duration::from_secs(30), Duration::from_micros(200));
    let target = echo_server().await;
    wire.lane();
    let mut tasks = Vec::new();
    for i in 0..8usize {
        let user = user_through(&wire, &target).await;
        let data = payload(1024 * 1024 + i * 1000);
        let want = digest(&data);
        tasks.push((tokio::spawn(echo_through(user, data)), want));
    }
    for round in 0..4 {
        tokio::time::sleep(Duration::from_millis(60)).await;
        let live = *wire.pumps.keys().next().unwrap();
        wire.kill(live);
        tokio::time::sleep(Duration::from_millis(20 + round * 10)).await;
        wire.lane();
    }
    for (t, want) in tasks {
        assert_eq!(digest(&t.await.unwrap()), want);
    }
    assert!(
        wire.entry.resent() + wire.exit.resent() > 0,
        "the kills must have cost something to repair"
    );
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_random_lane_losses_never_change_a_byte() {
    let seeds = std::env::var("RESUME_CHAOS_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6u64);
    for seed in 1..=seeds {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut wire = Wire::new(
            Duration::from_secs(30),
            Duration::from_micros(100 + rng.below(400)),
        );
        let target = echo_server().await;
        for _ in 0..1 + rng.below(3) {
            wire.lane();
        }
        let mut tasks = Vec::new();
        for i in 0..3 + rng.below(4) {
            let user = user_through(&wire, &target).await;
            let data: Vec<u8> = payload(200_000 + rng.below(900_000) as usize)
                .iter()
                .map(|b| b.wrapping_add((seed + i) as u8))
                .collect();
            let want = digest(&data);
            tasks.push((tokio::spawn(echo_through(user, data)), want));
        }
        for _ in 0..3 + rng.below(4) {
            tokio::time::sleep(Duration::from_millis(5 + rng.below(60))).await;
            let live: Vec<u64> = wire.pumps.keys().copied().collect();
            match (rng.below(4), live.is_empty()) {
                (_, true) | (2, _) => {
                    wire.lane();
                }
                (3, false) => {
                    let id = live[rng.below(live.len() as u64) as usize];
                    if rng.below(2) == 0 {
                        wire.entry.lane_down(id);
                    } else {
                        wire.exit.lane_down(id);
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    wire.kill(id);
                }
                (_, false) => {
                    let id = live[rng.below(live.len() as u64) as usize];
                    wire.kill(id);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        if wire.pumps.is_empty() {
            wire.lane();
        }
        for (t, want) in tasks {
            assert_eq!(digest(&t.await.unwrap()), want, "seed {seed}");
        }
    }
}

#[tokio::test]
async fn a_stream_with_no_lane_for_too_long_is_given_up() {
    let mut wire = Wire::new(Duration::from_secs(1), Duration::from_micros(100));
    let target = echo_server().await;
    let first = wire.lane();
    let user = user_through(&wire, &target).await;
    let (mut rd, mut wr) = user.into_split();
    wr.write_all(b"hello").await.unwrap();
    let mut hello = [0u8; 5];
    rd.read_exact(&mut hello).await.unwrap();
    wire.kill(first);
    let mut rest = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(6), rd.read_to_end(&mut rest)).await;
    assert!(
        r.is_ok(),
        "the user's connection is closed after the grace period"
    );
    assert_eq!(wire.entry.streams(), 0);
}

#[tokio::test]
async fn both_ends_forget_a_stream_the_user_hung_up() {
    let mut wire = Wire::new(Duration::from_secs(30), Duration::from_micros(100));
    let target = echo_server().await;
    wire.lane();
    let user = user_through(&wire, &target).await;
    let (mut rd, mut wr) = user.into_split();
    wr.write_all(b"hi").await.unwrap();
    let mut two = [0u8; 2];
    rd.read_exact(&mut two).await.unwrap();
    assert_eq!((wire.entry.streams(), wire.exit.streams()), (1, 1));
    drop((rd, wr));
    for _ in 0..50 {
        if wire.entry.streams() == 0 && wire.exit.streams() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "streams left behind: entry {}, exit {}",
        wire.entry.streams(),
        wire.exit.streams()
    );
}

#[tokio::test]
async fn a_new_stream_is_opened_again_when_its_open_was_lost_with_the_lane() {
    let mut wire = Wire::new(Duration::from_secs(30), Duration::from_millis(80));
    let target = echo_server().await;
    let first = wire.lane();
    let user = user_through(&wire, &target).await;
    let (mut rd, mut wr) = user.into_split();
    wr.write_all(b"before the loss").await.unwrap();
    wire.kill(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    wire.lane();
    let mut got = vec![0u8; 15];
    tokio::time::timeout(Duration::from_secs(10), rd.read_exact(&mut got))
        .await
        .expect("echo arrived")
        .unwrap();
    assert_eq!(&got, b"before the loss");
}
