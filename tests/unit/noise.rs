use super::*;
use async_trait::async_trait;
use std::io;

fn session_for(
    mode: Mode,
) -> (
    Enc,
    Enc,
    snow::StatelessTransportState,
    snow::StatelessTransportState,
) {
    let (ipriv, _) = generate_keypair().unwrap();
    let (rpriv, rpub) = generate_keypair().unwrap();
    let psk = derive_psk("test token");
    let mk = || Builder::new(PARAMS.parse().unwrap());
    let mut i = mk()
        .local_private_key(&ipriv)
        .unwrap()
        .remote_public_key(&rpub)
        .unwrap()
        .psk(2, &psk)
        .unwrap()
        .prologue(mode.prologue())
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut r = mk()
        .local_private_key(&rpriv)
        .unwrap()
        .psk(2, &psk)
        .unwrap()
        .prologue(mode.prologue())
        .unwrap()
        .build_responder()
        .unwrap();
    let (mut b, mut p) = ([0u8; 1024], [0u8; 1024]);
    let n = i.write_message(&[VERSION], &mut b).unwrap();
    r.read_message(&b[..n], &mut p).unwrap();
    let n = r.write_message(&[VERSION], &mut b).unwrap();
    i.read_message(&b[..n], &mut p).unwrap();
    let (ik1, ik2) = i.dangerously_get_raw_split();
    let (rk1, rk2) = r.dangerously_get_raw_split();
    assert_eq!((ik1, ik2), (rk1, rk2), "both sides derive the same split");
    let ie = Enc::from_raw_split(ik1, ik2, true, mode);
    let re = Enc::from_raw_split(rk1, rk2, false, mode);
    (
        ie,
        re,
        i.into_stateless_transport_mode().unwrap(),
        r.into_stateless_transport_mode().unwrap(),
    )
}

fn msg(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|j| (j as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

fn seal(e: &Enc, m: &[u8]) -> Vec<u8> {
    let mut v = m.to_vec();
    v.reserve(TAG);
    e.seal_in_place(&mut v);
    v
}

#[test]
fn ring_records_are_byte_identical_to_snow() {
    let (ie, re, its, rts) = session_for(Mode::Full);
    for (n, len) in [1usize, 5, 64, 1400, 16384, 16389].into_iter().enumerate() {
        let m = msg(len, n as u8);
        let mut ours = m.clone();
        ours.reserve(TAG);
        ie.seal_in_place(&mut ours);
        let mut theirs = vec![0u8; len + TAG];
        let w = its.write_message(n as u64, &m, &mut theirs).unwrap();
        assert_eq!(
            &ours[..],
            &theirs[..w],
            "initiator record {n} differs from snow's"
        );
        let mut out = vec![0u8; len + TAG];
        let got = rts.read_message(n as u64, &ours, &mut out).unwrap();
        assert_eq!(&out[..got], &m[..], "snow opens our record");
        assert_eq!(
            &re.open_vec(ours).unwrap()[..],
            &m[..],
            "we open our own record"
        );
        let mut back = m.clone();
        re.seal_in_place(&mut back);
        let mut sn = vec![0u8; len + TAG];
        let w = rts.write_message(n as u64, &m, &mut sn).unwrap();
        assert_eq!(
            &back[..],
            &sn[..w],
            "responder record {n} differs from snow's"
        );
        let mut out = vec![0u8; len + TAG];
        let got = its.read_message(n as u64, &back, &mut out).unwrap();
        assert_eq!(&out[..got], &m[..]);
        assert_eq!(&ie.open_vec(back).unwrap()[..], &m[..]);
    }
}

#[test]
fn tamper_replay_and_reorder_are_rejected() {
    let (ie, re, _, _) = session_for(Mode::Full);
    let r0 = seal(&ie, b"zero");
    let r1 = seal(&ie, b"one");
    assert!(re.open_vec(r1.clone()).is_err());
    let mut bad = r0.clone();
    bad[0] ^= 1;
    assert!(re.open_vec(bad).is_err());
    assert_eq!(&re.open_vec(r0.clone()).unwrap()[..], b"zero");
    assert!(re.open_vec(r0).is_err());
    assert_eq!(&re.open_vec(r1).unwrap()[..], b"one");
    let loop_back = seal(&ie, b"mirror");
    assert!(ie.open_vec(loop_back).is_err());
}

#[test]
fn none_mode_sends_records_as_they_are_after_record_zero() {
    let (ie, re, _, _) = session_for(Mode::None);
    let r0 = seal(&ie, b"confirm");
    assert_eq!(r0.len(), 7 + TAG);
    assert_ne!(
        &r0[..7],
        b"confirm",
        "record 0 is encrypted even in none mode"
    );
    assert_eq!(&re.open_vec(r0).unwrap()[..], b"confirm");
    let r1 = seal(&ie, b"plain data");
    assert_eq!(&r1[..], b"plain data");
    assert_eq!(&re.open_vec(r1).unwrap()[..], b"plain data");
    let b0 = seal(&re, b"first");
    assert_ne!(&b0[..5], b"first");
    assert_eq!(&ie.open_vec(b0).unwrap()[..], b"first");
    assert_eq!(&seal(&re, b"second")[..], b"second");
}

struct ChanTx(tokio::sync::mpsc::UnboundedSender<Vec<u8>>);
struct ChanRx(tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>);

#[async_trait]
impl FrameTx for ChanTx {
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.0
            .send(frame)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}

#[async_trait]
impl FrameRx for ChanRx {
    async fn recv(&mut self) -> io::Result<bytes::BytesMut> {
        self.0
            .recv()
            .await
            .map(|v| bytes::BytesMut::from(&v[..]))
            .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }
}

type End = (ChanTx, ChanRx);

fn link() -> (End, End) {
    let (a_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
    ((ChanTx(a_tx), ChanRx(a_rx)), (ChanTx(b_tx), ChanRx(b_rx)))
}

fn keys() -> ([u8; 32], [u8; 32]) {
    let (private, public) = generate_keypair().unwrap();
    (private.try_into().unwrap(), public.try_into().unwrap())
}

#[tokio::test]
async fn every_mode_connects_and_carries_records_both_ways() {
    for mode in [Mode::Full, Mode::None] {
        let ((ipriv, ipub), (rpriv, rpub)) = (keys(), keys());
        let psk = derive_psk("a token");
        let ((mut itx, mut irx), (mut rtx, mut rrx)) = link();
        let admitted = [ipub];
        let (ie, re) = tokio::join!(
            client_handshake(&mut itx, &mut irx, &ipriv, &rpub, &psk, mode),
            server_handshake(&mut rtx, &mut rrx, &rpriv, &psk, &admitted, mode)
        );
        let (ie, re) = (ie.unwrap(), re.unwrap().0);
        for round in 0..4u8 {
            let m = msg(1000 + round as usize, round);
            itx.send(seal(&ie, &m)).await.unwrap();
            assert_eq!(
                &re.open_bytes(rrx.recv().await.unwrap()).unwrap()[..],
                &m[..],
                "{mode:?} i->r round {round}"
            );
            rtx.send(seal(&re, &m)).await.unwrap();
            assert_eq!(
                &ie.open_bytes(irx.recv().await.unwrap()).unwrap()[..],
                &m[..],
                "{mode:?} r->i round {round}"
            );
        }
    }
}

#[tokio::test]
async fn ends_with_different_modes_never_connect() {
    for (cm, sm) in [(Mode::Full, Mode::None), (Mode::None, Mode::Full)] {
        let ((ipriv, ipub), (rpriv, rpub)) = (keys(), keys());
        let psk = derive_psk("a token");
        let ((mut itx, mut irx), (mut rtx, mut rrx)) = link();
        let server = tokio::spawn(async move {
            server_handshake_within(
                &mut rtx,
                &mut rrx,
                &rpriv,
                &psk,
                &[ipub],
                sm,
                Duration::from_millis(300),
            )
            .await
            .map(|_| ())
        });
        let client = tokio::spawn(async move {
            client_handshake(&mut itx, &mut irx, &ipriv, &rpub, &psk, cm)
                .await
                .map(|_| ())
        });
        let (server, client) = (server.await.unwrap(), client.await.unwrap());
        assert!(
            server.is_err(),
            "server {sm:?} accepted a client configured {cm:?}"
        );
        assert!(
            client.is_err(),
            "client {cm:?} connected to a server configured {sm:?}"
        );
    }
}

#[tokio::test]
async fn ends_with_different_resume_settings_never_connect() {
    for (cr, sr) in [(true, false), (false, true)] {
        let ((ipriv, ipub), (rpriv, rpub)) = (keys(), keys());
        let psk = derive_psk("a token");
        let ((mut itx, mut irx), (mut rtx, mut rrx)) = link();
        let server = tokio::spawn(async move {
            server_handshake_within(
                &mut rtx,
                &mut rrx,
                &rpriv,
                &psk,
                &[ipub],
                Proto {
                    mode: Mode::Full,
                    resume: sr,
                },
                Duration::from_millis(300),
            )
            .await
            .map(|_| ())
        });
        let client = tokio::spawn(async move {
            client_handshake(
                &mut itx,
                &mut irx,
                &ipriv,
                &rpub,
                &psk,
                Proto {
                    mode: Mode::Full,
                    resume: cr,
                },
            )
            .await
            .map(|_| ())
        });
        let (server, client) = (server.await.unwrap(), client.await.unwrap());
        assert!(
            server.is_err() && client.is_err(),
            "resume {cr} vs {sr} must not connect"
        );
    }
    let ((ipriv, ipub), (rpriv, rpub)) = (keys(), keys());
    let psk = derive_psk("a token");
    let ((mut itx, mut irx), (mut rtx, mut rrx)) = link();
    let p = Proto {
        mode: Mode::Full,
        resume: true,
    };
    let admitted = [ipub];
    let (c, s) = tokio::join!(
        client_handshake(&mut itx, &mut irx, &ipriv, &rpub, &psk, p),
        server_handshake(&mut rtx, &mut rrx, &rpriv, &psk, &admitted, p)
    );
    assert!(c.is_ok() && s.is_ok());
}

#[tokio::test]
async fn a_replayed_handshake_never_opens_a_plaintext_lane() {
    for mode in [Mode::None] {
        let ((ipriv, ipub), (rpriv, rpub)) = (keys(), keys());
        let psk = derive_psk("a token");
        let mut victim = Builder::new(PARAMS.parse().unwrap())
            .local_private_key(&ipriv)
            .unwrap()
            .remote_public_key(&rpub)
            .unwrap()
            .psk(2, &psk)
            .unwrap()
            .prologue(mode.prologue())
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut buf = [0u8; 1024];
        let n = victim.write_message(&[VERSION], &mut buf).unwrap();
        let recorded = buf[..n].to_vec();

        let ((atx, _arx), (mut rtx, mut rrx)) = link();
        atx.0.send(recorded.clone()).unwrap();
        let err = server_handshake_within(
            &mut rtx,
            &mut rrx,
            &rpriv,
            &psk,
            &[ipub],
            mode,
            Duration::from_millis(200),
        )
        .await;
        assert!(
            err.is_err(),
            "{mode:?}: replay with no confirmation was accepted"
        );

        let ((atx, _arx), (mut rtx, mut rrx)) = link();
        atx.0.send(recorded).unwrap();
        atx.0.send(msg(32 + TAG, 7)).unwrap();
        let err = server_handshake_within(
            &mut rtx,
            &mut rrx,
            &rpriv,
            &psk,
            &[ipub],
            mode,
            Duration::from_millis(200),
        )
        .await;
        assert!(
            err.is_err(),
            "{mode:?}: replay with a forged confirmation was accepted"
        );
    }
}

#[test]
fn modes_parse_and_reject_typos() {
    assert_eq!(Mode::parse("full").unwrap(), Mode::Full);
    assert_eq!(Mode::parse(" NONE ").unwrap(), Mode::None);
    assert!(Mode::parse("auth").is_err());
    assert!(Mode::parse("off").is_err());
    assert!(Mode::parse("").is_err());
}

#[tokio::test]
async fn a_responder_admits_any_pinned_identity_and_says_which() {
    let ((a_priv, a_pub), (b_priv, b_pub)) = (keys(), keys());
    let ((r_priv, r_pub), (x_priv, x_pub)) = (keys(), keys());
    let psk = derive_psk("a shared token");
    let admitted = [a_pub, b_pub];

    for (want, (priv_key, _)) in [(0usize, (a_priv, a_pub)), (1, (b_priv, b_pub))] {
        let ((mut itx, mut irx), (mut rtx, mut rrx)) = link();
        let (client, server) = tokio::join!(
            client_handshake(&mut itx, &mut irx, &priv_key, &r_pub, &psk, Mode::Full),
            server_handshake(&mut rtx, &mut rrx, &r_priv, &psk, &admitted, Mode::Full)
        );
        client.unwrap();
        let (_, which) = server.unwrap();
        assert_eq!(
            which, want,
            "the responder must report which identity it admitted"
        );
    }

    let _ = x_pub;
    let ((mut itx, mut irx), (mut rtx, mut rrx)) = link();
    let (_, server) = tokio::join!(
        client_handshake(&mut itx, &mut irx, &x_priv, &r_pub, &psk, Mode::Full),
        server_handshake(&mut rtx, &mut rrx, &r_priv, &psk, &admitted, Mode::Full)
    );
    let err = match server {
        Ok(_) => panic!("an identity outside the set was admitted"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("matches none of the 2 pinned"),
        "an identity outside the set must be refused, got: {err}"
    );
}
