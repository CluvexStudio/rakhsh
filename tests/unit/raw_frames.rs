use super::*;

fn craft() -> L2Craft {
    L2Craft {
        src_mac: [0x52, 0x54, 0x00, 0x11, 0x22, 0x33],
        gw_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        src_ip: Ipv4Addr::new(10, 0, 0, 1),
        peer: Ipv4Addr::new(10, 0, 0, 2),
        sport: 28518,
        dport: 35050,
        seq: 0x1234_5678,
        tsval: 99,
        ip_id: 7,
    }
}

#[test]
fn l2_frame_layout_and_checksums() {
    let c = craft();
    let payload = b"rakhsh-l2-payload";
    let mut f = Vec::new();
    craft_l2_frame(&c, payload, &mut f);

    assert_eq!(&f[0..6], &c.gw_mac, "destination MAC is the gateway");
    assert_eq!(&f[6..12], &c.src_mac);
    assert_eq!(&f[12..14], &[0x08, 0x00], "ethertype IPv4");

    let ip = ETH_HDR;
    let tcp = ETH_HDR + IP4_HDR;
    assert_eq!(f[ip], 0x45, "IPv4 with a 5-word header");
    assert_eq!(
        u16::from_be_bytes([f[ip + 2], f[ip + 3]]) as usize,
        f.len() - ETH_HDR,
        "IP total length covers everything after the Ethernet header"
    );
    assert_eq!(f[ip + 9], 6, "protocol TCP");
    assert_eq!(checksum(&f[ip..tcp], 0), 0, "IP header checksum");

    assert_eq!(u16::from_be_bytes([f[tcp], f[tcp + 1]]), c.sport);
    assert_eq!(u16::from_be_bytes([f[tcp + 2], f[tcp + 3]]), c.dport);
    assert_eq!(
        u32::from_be_bytes([f[tcp + 4], f[tcp + 5], f[tcp + 6], f[tcp + 7]]),
        c.seq
    );
    assert_eq!(
        f[tcp + 12] >> 4,
        ((20 + L2_OPTS) / 4) as u8,
        "data offset covers the options"
    );
    assert_eq!(f[tcp + 13], 0b0001_1000, "PSH|ACK: looks mid-stream");
    let total = f.len() - ETH_HDR;
    assert_eq!(
        checksum(&f[tcp..], pseudo_sum(c.src_ip, c.peer, 6, total - IP4_HDR)),
        0,
        "TCP checksum over the pseudo-header"
    );
    assert_eq!(
        &f[tcp + 20 + L2_OPTS..],
        payload,
        "payload carried verbatim"
    );
}

#[test]
fn l2_frame_is_identical_in_a_recycled_buffer() {
    let c = craft();
    let mut fresh = Vec::new();
    craft_l2_frame(&c, b"second", &mut fresh);
    let mut reused = Vec::new();
    craft_l2_frame(&c, b"a much longer first packet", &mut reused);
    craft_l2_frame(&c, b"second", &mut reused);
    assert_eq!(fresh, reused);
}

#[test]
fn tcp_segment_layout_and_checksum() {
    let (src, peer) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
    let payload = b"rakhsh-faketcp";
    let mut seg = Vec::new();
    craft_tcp_segment(src, peer, 20001, 30002, 42, payload, &mut seg);
    assert_eq!(u16::from_be_bytes([seg[0], seg[1]]), 20001);
    assert_eq!(u16::from_be_bytes([seg[2], seg[3]]), 30002);
    assert_eq!(seg[12] >> 4, 5, "no options on the raw-socket variant");
    assert_eq!(seg[13], 0b0001_1000);
    assert_eq!(
        checksum(&seg, pseudo_sum(src, peer, 6, seg.len())),
        0,
        "TCP checksum"
    );
    assert_eq!(&seg[20..], payload);
    craft_tcp_segment(src, peer, 20001, 30002, 43, b"x", &mut seg);
    assert_eq!(
        seg.len(),
        21,
        "the recycled buffer holds one segment, not two"
    );
}

struct Sink(Mutex<Vec<Vec<u8>>>);

#[async_trait]
impl RawLink for Sink {
    async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        self.0.lock().unwrap().push(payload.to_vec());
        Ok(())
    }
    async fn recv(&self, _out: &mut [u8]) -> std::io::Result<usize> {
        std::future::pending().await
    }
}

struct Replay(Mutex<VecDeque<Vec<u8>>>);

#[async_trait]
impl RawLink for Replay {
    async fn send(&self, _payload: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    async fn recv(&self, out: &mut [u8]) -> std::io::Result<usize> {
        let next = self.0.lock().unwrap().pop_front();
        match next {
            Some(p) => {
                out[..p.len()].copy_from_slice(&p);
                Ok(p.len())
            }
            None => std::future::pending().await,
        }
    }
}

#[tokio::test]
async fn fec_recovers_a_lost_data_shard() {
    let sink = Arc::new(Sink(Mutex::new(Vec::new())));
    let tx = FecLink::new(sink.clone(), 10, 3);
    let payloads: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i + 1; 100 + i as usize]).collect();
    for p in &payloads {
        tx.send(p).await.unwrap();
    }
    let wire = sink.0.lock().unwrap().clone();
    assert_eq!(wire.len(), 13, "ten data shards and three parity shards");

    let kept: VecDeque<Vec<u8>> = wire
        .into_iter()
        .enumerate()
        .filter(|(i, _)| *i != 3)
        .map(|(_, w)| w)
        .collect();
    let rx = FecLink::new(Arc::new(Replay(Mutex::new(kept))), 10, 3);
    let mut buf = scratch64k();
    let mut got = Vec::new();
    for _ in 0..payloads.len() {
        let n = rx.recv(&mut buf).await.unwrap();
        got.push(buf[..n].to_vec());
    }
    got.sort();
    let mut want = payloads;
    want.sort();
    assert_eq!(got, want, "the dropped shard came back out of the parity");
}
