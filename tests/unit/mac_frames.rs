use super::*;
use std::time::Duration;

#[test]
fn link_layers_unwrap_to_ip() {
    let ip = Segment::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 1, 2).frame(b"x");
    let mut null_frame = 2u32.to_ne_bytes().to_vec();
    null_frame.extend_from_slice(&ip);
    assert_eq!(link_payload(0, &null_frame), Some(&ip[..]));
    assert_eq!(link_payload(12, &ip), Some(&ip[..]));
    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    assert_eq!(link_payload(1, &eth), Some(&ip[..]));
    assert_eq!(link_payload(127, &eth), None);
}

#[test]
fn pcap_header_puts_caplen_after_the_timestamp() {
    assert_eq!(std::mem::offset_of!(PktHdr, caplen), 16);
}

#[test]
#[ignore = "needs root: opens /dev/bpf, a raw socket and a pf anchor"]
fn faketcp_over_loopback() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let params = crate::raw::RawParams::derive("faketcp-loopback-test");
        let lo = Some(Ipv4Addr::LOCALHOST);
        let (mut a_tx, mut a_rx) = connect_faketcp(&params, lo, true, 0).unwrap();
        let (mut b_tx, mut b_rx) = connect_faketcp(&params, lo, false, 0).unwrap();
        a_tx.send(b"ping".to_vec()).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), b_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got[..], b"ping");
        b_tx.send(b"pong".to_vec()).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), a_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got[..], b"pong");
    });
}
