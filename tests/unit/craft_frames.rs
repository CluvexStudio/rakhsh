use super::*;

fn seg() -> Segment {
    Segment::new(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(203, 0, 113, 7),
        31000,
        32000,
    )
}

#[test]
fn frame_has_valid_checksums() {
    let s = seg();
    let p = s.frame(b"hello");
    assert_eq!(p.len(), IP_HDR + TCP_HDR + 5);
    assert_eq!(checksum(&p[..IP_HDR], 0), 0);
    let tcp_len = p.len() - IP_HDR;
    assert_eq!(
        checksum(&p[IP_HDR..], pseudo_sum(s.src, s.peer, 6, tcp_len)),
        0
    );
}

#[test]
fn sequence_advances_by_payload() {
    let s = seg();
    let a = s.frame(b"abc");
    let b = s.frame(b"");
    let seq = |p: &[u8]| u32::from_be_bytes(p[IP_HDR + 4..IP_HDR + 8].try_into().unwrap());
    assert_eq!(seq(&b), seq(&a) + 3);
}

#[test]
fn payload_comes_back_only_for_our_ports() {
    let s = seg();
    let reply = Segment::new(s.peer, s.src, s.dport, s.sport);
    let p = reply.frame(b"pong");
    assert_eq!(tcp_payload(&p, s.sport, s.dport), Some(&b"pong"[..]));
    assert_eq!(tcp_payload(&p, s.sport + 1, s.dport), None);
    assert_eq!(tcp_payload(&p[..IP_HDR + 4], s.sport, s.dport), None);
}

#[test]
fn ethernet_and_vlan_frames_unwrap_to_ip() {
    let ip = seg().frame(b"x");
    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    assert_eq!(ethernet_payload(&eth), Some(&ip[..]));
    let mut vlan = vec![0u8; 12];
    vlan.extend_from_slice(&[0x81, 0x00, 0x00, 0x05, 0x08, 0x00]);
    vlan.extend_from_slice(&ip);
    assert_eq!(ethernet_payload(&vlan), Some(&ip[..]));
    let mut arp = vec![0u8; 12];
    arp.extend_from_slice(&[0x08, 0x06]);
    arp.extend_from_slice(&ip);
    assert_eq!(ethernet_payload(&arp), None);
}
