use super::*;

#[test]
fn parses_ipv4_domain_and_ipv6_datagrams() {
    let (d, off) = parse_udp_datagram(&[0, 0, 0, 1, 1, 2, 3, 4, 0, 53, b'h', b'i']).unwrap();
    assert_eq!(d.host, Host::Ip("1.2.3.4".parse().unwrap()));
    assert_eq!(d.port, 53);
    assert_eq!(&[0, 0, 0, 1, 1, 2, 3, 4, 0, 53, b'h', b'i'][off..], b"hi");
    let mut p = vec![0, 0, 0, 3, 11];
    p.extend_from_slice(b"example.com");
    p.extend_from_slice(&[1, 187]);
    p.extend_from_slice(b"x");
    let (d, off) = parse_udp_datagram(&p).unwrap();
    assert_eq!(d.host, Host::Domain("example.com".into()));
    assert_eq!(d.port, 443);
    assert_eq!(&p[off..], b"x");
    let mut p = vec![0, 0, 0, 4];
    p.extend_from_slice(&"::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    p.extend_from_slice(&[0, 80]);
    let (d, _) = parse_udp_datagram(&p).unwrap();
    assert_eq!(d.host, Host::Ip("::1".parse().unwrap()));
}

#[test]
fn rejects_fragments_and_truncated() {
    assert!(parse_udp_datagram(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 53]).is_none());
    assert!(parse_udp_datagram(&[0, 0, 0, 1, 1, 2]).is_none());
    assert!(parse_udp_datagram(&[0, 0, 0, 9, 1, 2, 3, 4, 0, 53]).is_none());
}

#[test]
fn reply_header_roundtrips_through_the_parser() {
    let from = Dest {
        host: Host::Ip("9.9.9.9".parse().unwrap()),
        port: 5353,
    };
    let mut dg = udp_reply_header(&from);
    dg.extend_from_slice(b"answer");
    let (d, off) = parse_udp_datagram(&dg).unwrap();
    assert_eq!(d.host, from.host);
    assert_eq!(d.port, 5353);
    assert_eq!(&dg[off..], b"answer");
}
