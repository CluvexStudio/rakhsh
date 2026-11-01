use super::*;

#[test]
fn candidate_forms() {
    assert_eq!(
        parse_candidates("8.8.4.4").unwrap(),
        vec!["8.8.4.4".parse::<Ipv4Addr>().unwrap()]
    );
    let c = parse_candidates("10.0.0.0/30").unwrap();
    assert_eq!(c.len(), 2);
    let r = parse_candidates("9.9.9.1-9.9.9.3").unwrap();
    assert_eq!(r.len(), 3);
    assert_eq!(parse_candidates("1.1.1.1, 2.2.2.2").unwrap().len(), 2);
    assert!(parse_candidates("10.0.0.0/8").is_err());
    assert!(parse_candidates("9.9.9.9-9.9.9.1").is_err());
}

#[test]
fn probe_tag_is_keyed() {
    let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
    assert_eq!(tag("a", ip, 1), tag("a", ip, 1));
    assert_ne!(tag("a", ip, 1), tag("b", ip, 1));
    assert_ne!(tag("a", ip, 1), tag("a", ip, 2));
}

#[test]
fn built_packet_has_valid_ip_header_checksum() {
    let p = build_udp(
        "1.2.3.4".parse().unwrap(),
        "5.6.7.8".parse().unwrap(),
        1000,
        2000,
        b"hello",
        7,
    );
    assert_eq!(checksum(&p[..20], 0), 0);
    assert_eq!(&p[12..16], &[1, 2, 3, 4]);
}
