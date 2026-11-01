use super::*;

fn response(query: &[u8], answers: &[(u32, [u8; 4])], code: u8) -> Vec<u8> {
    let end = parse_question(query).unwrap().3;
    let mut r = query[..end].to_vec();
    r[2] = 0x81;
    r[3] = 0x80 | code;
    r[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
    for (ttl, ip) in answers {
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&[0, 4]);
        r.extend_from_slice(ip);
    }
    r
}

#[test]
fn questions_parse_and_names_are_lowercased() {
    let q = build_query(0xBEEF, "WWW.Example.COM.", 28);
    let (name, t, c, end) = parse_question(&q).unwrap();
    assert_eq!(
        (name.as_str(), t, c, end),
        ("www.example.com", 28, 1, q.len())
    );
    assert!(parse_question(&q[..8]).is_none());
    let mut two = q.clone();
    two[5] = 2;
    assert!(parse_question(&two).is_none());
    let mut ptr = q.clone();
    ptr[12] = 0xC0;
    assert!(parse_question(&ptr).is_none());
}

#[test]
fn answers_ttls_and_addresses_are_read_through_compression() {
    let q = build_query(1, "a.example", 1);
    let r = response(&q, &[(300, [1, 2, 3, 4]), (60, [5, 6, 7, 8])], 0);
    assert_eq!(
        answer_ips(&r),
        vec![IpAddr::from([1, 2, 3, 4]), IpAddr::from([5, 6, 7, 8])]
    );
    assert_eq!(min_ttl(&r), Some(60));
    assert_eq!(rcode(&r), 0);
    assert!(!truncated(&r));
    assert_eq!(
        skip_name(&r, 12),
        Some(12 + 1 + 1 + 1 + 7 + 1),
        "labels end at the zero byte"
    );
    assert_eq!(
        skip_name(&[0xC0, 0x0C, 9], 0),
        Some(2),
        "a pointer is two bytes"
    );
    assert!(
        min_ttl(&r[..r.len() - 3]).is_none(),
        "a cut record is rejected, not misread"
    );
}

#[test]
fn error_replies_keep_the_id_and_question_and_drop_the_answers() {
    let q = build_query(0xABCD, "blocked.example", 1);
    let r = error_reply(&q, RCODE_NXDOMAIN);
    assert_eq!(&r[..2], &[0xAB, 0xCD]);
    assert_eq!(rcode(&r), RCODE_NXDOMAIN);
    assert_eq!(r[2] & 0x80, 0x80, "QR set");
    assert_eq!(r[2] & 0x01, 0x01, "RD echoed");
    assert_eq!(&r[6..12], &[0; 6]);
    assert_eq!(parse_question(&r).unwrap().0, "blocked.example");
    assert_eq!(
        error_reply(&q[..5], RCODE_FORMERR).len(),
        12,
        "garbage still gets a header-only reply"
    );
}

#[test]
fn cache_serves_until_the_ttl_and_never_grows_without_bound() {
    let mut c = Cache {
        map: HashMap::new(),
        cap: 2,
    };
    let t0 = Instant::now();
    let k = |n: &str| (n.to_string(), 1u16, 1u16);
    c.put(k("a"), vec![1], Duration::from_secs(10), t0);
    assert_eq!(c.get(&k("a"), t0 + Duration::from_secs(9)), Some(vec![1]));
    assert_eq!(
        c.get(&k("a"), t0 + Duration::from_secs(10)),
        None,
        "expired"
    );
    c.put(k("b"), vec![2], Duration::from_secs(100), t0);
    c.put(k("c"), vec![3], Duration::from_secs(100), t0);
    assert!(c.map.len() <= 2, "capacity holds");
    let mut off = Cache {
        map: HashMap::new(),
        cap: 0,
    };
    off.put(k("x"), vec![0], Duration::from_secs(5), t0);
    assert!(off.map.is_empty(), "cache = 0 turns it off");
}

#[test]
fn servers_and_resolv_conf_parse() {
    assert_eq!(
        parse_server("1.1.1.1").unwrap(),
        "1.1.1.1:53".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(parse_server("9.9.9.9:5353").unwrap().port(), 5353);
    assert_eq!(parse_server("[2606:4700:4700::1111]").unwrap().port(), 53);
    assert!(parse_server("not-an-ip").is_err());
    let conf = "# comment\nsearch lan\nnameserver 10.0.0.1\nnameserver  127.0.0.53  extra\noptions edns0\n";
    assert_eq!(
        resolv_conf(conf),
        vec![
            "10.0.0.1:53".parse::<SocketAddr>().unwrap(),
            "127.0.0.53:53".parse().unwrap()
        ]
    );
}
