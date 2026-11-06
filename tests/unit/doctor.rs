use super::*;
use crate::config::Config;

fn base() -> Config {
    let text = "role = \"entry\"\n\
                token = \"ERERERERERERERERERERERERERERERERERERERERERE=\"\n\
                static_secret = \"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\"\n\
                peer_public = \"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=\"\n\
                carrier = \"wss\"\n\
                tunnel_listen = \"0.0.0.0:7000\"\n";
    toml::from_str(text).expect("the base config parses")
}

fn verdict(carrier: &str, handshook: bool, held: bool, mbit: f64) -> Verdict {
    Verdict {
        carrier: carrier.to_string(),
        reached: handshook,
        handshook,
        held,
        mbit,
        note: String::new(),
    }
}

#[test]
fn a_probe_config_keeps_the_identity_and_drops_everything_else() {
    let mut b = base();
    b.lanes = Some(8);
    b.forward.push(crate::config::Forward {
        listen: "0.0.0.0:443".into(),
        target: "127.0.0.1:8443".into(),
        udp: false,
        limits: Default::default(),
        proxy_protocol: false,
    });

    let cfg = probe_config(&b, "quic", 7901, Some("198.51.100.7:7901"));
    assert_eq!(cfg.carrier.as_deref(), Some("quic"));
    assert_eq!(cfg.lanes, Some(1), "one lane is enough to measure a path");
    assert_eq!(cfg.tunnel_listen.as_deref(), Some("0.0.0.0:7901"));
    assert_eq!(cfg.tunnel_connect.as_deref(), Some("198.51.100.7:7901"));
    assert!(cfg.forward.is_empty(), "a probe carries no user traffic");
    assert!(
        cfg.link.is_empty(),
        "the links under test are tried one by one"
    );
    assert!(cfg.openvpn.is_none());
    assert_eq!(
        cfg.token, b.token,
        "the identity is kept, or nothing connects"
    );
    assert_eq!(cfg.static_secret, b.static_secret);
}

#[test]
fn a_verdict_reads_as_its_state() {
    assert!(verdict("tcp", true, true, 420.0).usable());
    assert!(!verdict("quic", true, false, 0.0).usable());
    assert!(!verdict("icmp", false, false, 0.0).usable());

    assert!(verdict("tcp", true, true, 420.0).line().contains("ok"));
    assert!(verdict("quic", true, false, 0.0).line().contains("cut"));
    assert!(Verdict::refused("kcp", "no route")
        .line()
        .contains("unreachable"));
    assert!(Verdict::refused("kcp", "no route")
        .line()
        .contains("no route"));
}

#[test]
fn the_report_orders_by_measured_speed() {
    let r = Report {
        verdicts: vec![
            verdict("tcp", true, true, 120.0),
            verdict("quic", true, false, 0.0),
            verdict("wss", true, true, 480.0),
            verdict("kcp", true, true, 95.0),
            verdict("icmp", false, false, 0.0),
        ],
        protocols: vec![],
    };
    let order: Vec<&str> = r.ordered().iter().map(|v| v.carrier.as_str()).collect();
    assert_eq!(
        order,
        vec!["wss", "tcp", "kcp"],
        "only carriers that held, fastest first"
    );
}

#[test]
fn the_emitted_config_puts_the_fastest_first_and_the_rest_as_links() {
    let r = Report {
        verdicts: vec![
            verdict("tcp", true, true, 120.0),
            verdict("wss", true, true, 480.0),
            verdict("quic", true, false, 0.0),
        ],
        protocols: vec![
            (47, "GRE".into(), 5, String::new()),
            (50, "ESP".into(), 0, String::new()),
            (4, "IPv4-in-IPv4".into(), 0, "needs CAP_NET_RAW".into()),
        ],
    };
    let cfg = r.config("198.51.100.7", 443, true);
    assert!(cfg.contains("carrier = \"wss\""), "{cfg}");
    assert!(
        cfg.contains("tunnel_connect = \"198.51.100.7:443\""),
        "{cfg}"
    );
    assert!(cfg.contains("[[link]]\ncarrier = \"tcp\""), "{cfg}");
    assert!(
        !cfg.contains("quic"),
        "a carrier that did not hold must not be offered: {cfg}"
    );

    let head = "token = \"ERERERERERERERERERERERERERERERERERERERERERE=\"\n\
                static_secret = \"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\"\n\
                peer_public = \"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=\"\n";

    for (role, dialing, wanted) in [
        ("exit", true, "tunnel_connect"),
        ("entry", false, "tunnel_listen"),
    ] {
        let body = r.config("198.51.100.7", 443, dialing);
        assert!(
            body.contains(wanted),
            "the {role} side needs {wanted}:\n{body}"
        );
        let text = format!("role = \"{role}\"\n{head}{body}");
        let parsed: Config = match toml::from_str(&text) {
            Ok(c) => c,
            Err(e) => panic!("the doctor must emit a config rakhsh parses: {e}\n{text}"),
        };
        assert!(
            crate::links::describe(&parsed).is_ok(),
            "and one rakhsh can make links from: {:?}",
            crate::links::describe(&parsed).err()
        );
    }
}

#[test]
fn a_path_where_nothing_worked_says_so_instead_of_emitting_a_config() {
    let r = Report {
        verdicts: vec![
            verdict("tcp", false, false, 0.0),
            verdict("wss", true, false, 0.0),
        ],
        protocols: vec![],
    };
    let cfg = r.config("198.51.100.7", 443, true);
    assert!(cfg.contains("No carrier"), "{cfg}");
    assert!(!cfg.contains("carrier = "), "{cfg}");
}

#[test]
fn a_peer_may_carry_its_own_port() {
    assert_eq!(
        parse_peer("198.51.100.7", 7900).unwrap(),
        ("198.51.100.7".to_string(), 7900)
    );
    assert_eq!(
        parse_peer("198.51.100.7:9000", 7900).unwrap(),
        ("198.51.100.7".to_string(), 9000)
    );
    assert!(parse_peer("198.51.100.7:nope", 7900).is_err());
}

#[test]
fn the_plan_is_bounded_so_a_run_cannot_outlast_its_welcome() {
    let all = Plan::new(&[], 8, false).expect("the default plan fits");
    assert_eq!(all.carriers.len(), STREAM_CARRIERS.len());
    assert!(
        all.budget() <= CEILING,
        "a full run must fit in five minutes, it claims {:?}",
        all.budget()
    );

    let one = Plan::new(&["wss".to_string()], 8, false).expect("one carrier fits");
    assert_eq!(one.carriers, vec!["wss"]);
    assert!(one.budget() < all.budget());

    assert!(
        Plan::new(&[], 600, false).is_err(),
        "a plan that would run for an hour must be refused, not started"
    );
    assert!(
        Plan::new(&["nonsense".to_string()], 8, false).is_err(),
        "a carrier rakhsh does not have must be refused before the run"
    );

    let raw = Plan::new(&["l2tcp".to_string(), "wss".to_string()], 8, false).unwrap();
    assert_eq!(raw.privileged(), vec!["l2tcp"], "raw carriers are flagged");
    assert!(Plan::new(&["wss".to_string()], 8, false)
        .unwrap()
        .privileged()
        .is_empty());

    assert!(
        Plan::new(&[], 8, true).unwrap().budget() > all.budget(),
        "asking for the protocol sweep costs time, and the plan says so"
    );
}

#[test]
fn the_protocols_that_crossed_are_recorded_for_the_reader() {
    let r = Report {
        verdicts: vec![verdict("wss", true, true, 10.0)],
        protocols: vec![
            (47, "GRE".into(), 5, String::new()),
            (50, "ESP".into(), 2, String::new()),
            (4, "IPv4-in-IPv4".into(), 0, String::new()),
            (97, "ETHERIP".into(), 0, "needs CAP_NET_RAW".into()),
        ],
    };
    assert_eq!(r.crossing(), vec!["GRE (47)", "ESP (50)"]);
    assert!(r
        .config("198.51.100.7", 443, true)
        .contains("GRE (47), ESP (50)"));
}

#[test]
fn the_written_config_only_sets_what_the_winning_carrier_reads() {
    let stream = Report {
        verdicts: vec![
            verdict("wss", true, true, 90.0),
            verdict("quic", true, true, 50.0),
        ],
        protocols: vec![],
    };
    let text = stream.config("198.51.100.7", 443, true);
    assert!(text.contains("lanes = 4"), "{text}");
    assert!(text.contains("[[link]]\ncarrier = \"quic\""), "{text}");
    assert!(
        !text.contains("peer_ip"),
        "a stream carrier learns the peer from its socket"
    );

    let raw = Report {
        verdicts: vec![verdict("faketcp", true, true, 40.0)],
        protocols: vec![],
    };
    let text = raw.config("198.51.100.7", 443, true);
    assert!(
        text.contains("lanes = 1"),
        "a raw carrier runs one lane: {text}"
    );
    assert!(text.contains("peer_ip = \"198.51.100.7\""), "{text}");

    let dgram = Report {
        verdicts: vec![
            verdict("shabdiz-gre", true, true, 200.0),
            verdict("wss", true, true, 90.0),
        ],
        protocols: vec![],
    };
    let text = dgram.config("198.51.100.7", 443, true);
    assert!(
        !text.contains("lanes ="),
        "a datagram carrier reads no lanes: {text}"
    );
    assert!(!text.contains("\n[[link]]"), "nor any links: {text}");
    assert!(
        text.contains("# The carriers that also held, in measured order: wss."),
        "{text}"
    );
    assert!(text.contains("peer_ip = \"198.51.100.7\""), "{text}");
    assert!(
        text.contains("udp = true"),
        "it carries one udp forward: {text}"
    );
    let cfg: Config = toml::from_str(&format!(
        "role = \"entry\"\n\
         token = \"ERERERERERERERERERERERERERERERERERERERERERE=\"\n\
         static_secret = \"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\"\n\
         peer_public = \"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=\"\n{text}"
    ))
    .expect("what doctor writes parses");
    assert_eq!(cfg.carrier.as_deref(), Some("shabdiz-gre"));
    assert!(
        crate::dgram::validate(&cfg).is_ok(),
        "and it is a config run would take"
    );
    assert!(
        crate::dgram::ignored(&cfg).is_empty(),
        "with nothing inert in it"
    );
}

#[test]
fn a_protocol_line_says_which_of_the_three_outcomes_it_is() {
    assert!(protocol_line(47, "GRE", 5, "").contains("passes"));
    assert!(protocol_line(50, "ESP", 2, "").contains("partial"));
    assert!(protocol_line(4, "IPIP", 0, "").contains("blocked"));
    assert!(protocol_line(4, "IPIP", 0, "needs CAP_NET_RAW").contains("CAP_NET_RAW"));
}

#[test]
fn a_protocol_body_is_the_token_and_nothing_identifying() {
    let a = protocol_body("one token");
    let b = protocol_body("another token");
    assert_ne!(a[..8], b[..8], "the magic separates two unrelated runs");
    assert_eq!(a.len(), b.len());
    assert!(a[8..].iter().all(|&x| x == 0));
}

#[test]
fn the_far_ends_counts_parse_back() {
    let got = parse_protocol_counts("47=5,50=0,4=!needs CAP_NET_RAW");
    assert_eq!(got[0], (47, 5, String::new()));
    assert_eq!(got[1], (50, 0, String::new()));
    assert_eq!(got[2], (4, 0, "needs CAP_NET_RAW".to_string()));
    assert!(parse_protocol_counts("").is_empty());
    assert!(parse_protocol_counts("rubbish").is_empty());
}

#[test]
fn every_protocol_number_is_named_and_distinct() {
    assert!(PROTOCOLS.iter().any(|(n, name)| *n == 47 && *name == "GRE"));
    assert!(PROTOCOLS.iter().any(|(n, name)| *n == 50 && *name == "ESP"));
    let mut numbers: Vec<u8> = PROTOCOLS.iter().map(|(n, _)| *n).collect();
    numbers.sort_unstable();
    let before = numbers.len();
    numbers.dedup();
    assert_eq!(before, numbers.len(), "a protocol number is listed twice");
    assert!(
        !PROTOCOLS.iter().any(|(n, _)| matches!(n, 1 | 6 | 17)),
        "icmp, tcp and udp are carriers of their own, not protocol-number probes"
    );
}

#[tokio::test]
async fn a_portless_carrier_behind_nat_is_refused_with_the_reason() {
    let Some(local) = behind_nat("203.0.113.1") else {
        eprintln!("this host has a public route; nothing to check");
        return;
    };
    let v = measure(&base(), "shabdiz-gre", "203.0.113.1:7901", 1).await;
    assert!(
        !v.usable() && !v.reached,
        "it cannot work, so it must not try"
    );
    for part in [&local.to_string(), "no ports", "public address"] {
        assert!(
            v.note.contains(part),
            "the note must explain why, not just time out: {}",
            v.note
        );
    }

    let other = measure(&base(), "shabdiz-udp", "127.0.0.1:1", 1).await;
    assert!(
        !other.note.contains("public address"),
        "a carrier with ports is unaffected: {}",
        other.note
    );
}
