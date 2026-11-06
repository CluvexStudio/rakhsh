use super::*;
use crate::config::Config;

fn spec(exits: &[&str], entries: &[&str], dial: Dial) -> Spec {
    Spec {
        exits: exits
            .iter()
            .map(|s| Host::parse(s, 7000).unwrap())
            .collect(),
        entries: entries
            .iter()
            .map(|s| Host::parse(s, 7000).unwrap())
            .collect(),
        carrier: "wss".into(),
        sni: "www.cloudflare.com".into(),
        dial,
        lanes: 4,
        port: 7000,
        proxy: Some("0.0.0.0:1080".into()),
        forwards: vec![],
    }
}

fn parse(n: &Node) -> Config {
    toml::from_str::<Config>(&n.config)
        .unwrap_or_else(|e| panic!("{} does not parse: {e}\n{}", n.name, n.config))
}

#[test]
fn a_name_and_an_address_are_both_required() {
    assert_eq!(
        Host::parse("de=1.2.3.4", 7000).unwrap().addr,
        "1.2.3.4:7000"
    );
    assert_eq!(Host::parse("de=1.2.3.4:9", 7000).unwrap().addr, "1.2.3.4:9");
    assert!(Host::parse("1.2.3.4", 7000).is_err(), "no name");
    assert!(Host::parse("de=", 7000).is_err(), "no address");
    assert!(
        Host::parse("a b=1.2.3.4", 7000).is_err(),
        "a name that cannot be a filename"
    );
}

#[test]
fn every_generated_config_is_one_rakhsh_will_accept() {
    let nodes = plan(&spec(
        &["de=1.1.1.1", "nl=2.2.2.2"],
        &["ir-a=3.3.3.3", "ir-b=4.4.4.4"],
        Dial::Exit,
    ))
    .unwrap();
    assert_eq!(nodes.len(), 4);
    for n in &nodes {
        let c = parse(n);
        assert_eq!(c.role, n.role);
        assert!(!c.token.is_empty() && !c.static_secret.is_empty());
    }
}

#[test]
fn the_whole_fleet_shares_one_token_and_nothing_else() {
    let nodes = plan(&spec(
        &["de=1.1.1.1", "nl=2.2.2.2"],
        &["ir-a=3.3.3.3"],
        Dial::Exit,
    ))
    .unwrap();
    let cfgs: Vec<Config> = nodes.iter().map(parse).collect();
    let token = cfgs[0].token.clone();
    assert!(
        cfgs.iter().all(|c| c.token == token),
        "one psk for the fleet"
    );
    let mut secrets: Vec<&str> = cfgs.iter().map(|c| c.static_secret.as_str()).collect();
    secrets.sort_unstable();
    secrets.dedup();
    assert_eq!(
        secrets.len(),
        nodes.len(),
        "every node has its own private key"
    );
}

#[test]
fn each_side_admits_every_node_on_the_other_side() {
    let nodes = plan(&spec(
        &["de=1.1.1.1", "nl=2.2.2.2"],
        &["ir-a=3.3.3.3", "ir-b=4.4.4.4"],
        Dial::Exit,
    ))
    .unwrap();
    for n in &nodes {
        let c = parse(n);
        assert_eq!(
            c.peers.len(),
            2,
            "{} should admit both of the other side",
            n.name
        );
        assert_eq!(
            c.peer_keys().unwrap().len(),
            2,
            "{} admits two identities",
            n.name
        );
        assert!(c.peer_public.is_empty(), "the fleet uses [[peer]] only");
    }
}

#[test]
fn the_dialling_side_gets_addresses_and_the_listening_side_a_port() {
    for dial in [Dial::Exit, Dial::Entry] {
        let nodes = plan(&spec(&["de=1.1.1.1"], &["ir-a=3.3.3.3"], dial)).unwrap();
        for n in &nodes {
            let c = parse(n);
            let dials = (n.role == "entry") == (dial == Dial::Entry);
            if dials {
                assert!(
                    c.tunnel_listen.is_none(),
                    "{} dials, it should not listen",
                    n.name
                );
                assert!(
                    c.peers.iter().all(|p| p.connect.is_some()),
                    "{} dials, so every peer needs an address",
                    n.name
                );
            } else {
                assert!(c.tunnel_listen.is_some(), "{} listens", n.name);
                assert!(
                    c.peers.iter().all(|p| p.connect.is_none()),
                    "{} listens, so a peer address would be noise",
                    n.name
                );
            }
        }
    }
}

#[test]
fn losing_one_exit_still_leaves_each_entry_a_way_out() {
    let nodes = plan(&spec(
        &["de=1.1.1.1", "nl=2.2.2.2"],
        &["ir-a=3.3.3.3"],
        Dial::Entry,
    ))
    .unwrap();
    let entry = nodes.iter().find(|n| n.role == "entry").unwrap();
    let c = parse(entry);
    let points = crate::links::points(&c, "1.1.1.1:7000", true).unwrap();
    assert_eq!(points.len(), 2, "one dial point per exit");
    assert_ne!(
        points[0].peer, points[1].peer,
        "and each with its own pinned key"
    );
}

#[test]
fn a_repeated_node_name_is_refused() {
    let err = plan(&spec(&["de=1.1.1.1"], &["de=3.3.3.3"], Dial::Exit))
        .unwrap_err()
        .to_string();
    assert!(err.contains("both called"), "got: {err}");
}

#[test]
fn a_datagram_carrier_is_refused_rather_than_generated_broken() {
    for carrier in ["shabdiz-gre", "shabdiz-l2", "shabdiz-udp", "shabdiz-tcp"] {
        let mut s = spec(&["de=1.1.1.1"], &["ir=3.3.3.3"], Dial::Exit);
        s.carrier = carrier.into();
        let err = plan(&s).unwrap_err().to_string();
        assert!(err.contains("one datagram tunnel"), "{carrier}: {err}");
        assert!(
            err.contains("rakhsh init"),
            "the error says what to run: {err}"
        );
    }
}

#[test]
fn a_fleet_needs_both_sides() {
    assert!(plan(&spec(&[], &["ir-a=3.3.3.3"], Dial::Exit)).is_err());
    assert!(plan(&spec(&["de=1.1.1.1"], &[], Dial::Exit)).is_err());
}

#[test]
fn the_control_file_lists_every_node_once() {
    let nodes = plan(&spec(
        &["de=1.1.1.1"],
        &["ir-a=3.3.3.3", "ir-b=4.4.4.4"],
        Dial::Exit,
    ))
    .unwrap();
    let text = control_config(&nodes, "0.0.0.0:8443");
    for n in &nodes {
        assert_eq!(
            text.matches(&format!("name = \"{}\"", n.name)).count(),
            1,
            "{} should appear once in control.toml",
            n.name
        );
    }
    assert!(
        text.contains("ssh = \"root@1.1.1.1\""),
        "the ssh host drops the tunnel port"
    );
}

#[test]
fn a_listening_node_binds_the_port_it_is_published_on() {
    let nodes = plan(&spec(
        &["x1=127.0.0.1:18001", "x2=127.0.0.1:18002"],
        &["e1=127.0.0.1:18101"],
        Dial::Entry,
    ))
    .unwrap();
    let mut bound: Vec<String> = nodes
        .iter()
        .filter(|n| n.role == "exit")
        .map(|n| parse(n).tunnel_listen.unwrap())
        .collect();
    bound.sort();
    assert_eq!(
        bound,
        vec!["0.0.0.0:18001".to_string(), "0.0.0.0:18002".to_string()],
        "each listener takes its own port, or two of them cannot share a fleet"
    );
}

#[test]
fn a_proxy_anyone_can_reach_gets_a_login_and_a_local_one_does_not() {
    for (listen, public) in [("0.0.0.0:1080", true), ("127.0.0.1:1080", false)] {
        let mut s = spec(&["de=1.1.1.1"], &["ir=3.3.3.3"], Dial::Exit);
        s.proxy = Some(listen.into());
        let nodes = plan(&s).unwrap();
        let entry = nodes.iter().find(|n| n.role == "entry").unwrap();
        let proxy = parse(entry).inbound.into_iter().next().expect("the proxy");
        assert_eq!(
            proxy.password.is_some() && proxy.username.is_some(),
            public,
            "a proxy on {listen} must {} a login: {}",
            if public { "have" } else { "not need" },
            entry.config
        );
    }
}
