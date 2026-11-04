use super::*;
use crate::config::Config;

fn cfg(carrier: &str, body: &str) -> Config {
    let text = format!(
        "role = \"entry\"\n\
         token = \"ERERERERERERERERERERERERERERERERERERERERERE=\"\n\
         static_secret = \"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\"\n\
         peer_public = \"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=\"\n\
         carrier = \"{carrier}\"\n\
         tunnel_listen = \"0.0.0.0:7000\"\n\
         peer_ip = \"198.51.100.9\"\n\
         {body}"
    );
    toml::from_str(&text).expect("the test config parses")
}

#[test]
fn a_bare_spec_is_udp_on_the_default_port() {
    let ov = OpenVpn::parse_spec("").unwrap();
    assert_eq!(ov.proto, Proto::Udp);
    assert_eq!(ov.port, 1194);
    assert_eq!(ov.device, Device::Tun);
    assert_eq!(ov.crypto, Crypto::Aead);
}

#[test]
fn a_spec_can_name_the_proto_the_port_the_device_and_the_crypto() {
    let ov = OpenVpn::parse_spec("tcp:443/tap/cbc-sha256").unwrap();
    assert_eq!(ov.proto, Proto::Tcp);
    assert_eq!(ov.port, 443);
    assert_eq!(ov.device, Device::Tap);
    assert_eq!(ov.crypto, Crypto::CbcSha256);

    assert_eq!(OpenVpn::parse_spec("1195").unwrap().port, 1195);
    assert_eq!(OpenVpn::parse_spec("tcp").unwrap().proto, Proto::Tcp);
    assert_eq!(OpenVpn::parse_spec("udp:1194").unwrap().port, 1194);
}

#[test]
fn a_spec_that_is_not_a_proto_or_a_port_is_refused() {
    for spec in ["sctp:1194", "udp:notaport", "udp:1194/sha9000", "udp:99999"] {
        assert!(
            OpenVpn::parse_spec(spec).is_err(),
            "{spec:?} must not be accepted"
        );
    }
}

#[test]
fn the_overhead_is_the_sum_of_what_openvpn_adds() {
    let aead = OpenVpn::parse_spec("udp:1194").unwrap();
    assert_eq!(
        aead.overhead_bytes(),
        1 + 3 + 8 + 16,
        "openvpn 2.7 negotiates the aead epoch format: 8 bytes of epoch and counter, \
         not the 4-byte packet id of 2.6 and earlier. Measured on a live tunnel"
    );

    let classic = OpenVpn::parse_spec("udp:1194/no-epoch").unwrap();
    assert_eq!(classic.overhead_bytes(), 1 + 3 + 4 + 16, "openvpn 2.6 and earlier");

    let no_peer_id = OpenVpn::parse_spec("udp:1194/no-epoch/no-peer-id").unwrap();
    assert_eq!(no_peer_id.overhead_bytes(), 1 + 4 + 16);

    let tap = OpenVpn::parse_spec("udp:1194/tap").unwrap();
    assert_eq!(tap.overhead_bytes(), aead.overhead_bytes() + 14);

    let compressed = OpenVpn::parse_spec("udp:1194/compress").unwrap();
    assert_eq!(compressed.overhead_bytes(), aead.overhead_bytes() + 1);

    let cbc = OpenVpn::parse_spec("udp:1194/cbc-sha256").unwrap();
    assert_eq!(
        cbc.overhead_bytes(),
        1 + 3 + 32 + 16 + 4 + 16,
        "the epoch format is aead only, so a cbc cipher keeps the 4-byte packet id"
    );
    let cbc_epoch = OpenVpn::parse_spec("udp:1194/cbc-sha256/no-epoch").unwrap();
    assert_eq!(cbc.overhead_bytes(), cbc_epoch.overhead_bytes());

    let explicit = OpenVpn::parse_spec("udp:1194+41").unwrap();
    assert_eq!(explicit.overhead_bytes(), 41);
}

#[test]
fn the_tun_mtu_is_what_the_carrier_carries_minus_what_openvpn_adds() {
    let ov = OpenVpn::parse_spec("udp:1194").unwrap();
    for (carrier, carried) in [
        ("shabdiz-gre", 1427usize),
        ("shabdiz-l2", 1405),
        ("shabdiz-udp", 1437),
        ("shabdiz-tcp", 1365),
    ] {
        let c = cfg(carrier, "");
        let p = plan(&c, &ov);
        assert_eq!(p.carried, Some(carried), "{carrier}");
        assert_eq!(p.tun_mtu, Some(carried - 28), "{carrier}");
        assert_eq!(p.mss(), Some(carried - 28 - 40), "{carrier}");
        assert!(p.datagram, "{carrier} is a datagram carrier");
    }
}

#[test]
fn tcp_mode_has_no_mtu_arithmetic() {
    let ov = OpenVpn::parse_spec("tcp:443").unwrap();
    let p = plan(&cfg("wss", ""), &ov);
    assert_eq!(p.carried, None);
    assert_eq!(p.tun_mtu, None);
    assert_eq!(p.mss(), None);
}

#[test]
fn check_insists_on_a_forward_that_matches_the_mode() {
    let udp_without = cfg("shabdiz-gre", "[openvpn]\nproto = \"udp\"\nport = 1194\n");
    let err = validate(&udp_without).expect_err("a udp openvpn with no udp forward is incomplete");
    assert!(
        format!("{err}").contains("udp = true"),
        "the error names what is missing: {err}"
    );

    let tcp_forward_for_udp = cfg(
        "shabdiz-gre",
        "[openvpn]\nproto = \"udp\"\nport = 1194\n\n\
         [[forward]]\nlisten = \"0.0.0.0:1194\"\ntarget = \"127.0.0.1:1194\"\n",
    );
    assert!(
        validate(&tcp_forward_for_udp).is_err(),
        "a stream forward does not satisfy proto = \"udp\""
    );

    let complete = cfg(
        "shabdiz-gre",
        "[openvpn]\nproto = \"udp\"\nport = 1194\n\n\
         [[forward]]\nlisten = \"0.0.0.0:1194\"\ntarget = \"127.0.0.1:1194\"\nudp = true\n",
    );
    validate(&complete).expect("a matching udp forward is enough");
}

#[test]
fn check_refuses_openvpn_on_a_node() {
    let text = "role = \"node\"\n\n\
                [openvpn]\nproto = \"udp\"\nport = 1194\n\n\
                [[forward]]\nlisten = \"0.0.0.0:1194\"\ntarget = \"127.0.0.1:1194\"\nudp = true\n";
    let c: Config = toml::from_str(text).expect("the node config parses");
    assert!(
        validate(&c).is_err(),
        "a node has no peer, so it cannot carry openvpn"
    );
}

#[test]
fn describe_warns_when_udp_rides_a_reliable_carrier() {
    let c = cfg(
        "wss",
        "[openvpn]\nproto = \"udp\"\nport = 1194\n\n\
         [[forward]]\nlisten = \"0.0.0.0:1194\"\ntarget = \"127.0.0.1:1194\"\nudp = true\n",
    );
    let said = describe(&c).join("\n");
    assert!(said.contains("WARNING"), "{said}");
    assert!(said.contains("shabdiz-"), "it names the fix: {said}");
    assert!(
        said.contains("max-packet-size"),
        "check must mention the control-channel bound: {said}"
    );
}

#[test]
fn describe_warns_when_tcp_rides_a_datagram_carrier() {
    let c = cfg(
        "shabdiz-gre",
        "[openvpn]\nproto = \"tcp\"\nport = 443\n\n\
         [[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"\n",
    );
    let said = describe(&c).join("\n");
    assert!(said.contains("WARNING"), "{said}");
}

#[test]
fn the_directives_carry_the_computed_mtu_to_both_ends() {
    let c = cfg(
        "shabdiz-gre",
        "[openvpn]\nproto = \"udp\"\nport = 1194\nserver = \"127.0.0.1:1194\"\n\n\
         [[forward]]\nlisten = \"0.0.0.0:1194\"\ntarget = \"127.0.0.1:1194\"\nudp = true\n",
    );
    let text = directives(&c).expect("directives for a complete config");
    let directive = |want: &str| {
        text.lines()
            .filter(|l| l.trim() == want)
            .count()
    };
    assert_eq!(directive("tun-mtu 1399"), 2, "once per end: {text}");
    assert_eq!(directive("mssfix 1399 mtu"), 2, "once per end: {text}");
    assert_eq!(
        directive("max-packet-size 1427"),
        2,
        "the control channel needs bounding too, or a small path never handshakes: {text}"
    );
    assert!(text.contains("proto udp"), "{text}");
    assert!(text.contains("remote <the entry's public address> 1194"), "{text}");
    assert!(text.contains("ping -M do"), "it says how to verify: {text}");
}

#[test]
fn the_directives_for_tcp_mode_set_no_mtu() {
    let c = cfg(
        "wss",
        "[openvpn]\nproto = \"tcp\"\nport = 443\n\n\
         [[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"\n",
    );
    let text = directives(&c).expect("directives for a complete config");
    assert!(!text.contains("tun-mtu"), "{text}");
    assert!(
        !text.contains("max-packet-size"),
        "a stream carrier needs no size bound: {text}"
    );
    assert!(text.contains("proto tcp-server"), "{text}");
    assert!(text.contains("proto tcp-client"), "{text}");
}

#[test]
fn a_config_without_the_section_is_silent_and_valid() {
    let c = cfg("wss", "");
    validate(&c).expect("no [openvpn] is not an error");
    assert!(describe(&c).is_empty());
    assert!(directives(&c).is_err());
}

#[test]
fn the_generated_toml_reads_back_as_the_same_settings() {
    let ov = OpenVpn::parse_spec("udp:1195/tap/cbc-sha512/no-epoch").unwrap();
    let text = format!(
        "role = \"entry\"\n\
         token = \"ERERERERERERERERERERERERERERERERERERERERERE=\"\n\
         static_secret = \"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\"\n\
         peer_public = \"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=\"\n\
         carrier = \"shabdiz-gre\"\n\
         tunnel_listen = \"0.0.0.0:7000\"\n\
         peer_ip = \"198.51.100.9\"\n\
         {}{}",
        forward_toml(&ov),
        config_toml(&ov)
    );
    let c: Config = toml::from_str(&text).expect("the generated config parses");
    let back = c
        .openvpn
        .clone()
        .expect("the section survived the round trip");
    assert_eq!(back.proto, Proto::Udp);
    assert_eq!(back.port, 1195);
    assert_eq!(back.device, Device::Tap);
    assert_eq!(back.crypto, Crypto::CbcSha512);
    assert!(!back.epoch, "the epoch setting survives the round trip");
    assert_eq!(back.overhead_bytes(), ov.overhead_bytes());
    validate(&c).expect("the generated pair is self-consistent");
}
