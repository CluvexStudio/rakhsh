use super::*;

fn with_peer(peer: Option<&str>, connect: Option<&str>) -> Config {
    let text = "role = \"entry\"\n\
                token = \"ERERERERERERERERERERERERERERERERERERERERERE=\"\n\
                static_secret = \"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\"\n\
                peer_public = \"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=\"\n\
                carrier = \"shabdiz-gre\"\n";
    let mut c: Config = toml::from_str(text).expect("the fixture config parses");
    c.peer_ip = peer.map(str::to_string);
    c.tunnel_connect = connect.map(str::to_string);
    c
}

#[test]
fn a_literal_address_and_a_name_are_both_accepted_by_the_syntax_check() {
    for good in ["203.0.113.9", "exit.example.com", "  exit.example.com  "] {
        let c = with_peer(Some(good), None);
        assert_eq!(
            peer_host(&c, "shabdiz-gre").expect("{good} should pass"),
            good.trim()
        );
    }
}

#[test]
fn a_missing_or_empty_peer_is_refused_with_the_reason() {
    assert!(peer_host(&with_peer(None, None), "shabdiz-gre").is_err());
    let e = peer_host(&with_peer(Some("   "), None), "shabdiz-gre").unwrap_err();
    assert!(e.to_string().contains("empty"), "{e}");
}

#[test]
fn ipv6_is_refused_because_these_carriers_ride_on_ipv4() {
    let e = peer_host(&with_peer(Some("2001:db8::1"), None), "shabdiz-gre").unwrap_err();
    assert!(e.to_string().contains("IPv4"), "{e}");
}

#[test]
fn the_host_is_taken_out_of_tunnel_connect_when_peer_ip_is_unset() {
    let c = with_peer(None, Some("exit.example.com:7443"));
    assert_eq!(peer_host(&c, "shabdiz-gre").unwrap(), "exit.example.com");
}

#[tokio::test]
async fn a_literal_address_needs_no_lookup_and_a_name_is_resolved() {
    assert_eq!(
        peer_ipv4("203.0.113.9", "peer_ip").await.unwrap(),
        "203.0.113.9".parse::<Ipv4Addr>().unwrap()
    );
    assert_eq!(
        peer_ipv4("localhost", "peer_ip").await.unwrap(),
        Ipv4Addr::LOCALHOST
    );
}

#[tokio::test]
async fn a_name_that_does_not_resolve_says_so_instead_of_timing_out() {
    let e = peer_ipv4("no-such-host.invalid", "peer_ip")
        .await
        .expect_err("an unresolvable name must fail");
    let s = e.to_string();
    assert!(
        s.contains("no-such-host.invalid"),
        "the failure has to name the host: {s}"
    );
}
