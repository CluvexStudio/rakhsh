use super::*;
use base64::Engine;

#[test]
fn penalties_double_then_cap() {
    let secs: Vec<u64> = (1..=9).map(|f| penalty(f).as_secs()).collect();
    assert_eq!(secs, [3, 6, 12, 24, 48, 60, 60, 60, 60]);
    assert_eq!(penalty(0).as_secs(), 3);
}

#[test]
fn policy_parses_and_rejects_typos() {
    assert_eq!(Policy::parse(None).unwrap(), Policy::Failover);
    assert_eq!(Policy::parse(Some("spread")).unwrap(), Policy::Spread);
    assert!(Policy::parse(Some("race")).is_err());
}

#[test]
fn dialing_follows_role_and_mode() {
    let mk = |role: &str, dial: Option<&str>| {
        let mut s = format!("role = \"{role}\"\n");
        if let Some(d) = dial {
            s.push_str(&format!("dial = \"{d}\"\n"));
        }
        toml::from_str::<Config>(&s).unwrap()
    };
    assert!(dialing(&mk("exit", None)), "reverse: the exit dials");
    assert!(!dialing(&mk("entry", None)), "reverse: the entry listens");
    assert!(
        dialing(&mk("entry", Some("entry"))),
        "direct: the entry dials"
    );
    assert!(
        !dialing(&mk("exit", Some("entry"))),
        "direct: the exit listens"
    );
}

fn cfg_of(extra: &str) -> Config {
    let key = |n: u8| base64::prelude::BASE64_STANDARD.encode([n; 32]);
    let base = format!(
        "role = \"entry\"\ndial = \"entry\"\ntoken = \"t\"\nstatic_secret = \"{}\"\n\
         tunnel_connect = \"10.0.0.1:7000\"\n",
        key(1)
    );
    toml::from_str::<Config>(&(base + extra)).expect("config parses")
}

fn key_of(n: u8) -> String {
    base64::prelude::BASE64_STANDARD.encode([n; 32])
}

#[test]
fn one_pinned_key_is_still_the_whole_story() {
    let c = cfg_of(&format!("peer_public = \"{}\"\n", key_of(2)));
    let admitted = c.peer_keys().unwrap();
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted[0].name, "peer");
    assert_eq!(admitted[0].key, [2u8; 32]);
}

#[test]
fn several_exits_each_keep_their_own_identity() {
    let c = cfg_of(&format!(
        "peer_public = \"{}\"\n\
         [[peer]]\nname = \"de\"\npublic = \"{}\"\nconnect = \"10.0.0.2:7000\"\n\
         [[peer]]\nname = \"nl\"\npublic = \"{}\"\nconnect = \"10.0.0.3:7000\"\n",
        key_of(2),
        key_of(3),
        key_of(4)
    ));
    let admitted = c.peer_keys().unwrap();
    assert_eq!(admitted.len(), 3, "the pinned key plus two named peers");

    let pts = points(&c, "10.0.0.1:7000", true).unwrap();
    assert_eq!(
        pts.len(),
        3,
        "one dial point each: {:?}",
        pts.iter().map(Point::label).collect::<Vec<_>>()
    );
    assert_eq!(pts[0].peer, [2u8; 32]);
    assert_eq!(
        (pts[1].addr.as_str(), pts[1].peer),
        ("10.0.0.2:7000", [3u8; 32])
    );
    assert_eq!(
        (pts[2].addr.as_str(), pts[2].peer),
        ("10.0.0.3:7000", [4u8; 32])
    );
    assert!(
        pts[2].label().contains("nl"),
        "the label names the peer: {}",
        pts[2].label()
    );
}

#[test]
fn a_fleet_can_be_defined_without_a_primary_key_at_all() {
    let c = cfg_of(&format!(
        "[[peer]]\nname = \"de\"\npublic = \"{}\"\nconnect = \"10.0.0.2:7000\"\n\
         [[peer]]\nname = \"nl\"\npublic = \"{}\"\nconnect = \"10.0.0.3:7000\"\n",
        key_of(3),
        key_of(4)
    ));
    let pts = points(&c, "10.0.0.1:7000", true).unwrap();
    assert_eq!(pts.len(), 2, "no peer_public, so no point for it");
    assert_eq!(pts[0].peer, [3u8; 32]);
}

#[test]
fn a_peer_with_no_address_is_admitted_but_never_dialled() {
    let c = cfg_of(&format!(
        "peer_public = \"{}\"\n[[peer]]\nname = \"iran-b\"\npublic = \"{}\"\n",
        key_of(2),
        key_of(5)
    ));
    assert_eq!(c.peer_keys().unwrap().len(), 2, "both are admitted");
    let pts = points(&c, "10.0.0.1:7000", true).unwrap();
    assert_eq!(pts.len(), 1, "only the one with an address is dialled");
}

#[test]
fn the_listening_side_admits_every_identity_and_dials_none() {
    let c = cfg_of(&format!(
        "peer_public = \"{}\"\n\
         [[peer]]\nname = \"iran-b\"\npublic = \"{}\"\nconnect = \"10.0.0.9:7000\"\n",
        key_of(2),
        key_of(6)
    ));
    let pts = points(&c, "0.0.0.0:7000", false).unwrap();
    assert_eq!(pts.len(), 1, "one listener, however many peers it admits");
    assert_eq!(c.peer_keys().unwrap().len(), 2);
}

#[test]
fn a_repeated_key_is_refused_rather_than_silently_shadowing() {
    let c = cfg_of(&format!(
        "peer_public = \"{}\"\n[[peer]]\nname = \"twin\"\npublic = \"{}\"\n",
        key_of(2),
        key_of(2)
    ));
    let err = c.peer_keys().unwrap_err().to_string();
    assert!(err.contains("repeats a public key"), "got: {err}");
}
