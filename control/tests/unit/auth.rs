use super::{ct_eq, rand_pass, Config};

#[test]
fn a_comparison_that_matches_only_on_the_whole_string() {
    assert!(ct_eq("rkq7mTdv2x", "rkq7mTdv2x"));
    assert!(!ct_eq("rkq7mTdv2x", "rkq7mTdv2y"));
    assert!(!ct_eq("rkq7mTdv2x", "rkq7mTdv2"), "a prefix is not a match");
    assert!(!ct_eq("", "x"));
    assert!(ct_eq("", ""));
}

#[test]
fn a_generated_password_is_long_and_unambiguous() {
    let a = rand_pass(20);
    let b = rand_pass(20);
    assert_eq!(a.chars().count(), 20);
    assert_ne!(a, b, "two calls must not agree");
    // 8 stays in because its lookalike B is out; the rest of each confusable
    // pair (0/O, 1/l/I) is excluded outright.
    for c in a.chars().chain(b.chars()) {
        assert!(c.is_ascii_alphanumeric(), "{c:?} is not typable");
        assert!(
            !"0OlI1B".contains(c),
            "{c:?} is read back wrong over the phone"
        );
    }
}

#[test]
fn the_username_defaults_rather_than_being_required() {
    let cfg: Config = toml::from_str("listen = \"0.0.0.0:8443\"\npassword = \"x\"\n")
        .expect("a config without a username still parses");
    assert_eq!(cfg.username, "admin");

    let cfg: Config = toml::from_str("username = \"rkabc\"\npassword = \"x\"\n").unwrap();
    assert_eq!(cfg.username, "rkabc");
}

#[test]
fn the_sample_carries_the_lines_init_rewrites() {
    let s = super::SAMPLE;
    for line in [
        "listen = \"0.0.0.0:8443\"",
        "username = \"admin\"              # panel login",
        "password = \"change-me\"          # panel password (empty = no auth; only behind a trusted network)",
    ] {
        assert!(
            s.contains(line),
            "init rewrites this line, so the sample must still carry it verbatim:\n{line}"
        );
    }
}
