use super::*;

fn cfg(domain: &str) -> Result<Acme> {
    Acme::from_config(domain, &None, &None, None, None)
}

#[test]
fn a_name_is_accepted_and_folded_to_lower_case() {
    let a = cfg("VPN.Example.COM").expect("a plain name is valid");
    assert_eq!(a.domain, "vpn.example.com");
    assert_eq!(a.port, 80);
    assert!(!a.staging);
    assert_eq!(a.dir, PathBuf::from("/var/lib/rakhsh/acme"));
}

#[test]
fn an_address_is_refused_because_no_authority_will_sign_one() {
    for bad in ["203.0.113.1", "2001:db8::1"] {
        let e = cfg(bad).expect_err("an address is not a name").to_string();
        assert!(
            e.contains("must be a name"),
            "the refusal must say why, not just fail: {e}"
        );
    }
}

#[test]
fn a_name_without_a_dot_is_refused_before_any_request_is_made() {
    for bad in ["localhost", "", "   ", ".example.com", "example.com."] {
        assert!(cfg(bad).is_err(), "{bad:?} should not be accepted");
    }
}

#[test]
fn a_wildcard_is_refused_with_the_reason_it_cannot_work_here() {
    let e = cfg("*.example.com").expect_err("wildcards need dns-01");
    assert!(e.to_string().contains("dns-01"), "{e}");
}

#[test]
fn an_address_that_is_not_one_is_refused() {
    let e = Acme::from_config(
        "ok.example.com",
        &Some("notanemail".into()),
        &None,
        None,
        None,
    )
    .expect_err("an email without an @ is not an address");
    assert!(e.to_string().contains("not an address"), "{e}");
    Acme::from_config(
        "ok.example.com",
        &Some("me@example.com".into()),
        &None,
        None,
        None,
    )
    .expect("a real address is fine");
}

#[test]
fn staging_and_production_keep_separate_accounts_and_directories() {
    let prod = Acme::from_config("a.example.com", &None, &None, None, Some(false)).unwrap();
    let test = Acme::from_config("a.example.com", &None, &None, None, Some(true)).unwrap();
    assert_ne!(prod.account_file(), test.account_file());
    assert_ne!(prod.directory(), test.directory());
    assert!(test.directory().contains("staging"));
}

#[test]
fn each_domain_gets_its_own_pair_of_files() {
    let a = Acme::from_config("a.example.com", &None, &Some("/tmp/x".into()), None, None).unwrap();
    let b = Acme::from_config("b.example.com", &None, &Some("/tmp/x".into()), None, None).unwrap();
    assert_ne!(a.cert_file(), b.cert_file());
    assert_ne!(a.key_file(), b.key_file());
    assert_ne!(a.cert_file(), a.key_file());
}

#[test]
fn a_self_signed_placeholder_is_served_until_a_real_one_arrives() {
    let ck = self_signed("vpn.example.com").expect("a placeholder is always available");
    assert!(!ck.cert.is_empty(), "the placeholder needs a certificate");
}

#[test]
fn the_resolver_answers_every_hello_and_reports_whether_it_is_real_yet() {
    let r = Resolver {
        current: RwLock::new(self_signed("vpn.example.com").unwrap()),
        real: RwLock::new(false),
    };
    assert!(!r.has_real_certificate());
    r.install(self_signed("vpn.example.com").unwrap());
    assert!(r.has_real_certificate());
}

#[test]
fn a_pem_chain_round_trips_into_something_rustls_can_serve() {
    let ck = rcgen::generate_simple_self_signed(vec!["vpn.example.com".into()]).unwrap();
    let cert_pem = ck.cert.pem();
    let key_pem = ck.signing_key.serialize_pem();
    let out = certified(&cert_pem, &key_pem).expect("our own pem must load");
    assert_eq!(out.cert.len(), 1);
}

#[test]
fn a_chain_with_no_certificate_block_is_refused_rather_than_served_empty() {
    let ck = rcgen::generate_simple_self_signed(vec!["vpn.example.com".into()]).unwrap();
    let key_pem = ck.signing_key.serialize_pem();
    assert!(certified("not a pem at all", &key_pem).is_err());
    assert!(certified(&ck.cert.pem(), "not a pem at all").is_err());
}

#[test]
fn the_challenge_path_is_the_one_the_authority_fetches() {
    assert_eq!(CHALLENGE_PATH, "/.well-known/acme-challenge/");
}

#[test]
fn renewal_starts_well_before_a_ninety_day_certificate_runs_out() {
    assert!(
        RENEW_BEFORE < Duration::from_secs(90 * 24 * 3600),
        "renewing later than the certificate lives would never renew"
    );
    assert!(
        CHECK_EVERY < RENEW_BEFORE,
        "a check less often than the renewal window can miss it entirely"
    );
}

#[tokio::test]
async fn the_challenge_server_answers_the_token_it_was_given_and_nothing_else() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let answers: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    answers
        .write()
        .unwrap()
        .insert("tok123".into(), "tok123.keyauth".into());
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve(listener, answers));

    async fn get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    let good = get(addr, "/.well-known/acme-challenge/tok123").await;
    assert!(good.starts_with("HTTP/1.1 200"), "{good}");
    assert!(good.ends_with("tok123.keyauth"), "{good}");

    for miss in [
        "/.well-known/acme-challenge/other",
        "/",
        "/.well-known/acme-challenge/",
        "/etc/passwd",
    ] {
        let r = get(addr, miss).await;
        assert!(
            r.starts_with("HTTP/1.1 404"),
            "{miss} must not be answered: {r}"
        );
    }
    task.abort();
}

#[test]
fn a_stored_certificate_reports_the_time_it_has_left() {
    let dir = std::env::temp_dir().join(format!("rakhsh-acme-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a = Acme::from_config(
        "vpn.example.com",
        &None,
        &Some(dir.to_string_lossy().into_owned()),
        None,
        None,
    )
    .unwrap();

    assert!(
        remaining(&a).unwrap().is_none(),
        "no file means nothing to renew yet, not an error"
    );

    let ck = rcgen::generate_simple_self_signed(vec!["vpn.example.com".into()]).unwrap();
    std::fs::write(a.cert_file(), ck.cert.pem()).unwrap();
    let left = remaining(&a).unwrap().expect("a stored cert has an expiry");
    assert!(
        left > Duration::from_secs(3600),
        "a freshly made certificate should not read as nearly expired: {left:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn inspecting_a_config_never_reaches_for_a_certificate() {
    let src = std::fs::read_to_string("src/carrier.rs").expect("the carrier source is readable");
    let at = src
        .find("fn server_tls")
        .expect("the tls acceptor chooser must exist");
    let body = &src[at..at + 900];
    let guard = body
        .find("inspect_only")
        .expect("`rakhsh check` must not register an account or ask for a certificate");
    let start = body
        .find("acme::start")
        .expect("the live path must still start acme");
    assert!(
        guard < start,
        "the inspect-only guard has to come before anything that talks to the authority"
    );
}
