use super::*;
use crate::config::Rule;

fn router(rules: Vec<Rule>, fallback: &str) -> Router {
    let tags = vec![
        "direct".to_string(),
        "tunnel".to_string(),
        "block".to_string(),
    ];
    let route = Route {
        fallback: Some(fallback.into()),
        rule: rules,
        resolve: Some(false),
    };
    Router::compile(&route, &tags, "tunnel").unwrap()
}
fn d(h: &str, p: u16) -> Dest {
    Dest {
        host: Host::parse(h),
        port: p,
    }
}
fn rt(r: &Router, inb: &str, dest: Dest) -> String {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(r.route(inb, &dest))
        .outbound
}

#[test]
fn suffix_exact_keyword_and_fallback() {
    let r = router(
        vec![
            Rule {
                outbound: "direct".into(),
                domain_suffix: vec![".ir".into()],
                ..Default::default()
            },
            Rule {
                outbound: "block".into(),
                domain_keyword: vec!["ads".into()],
                ..Default::default()
            },
            Rule {
                outbound: "direct".into(),
                domain: vec!["example.com".into()],
                ..Default::default()
            },
        ],
        "tunnel",
    );
    assert_eq!(rt(&r, "p", d("www.digikala.ir", 443)), "direct");
    assert_eq!(rt(&r, "p", d("ir", 443)), "direct");
    assert_eq!(rt(&r, "p", d("notir", 443)), "tunnel");
    assert_eq!(rt(&r, "p", d("ads.tracker.net", 80)), "block");
    assert_eq!(rt(&r, "p", d("example.com", 80)), "direct");
    assert_eq!(rt(&r, "p", d("sub.example.com", 80)), "tunnel");
    assert_eq!(rt(&r, "p", d("google.com", 443)), "tunnel");
}

#[test]
fn cidr_ports_and_inbound() {
    let r = router(
        vec![
            Rule {
                outbound: "direct".into(),
                ip_cidr: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
                ..Default::default()
            },
            Rule {
                outbound: "block".into(),
                port: vec!["25".into(), "6881-6889".into()],
                ..Default::default()
            },
            Rule {
                outbound: "direct".into(),
                inbound: vec!["lan".into()],
                ..Default::default()
            },
        ],
        "tunnel",
    );
    assert_eq!(rt(&r, "p", d("10.1.2.3", 80)), "direct");
    assert_eq!(rt(&r, "p", d("2001:db8::1", 80)), "direct");
    assert_eq!(rt(&r, "p", d("11.0.0.1", 80)), "tunnel");
    assert_eq!(rt(&r, "p", d("8.8.8.8", 25)), "block");
    assert_eq!(rt(&r, "p", d("8.8.8.8", 6885)), "block");
    assert_eq!(rt(&r, "lan", d("8.8.8.8", 443)), "direct");
    assert_eq!(rt(&r, "p", d("8.8.8.8", 443)), "tunnel");
}

#[test]
fn rule_file_lines() {
    let mut m = DestMatch::default();
    for l in [
        "# comment",
        "domain:exact.com",
        "suffix:.ir",
        "keyword:adx",
        "cidr:5.0.0.0/8",
        "1.2.3.4",
        "digikala.com  # bare = suffix",
    ] {
        m.add_line(l);
    }
    assert!(m.domain_hit("exact.com") && !m.domain_hit("a.exact.com"));
    assert!(m.domain_hit("x.ir") && m.domain_hit("api.digikala.com") && m.domain_hit("myadx.net"));
    assert!(m.ip_hit(&"5.9.9.9".parse().unwrap()) && m.ip_hit(&"1.2.3.4".parse().unwrap()));
    assert!(!m.ip_hit(&"1.2.3.5".parse().unwrap()));
}
