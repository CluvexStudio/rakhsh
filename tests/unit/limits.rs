use super::*;

#[test]
fn rates_parse() {
    assert_eq!(parse_rate("8Mbit").unwrap(), 1_000_000.0);
    assert_eq!(parse_rate("8 Mbit/s").unwrap(), 1_000_000.0);
    assert_eq!(parse_rate("8mbps").unwrap(), 1_000_000.0);
    assert_eq!(parse_rate("1.5Gbit").unwrap(), 187_500_000.0);
    assert_eq!(parse_rate("800kbit").unwrap(), 100_000.0);
    assert_eq!(parse_rate("5MB/s").unwrap(), 5_000_000.0);
    assert_eq!(parse_rate("64Mb/s").unwrap(), 8_000_000.0);
    assert!(parse_rate("fast").is_err());
    assert!(parse_rate("10").is_err(), "a bare number has no unit");
    assert!(parse_rate("10Mbyte").is_err());
    assert!(parse_rate("0bit").is_err());
}

#[test]
fn sizes_parse() {
    assert_eq!(parse_size("500GB").unwrap(), 500_000_000_000);
    assert_eq!(parse_size("1.5TB").unwrap(), 1_500_000_000_000);
    assert_eq!(parse_size("10GiB").unwrap(), 10 * 1024 * 1024 * 1024);
    assert_eq!(parse_size("250 mb").unwrap(), 250_000_000);
    assert_eq!(parse_size("4096").unwrap(), 4096);
    assert!(parse_size("lots").is_err());
    assert_eq!(human(1_500_000), "1.50 MB");
}

#[test]
fn calendar_round_trips_and_periods_have_the_right_edges() {
    for days in [-1000, 0, 365, 11_000, 19_000, 20_000, 25_000] {
        let (y, m, d) = civil_from_days(days);
        assert_eq!(days_from_civil(y, m, d), days);
    }
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    let t = days_from_civil(2024, 2, 29) * 86_400 + 43_200;
    assert_eq!(
        Period::Day.bounds(t),
        (
            days_from_civil(2024, 2, 29) * 86_400,
            days_from_civil(2024, 3, 1) * 86_400
        )
    );
    assert_eq!(
        Period::Month.bounds(t),
        (
            days_from_civil(2024, 2, 1) * 86_400,
            days_from_civil(2024, 3, 1) * 86_400
        )
    );
    let (ws, we) = Period::Week.bounds(t);
    assert_eq!(
        ws,
        days_from_civil(2024, 2, 26) * 86_400,
        "weeks start on Monday"
    );
    assert_eq!(we - ws, 7 * 86_400);
    let dec = days_from_civil(2025, 12, 31) * 86_400;
    assert_eq!(
        Period::Month.bounds(dec).1,
        days_from_civil(2026, 1, 1) * 86_400
    );
    assert_eq!(Period::Never.bounds(t), (0, i64::MAX));
}

#[test]
fn quota_counts_resets_with_the_period_and_restores_only_the_same_period() {
    let now = days_from_civil(2026, 10, 24) * 86_400 + 5;
    let q = Quota::new("t", 1000, Period::Day, now);
    q.add(400);
    assert_eq!(q.used(), 400);
    assert!(q.used() < q.limit);
    q.add(700);
    assert!(q.used() >= q.limit);
    q.roll_at(now + 86_400);
    assert_eq!(q.used(), 0, "a new period starts at zero");
    let saved = Saved {
        start: q.bounds.lock().unwrap().0,
        used: 123,
    };
    q.restore(saved);
    assert_eq!(q.used(), 123);
    q.restore(Saved {
        start: 1,
        used: 999,
    });
    assert_eq!(q.used(), 123, "usage from another period is ignored");
}

#[tokio::test]
async fn the_limiter_holds_the_long_run_rate() {
    let r = Rate::new(1_000_000.0);
    let t = Instant::now();
    for _ in 0..30 {
        r.take(20_000).await;
    }
    let secs = t.elapsed().as_secs_f64();
    assert!(
        (0.4..0.7).contains(&secs),
        "600 KB at 1 MB/s should take ~0.5 s, took {secs:.2}"
    );
}

#[tokio::test]
async fn a_scope_is_capped_by_its_own_limits_and_its_parents() {
    let limiter = Limiter::new(
        &toml::from_str("role = \"node\"\nquota = \"1KB\"").unwrap(),
        false,
    )
    .unwrap();
    let global = limiter.global().expect("global meter");
    let child = limiter
        .meter(
            "fwd",
            &Limits {
                quota: Some("10KB".into()),
                ..Default::default()
            },
            Some(global),
        )
        .unwrap()
        .unwrap();
    let s = child.open().expect("allowed at first");
    assert!(s.up(600).await, "within both quotas");
    assert!(
        s.down(600).await,
        "the global quota (1 KB) counts both directions: this one crosses it but is let through"
    );
    assert!(!s.up(1).await, "now the global quota is used up");
    assert!(child.open().is_none(), "and no new stream may start");
}
