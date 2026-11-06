use super::*;

#[test]
fn human_formatters() {
    assert_eq!(bytes(0), "0.0 B");
    assert_eq!(bytes(1536), "1.5 KiB");
    assert_eq!(bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
    assert_eq!(dur(90), "1m 30s");
    assert_eq!(dur(3700), "1h 1m 40s");
    assert_eq!(dur(90000), "1d 1h 0m");
    assert_eq!(mbit(2_500_000), "2.5 Mbit/s");
}

#[test]
fn parses_proc_fields() {
    let meminfo = "MemTotal:       16004512 kB\nMemFree:  100 kB\nMemAvailable:   8000000 kB\n";
    assert_eq!(field_kb(meminfo, "MemTotal:"), 16004512);
    assert_eq!(field_kb(meminfo, "MemAvailable:"), 8000000);
    assert_eq!(field_kb(meminfo, "Nope:"), 0);

    let stat = "cpu  100 20 50 1000 30 0 10 0 0 0\ncpu0 1 2 3 4\n";
    let (total, idle) = parse_stat_cpu(stat);
    assert_eq!(total, 100 + 20 + 50 + 1000 + 30 + 10);
    assert_eq!(idle, 1000 + 30);
}

#[test]
fn loss_and_rtt_fold() {
    let mut l = LaneInfo::default();
    assert_eq!(l.loss_pct(), 0.0);
    l.pings = 10;
    l.pongs = 8;
    assert!((l.loss_pct() - 20.0).abs() < 1e-9);
    l.pongs = 20;
    assert_eq!(l.loss_pct(), 0.0);
}

#[tokio::test]
async fn a_second_server_leaves_a_live_socket_to_its_owner() {
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;
    let path = std::env::temp_dir()
        .join(format!("rakhsh-status-{}.sock", std::process::id()))
        .display()
        .to_string();
    let first = tokio::spawn(serve(path.clone()));
    for _ in 0..100 {
        if tokio::net::UnixStream::connect(&path).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let owner = std::fs::metadata(&path)
        .expect("the first server bound")
        .ino();

    tokio::time::timeout(Duration::from_secs(2), serve(path.clone()))
        .await
        .expect("the second server gives up instead of taking the socket over");

    assert_eq!(
        std::fs::metadata(&path).unwrap().ino(),
        owner,
        "the socket file is still the first server's"
    );
    assert!(
        tokio::net::UnixStream::connect(&path).await.is_ok(),
        "and the first server still answers on it"
    );
    first.abort();
    let _ = std::fs::remove_file(&path);
}
