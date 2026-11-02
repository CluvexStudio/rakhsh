use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
    log: std::path::PathBuf,
}

impl Daemon {
    fn complaint(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("a loopback port")
        .local_addr()
        .unwrap()
        .port()
}

fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("an echo listener");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().take(4) {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

fn wait_for(port: u16, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn socks_connect(socks: u16, target: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", socks)).expect("the proxy accepts");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();

    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).expect("a greeting back");
    assert_eq!(greeting, [0x05, 0x00], "SOCKS5, no authentication");

    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&target.to_be_bytes());
    s.write_all(&request).unwrap();

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).expect("a reply to the connect");
    assert_eq!(reply[1], 0x00, "the proxy opened the connection: {reply:?}");
    s
}

fn run(bin: &str, args: &[&str]) -> String {
    let out = Command::new(bin).args(args).output().expect("the binary runs");
    assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("utf-8 output")
}

#[test]
fn a_tunnel_carries_traffic_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_rakhsh");
    let dir = std::env::temp_dir().join(format!("rakhsh-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a working directory");

    let (tunnel, socks, echo) = (free_port(), free_port(), echo_server());

    let printed = run(
        bin,
        &[
            "init",
            "--direct",
            "--tunnel-addr",
            &format!("127.0.0.1:{tunnel}"),
            "--carrier",
            "tcp",
            "--lanes",
            "2",
            "--proxy",
            &format!("127.0.0.1:{socks}"),
        ],
    );
    let parts: Vec<&str> = printed.split("##########").collect();
    assert_eq!(parts.len(), 5, "init prints an entry and an exit config");

    let entry = dir.join("entry.toml");
    let exit = dir.join("exit.toml");
    let sock = |name: &str| format!("control_socket = \"{}\"\n", dir.join(name).display());
    std::fs::write(&entry, parts[2].trim_start().to_string() + &sock("entry.sock")).unwrap();
    std::fs::write(&exit, parts[4].trim_start().to_string() + &sock("exit.sock")).unwrap();

    for file in [&entry, &exit] {
        let said = run(bin, &["check", "-c", &file.display().to_string()]);
        assert!(said.contains("config OK"), "{}: {said}", file.display());
    }

    let spawn = |file: &std::path::Path, name: &str| {
        let log = dir.join(format!("{name}.log"));
        let sink = std::fs::File::create(&log).expect("a log file for the daemon");
        Daemon {
            child: Command::new(bin)
                .args(["run", "-c", &file.display().to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::from(sink))
                .spawn()
                .expect("the daemon starts"),
            log,
        }
    };
    let far = spawn(&exit, "exit");
    assert!(
        wait_for(tunnel, Duration::from_secs(20)),
        "the far side listens on {tunnel}; it said:\n{}",
        far.complaint()
    );
    let near = spawn(&entry, "entry");
    assert!(
        wait_for(socks, Duration::from_secs(20)),
        "the near side offers a proxy on {socks}; it said:\n{}",
        near.complaint()
    );

    let mut through = socks_connect(socks, echo);
    let sent = b"the quick brown fox crosses the tunnel";
    through.write_all(sent).unwrap();
    let mut got = vec![0u8; sent.len()];
    through
        .read_exact(&mut got)
        .expect("the bytes come back from the other side");
    assert_eq!(&got[..], &sent[..], "what arrived is what was sent");

    let big: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    through.write_all(&big).unwrap();
    let mut back = vec![0u8; big.len()];
    through
        .read_exact(&mut back)
        .expect("a quarter of a megabyte survives the round trip");
    assert_eq!(back, big, "every byte of the larger transfer matches");

    let _ = through.shutdown(Shutdown::Both);
    let _ = std::fs::remove_dir_all(&dir);
}
