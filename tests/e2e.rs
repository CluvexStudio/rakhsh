use std::io::{Read, Write};
#[cfg(unix)]
use std::net::UdpSocket;
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

fn socks_connect(socks: u16, target: u16, limit: Duration) -> TcpStream {
    let deadline = Instant::now() + limit;
    loop {
        match try_socks(socks, target) {
            Ok(s) => return s,
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("the proxy never carried a connection to {target}: {e}");
                }
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn try_socks(socks: u16, target: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", socks))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;

    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting)?;
    if greeting != [0x05, 0x00] {
        return Err(std::io::Error::other(format!(
            "the proxy did not offer SOCKS5 without authentication: {greeting:?}"
        )));
    }

    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&target.to_be_bytes());
    s.write_all(&request)?;

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    if reply[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "the proxy refused to open the connection: {reply:?}"
        )));
    }
    Ok(s)
}

#[cfg(unix)]
fn lanes_up(bin: &str, socket: &str, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        let out = Command::new(bin)
            .args(["status", "--socket", socket, "--json"])
            .output();
        if let Ok(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(rest) = text.split("\"lanes_up\":").nth(1) {
                let n: u32 = rest
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0);
                if n > 0 {
                    return true;
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn run(bin: &str, args: &[&str]) -> String {
    let out = Command::new(bin)
        .args(args)
        .output()
        .expect("the binary runs");
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 output")
}

fn write_pair(dir: &std::path::Path, printed: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let parts: Vec<&str> = printed.split("##########").collect();
    assert_eq!(parts.len(), 5, "init prints an entry and an exit config");
    let file = |name: &str, body: &str| {
        let path = dir.join(format!("{name}.toml"));
        let socket = if cfg!(unix) {
            format!(
                "control_socket = '{}'\n",
                dir.join(format!("{name}.sock")).display()
            )
        } else {
            String::new()
        };
        std::fs::write(&path, socket + body.trim_start()).expect("the config is written");
        path
    };
    (file("entry", parts[2]), file("exit", parts[4]))
}

fn daemon(bin: &str, dir: &std::path::Path, file: &std::path::Path, name: &str) -> Daemon {
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
}

#[cfg(unix)]
fn udp_echo_server(ip: &str) -> u16 {
    let sock = UdpSocket::bind((ip, 0)).expect("a udp echo socket");
    let port = sock.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let _ = sock.send_to(&buf[..n], from);
        }
    });
    port
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
    let (entry, exit) = write_pair(&dir, &printed);

    for file in [&entry, &exit] {
        let said = run(bin, &["check", "-c", &file.display().to_string()]);
        assert!(said.contains("config OK"), "{}: {said}", file.display());
    }

    let far = daemon(bin, &dir, &exit, "exit");
    assert!(
        wait_for(tunnel, Duration::from_secs(20)),
        "the far side listens on {tunnel}; it said:\n{}",
        far.complaint()
    );
    let near = daemon(bin, &dir, &entry, "entry");
    assert!(
        wait_for(socks, Duration::from_secs(20)),
        "the near side offers a proxy on {socks}; it said:\n{}",
        near.complaint()
    );

    #[cfg(unix)]
    {
        let status = dir.join("entry.sock").display().to_string();
        assert!(
            lanes_up(bin, &status, Duration::from_secs(20)),
            "the proxy port opens before the lanes do, so wait for a lane before using it; \
             the near side said:\n{}",
            near.complaint()
        );
    }

    let mut through = socks_connect(socks, echo, Duration::from_secs(30));
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

#[cfg(unix)]
#[test]
fn a_shabdiz_tunnel_carries_udp_and_answers_status() {
    let bin = env!("CARGO_BIN_EXE_rakhsh");
    let dir = std::env::temp_dir().join(format!("rakhsh-e2e-dgram-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a working directory");

    let (tunnel, forward, echo) = (free_port(), free_port(), udp_echo_server("127.0.0.1"));
    let printed = run(
        bin,
        &[
            "init",
            "--tunnel-addr",
            &format!("127.0.0.1:{tunnel}"),
            "--carrier",
            "shabdiz-udp",
            "--peer-ip",
            "127.0.0.1",
            "--forward",
            &format!("127.0.0.1:{forward}=127.0.0.1:{echo}/udp"),
        ],
    );
    let (entry, exit) = write_pair(&dir, &printed);

    let near = daemon(bin, &dir, &entry, "entry");
    let far = daemon(bin, &dir, &exit, "exit");

    udp_round_trip(forward, &near, &far);

    let status = dir.join("entry.sock").display().to_string();
    assert!(
        lanes_up(bin, &status, Duration::from_secs(5)),
        "a shabdiz entry answers status with its live session; it said:\n{}",
        near.complaint()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_shabdiz_tunnel_runs_over_ipv6() {
    if UdpSocket::bind("[::1]:0").is_err() {
        return;
    }
    let bin = env!("CARGO_BIN_EXE_rakhsh");
    let dir = std::env::temp_dir().join(format!("rakhsh-e2e-dgram6-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a working directory");

    let (tunnel, forward, echo) = (free_port(), free_port(), udp_echo_server("::1"));
    let printed = run(
        bin,
        &[
            "init",
            "--tunnel-addr",
            &format!("[::1]:{tunnel}"),
            "--carrier",
            "shabdiz-udp",
            "--peer-ip",
            "::1",
            "--forward",
            &format!("127.0.0.1:{forward}=[::1]:{echo}/udp"),
        ],
    );
    let (entry, exit) = write_pair(&dir, &printed);

    let near = daemon(bin, &dir, &entry, "entry");
    let far = daemon(bin, &dir, &exit, "exit");
    udp_round_trip(forward, &near, &far);

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
fn udp_round_trip(forward: u16, near: &Daemon, far: &Daemon) {
    let probe = UdpSocket::bind("127.0.0.1:0").expect("a probe socket");
    probe
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let sent = b"a datagram that rides shabdiz there and back";
    let mut got = [0u8; 128];
    let deadline = Instant::now() + Duration::from_secs(20);
    let n = loop {
        let _ = probe.send_to(sent, ("127.0.0.1", forward));
        if let Ok((n, _)) = probe.recv_from(&mut got) {
            break n;
        }
        assert!(
            Instant::now() < deadline,
            "nothing came back through the tunnel; the near side said:\n{}\nthe far side said:\n{}",
            near.complaint(),
            far.complaint()
        );
    };
    assert_eq!(&got[..n], &sent[..], "the datagram comes back unchanged");
}
