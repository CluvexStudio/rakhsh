use std::process::Command;

fn rakhsh(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rakhsh"))
        .args(args)
        .output()
        .expect("the binary runs");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn config(body: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rakhsh-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a working directory");
    let path = dir.join(format!("{:x}.toml", body.len() as u64 * 2654435761));
    let head = "role = \"entry\"\n\
                token = \"ERERERERERERERERERERERERERERERERERERERERERE=\"\n\
                static_secret = \"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\"\n\
                peer_public = \"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=\"\n\
                tunnel_listen = \"0.0.0.0:7000\"\n";
    std::fs::write(&path, format!("{head}{body}")).expect("writing the config");
    path
}

#[test]
fn a_forward_without_a_target_is_refused_rather_than_duplicated() {
    let (ok, said) = rakhsh(&[
        "init",
        "--tunnel-addr",
        "198.51.100.7:443",
        "--forward",
        "0.0.0.0:8443:127.0.0.1:2096",
    ]);
    assert!(
        !ok,
        "a forward spec with no '=' must not be accepted: {said}"
    );
    assert!(
        said.contains("listen=target"),
        "the error says the syntax: {said}"
    );
}

#[test]
fn a_forward_spec_becomes_two_separate_keys() {
    let (ok, said) = rakhsh(&[
        "init",
        "--tunnel-addr",
        "198.51.100.7:443",
        "--forward",
        "0.0.0.0:8443=127.0.0.1:2096",
        "--forward",
        "0.0.0.0:51820=127.0.0.1:51820/udp",
    ]);
    assert!(ok, "init accepts listen=target: {said}");
    assert!(said.contains("listen = \"0.0.0.0:8443\""), "{said}");
    assert!(said.contains("target = \"127.0.0.1:2096\""), "{said}");
    assert!(
        said.contains("udp = true"),
        "the /udp suffix survives: {said}"
    );
}

#[test]
fn check_reports_every_forward() {
    let path = config(
        "\n[[forward]]\nlisten = \"0.0.0.0:8443\"\ntarget = \"127.0.0.1:2096\"\n\
         \n[[forward]]\nlisten = \"0.0.0.0:51820\"\ntarget = \"127.0.0.1:51820\"\nudp = true\n",
    );
    let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
    assert!(ok, "the config is valid: {said}");
    assert!(
        said.contains("forward tcp 0.0.0.0:8443 -> 127.0.0.1:2096"),
        "{said}"
    );
    assert!(
        said.contains("forward udp 0.0.0.0:51820 -> 127.0.0.1:51820"),
        "{said}"
    );
}

#[test]
fn init_writes_a_whole_openvpn_tunnel_that_checks_out() {
    let (ok, said) = rakhsh(&[
        "init",
        "--tunnel-addr",
        "198.51.100.7:7030",
        "--peer-ip",
        "203.0.113.9",
        "--carrier",
        "shabdiz-gre",
        "--openvpn",
        "udp:1194",
    ]);
    assert!(ok, "init accepts --openvpn: {said}");

    let halves: Vec<&str> = said.split("##########").collect();
    assert_eq!(halves.len(), 5, "an entry and an exit: {said}");

    let dir = std::env::temp_dir().join(format!("rakhsh-ovpn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a working directory");
    for (name, body) in [("entry", halves[2]), ("exit", halves[4])] {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(&path, body.trim_start()).expect("writing the config");
        let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
        assert!(ok, "{name} checks out: {said}");
        assert!(said.contains("config OK"), "{name}: {said}");
        assert!(
            !said.contains("set peer_ip"),
            "{name} already has its peer_ip, so check must not ask for one: {said}"
        );
    }

    let entry = dir.join("entry.toml");
    let (ok, said) = rakhsh(&["check", "-c", &entry.display().to_string()]);
    assert!(ok, "{said}");
    assert!(
        said.contains("forward udp 0.0.0.0:1194 -> 127.0.0.1:1194"),
        "{said}"
    );
    assert!(said.contains("openvpn: udp on 0.0.0.0:1194"), "{said}");
    assert!(
        said.contains("tun-mtu 1399"),
        "the mtu arithmetic is shown: {said}"
    );

    let (ok, said) = rakhsh(&["openvpn", "-c", &entry.display().to_string()]);
    assert!(ok, "the openvpn command runs: {said}");
    assert!(said.contains("proto udp"), "{said}");
    assert!(said.contains("tun-mtu 1399"), "{said}");
    assert!(said.contains("mssfix 1399 mtu"), "{said}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn init_writes_nothing_that_check_calls_inert() {
    for (carrier, forward) in [
        ("wss", "0.0.0.0:8443=127.0.0.1:8443"),
        ("quic", "0.0.0.0:8443=127.0.0.1:8443"),
        ("faketcp", "0.0.0.0:8443=127.0.0.1:8443"),
        ("shabdiz-gre", "0.0.0.0:1194=127.0.0.1:1194/udp"),
        ("shabdiz-udp", "0.0.0.0:1194=127.0.0.1:1194/udp"),
    ] {
        let (ok, said) = rakhsh(&[
            "init",
            "--tunnel-addr",
            "198.51.100.7:7030",
            "--peer-ip",
            "203.0.113.9",
            "--carrier",
            carrier,
            "--forward",
            forward,
        ]);
        assert!(ok, "init {carrier}: {said}");
        let halves: Vec<&str> = said.split("##########").collect();
        assert_eq!(halves.len(), 5, "init {carrier}: {said}");

        let dir =
            std::env::temp_dir().join(format!("rakhsh-init-{}-{carrier}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a working directory");
        for (name, body) in [("entry", halves[2]), ("exit", halves[4])] {
            let path = dir.join(format!("{name}.toml"));
            std::fs::write(&path, body.trim_start()).expect("writing the config");
            let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
            assert!(ok, "{carrier} {name}: {said}");
            for bad in ["WARNING", "note:"] {
                assert!(
                    !said.contains(bad),
                    "init wrote a {carrier} {name} that check calls out with {bad}: {said}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn a_datagram_carrier_puts_the_udp_forward_on_both_ends() {
    let (ok, said) = rakhsh(&[
        "init",
        "--tunnel-addr",
        "198.51.100.7:7030",
        "--peer-ip",
        "203.0.113.9",
        "--carrier",
        "shabdiz-gre",
        "--openvpn",
        "udp:1194",
    ]);
    assert!(ok, "{said}");
    let halves: Vec<&str> = said.split("##########").collect();
    assert_eq!(halves.len(), 5, "{said}");

    for (name, body) in [("entry", halves[2]), ("exit", halves[4])] {
        assert!(
            body.contains("udp = true"),
            "{name} needs the udp forward: a datagram carrier reads it on both ends\n{body}"
        );
        assert!(
            body.contains("[openvpn]"),
            "{name} keeps the section too\n{body}"
        );
    }

    let (ok, said) = rakhsh(&[
        "init",
        "--tunnel-addr",
        "198.51.100.7:443",
        "--carrier",
        "wss",
        "--forward",
        "0.0.0.0:443=127.0.0.1:8443",
    ]);
    assert!(ok, "{said}");
    let halves: Vec<&str> = said.split("##########").collect();
    assert!(halves[2].contains("[[forward]]"), "the entry forwards");
    assert!(
        !halves[4].contains("[[forward]]"),
        "a stream carrier keeps forwards on the entry only:\n{}",
        halves[4]
    );
}

#[test]
fn check_refuses_a_datagram_config_that_run_would_refuse() {
    let base = "carrier = \"shabdiz-gre\"\npeer_ip = \"203.0.113.9\"\n";
    let fwd = "\n[[forward]]\nlisten = \"0.0.0.0:1194\"\ntarget = \"127.0.0.1:1194\"\nudp = true\n";

    let no_forward = config(base);
    let (ok, said) = rakhsh(&["check", "-c", &no_forward.display().to_string()]);
    assert!(
        !ok,
        "a datagram carrier with no udp forward cannot run: {said}"
    );
    assert!(
        said.contains("udp = true"),
        "the error names the fix: {said}"
    );

    let tcp_forward = config(&format!(
        "{base}\n[[forward]]\nlisten = \"0.0.0.0:1194\"\ntarget = \"127.0.0.1:1194\"\n"
    ));
    let (ok, _) = rakhsh(&["check", "-c", &tcp_forward.display().to_string()]);
    assert!(!ok, "a stream forward does not satisfy a datagram carrier");

    let two = config(&format!("{base}{fwd}{fwd}"));
    let (ok, said) = rakhsh(&["check", "-c", &two.display().to_string()]);
    assert!(!ok, "two udp forwards is one too many: {said}");

    let no_peer = config(&format!("carrier = \"shabdiz-gre\"\n{fwd}"));
    let (ok, said) = rakhsh(&["check", "-c", &no_peer.display().to_string()]);
    assert!(!ok, "a raw carrier with no peer address cannot run: {said}");
    assert!(said.contains("peer_ip"), "the error names the fix: {said}");

    let whole = config(&format!("{base}{fwd}"));
    let (ok, said) = rakhsh(&["check", "-c", &whole.display().to_string()]);
    assert!(ok, "a complete datagram config passes: {said}");
    assert!(
        said.contains("carries udp 0.0.0.0:1194 -> 127.0.0.1:1194"),
        "{said}"
    );
}

#[test]
fn the_openvpn_command_needs_the_section() {
    let path = config("");
    let (ok, said) = rakhsh(&["openvpn", "-c", &path.display().to_string()]);
    assert!(
        !ok,
        "a config with no [openvpn] has nothing to print: {said}"
    );
    assert!(said.contains("no [openvpn]"), "{said}");
}

#[test]
fn check_refuses_a_forward_that_is_not_an_address() {
    for body in [
        "\n[[forward]]\nlisten = \"0.0.0.0:8443:127.0.0.1:2096\"\ntarget = \"127.0.0.1:2096\"\n",
        "\n[[forward]]\nlisten = \"0.0.0.0:8443\"\ntarget = \"127.0.0.1\"\n",
        "\n[[forward]]\nlisten = \"0.0.0.0:8443\"\ntarget = \"127.0.0.1:not-a-port\"\n",
    ] {
        let path = config(body);
        let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
        assert!(!ok, "check must reject {body:?}, it said: {said}");
        assert!(!said.contains("config OK"), "{said}");
    }
}

#[test]
fn a_top_level_key_written_after_a_table_is_refused() {
    // TOML gives the key to the table above it, where it would do nothing.
    for (body, where_) in [
        (
            "\n[route]\nfinal = \"direct\"\ncontrol_socket = \"/run/x.sock\"\n",
            "route",
        ),
        (
            "\n[[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:8443\"\nlanes = 4\n",
            "forward",
        ),
        (
            "\n[[inbound]]\ntype = \"socks\"\nlisten = \"127.0.0.1:1080\"\nresume_grace = 30\n",
            "inbound",
        ),
        (
            "\n[dns]\nlisten = \"127.0.0.1:53\"\nmss_clamp = 1380\n",
            "dns",
        ),
    ] {
        let path = config(body);
        let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
        assert!(!ok, "a stray key in [{where_}] must be refused: {said}");
        assert!(
            said.contains("unknown field"),
            "and the error must name it: {said}"
        );
    }
}

#[test]
fn the_strict_table_key_lists_match_the_structs() {
    // The [[inbound]]/[[forward]] check keeps its own key list, because serde
    // cannot deny unknown fields next to a flattened struct. Keep them in step.
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"))
        .expect("config.rs is readable");
    let fields = |name: &str| -> Vec<String> {
        let start = src.find(&format!("pub struct {name} {{")).expect(name);
        let body = &src[start..start + src[start..].find("\n}").expect("struct end")];
        body.lines()
            .filter_map(|l| l.trim().strip_prefix("pub "))
            .filter_map(|l| l.split(':').next())
            .filter(|n| !n.contains(' ') && *n != "limits")
            .map(|n| {
                if n == "kind" {
                    "type".into()
                } else {
                    n.to_string()
                }
            })
            .collect()
    };
    for (name, list) in [
        ("Inbound", rakhsh_keys("INBOUND_KEYS", &src)),
        ("Forward", rakhsh_keys("FORWARD_KEYS", &src)),
        ("Limits", rakhsh_keys("LIMIT_KEYS", &src)),
    ] {
        let mut want = fields(name);
        want.sort();
        let mut got = list;
        got.sort();
        assert_eq!(got, want, "{name} and its key list disagree");
    }
}

fn rakhsh_keys(konst: &str, src: &str) -> Vec<String> {
    let start = src.find(&format!("pub const {konst}")).expect(konst);
    let body = &src[start..start + src[start..].find("];").expect("list end")];
    body.match_indices('"')
        .step_by(2)
        .map(|(i, _)| {
            let rest = &body[i + 1..];
            rest[..rest.find('"').unwrap()].to_string()
        })
        .collect()
}

#[test]
fn a_sync_listen_with_a_port_is_refused_before_it_fails_to_bind() {
    let path = config("accept_sync = true\nsync_listen = \"127.0.0.1:7777\"\n");
    let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
    assert!(
        !ok,
        "the port of a pushed forward comes from the panel: {said}"
    );
    assert!(
        said.contains("bare address"),
        "the error says the shape: {said}"
    );
    let path = config("accept_sync = true\nsync_listen = \"127.0.0.1\"\n");
    let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
    assert!(ok, "a bare address is what it wants: {said}");
}

#[test]
fn check_says_where_mss_clamp_applies() {
    let path = config("mss_clamp = 1380\n");
    let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
    assert!(ok, "{said}");
    assert!(
        said.contains("mss_clamp is read in layer-3 mode only"),
        "a key that does nothing here is said to do nothing: {said}"
    );

    let path = config("l3_addr = \"10.77.0.1/30\"\nl3_auto_mtu = true\nmss_clamp = 1300\n");
    let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
    assert!(ok, "{said}");
    assert!(
        said.contains("layer 3: a tun device on 10.77.0.1/30"),
        "{said}"
    );
    assert!(
        said.contains("mtu 1380"),
        "tcp carries 1380 under l3_auto_mtu: {said}"
    );
    assert!(said.contains("mss clamped to 1300, against 1340"), "{said}");
    assert!(
        !said.contains("mss_clamp is read in layer-3 mode only"),
        "{said}"
    );

    let path = config("l3_addr = \"10.77.0.1/30\"\nl3_mtu = 1280\nmss_clamp = 1380\n");
    let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
    assert!(ok, "{said}");
    assert!(
        said.contains("WARNING: mss_clamp = 1380 is above the 1240"),
        "a clamp wider than the device is a warning: {said}"
    );
}

#[test]
fn check_names_what_a_datagram_carrier_does_not_read() {
    let path = config(
        "carrier = \"shabdiz-udp\"\nresume = true\nlanes = 4\nlimit = \"100mbit\"\n\
         \n[[forward]]\nlisten = \"0.0.0.0:1194\"\ntarget = \"127.0.0.1:1194\"\nudp = true\n\
         \n[[inbound]]\ntype = \"socks\"\nlisten = \"127.0.0.1:1080\"\n",
    );
    let (ok, said) = rakhsh(&["check", "-c", &path.display().to_string()]);
    assert!(ok, "the config is valid, just partly inert: {said}");
    for key in ["lanes", "resume", "[[inbound]]", "the limit and quota keys"] {
        assert!(said.contains(key), "{key} is not named as ignored: {said}");
    }
}
