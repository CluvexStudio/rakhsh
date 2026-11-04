use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn reference() -> PathBuf {
    root().join("rakhsh.example.toml")
}

fn examples() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(root().join("examples"))
        .expect("an examples directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    v.sort();
    assert!(v.len() >= 9, "the example configs are missing: {v:?}");
    v
}

fn every_config() -> Vec<PathBuf> {
    let mut v = vec![reference()];
    v.extend(examples());
    v
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn check(path: &Path) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rakhsh"))
        .args(["check", "-c", &path.display().to_string()])
        .output()
        .expect("the binary runs");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn deserialized_fields(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut derives = false;
    let mut inside = false;
    let mut rename: Option<String> = None;
    let mut skip = false;
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with("#[derive(") {
            derives = t.contains("Deserialize");
            continue;
        }
        if t.starts_with("pub struct ") {
            inside = derives;
            derives = false;
            continue;
        }
        if t == "}" {
            inside = false;
            continue;
        }
        if !inside {
            continue;
        }
        if t.starts_with("#[serde(") {
            skip = t.contains("skip") || t.contains("flatten");
            if let Some(i) = t.find("rename = \"") {
                let rest = &t[i + "rename = \"".len()..];
                rename = rest.find('"').map(|j| rest[..j].to_string());
            }
            continue;
        }
        if let Some(rest) = t.strip_prefix("pub ") {
            let name = rest.split(':').next().unwrap_or("");
            if !name.is_empty() && !name.contains(' ') && !name.contains('(') && !skip {
                out.insert(rename.take().unwrap_or_else(|| name.to_string()));
            }
        }
        rename = None;
        skip = false;
    }
    out
}

fn config_keys() -> BTreeSet<String> {
    let mut f = deserialized_fields(&read(&root().join("src/config.rs")));
    f.extend(deserialized_fields(&read(&root().join("src/openvpn.rs"))));
    assert!(f.contains("token"), "the field scan found nothing: {f:?}");
    f
}

fn keys_written(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim_start().trim_start_matches('#').trim_start();
        let Some((name, _)) = t.split_once(" = ") else {
            continue;
        };
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            out.insert(name.to_string());
        }
    }
    out
}

fn tables_written(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim_start().trim_start_matches('#').trim_start();
        let t = t.trim_end();
        if !t.starts_with('[') || !t.ends_with(']') {
            continue;
        }
        for part in t.trim_matches(|c| c == '[' || c == ']').split('.') {
            out.insert(part.to_string());
        }
    }
    out
}

fn table(path: &Path) -> toml::Table {
    read(path)
        .parse::<toml::Table>()
        .unwrap_or_else(|e| panic!("{} is not valid TOML: {e}", path.display()))
}

#[test]
fn every_shipped_config_passes_check_with_no_warning() {
    for p in every_config() {
        let (ok, text) = check(&p);
        assert!(ok, "check rejected {}:\n{text}", p.display());
        for bad in ["WARNING", "ERROR", "note:"] {
            assert!(
                !text.contains(bad),
                "check reports a {bad} for {} — a shipped config must be clean:\n{text}",
                p.display()
            );
        }
        assert!(
            text.contains("config OK"),
            "check did not finish for {}:\n{text}",
            p.display()
        );
    }
}

#[test]
fn the_reference_documents_every_key_the_parser_accepts() {
    let text = read(&reference());
    let written: BTreeSet<String> = keys_written(&text)
        .union(&tables_written(&text))
        .cloned()
        .collect();
    let missing: Vec<String> = config_keys()
        .into_iter()
        .filter(|k| !written.contains(k))
        .collect();
    assert!(
        missing.is_empty(),
        "rakhsh.example.toml does not mention {missing:?} — every key the parser accepts belongs \
         in the reference, commented out if it does not apply to the live example"
    );
}

#[test]
fn no_shipped_config_sets_a_key_the_parser_would_ignore() {
    let known = config_keys();
    for p in every_config() {
        let text = read(&p);
        let unknown: Vec<String> = keys_written(&text)
            .into_iter()
            .filter(|k| !known.contains(k))
            .collect();
        assert!(
            unknown.is_empty(),
            "{} writes {unknown:?}, which the parser does not read",
            p.display()
        );
    }
}

#[test]
fn no_shipped_config_carries_real_key_material() {
    use base64::prelude::{Engine, BASE64_STANDARD};
    let mut seen = 0;
    for p in every_config() {
        let t = table(&p);
        let mut values: Vec<(&str, &str)> = Vec::new();
        for name in ["token", "static_secret", "peer_public"] {
            if let Some(v) = t.get(name).and_then(|v| v.as_str()) {
                values.push((name, v));
            }
        }
        if let Some(peers) = t.get("peer").and_then(|v| v.as_array()) {
            for peer in peers.iter().filter_map(|v| v.as_table()) {
                if let Some(v) = peer.get("public").and_then(|v| v.as_str()) {
                    values.push(("[[peer]] public", v));
                }
            }
        }
        for (name, value) in values {
            let raw = BASE64_STANDARD
                .decode(value)
                .unwrap_or_else(|e| panic!("{} has a bad {name}: {e}", p.display()));
            assert_eq!(raw.len(), 32, "{} has a short {name}", p.display());
            assert!(
                raw.iter().all(|b| *b == raw[0]),
                "{} carries a real-looking {name}: a shipped config must hold an obvious \
                 placeholder, never key material",
                p.display()
            );
            seen += 1;
        }
    }
    assert!(seen >= 25, "only {seen} identity values were checked");
}

#[test]
fn each_example_pair_agrees_on_what_the_handshake_binds() {
    let must_match = [
        "token",
        "carrier",
        "encryption",
        "resume",
        "resume_grace",
        "dial",
        "sni",
        "ws_path",
        "ws_credential",
        "reliability",
        "link_encrypt",
        "fec_data",
        "fec_parity",
        "l3_gre",
        "gre_key",
        "l3_mtu",
        "l3_auto_mtu",
        "mss_clamp",
        "l3_paths",
        "pace_burst",
        "pace_gap_us",
        "pace_pps",
        "pace_auto",
    ];
    let pairs = [
        ("entry.toml", "exit.toml"),
        ("openvpn-entry.toml", "openvpn-exit.toml"),
        ("l3-entry.toml", "l3-exit.toml"),
        ("raw-entry.toml", "raw-exit.toml"),
    ];
    for (a, b) in pairs {
        let dir = root().join("examples");
        let (ea, eb) = (table(&dir.join(a)), table(&dir.join(b)));
        assert_eq!(ea["role"].as_str(), Some("entry"), "{a}");
        assert_eq!(eb["role"].as_str(), Some("exit"), "{b}");
        assert!(ea.contains_key("carrier"), "{a} names no carrier");
        for key in must_match {
            match (ea.get(key), eb.get(key)) {
                (Some(x), Some(y)) => assert_eq!(x, y, "{a} and {b} disagree on {key}"),
                (None, None) => {}
                (x, y) => panic!("{key} is set on one half only: {a} {x:?}, {b} {y:?}"),
            }
        }
        for key in ["static_secret", "peer_public"] {
            assert_ne!(ea.get(key), eb.get(key), "{a} and {b} share {key}");
        }
        if let (Some(listen), Some(connect)) = (
            ea.get("tunnel_listen").and_then(|v| v.as_str()),
            eb.get("tunnel_connect").and_then(|v| v.as_str()),
        ) {
            assert_eq!(
                listen.rsplit(':').next(),
                connect.rsplit(':').next(),
                "{a} listens on another port than {b} dials"
            );
        }
        let forwards = |t: &toml::Table| -> Vec<BTreeMap<String, String>> {
            t.get("forward")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|f| f.as_table())
                        .map(|f| {
                            f.iter()
                                .map(|(k, v)| (k.clone(), v.to_string()))
                                .collect::<BTreeMap<_, _>>()
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        if ea["carrier"]
            .as_str()
            .is_some_and(|c| c.starts_with("shabdiz-"))
        {
            assert_eq!(
                forwards(&ea),
                forwards(&eb),
                "a datagram carrier carries one udp forward, and both halves must name the same one"
            );
            assert_eq!(
                ea.get("openvpn"),
                eb.get("openvpn"),
                "{a} and {b} disagree on [openvpn]"
            );
            for half in [(a, &ea), (b, &eb)] {
                assert!(
                    half.1.contains_key("peer_ip"),
                    "{} needs peer_ip: a forged packet carries no connection to learn it from",
                    half.0
                );
            }
        }
    }
}
