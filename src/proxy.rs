use anyhow::{anyhow, bail, Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::route::{Dest, Host};

pub struct Auth {
    pub user: String,
    pub pass: String,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Socks,
    SocksUdp,
    HttpConnect,
    HttpPlain,
}

pub struct Request {
    pub dest: Dest,
    pub kind: Kind,
    pub early: Vec<u8>,
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn accept(s: &mut TcpStream, mode: &str, auth: &Option<Auth>) -> Result<Request> {
    let socks = match mode {
        "socks" => true,
        "http" => false,
        _ => {
            let mut b = [0u8; 1];
            if s.peek(&mut b).await? == 0 {
                bail!("client closed before sending anything");
            }
            b[0] == 5
        }
    };
    if socks {
        socks5(s, auth).await
    } else {
        http(s, auth).await
    }
}

async fn socks5(s: &mut TcpStream, auth: &Option<Auth>) -> Result<Request> {
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        bail!("not a SOCKS5 client");
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    s.read_exact(&mut methods).await?;
    let want = if auth.is_some() { 2u8 } else { 0u8 };
    if !methods.contains(&want) {
        s.write_all(&[5, 0xff]).await?;
        bail!("client offers no acceptable auth method");
    }
    s.write_all(&[5, want]).await?;
    if let Some(a) = auth {
        let mut v = [0u8; 2];
        s.read_exact(&mut v).await?;
        let mut u = vec![0u8; v[1] as usize];
        s.read_exact(&mut u).await?;
        let mut pl = [0u8; 1];
        s.read_exact(&mut pl).await?;
        let mut p = vec![0u8; pl[0] as usize];
        s.read_exact(&mut p).await?;
        let ok = v[0] == 1 && ct_eq(&u, a.user.as_bytes()) & ct_eq(&p, a.pass.as_bytes());
        s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
        if !ok {
            bail!("socks5 authentication failed");
        }
    }
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await?;
    if r[0] != 5 {
        bail!("bad socks5 request version");
    }
    let host = match r[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            Host::Ip(IpAddr::from(a))
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            Host::Domain(
                String::from_utf8(d)
                    .context("non-utf8 domain")?
                    .to_ascii_lowercase(),
            )
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            Host::Ip(IpAddr::from(a))
        }
        _ => {
            socks_reply(s, 0x08).await?;
            bail!("unsupported socks5 address type {}", r[3]);
        }
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    match r[1] {
        1 => Ok(Request {
            dest: Dest {
                host,
                port: u16::from_be_bytes(p),
            },
            kind: Kind::Socks,
            early: Vec::new(),
        }),
        3 => Ok(Request {
            dest: Dest {
                host,
                port: u16::from_be_bytes(p),
            },
            kind: Kind::SocksUdp,
            early: Vec::new(),
        }),
        c => {
            socks_reply(s, 0x07).await?;
            bail!("socks5 command {c} not supported (CONNECT and UDP ASSOCIATE only)");
        }
    }
}

pub async fn socks_reply_addr(
    s: &mut TcpStream,
    addr: std::net::SocketAddr,
) -> std::io::Result<()> {
    let mut v = vec![5, 0, 0];
    match addr.ip() {
        IpAddr::V4(a) => {
            v.push(1);
            v.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            v.push(4);
            v.extend_from_slice(&a.octets());
        }
    }
    v.extend_from_slice(&addr.port().to_be_bytes());
    s.write_all(&v).await
}

pub fn parse_udp_datagram(d: &[u8]) -> Option<(Dest, usize)> {
    if d.len() < 10 || d[2] != 0 {
        return None;
    }
    let (host, off) = match d[3] {
        1 => (Host::Ip(IpAddr::from([d[4], d[5], d[6], d[7]])), 8),
        3 => {
            let l = *d.get(4)? as usize;
            let name = std::str::from_utf8(d.get(5..5 + l)?)
                .ok()?
                .to_ascii_lowercase();
            (Host::Domain(name), 5 + l)
        }
        4 => {
            let a: [u8; 16] = d.get(4..20)?.try_into().ok()?;
            (Host::Ip(IpAddr::from(a)), 20)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*d.get(off)?, *d.get(off + 1)?]);
    Some((Dest { host, port }, off + 2))
}

pub fn udp_reply_header(from: &Dest) -> Vec<u8> {
    let mut v = vec![0, 0, 0];
    match &from.host {
        Host::Ip(IpAddr::V4(a)) => {
            v.push(1);
            v.extend_from_slice(&a.octets());
        }
        Host::Ip(IpAddr::V6(a)) => {
            v.push(4);
            v.extend_from_slice(&a.octets());
        }
        Host::Domain(d) => {
            v.push(3);
            v.push(d.len().min(255) as u8);
            v.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
        }
    }
    v.extend_from_slice(&from.port.to_be_bytes());
    v
}

pub async fn socks_reply(s: &mut TcpStream, code: u8) -> std::io::Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

pub fn socks_code(e: &std::io::Error) -> u8 {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => 5,
        TimedOut => 6,
        NetworkUnreachable => 3,
        HostUnreachable => 4,
        _ => 1,
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn split_hostport(a: &str, default: u16) -> Result<(String, u16)> {
    if let Some(r) = a.strip_prefix('[') {
        let (h, rest) = r
            .split_once(']')
            .ok_or_else(|| anyhow!("bad IPv6 authority {a}"))?;
        let port = match rest.strip_prefix(':') {
            Some(p) => p.parse()?,
            None => default,
        };
        return Ok((h.to_string(), port));
    }
    match a.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h.to_string(), p.parse()?)),
        _ => Ok((a.to_string(), default)),
    }
}

async fn http(s: &mut TcpStream, auth: &Option<Auth>) -> Result<Request> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            bail!("client closed mid-request");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 32 * 1024 {
            bail!("HTTP request head too large");
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let rest = buf[head_end..].to_vec();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("empty request line"))?;
    let target = parts
        .next()
        .ok_or_else(|| anyhow!("request line has no target"))?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    if let Some(a) = auth {
        let expect = format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{}:{}", a.user, a.pass))
        );
        let given = head
            .split("\r\n")
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("proxy-authorization")
                    .then(|| v.trim().to_string())
            })
            .unwrap_or_default();
        if !ct_eq(given.as_bytes(), expect.as_bytes()) {
            let _ = s
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"rakhsh\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            bail!("proxy authentication failed");
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (h, p) = split_hostport(target, 443)?;
        return Ok(Request {
            dest: Dest {
                host: Host::parse(&h),
                port: p,
            },
            kind: Kind::HttpConnect,
            early: rest,
        });
    }

    let after = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))
        .ok_or_else(|| {
            anyhow!("unsupported proxy request target {target:?} (https needs CONNECT)")
        })?;
    let (authority, path) = match after.find('/') {
        Some(i) => (&after[..i], &after[i..]),
        None => (after, "/"),
    };
    let (h, p) = split_hostport(authority, 80)?;
    let mut out = format!("{method} {path} {version}\r\n");
    let mut has_host = false;
    for l in lines {
        if l.is_empty() {
            continue;
        }
        let name = l
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match name.as_str() {
            "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive" => continue,
            "host" => has_host = true,
            _ => {}
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    if !has_host {
        out.push_str(&format!("Host: {authority}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    let mut early = out.into_bytes();
    early.extend_from_slice(&rest);
    Ok(Request {
        dest: Dest {
            host: Host::parse(&h),
            port: p,
        },
        kind: Kind::HttpPlain,
        early,
    })
}

pub fn proxy_v2(client: std::net::SocketAddr, target: std::net::SocketAddr) -> Vec<u8> {
    use std::net::SocketAddr::{V4, V6};
    let mut h = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    h.push(0x21);
    match client {
        V4(c) => {
            h.push(0x11);
            h.extend_from_slice(&12u16.to_be_bytes());
            h.extend_from_slice(&c.ip().octets());
            match target {
                V4(t) => h.extend_from_slice(&t.ip().octets()),
                _ => h.extend_from_slice(&[0, 0, 0, 0]),
            }
            h.extend_from_slice(&c.port().to_be_bytes());
            h.extend_from_slice(&target.port().to_be_bytes());
        }
        V6(c) => {
            h.push(0x21);
            h.extend_from_slice(&36u16.to_be_bytes());
            h.extend_from_slice(&c.ip().octets());
            match target {
                V6(t) => h.extend_from_slice(&t.ip().octets()),
                _ => h.extend_from_slice(&[0u8; 16]),
            }
            h.extend_from_slice(&c.port().to_be_bytes());
            h.extend_from_slice(&target.port().to_be_bytes());
        }
    }
    h
}

pub async fn http_connected(s: &mut TcpStream) -> std::io::Result<()> {
    s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
}

pub async fn http_fail(s: &mut TcpStream, status: &str) {
    let _ = s
        .write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await;
}

#[cfg(test)]
#[path = "../tests/unit/proxy_udp.rs"]
mod udp_tests;
