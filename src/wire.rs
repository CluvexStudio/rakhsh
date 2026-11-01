use bytes::Bytes;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

pub const T_OPEN: u8 = 1;
pub const T_DATA: u8 = 2;
pub const T_CLOSE: u8 = 3;
pub const T_PING: u8 = 4;
pub const T_PONG: u8 = 5;
pub const T_CREDIT: u8 = 6;
pub const T_L3: u8 = 7;
pub const T_FIN: u8 = 8;
pub const T_SYNC: u8 = 9;

pub const MAX_PAYLOAD: usize = 16 * 1024;

pub const FLAG_UDP: u8 = 1;
pub const FLAG_PROXY: u8 = 2;

#[derive(Debug)]
pub enum Frame {
    Open {
        id: u32,
        flags: u8,
        target: String,
        client: Option<String>,
    },
    Data {
        id: u32,
        data: Bytes,
    },
    Close {
        id: u32,
    },
    Ping,
    Pong,
    Credit {
        id: u32,
        n: u32,
    },
    L3 {
        pkt: Bytes,
    },
    Fin {
        id: u32,
    },
    Sync {
        json: Bytes,
    },
}

pub fn open(id: u32, flags: u8, target: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(6 + target.len());
    v.push(T_OPEN);
    v.extend_from_slice(&id.to_be_bytes());
    v.push(flags);
    v.extend_from_slice(target.as_bytes());
    v
}

pub fn open_pp(id: u32, flags: u8, target: &str, client: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + client.len() + target.len());
    v.push(T_OPEN);
    v.extend_from_slice(&id.to_be_bytes());
    v.push(flags | FLAG_PROXY);
    v.extend_from_slice(&(client.len() as u16).to_be_bytes());
    v.extend_from_slice(client.as_bytes());
    v.extend_from_slice(target.as_bytes());
    v
}

use crate::noise::TAG;

pub fn data(id: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + payload.len() + TAG);
    v.push(T_DATA);
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

pub fn close(id: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + TAG);
    v.push(T_CLOSE);
    v.extend_from_slice(&id.to_be_bytes());
    v
}

pub fn sync(json: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + json.len());
    v.push(T_SYNC);
    v.extend_from_slice(json);
    v
}

pub fn fin(id: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + TAG);
    v.push(T_FIN);
    v.extend_from_slice(&id.to_be_bytes());
    v
}

pub fn credit(id: u32, n: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + TAG);
    v.push(T_CREDIT);
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&n.to_be_bytes());
    v
}

pub fn l3(pkt: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + pkt.len() + TAG);
    v.push(T_L3);
    v.extend_from_slice(pkt);
    v
}

pub fn ping() -> Vec<u8> {
    vec![T_PING]
}

pub fn pong() -> Vec<u8> {
    vec![T_PONG]
}

pub fn parse(buf: &Bytes) -> Option<Frame> {
    let plain: &[u8] = buf;
    let t = *plain.first()?;
    match t {
        T_PING => return Some(Frame::Ping),
        T_PONG => return Some(Frame::Pong),
        T_L3 => {
            return Some(Frame::L3 {
                pkt: buf.slice(1..),
            })
        }
        T_SYNC => {
            return Some(Frame::Sync {
                json: buf.slice(1..),
            })
        }
        _ => {}
    }
    if plain.len() < 5 {
        return None;
    }
    let id = u32::from_be_bytes([plain[1], plain[2], plain[3], plain[4]]);
    let body = &plain[5..];
    match t {
        T_OPEN => {
            let flags = *body.first()?;
            let rest = &body[1..];
            if flags & FLAG_PROXY != 0 {
                if rest.len() < 2 {
                    return None;
                }
                let clen = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                if rest.len() < 2 + clen {
                    return None;
                }
                let client = String::from_utf8(rest[2..2 + clen].to_vec()).ok()?;
                let target = String::from_utf8(rest[2 + clen..].to_vec()).ok()?;
                Some(Frame::Open {
                    id,
                    flags,
                    target,
                    client: Some(client),
                })
            } else {
                let target = String::from_utf8(rest.to_vec()).ok()?;
                Some(Frame::Open {
                    id,
                    flags,
                    target,
                    client: None,
                })
            }
        }
        T_DATA => Some(Frame::Data {
            id,
            data: buf.slice(5..),
        }),
        T_CLOSE => Some(Frame::Close { id }),
        T_FIN => Some(Frame::Fin { id }),
        T_CREDIT => {
            if body.len() < 4 {
                return None;
            }
            let n = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            Some(Frame::Credit { id, n })
        }
        _ => None,
    }
}

pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length frame",
        ));
    }
    let mut buf: Vec<u8> = Vec::with_capacity(n);
    let mut limited = tokio::io::AsyncReadExt::take(&mut *r, n as u64);
    while buf.len() < n {
        if limited.read_buf(&mut buf).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof inside record",
            ));
        }
    }
    Ok(buf)
}

pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, body: &[u8]) -> io::Result<()> {
    if body.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = Vec::with_capacity(2 + body.len());
    buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
    buf.extend_from_slice(body);
    w.write_all(&buf).await
}
