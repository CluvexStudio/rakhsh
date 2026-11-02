use anyhow::{anyhow, bail, Context, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use snow::Builder;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::Arc;
use std::time::Duration;

use crate::carrier::{FrameRx, FrameTx};

pub const PARAMS: &str = "Noise_IKpsk2_25519_AESGCM_BLAKE2s";
pub const PROLOGUE: &[u8] = b"rakhsh-v1";
const VERSION: u8 = 1;

const CONFIRM_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Full,
    None,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "full" => Ok(Mode::Full),
            "none" => Ok(Mode::None),
            other => bail!("encryption must be \"full\" or \"none\" (got \"{other}\")"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Full => "full",
            Mode::None => "none",
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            Mode::Full => "AES-256-GCM on every record",
            Mode::None => "NO data protection after the handshake: only for traffic that is already encrypted end to end",
        }
    }

    pub fn announce(self) {
        match self {
            Mode::Full => tracing::info!("data protection: full ({})", self.summary()),
            Mode::None => tracing::warn!("data protection: none — {}", self.summary()),
        }
    }

    fn prologue(self) -> &'static [u8] {
        match self {
            Mode::Full => PROLOGUE,
            Mode::None => b"rakhsh-v1/none",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proto {
    pub mode: Mode,
    pub resume: bool,
}

impl From<Mode> for Proto {
    fn from(mode: Mode) -> Proto {
        Proto {
            mode,
            resume: false,
        }
    }
}

impl Proto {
    fn prologue(self) -> Vec<u8> {
        let mut p = self.mode.prologue().to_vec();
        if self.resume {
            p.extend_from_slice(b"/resume");
        }
        p
    }
}

#[derive(Clone)]
pub struct Keys {
    pub local: [u8; 32],
    pub admitted: Vec<[u8; 32]>,
    pub names: Vec<String>,
    pub psk: [u8; 32],
    pub mode: Mode,
    pub resume: bool,
}

impl Keys {
    pub fn from_cfg(cfg: &crate::config::Config) -> Result<Keys> {
        let admitted = cfg.peer_keys()?;
        Ok(Keys {
            local: cfg.secret_key()?,
            names: admitted.iter().map(|p| p.name.clone()).collect(),
            admitted: admitted.iter().map(|p| p.key).collect(),
            psk: derive_psk(&cfg.token),
            mode: cfg.crypto_mode()?,
            resume: cfg.resume,
        })
    }

    pub async fn connect_to(
        &self,
        peer: &[u8; 32],
        tx: &mut dyn FrameTx,
        rx: &mut dyn FrameRx,
    ) -> Result<Enc> {
        client_handshake(
            tx,
            rx,
            &self.local,
            peer,
            &self.psk,
            Proto {
                mode: self.mode,
                resume: self.resume,
            },
        )
        .await
    }

    pub async fn accept(&self, tx: &mut dyn FrameTx, rx: &mut dyn FrameRx) -> Result<(Enc, usize)> {
        server_handshake(
            tx,
            rx,
            &self.local,
            &self.psk,
            &self.admitted,
            Proto {
                mode: self.mode,
                resume: self.resume,
            },
        )
        .await
    }

    pub fn admitted_name(&self, i: usize) -> &str {
        self.names.get(i).map(String::as_str).unwrap_or("peer")
    }
}

pub fn derive_psk(token: &str) -> [u8; 32] {
    blake3::derive_key("rakhsh psk v1", token.as_bytes())
}

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let kp = Builder::new(PARAMS.parse()?).generate_keypair()?;
    Ok((kp.private, kp.public))
}

pub const TAG: usize = 16;

#[derive(Clone)]
pub struct Enc(Arc<EncInner>);

struct EncInner {
    seal: LessSafeKey,
    open: LessSafeKey,
    mode: Mode,
    send_n: AtomicU64,
    recv_n: AtomicU64,
}

fn nonce(n: u64) -> Nonce {
    let mut b = [0u8; 12];
    b[4..].copy_from_slice(&n.to_be_bytes());
    Nonce::assume_unique_for_key(b)
}

impl Enc {
    fn from_raw_split(i2r: [u8; 32], r2i: [u8; 32], initiator: bool, mode: Mode) -> Self {
        let (send, recv) = if initiator { (i2r, r2i) } else { (r2i, i2r) };
        let key = |k: &[u8; 32]| {
            LessSafeKey::new(UnboundKey::new(&AES_256_GCM, k).expect("AES-256 key is 32 bytes"))
        };
        Enc(Arc::new(EncInner {
            seal: key(&send),
            open: key(&recv),
            mode,
            send_n: AtomicU64::new(0),
            recv_n: AtomicU64::new(0),
        }))
    }

    pub fn seal_in_place(&self, buf: &mut Vec<u8>) {
        let n = self.0.send_n.fetch_add(1, SeqCst);
        assert!(n != u64::MAX, "record nonce space exhausted");
        match self.0.mode {
            Mode::Full => self
                .0
                .seal
                .seal_in_place_append_tag(nonce(n), Aad::empty(), buf)
                .expect("seal"),
            Mode::None if n == 0 => self
                .0
                .seal
                .seal_in_place_append_tag(nonce(n), Aad::empty(), buf)
                .expect("seal"),
            Mode::None => {}
        }
        crate::stats::add_tx(buf.len());
    }

    pub fn open_in_place(&self, buf: &mut [u8]) -> Result<usize> {
        let n = self.0.recv_n.load(SeqCst);
        let bad = |_| anyhow!("record failed authentication");
        let len = match self.0.mode {
            Mode::Full => self
                .0
                .open
                .open_in_place(nonce(n), Aad::empty(), buf)
                .map_err(bad)?
                .len(),
            Mode::None if n == 0 => self
                .0
                .open
                .open_in_place(nonce(n), Aad::empty(), buf)
                .map_err(bad)?
                .len(),
            Mode::None => buf.len(),
        };
        self.0.recv_n.store(n + 1, SeqCst);
        crate::stats::add_rx(len);
        Ok(len)
    }

    pub fn open_bytes(&self, mut rec: bytes::BytesMut) -> Result<bytes::Bytes> {
        let len = self.open_in_place(&mut rec)?;
        rec.truncate(len);
        Ok(rec.freeze())
    }

    #[cfg(test)]
    pub fn open_vec(&self, v: Vec<u8>) -> Result<bytes::Bytes> {
        self.open_bytes(bytes::BytesMut::from(&v[..]))
    }
}

fn finish(mut hs: snow::HandshakeState, initiator: bool, mode: Mode) -> Result<(Enc, Vec<u8>)> {
    if !hs.is_handshake_finished() {
        bail!("noise handshake did not complete");
    }
    let hash = hs.get_handshake_hash().to_vec();
    let (i2r, r2i) = hs.dangerously_get_raw_split();
    Ok((Enc::from_raw_split(i2r, r2i, initiator, mode), hash))
}

fn handshake_err(e: snow::Error) -> anyhow::Error {
    anyhow!("noise handshake failed ({e}); both ends need the same token, keys, `encryption` and `resume` settings")
}

pub async fn client_handshake(
    tx: &mut dyn FrameTx,
    rx: &mut dyn FrameRx,
    local_priv: &[u8; 32],
    peer_pub: &[u8; 32],
    psk: &[u8; 32],
    proto: impl Into<Proto>,
) -> Result<Enc> {
    let proto: Proto = proto.into();
    let mode = proto.mode;
    let mut hs = Builder::new(PARAMS.parse()?)
        .local_private_key(local_priv)?
        .remote_public_key(peer_pub)?
        .psk(2, psk)?
        .prologue(&proto.prologue())?
        .build_initiator()?;

    let mut buf = [0u8; 1024];
    let n = hs.write_message(&[VERSION], &mut buf)?;
    tx.send(buf[..n].to_vec()).await?;
    tx.flush().await?;

    let msg = rx.recv().await?;
    let mut payload = [0u8; 1024];
    hs.read_message(&msg, &mut payload).map_err(handshake_err)?;

    let (enc, hash) = finish(hs, true, mode)?;
    if mode != Mode::Full {
        let mut confirm = hash;
        confirm.reserve(TAG);
        enc.seal_in_place(&mut confirm);
        tx.send(confirm).await?;
        tx.flush().await?;
    }
    Ok(enc)
}

pub async fn server_handshake(
    tx: &mut dyn FrameTx,
    rx: &mut dyn FrameRx,
    local_priv: &[u8; 32],
    psk: &[u8; 32],
    allowed: &[[u8; 32]],
    proto: impl Into<Proto>,
) -> Result<(Enc, usize)> {
    server_handshake_within(tx, rx, local_priv, psk, allowed, proto, CONFIRM_TIMEOUT).await
}

async fn server_handshake_within(
    tx: &mut dyn FrameTx,
    rx: &mut dyn FrameRx,
    local_priv: &[u8; 32],
    psk: &[u8; 32],
    allowed: &[[u8; 32]],
    proto: impl Into<Proto>,
    confirm_timeout: Duration,
) -> Result<(Enc, usize)> {
    let proto: Proto = proto.into();
    let mode = proto.mode;
    let mut hs = Builder::new(PARAMS.parse()?)
        .local_private_key(local_priv)?
        .psk(2, psk)?
        .prologue(&proto.prologue())?
        .build_responder()?;

    let msg = rx.recv().await?;
    let mut payload = [0u8; 1024];
    hs.read_message(&msg, &mut payload).map_err(handshake_err)?;

    let mut buf = [0u8; 1024];
    let n = hs.write_message(&[VERSION], &mut buf)?;
    tx.send(buf[..n].to_vec()).await?;
    tx.flush().await?;

    let admitted = match hs.get_remote_static() {
        Some(rs) => allowed
            .iter()
            .position(|k| k.as_slice() == rs)
            .with_context(|| {
                format!(
                    "peer static key matches none of the {} pinned key(s)",
                    allowed.len()
                )
            })?,
        None => bail!("peer presented no static key"),
    };

    let (enc, hash) = finish(hs, false, mode)?;
    if mode != Mode::Full {
        let record = tokio::time::timeout(confirm_timeout, rx.recv())
            .await
            .map_err(|_| anyhow!("peer sent no key confirmation"))??;
        let plain = enc.open_bytes(record).map_err(|_| {
            anyhow!("key confirmation failed (wrong keys, or a replayed handshake)")
        })?;
        if plain[..] != hash[..] {
            bail!("key confirmation does not match this handshake");
        }
    }
    Ok((enc, admitted))
}

#[cfg(test)]
#[path = "../tests/unit/noise.rs"]
mod tests;
