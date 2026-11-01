use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncWriteExt};
use tokio::sync::OnceCell;

use rama::net::tls::ApplicationProtocol;
use rama::quic::proto::Version;
use rama::quic::tls::TlsOptions;
use rama::quic::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig,
};
use rama::rt::Executor;
use rama::tls::client::{ServerVerifyMode, TlsClientConfig};
use rama::tls::server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig};
use rama::utils::collections::smallvec::smallvec;

use crate::carrier::{BoxRx, BoxTx, FrameRx, FrameTx};
use crate::wire::{read_frame, write_frame};

const ALPN: &[u8] = b"h3";

fn transport() -> TransportConfig {
    let mut t = TransportConfig::default();
    if let Ok(idle) = Duration::from_secs(20).try_into() {
        t.set_max_idle_timeout(idle);
    }
    t.set_stream_receive_window(crate::carrier::QUIC_STREAM_WINDOW);
    t.set_send_window(crate::carrier::QUIC_SEND_WINDOW);
    t
}

fn client_config() -> Result<ClientConfig> {
    let tls = TlsClientConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
        .with_server_verify(ServerVerifyMode::Disable);
    let mut cc = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .map_err(|e| anyhow!("rama quic client config: {e}"))?;
    cc.set_transport_config(Arc::new(transport()));
    let cc = cc
        .try_with_version(Version::V2)
        .map_err(|e| anyhow!("force quic v2: {e}"))?;
    Ok(cc)
}

fn server_config() -> Result<ServerConfig> {
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())
        .map_err(|e| anyhow!("generate quic server cert: {e}"))?;
    let tls = TlsServerConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
        .with_server_auth(auth);
    let mut sc = ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .map_err(|e| anyhow!("rama quic server config: {e}"))?;
    sc.set_transport_config(Arc::new(transport()));
    Ok(sc)
}

struct QTx {
    s: SendStream,
    _keep: Arc<Connection>,
}
struct QRx {
    r: RecvStream,
    _keep: Arc<Connection>,
}

#[async_trait]
impl FrameTx for QTx {
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        write_frame(&mut self.s, &frame).await
    }
    async fn flush(&mut self) -> io::Result<()> {
        self.s.flush().await
    }
}

#[async_trait]
impl FrameRx for QRx {
    async fn recv(&mut self) -> io::Result<bytes::BytesMut> {
        read_frame(&mut self.r)
            .await
            .map(crate::carrier::into_bytes_mut)
    }
}

fn frames(send: SendStream, recv: RecvStream, conn: Connection) -> (BoxTx, BoxRx) {
    let keep = Arc::new(conn);
    (
        Box::new(QTx {
            s: send,
            _keep: keep.clone(),
        }),
        Box::new(QRx {
            r: recv,
            _keep: keep,
        }),
    )
}

pub struct RamaQuic {
    sni: String,
    client_ep: OnceCell<Endpoint>,
}

impl RamaQuic {
    pub fn new(sni: &str) -> RamaQuic {
        RamaQuic {
            sni: sni.to_string(),
            client_ep: OnceCell::new(),
        }
    }

    async fn client(&self) -> Result<&Endpoint> {
        self.client_ep
            .get_or_try_init(|| async {
                Endpoint::build(Executor::new())
                    .bind_address(SocketAddr::from(([0, 0, 0, 0], 0)))
                    .await
                    .map_err(|e| anyhow!("rama quic client endpoint: {e}"))
            })
            .await
    }

    pub async fn dial(&self, addr: &str) -> Result<(BoxTx, BoxRx)> {
        let peer: SocketAddr = addr.parse().context("quicv2 peer must be ip:port")?;
        let ep = self.client().await?;
        let conn = ep
            .connect_with(client_config()?, peer, &self.sni)
            .map_err(|e| anyhow!("quic connect: {e}"))?
            .await
            .map_err(|e| anyhow!("quic handshake: {e}"))?;
        let (send, recv) = conn.open_bi().await.map_err(|e| anyhow!("open_bi: {e}"))?;
        Ok(frames(send, recv, conn))
    }
}

pub async fn server_endpoint(addr: &str) -> Result<Endpoint> {
    let sa: SocketAddr = addr.parse().context("quicv2 bind must be ip:port")?;
    Endpoint::build(Executor::new())
        .with_server_config(server_config()?)
        .bind_address(sa)
        .await
        .map_err(|e| anyhow!("rama quic server endpoint: {e}"))
}

pub async fn accept(ep: &Endpoint) -> Result<(BoxTx, BoxRx)> {
    let incoming = ep
        .accept()
        .await
        .ok_or_else(|| anyhow!("quic endpoint closed"))?;
    let conn = incoming
        .await
        .map_err(|e| anyhow!("quic accept handshake: {e}"))?;
    let (send, recv) = conn
        .accept_bi()
        .await
        .map_err(|e| anyhow!("accept_bi: {e}"))?;
    Ok(frames(send, recv, conn))
}
