use super::*;

struct Pipe {
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
    tamper: bool,
}
#[async_trait]
impl RawLink for Pipe {
    async fn send(&self, p: &[u8]) -> std::io::Result<()> {
        let mut v = p.to_vec();
        if self.tamper {
            let last = v.len() - 1;
            v[last] ^= 0x01;
        }
        let _ = self.tx.send(v);
        Ok(())
    }
    async fn recv(&self, out: &mut [u8]) -> std::io::Result<usize> {
        let v = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("closed"))?;
        let n = v.len().min(out.len());
        out[..n].copy_from_slice(&v[..n]);
        Ok(n)
    }
}
fn pair(tamper_ab: bool) -> (Arc<dyn RawLink>, Arc<dyn RawLink>) {
    let (atx, brx) = tokio::sync::mpsc::unbounded_channel();
    let (btx, arx) = tokio::sync::mpsc::unbounded_channel();
    let a = Pipe {
        tx: atx,
        rx: tokio::sync::Mutex::new(arx),
        tamper: tamper_ab,
    };
    let b = Pipe {
        tx: btx,
        rx: tokio::sync::Mutex::new(brx),
        tamper: false,
    };
    (Arc::new(a), Arc::new(b))
}
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn roundtrip_both_directions() {
    rt().block_on(async {
        let key = [7u8; 32];
        let (a, b) = pair(false);
        let (a, b) = (
            AeadLink::wrap(a, &key, true),
            AeadLink::wrap(b, &key, false),
        );
        a.send(b"hello from dialer").await.unwrap();
        let mut buf = [0u8; 64];
        let n = b.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from dialer");
        b.send(b"reply from listener").await.unwrap();
        let n = a.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply from listener");
    });
}

#[test]
fn ciphertext_is_opaque_and_unique_per_packet() {
    rt().block_on(async {
        let key = [9u8; 32];
        let (a, b) = pair(false);
        let raw_b: Arc<dyn RawLink> = b.clone();
        let a = AeadLink::wrap(a, &key, true);
        a.send(&[0u8; 100]).await.unwrap();
        a.send(&[0u8; 100]).await.unwrap();
        let (mut p1, mut p2) = ([0u8; 200], [0u8; 200]);
        let n1 = raw_b.recv(&mut p1).await.unwrap();
        let n2 = raw_b.recv(&mut p2).await.unwrap();
        assert_eq!(n1, 12 + 100 + 16);
        assert_ne!(
            &p1[..n1],
            &p2[..n2],
            "same plaintext must not give the same wire bytes"
        );
        assert_ne!(&p1[12..24], &[0u8; 12], "plaintext must not appear");
        assert_ne!(&p1[..12], &p2[..12], "nonces must differ");
    });
}

#[test]
fn tampered_or_wrong_key_is_dropped() {
    rt().block_on(async {
        let key = [3u8; 32];
        let (a, b) = pair(true);
        let (a, b) = (
            AeadLink::wrap(a, &key, true),
            AeadLink::wrap(b, &key, false),
        );
        a.send(b"tampered").await.unwrap();
        let mut buf = [0u8; 64];
        let r = tokio::time::timeout(std::time::Duration::from_millis(150), b.recv(&mut buf)).await;
        assert!(r.is_err(), "a tampered datagram must never be delivered");

        let (a2, b2) = pair(false);
        let a2 = AeadLink::wrap(a2, &[1u8; 32], true);
        let b2 = AeadLink::wrap(b2, &[2u8; 32], false);
        a2.send(b"secret").await.unwrap();
        let r =
            tokio::time::timeout(std::time::Duration::from_millis(150), b2.recv(&mut buf)).await;
        assert!(
            r.is_err(),
            "a datagram under a different key must be dropped"
        );
    });
}

#[test]
fn directions_use_independent_keys() {
    rt().block_on(async {
        let key = [5u8; 32];
        let (a, b) = pair(false);
        let a = AeadLink::wrap(a, &key, true);
        let b_wrong = AeadLink::wrap(b, &key, true);
        a.send(b"x").await.unwrap();
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            b_wrong.recv(&mut buf),
        )
        .await;
        assert!(r.is_err());
    });
}
