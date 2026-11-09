use super::*;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::AsyncWriteExt;

struct Recorder(Arc<StdMutex<Vec<usize>>>);

impl AsyncWrite for Recorder {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut TaskCtx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().unwrap().push(buf.len());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn recorder(piece: usize) -> (FragWriter<Recorder>, Arc<StdMutex<Vec<usize>>>) {
    let log = Arc::new(StdMutex::new(Vec::new()));
    (FragWriter::new(Recorder(log.clone()), piece), log)
}

fn pieces(sizes: &[usize], piece: usize) -> (usize, usize) {
    let mut spent = 0;
    let mut n = 0;
    while spent < FRAG_BUDGET {
        assert!(
            sizes[n] <= piece,
            "write {n} of {sizes:?} exceeded the piece size"
        );
        spent += sizes[n];
        n += 1;
    }
    (n, spent)
}

#[tokio::test]
async fn splits_the_opening_write_and_loses_nothing() {
    let (mut w, log) = recorder(64);
    w.write_all(&[7u8; 300]).await.unwrap();
    let sizes = log.lock().unwrap().clone();
    assert!(
        sizes.len() >= 5,
        "300 bytes in 64-byte pieces is 5 writes: {sizes:?}"
    );
    assert!(
        sizes.iter().all(|&n| n <= 64),
        "a write exceeded the piece size: {sizes:?}"
    );
    assert_eq!(
        sizes.iter().sum::<usize>(),
        300,
        "bytes went missing: {sizes:?}"
    );
}

#[tokio::test]
async fn gets_out_of_the_way_past_the_budget() {
    let (mut w, log) = recorder(100);
    w.write_all(&[0u8; FRAG_BUDGET + 40_000]).await.unwrap();
    let sizes = log.lock().unwrap().clone();
    let (head, spent) = pieces(&sizes, 100);
    assert_eq!(
        spent, FRAG_BUDGET,
        "the budget was not spent in pieces: {sizes:?}"
    );
    assert_eq!(
        &sizes[head..],
        &[40_000],
        "past the budget the data path must keep full-size writes: {sizes:?}"
    );
}

#[tokio::test]
async fn zero_piece_is_a_pure_passthrough() {
    let (mut w, log) = recorder(0);
    w.write_all(&[1u8; 5000]).await.unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![5000],
        "unset `tls_frag` must not touch writes"
    );
}

#[tokio::test]
async fn budget_is_shared_across_separate_writes() {
    let (mut w, log) = recorder(40);
    for _ in 0..3 {
        w.write_all(&[2u8; 700]).await.unwrap();
    }
    let sizes = log.lock().unwrap().clone();
    assert_eq!(
        sizes.iter().sum::<usize>(),
        2100,
        "bytes went missing: {sizes:?}"
    );
    let (head, spent) = pieces(&sizes, 40);
    assert_eq!(
        spent, FRAG_BUDGET,
        "the budget reset mid-handshake: {sizes:?}"
    );
    assert_eq!(
        &sizes[head..],
        &[2100 - FRAG_BUDGET],
        "the tail should pass whole: {sizes:?}"
    );
}

#[test]
fn a_fragmented_client_hello_still_completes_the_handshake() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(fragmented_handshake())
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn fragmented_handshake() {
    let port = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let cfg = |extra: &str| {
        toml::from_str::<crate::config::Config>(&format!(
            "role = \"entry\"\ncarrier = \"tls\"\nsni = \"www.example.com\"\n{extra}"
        ))
        .unwrap()
    };

    let listener = Carrier::from_cfg(&cfg(""))
        .unwrap()
        .bind(&addr)
        .await
        .unwrap();
    let server = tokio::spawn(async move {
        let (mut tx, mut rx) = listener.accept().await.unwrap();
        let got = rx.recv().await.unwrap();
        tx.send(got.to_vec()).await.unwrap();
        tx.flush().await.unwrap();
    });

    let client = Carrier::from_cfg(&cfg("tls_frag = 40\n")).unwrap();
    let round_trip = async {
        let (mut tx, mut rx) = client.dial(&addr).await.unwrap();
        tx.send(b"shabdiz".to_vec()).await.unwrap();
        tx.flush().await.unwrap();
        assert_eq!(&rx.recv().await.unwrap()[..], b"shabdiz");
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), round_trip)
        .await
        .expect("a fragmented handshake must not hang");
    server.await.unwrap();
}
