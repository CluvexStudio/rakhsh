use super::*;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn vectored_writes_deliver_every_byte_in_order() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let chunks: Vec<Bytes> = (0..600u32)
        .map(|i| {
            Bytes::from(
                (0..16_000u32 + i)
                    .map(|j| (i + j) as u8)
                    .collect::<Vec<u8>>(),
            )
        })
        .collect();
    let want: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    let reader = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let (mut got, mut buf) = (Vec::new(), vec![0u8; 8192]);
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    });
    let (_rd, mut wr) = TcpStream::connect(addr).await.unwrap().into_split();
    for batch in chunks.chunks(17) {
        write_all_chunks(&mut wr, batch).await.unwrap();
    }
    wr.shutdown().await.unwrap();
    assert_eq!(reader.await.unwrap(), want);
}
