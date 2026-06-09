//! BUG-05g (docs/known-issues/05): a full accept backlog must not freeze the
//! endpoint. The demux loop used to `accept_tx.send(..).await` newly-accepted
//! connections to the application; once the bounded accept channel filled (the
//! app accepts slowly, or not at all, while handshakes keep arriving), that
//! await parked the loop that forwards datagrams to **every** established
//! connection on the socket — and they all died of their peers' idle timeouts.
//! Overflowing handshakes must be declined instead (the caller times out, as
//! with a full TCP SYN backlog), keeping live connections flowing.

use std::time::Duration;

use bytes::Bytes;
use srt::{Config, SrtListener, connect};

fn config() -> Config {
    Config {
        latency: Duration::from_millis(50),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: None,
        max_bw: 0,
        km_refresh_rate: 0,
        fec: None,
    }
}

#[tokio::test]
async fn a_full_accept_backlog_does_not_freeze_established_connections() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    // One real, accepted, working connection.
    let stream = connect("127.0.0.1:0".parse().unwrap(), addr, config())
        .await
        .expect("connect");
    let mut server = listener.accept().await.expect("accept");
    stream
        .send(Bytes::from_static(b"warm"))
        .await
        .expect("send");
    let first = tokio::time::timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("recv within 2s")
        .expect("warm-up message");
    assert_eq!(&first[..], b"warm");

    // Now far more handshakes than the accept backlog holds, never accepted.
    // Some may complete and some may time out — what matters is what they do
    // to the endpoint, not their own fate.
    for _ in 0..70 {
        tokio::spawn(async move {
            let _ = connect("127.0.0.1:0".parse().unwrap(), addr, config()).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // The established connection must still flow: its inbound datagrams go
    // through the same demux loop the backlog used to park.
    stream
        .send(Bytes::from_static(b"still flowing"))
        .await
        .expect("send with a full accept backlog");
    let message = tokio::time::timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("recv within 2s despite the full accept backlog")
        .expect("the message arrives");
    assert_eq!(&message[..], b"still flowing");
}
