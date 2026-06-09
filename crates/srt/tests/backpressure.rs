//! Send-side backpressure: with a small flow window and a slow pace, the app
//! cannot submit data faster than the connection drains it. `SrtStream::send`
//! blocks once the send window (unacknowledged + queued packets) is full, instead
//! of letting an unbounded backlog accumulate in memory.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use srt::{Config, SrtListener, connect};

fn paced_config() -> Config {
    Config {
        latency: Duration::from_millis(120),
        mtu: 1500,
        // A tiny flow window: at most this many packets may be unacknowledged or
        // queued before the sender must wait.
        flow_window: 16,
        stream_id: None,
        encryption: None,
        // A deliberately slow pace (~2 Mbps) so the queue cannot drain quickly —
        // the app will outrun it and must be held back.
        max_bw: 250_000,
        km_refresh_rate: 0,
        fec: None,
    }
}

#[tokio::test]
async fn send_blocks_when_the_window_is_full() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), paced_config()).unwrap();
    let addr = listener.local_addr();

    // The receiver drains continuously so ACKs keep flowing — the only limit on
    // the sender is the flow window and the pace, not a stalled reader.
    tokio::spawn(async move {
        let mut server = listener.accept().await.expect("accept");
        while server.recv().await.is_some() {}
    });

    let stream = connect("127.0.0.1:0".parse().unwrap(), addr, paced_config())
        .await
        .expect("connect");

    // A task that submits as fast as it is allowed to, counting completed sends.
    let completed = Arc::new(AtomicU64::new(0));
    let flooder_completed = completed.clone();
    let flooder = tokio::spawn(async move {
        let payload = Bytes::from(vec![0xCD; 1316]);
        loop {
            if stream.send(payload.clone()).await.is_err() {
                break;
            }
            flooder_completed.fetch_add(1, Ordering::Relaxed);
        }
    });

    // Let it run, then see how much it managed to push.
    tokio::time::sleep(Duration::from_millis(400)).await;
    flooder.abort();

    let count = completed.load(Ordering::Relaxed);
    // With backpressure, the count is bounded by the pace plus the small window
    // and the command-channel buffer — a few hundred at most. Without it, an
    // unbounded queue would let thousands through in the same window.
    assert!(
        count < 600,
        "backpressure must bound submitted sends, got {count}"
    );
    // Sanity: it must still make *some* progress (not deadlocked).
    assert!(count > 0, "the sender made progress, got {count}");
}
