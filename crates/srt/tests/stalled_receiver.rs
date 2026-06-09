//! BUG-05a (docs/known-issues/05): a stalled application reader must not freeze
//! the connection driver. Event delivery used to `.await` on the bounded data
//! channel inside the driver loop, so once the app stopped calling `recv()` the
//! loop blocked — no ACKs, no keepalives, no timers — and the *peer* tore the
//! connection down as idle. The driver must keep servicing the protocol while
//! the app is slow, holding undelivered data back in the core (where it also
//! shrinks the advertised receive window, closing the peer's send window).

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

/// Flood more messages than the driver→app channel holds (256), stall the app
/// reader well past the 5 s peer-idle timeout, then resume reading. The
/// connection must survive the stall: every message arrives, and the link still
/// carries new data afterwards.
#[tokio::test]
async fn a_stalled_app_reader_does_not_kill_the_connection() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let stream = connect("127.0.0.1:0".parse().unwrap(), addr, config())
        .await
        .expect("connect");
    let mut server = listener.accept().await.expect("accept");

    // Well past the data-channel capacity, well within the flow window.
    let n: u32 = 600;
    for i in 0..n {
        let tag = u8::try_from(i % 251).expect("fits");
        stream
            .send(Bytes::from(vec![tag; 200]))
            .await
            .expect("send during flood");
    }

    // The app goes away for longer than the 5 s peer-idle timeout. Keepalives
    // and ACKs must keep flowing in both directions throughout.
    tokio::time::sleep(Duration::from_secs(6)).await;

    // Resume reading: everything arrives, in order, intact.
    for i in 0..n {
        let tag = u8::try_from(i % 251).expect("fits");
        let message = tokio::time::timeout(Duration::from_secs(5), server.recv())
            .await
            .expect("recv within 5s")
            .expect("a message (connection still alive)");
        assert_eq!(&message[..], &vec![tag; 200][..], "message {i} intact");
    }

    // The connection survived the stall in *both* directions: a fresh message
    // still round-trips.
    stream
        .send(Bytes::from_static(b"alive after the stall"))
        .await
        .expect("send after the stall (sender connection alive)");
    let message = tokio::time::timeout(Duration::from_secs(5), server.recv())
        .await
        .expect("recv within 5s")
        .expect("the post-stall message arrives");
    assert_eq!(&message[..], b"alive after the stall");
}
