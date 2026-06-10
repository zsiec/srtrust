//! Lifecycle and cleanup: dropping handles must release their resources and
//! tear down exactly what they own — no orphaned driver tasks holding
//! connections alive, no callers left hanging, and a listener that serves
//! correctly through many short-lived connections.

use std::time::Duration;

use bytes::Bytes;
use srt::{Config, SrtListener, connect};

fn config() -> Config {
    Config::default().with_latency(Duration::from_millis(50))
}

/// Dropping a caller's `SrtStream` (without an explicit `close()`) must still
/// shut the connection down cleanly: its driver notices the closed command
/// channel, runs the orderly close, and the peer's `recv` ends — rather than
/// an orphaned driver task keeping a dead connection alive until the peer's
/// idle timeout.
#[tokio::test]
async fn dropping_a_stream_closes_the_connection_for_the_peer() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let (stream, server) = tokio::join!(connect(addr, config()), listener.accept());
    let (stream, mut server) = (stream.expect("connect"), server.expect("accept"));

    stream.send(Bytes::from_static(b"bye")).await.expect("send");
    drop(stream);

    // The peer receives the in-flight data, then a clean end-of-stream — well
    // before its 5 s peer-idle timeout could be the thing that ended it.
    let got = tokio::time::timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("data arrives")
        .expect("stream still open for the flush");
    assert_eq!(&got[..], b"bye");
    let end = tokio::time::timeout(Duration::from_secs(3), server.recv())
        .await
        .expect("the stream ends promptly after the peer handle drops");
    assert!(end.is_none(), "a clean end-of-stream, not data");
}

/// A `ConnRequest` dropped undecided must leave the listener fully healthy:
/// the ignored caller fails on its own connect timeout, and the next caller
/// is served normally.
#[tokio::test]
async fn dropping_a_request_undecided_leaves_the_listener_healthy() {
    let mut listener =
        SrtListener::bind_deferred("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    // An ignored caller with a short timeout, so the test stays fast.
    let ignored = tokio::spawn(connect(
        addr,
        config().with_connect_timeout(Duration::from_millis(400)),
    ));
    let request = tokio::time::timeout(Duration::from_secs(2), listener.incoming())
        .await
        .expect("request surfaces")
        .expect("listener alive");
    drop(request); // no decision, ever
    ignored
        .await
        .expect("join")
        .expect_err("the ignored caller times out");

    // The listener still serves the next caller.
    let (stream, server) = tokio::join!(connect(addr, config()), listener.accept());
    let (stream, mut server) = (stream.expect("connect"), server.expect("accept"));
    stream
        .send(Bytes::from_static(b"still here"))
        .await
        .expect("send");
    let got = tokio::time::timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("delivered")
        .expect("open");
    assert_eq!(&got[..], b"still here");
}

/// Many short-lived connections through one listener: every cycle must
/// connect, deliver, and close cleanly — exercising the endpoint's per-peer
/// demux bookkeeping (entries for closed connections must not break or starve
/// later ones).
#[tokio::test]
async fn a_listener_survives_many_short_lived_connections() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    for round in 0..20u8 {
        let (stream, server) = tokio::join!(connect(addr, config()), listener.accept());
        let (stream, mut server) = (stream.expect("connect"), server.expect("accept"));
        stream
            .send(Bytes::from(vec![round; 64]))
            .await
            .expect("send");
        let got = tokio::time::timeout(Duration::from_secs(2), server.recv())
            .await
            .expect("delivered")
            .expect("open");
        assert_eq!(got[0], round, "round {round} delivers its own data");
        stream.close().await.expect("close");
        // Wait for the server side to observe the close before the next round,
        // so closed-connection state is what the next handshake encounters.
        let end = tokio::time::timeout(Duration::from_secs(3), server.recv())
            .await
            .expect("the close arrives");
        assert!(end.is_none(), "clean end-of-stream in round {round}");
    }
}

/// What dropping a listener does to its accepted connections. Accepted
/// connections share the listener's UDP socket and receive through its demux
/// loop — so when the listener handle drops, they end too (cleanly, as
/// end-of-stream). This is the documented contract: keep the listener alive
/// for as long as its connections matter.
#[tokio::test]
async fn dropping_the_listener_ends_accepted_connections() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let (stream, server) = tokio::join!(connect(addr, config()), listener.accept());
    let (stream, mut server) = (stream.expect("connect"), server.expect("accept"));
    drop(listener);

    // The accepted side's receive path is gone: its stream ends.
    let end = tokio::time::timeout(Duration::from_secs(3), server.recv())
        .await
        .expect("the accepted stream ends rather than hanging");
    assert!(end.is_none());
    // The caller eventually notices too (shutdown or idle timeout); what
    // matters here is that nothing hangs.
    drop(stream);
}

/// Dropping just the receive half of a split stream must NOT tear the
/// connection down (cf. TCP read-half drop): inbound payloads are discarded,
/// and the send half keeps working.
#[tokio::test]
async fn dropping_the_recv_half_keeps_the_send_half_alive() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let (stream, server) = tokio::join!(connect(addr, config()), listener.accept());
    let (stream, mut server) = (stream.expect("connect"), server.expect("accept"));

    let (client_tx, client_rx) = stream.into_split();
    drop(client_rx); // this app never reads

    // The peer sends a few payloads into the void; the client must discard
    // them, not die.
    for _ in 0..3 {
        server
            .send(Bytes::from_static(b"ignored"))
            .await
            .expect("send");
    }
    tokio::time::sleep(Duration::from_millis(300)).await; // let them arrive

    // The client's send direction still works.
    client_tx
        .send(Bytes::from_static(b"still sending"))
        .await
        .expect("send half alive after recv half dropped");
    let got = tokio::time::timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("delivered")
        .expect("open");
    assert_eq!(&got[..], b"still sending");
}
