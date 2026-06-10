//! Accept semantics: the default listener completes handshakes into a backlog
//! with no application involvement (libsrt/srtgo-compatible — a caller's
//! `connect` resolves as soon as the wire handshake finishes), while
//! [`SrtListener::bind_deferred`] opts into per-connection vetting, where the
//! handshake completes only when the application accepts the request.

use std::time::Duration;

use bytes::Bytes;
use srt::{Config, SrtListener, connect};

fn config() -> Config {
    Config::default().with_latency(Duration::from_millis(50))
}

/// The libsrt-compatible default: a caller connects *before* the application
/// ever calls `accept()` — the handshake completed into the backlog.
#[tokio::test]
async fn default_bind_completes_handshakes_without_accept() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    // Sequential on purpose: this resolving at all is the semantics under test.
    let stream = tokio::time::timeout(Duration::from_secs(2), connect(addr, config()))
        .await
        .expect("the handshake completes with no accept() running")
        .expect("connect");

    // The backlog hands the established connection over afterwards.
    let mut server = listener.accept().await.expect("accept");
    stream
        .send(Bytes::from_static(b"early"))
        .await
        .expect("send");
    let got = tokio::time::timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("delivered")
        .expect("open");
    assert_eq!(&got[..], b"early");
}

/// Backlogged streams still carry their metadata — the acceptor can branch on
/// the Stream ID after a plain `accept()`.
#[tokio::test]
async fn backlogged_streams_keep_their_stream_id() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let stream = connect(addr, config().with_stream_id("live/cam9"))
        .await
        .expect("connect");
    let server = listener.accept().await.expect("accept");
    assert_eq!(server.stream_id(), Some("live/cam9"));
    drop(stream);
}

/// Deferred mode: nothing completes until the application decides.
#[tokio::test]
async fn bind_deferred_defers_the_handshake_to_the_application() {
    let mut listener =
        SrtListener::bind_deferred("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    // With nobody deciding, a short-timeout caller fails its handshake.
    let undecided = connect(
        addr,
        config().with_connect_timeout(Duration::from_millis(400)),
    );
    let request = tokio::join!(undecided, listener.incoming());
    request.0.expect_err("no decision: the caller times out");
    let request = request.1.expect("but the request surfaced");
    drop(request);

    // And with a decision, the caller connects.
    let caller = tokio::spawn(connect(addr, config().with_stream_id("vetted")));
    let request = listener.incoming().await.expect("incoming");
    assert_eq!(request.stream_id(), Some("vetted"));
    let _server = request.accept().await.expect("accept");
    caller.await.expect("join").expect("vetted caller connects");
}

/// `incoming()` on a default (auto-accept) listener is a programming error —
/// the handshake already completed, so there is nothing left to vet.
#[tokio::test]
#[should_panic(expected = "bind_deferred")]
async fn incoming_on_an_auto_listener_panics() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let _ = listener.incoming().await;
}
