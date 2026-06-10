//! The listener's connection-request API: `SrtListener::incoming()` yields a
//! [`ConnRequest`] per caller — Stream ID and address attached — which the
//! application accepts or rejects (with a real SRT rejection code the caller
//! sees). The plain `accept()` remains the auto-accept convenience.

use std::time::Duration;

use bytes::Bytes;
use srt::{Config, ConnectionError, Error, RejectReason, SrtListener, connect};

fn config() -> Config {
    Config::default().with_latency(Duration::from_millis(50))
}

#[tokio::test]
async fn incoming_surfaces_stream_id_and_addr_and_accept_connects() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let client = tokio::spawn(async move {
        connect(addr, config().with_stream_id("#!::r=live/cam1,m=publish")).await
    });

    let request = tokio::time::timeout(Duration::from_secs(3), listener.incoming())
        .await
        .expect("a request surfaces promptly")
        .expect("listener alive");
    assert_eq!(request.stream_id(), Some("#!::r=live/cam1,m=publish"));
    assert_eq!(
        request.remote_addr().ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );

    let mut server = request.accept().await.expect("accept");
    let stream = client.await.expect("join").expect("caller connects");

    stream
        .send(Bytes::from_static(b"ping"))
        .await
        .expect("send");
    let got = tokio::time::timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("delivered")
        .expect("open");
    assert_eq!(&got[..], b"ping");
}

#[tokio::test]
async fn reject_reaches_the_caller_with_the_reason() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let client =
        tokio::spawn(async move { connect(addr, config().with_stream_id("intruder")).await });

    let request = tokio::time::timeout(Duration::from_secs(3), listener.incoming())
        .await
        .expect("a request surfaces promptly")
        .expect("listener alive");
    assert_eq!(request.stream_id(), Some("intruder"));
    // An application-defined code (libsrt's user range starts at 2000).
    request
        .reject(RejectReason::Other(2403))
        .await
        .expect("reject delivered to the driver");

    let error = client
        .await
        .expect("join")
        .expect_err("the rejected caller must not connect");
    assert!(
        matches!(
            error,
            Error::Protocol(ConnectionError::Rejected(RejectReason::Other(2403)))
        ),
        "the caller sees the application's reason, got {error:?}"
    );
}

#[tokio::test]
async fn plain_accept_still_auto_accepts() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let client = tokio::spawn(async move { connect(addr, config()).await });
    let mut server = tokio::time::timeout(Duration::from_secs(3), listener.accept())
        .await
        .expect("accepts promptly")
        .expect("accept");
    let stream = client.await.expect("join").expect("caller connects");

    stream.send(Bytes::from_static(b"hi")).await.expect("send");
    let got = tokio::time::timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("delivered")
        .expect("open");
    assert_eq!(&got[..], b"hi");
}
