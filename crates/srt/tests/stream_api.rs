//! Stream-API ergonomics: `ToSocketAddrs` connect, stream metadata accessors,
//! `into_split`, and the `futures` Stream/Sink adapters — the surface that
//! makes `SrtStream` feel like `tokio::net::TcpStream`.

use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use srt::{Config, SrtListener, connect, connect_from};

fn config() -> Config {
    Config::default().with_latency(Duration::from_millis(50))
}

/// `connect` takes anything address-like (here a `&str` with a hostname-style
/// form) and binds an ephemeral local port itself; `connect_from` keeps the
/// explicit local binding for multihomed hosts.
#[tokio::test]
async fn connect_resolves_to_socket_addrs() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();
    let target = format!("127.0.0.1:{}", addr.port());

    let (stream, server) = tokio::join!(connect(target.as_str(), config()), listener.accept());
    let (stream, mut server) = (stream.expect("connect"), server.expect("accept"));

    stream
        .send(Bytes::from_static(b"hello"))
        .await
        .expect("send");
    let got = tokio::time::timeout(Duration::from_secs(2), server.recv())
        .await
        .expect("delivered")
        .expect("open");
    assert_eq!(&got[..], b"hello");
}

#[tokio::test]
async fn connect_from_binds_the_given_local_address() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let (stream, server) = tokio::join!(
        connect_from("127.0.0.1:0".parse().unwrap(), addr, config()),
        listener.accept(),
    );
    let (stream, _server) = (stream.expect("connect"), server.expect("accept"));
    assert_eq!(
        stream.local_addr().ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
}

/// Both ends expose who they are talking to and which stream was requested.
#[tokio::test]
async fn streams_expose_addresses_and_stream_id() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let (stream, server) = tokio::join!(
        connect(addr, config().with_stream_id("live/cam7")),
        listener.accept(),
    );
    let (stream, server) = (stream.expect("connect"), server.expect("accept"));

    // Caller side.
    assert_eq!(stream.peer_addr(), addr);
    assert_ne!(stream.local_addr().port(), 0, "a real ephemeral port");
    assert_eq!(stream.stream_id(), Some("live/cam7"));

    // Accepted side: mirror image.
    assert_eq!(server.local_addr(), addr);
    assert_eq!(server.peer_addr().port(), stream.local_addr().port());
    assert_eq!(
        server.stream_id(),
        Some("live/cam7"),
        "the acceptor sees the caller's advertised Stream ID"
    );
}

/// The halves move to independent tasks: one sends, one receives, full duplex.
#[tokio::test]
async fn into_split_gives_independent_halves() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let (stream, server) = tokio::join!(connect(addr, config()), listener.accept());
    let (stream, server) = (stream.expect("connect"), server.expect("accept"));

    let (client_tx, mut client_rx) = stream.into_split();
    assert_eq!(client_tx.peer_addr(), addr, "metadata survives the split");
    let (server_tx, mut server_rx) = server.into_split();

    // Echo server: its two halves live on one task but are separate values.
    let echo = tokio::spawn(async move {
        while let Some(payload) = server_rx.recv().await {
            if server_tx.send(payload).await.is_err() {
                break;
            }
        }
    });
    // Client sender on its own task, receiver on this one.
    let sender = tokio::spawn(async move {
        for i in 0..5u8 {
            client_tx
                .send(Bytes::from(vec![i; 32]))
                .await
                .expect("send");
        }
        client_tx // keep the half alive until the echoes return
    });

    for i in 0..5u8 {
        let got = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
            .await
            .expect("echo arrives")
            .expect("open");
        assert_eq!(got[0], i);
    }
    drop(sender.await.expect("sender task"));
    echo.abort();
}

/// `SrtStream` works with combinator-based code: `StreamExt::next` to read,
/// `SinkExt::send` to write.
#[tokio::test]
async fn stream_and_sink_adapters_work_with_futures_combinators() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let (stream, server) = tokio::join!(connect(addr, config()), listener.accept());
    let (mut stream, mut server) = (stream.expect("connect"), server.expect("accept"));

    // Sink on the caller, Stream on the acceptor.
    stream
        .send(Bytes::from_static(b"via sink"))
        .await
        .expect("plain send still works");
    SinkExt::send(&mut stream, Bytes::from_static(b"combinator"))
        .await
        .expect("sink send");

    let first = tokio::time::timeout(Duration::from_secs(2), server.next())
        .await
        .expect("delivered")
        .expect("open");
    assert_eq!(&first[..], b"via sink");
    let second = tokio::time::timeout(Duration::from_secs(2), server.next())
        .await
        .expect("delivered")
        .expect("open");
    assert_eq!(&second[..], b"combinator");
}

/// The split halves get the adapters too — the natural place to use them.
#[tokio::test]
async fn split_halves_implement_stream_and_sink() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let (stream, server) = tokio::join!(connect(addr, config()), listener.accept());
    let (stream, server) = (stream.expect("connect"), server.expect("accept"));

    let (mut client_tx, _client_rx) = stream.into_split();
    let (_server_tx, mut server_rx) = server.into_split();

    SinkExt::send(&mut client_tx, Bytes::from_static(b"half"))
        .await
        .expect("sink send on the send half");
    let got = tokio::time::timeout(Duration::from_secs(2), server_rx.next())
        .await
        .expect("delivered")
        .expect("open");
    assert_eq!(&got[..], b"half");
}
