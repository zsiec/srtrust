//! NAT rebind survival: mid-stream, the caller's traffic starts arriving from
//! a different source address (a NAT mapping expired and was reassigned — a
//! several-minute live stream over consumer networks *will* see this). The
//! listener must keep the connection alive by recognizing the packets'
//! destination socket id and re-pinning the peer's address, rather than
//! treating the new address as a stranger and letting the stream die.
//!
//! Modeled with a UDP forwarder between caller and listener that swaps its
//! listener-facing socket (fresh source port) halfway through the stream.

mod interop_util;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use interop_util::{assert_all_in_order, msg, recv_indices};
use srt::{Config, SrtListener, connect};
use tokio::net::UdpSocket;

fn config() -> Config {
    // A wide latency budget: the swap loses whatever is in flight, and ARQ
    // needs room to recover it before TSBPD would shed it.
    Config::default().with_latency(Duration::from_secs(1))
}

/// Forwards caller↔listener datagrams; after `swap_after` caller→listener
/// datagrams, replaces its listener-facing socket — the listener then sees
/// the same connection arriving from a brand-new source address.
async fn forwarder(
    caller_facing: UdpSocket,
    listener_addr: std::net::SocketAddr,
    swap_after: u32,
    swapped: Arc<AtomicBool>,
) {
    let mut upstream = UdpSocket::bind("127.0.0.1:0").await.expect("upstream");
    let forwarded = AtomicU32::new(0);
    let mut caller_addr = None;
    let mut buf_a = vec![0u8; 65536];
    let mut buf_b = vec![0u8; 65536];

    loop {
        tokio::select! {
            from_caller = caller_facing.recv_from(&mut buf_a) => {
                let Ok((len, from)) = from_caller else { return };
                caller_addr = Some(from);
                if forwarded.fetch_add(1, Ordering::Relaxed) == swap_after {
                    // The "NAT" reassigns: a fresh socket, a fresh source port.
                    upstream = UdpSocket::bind("127.0.0.1:0").await.expect("rebind");
                    swapped.store(true, Ordering::Relaxed);
                }
                let _ = upstream.send_to(&buf_a[..len], listener_addr).await;
            }
            from_listener = upstream.recv_from(&mut buf_b) => {
                let Ok((len, _)) = from_listener else { return };
                if let Some(caller) = caller_addr {
                    let _ = caller_facing.send_to(&buf_b[..len], caller).await;
                }
            }
        }
    }
}

#[tokio::test]
async fn a_connection_survives_a_mid_stream_source_address_change() {
    let total: u32 = 100;
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let listener_addr = listener.local_addr();

    let caller_facing = UdpSocket::bind("127.0.0.1:0").await.expect("front");
    let front_addr = caller_facing.local_addr().expect("front addr");
    let swapped = Arc::new(AtomicBool::new(false));
    let fwd = tokio::spawn(forwarder(
        caller_facing,
        listener_addr,
        // Swap once a good chunk of the data phase has flowed (the handshake
        // datagrams count too, so this lands mid-stream).
        total / 2,
        swapped.clone(),
    ));

    let (stream, server) = tokio::join!(connect(front_addr, config()), listener.accept());
    let (stream, mut server) = (stream.expect("connect"), server.expect("accept"));

    let sender = tokio::spawn(async move {
        for i in 0..total {
            stream.send(Bytes::from(msg(i, 64))).await.expect("send");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        stream // hold the connection open while retransmissions drain
    });

    let received = recv_indices(&mut server, total, Duration::from_secs(5)).await;
    let stream = sender.await.expect("sender");
    fwd.abort();

    assert!(
        swapped.load(Ordering::Relaxed),
        "the source-address swap actually happened mid-test"
    );
    assert_all_in_order(&received, total, "across a source-address rebind");
    drop(stream);
}
