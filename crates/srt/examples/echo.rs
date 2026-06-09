//! A self-contained end-to-end demo: spin up an SRT listener, connect a caller to
//! it, stream a handful of messages across the loopback, and print them as they
//! arrive at the receiver. No external tools or peers required.
//!
//! Run it with:
//!
//! ```console
//! cargo run --example echo
//! ```
//!
//! This is the "hello world" for the `srt` crate. For talking to the reference C
//! library instead, see `interop_caller.rs` / `interop_listener.rs`.

use std::time::Duration;

use bytes::Bytes;
use srt::{Config, SrtListener, connect};

/// A typical live-mode configuration: 120 ms latency budget, 1500-byte MTU, no
/// encryption, no pacing. Both ends of a connection use the same shape.
fn live_config() -> Config {
    Config {
        latency: Duration::from_millis(120),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: None,
        max_bw: 0,
        km_refresh_rate: 0,
        fec: None,
    }
}

#[tokio::main]
async fn main() -> srt::Result<()> {
    // Bind the listener first so it's ready before the caller dials in. Port 0
    // asks the OS for a free port; we read it back to point the caller at it.
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), live_config())?;
    let addr = listener.local_addr();
    println!("listener bound on {addr}");

    // The receiver: accept one connection and print everything it delivers, until
    // the caller closes and the stream ends (`recv` returns `None`).
    let receiver = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("accept");
        println!("listener: caller connected");
        let mut count = 0;
        while let Some(payload) = stream.recv().await {
            count += 1;
            println!("listener: received {:?}", String::from_utf8_lossy(&payload));
        }
        println!("listener: stream ended after {count} messages");
        count
    });

    // The sender: connect, send a few messages, then close gracefully (which
    // lingers until the data has been acknowledged before tearing the socket down).
    let caller = connect("127.0.0.1:0".parse().unwrap(), addr, live_config()).await?;
    println!("caller: connected, sending");
    for i in 0..5 {
        caller.send(Bytes::from(format!("message {i}"))).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    caller.close().await?;
    println!("caller: closed");

    let delivered = receiver.await.expect("receiver task");
    assert_eq!(delivered, 5, "all five messages should arrive");
    println!("done — {delivered}/5 delivered");
    Ok(())
}
