//! Live SRT sender for the Transit-WPT bench: read an MPEG-TS byte stream from
//! stdin and push it as a CALLER to a listener in ~1316-byte messages. Pairs with
//! `tx_receiver`. An impairment relay can sit between them; SRT's ARQ recovers it.
//!
//! Usage: `tx_sender <host:port>`   (built via `cargo build --release --example tx_sender -p srt`)
use bytes::Bytes;
use srt::{connect, Config};
use tokio::io::{stdin, AsyncReadExt};

#[tokio::main]
async fn main() {
    let remote = std::env::args().nth(1).expect("usage: tx_sender <host:port>");
    let config = Config::default().with_flow_window(8192);
    let stream = connect(remote.as_str(), config)
        .await
        .expect("srt connect");
    eprintln!("[srtrust] tx_sender connected to {remote}");

    let mut input = stdin();
    let mut buf = vec![0u8; 1316];
    loop {
        match input.read(&mut buf).await {
            Ok(0) => break, // EOF
            Ok(n) => {
                if stream.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}
