//! Live SRT receiver for the Transit-WPT bench: a LISTENER that accepts one caller
//! and writes the recovered MPEG-TS byte stream to stdout. Pairs with `tx_sender`.
//!
//! Usage: `tx_receiver <port>`   (built via `cargo build --release --example tx_receiver -p srt`)
use srt::{Config, SrtListener};
use tokio::io::{stdout, AsyncWriteExt};

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .expect("usage: tx_receiver <port>")
        .parse()
        .expect("port must be a number");
    let config = Config::default().with_flow_window(8192);
    let mut listener = SrtListener::bind(
        format!("127.0.0.1:{port}").parse().unwrap(),
        config,
    )
    .expect("srt bind");
    eprintln!("[srtrust] tx_receiver listening on {}", listener.local_addr());

    let mut stream = listener.accept().await.expect("srt accept");
    eprintln!("[srtrust] tx_receiver accepted a caller");

    let mut out = stdout();
    while let Some(msg) = stream.recv().await {
        if out.write_all(&msg).await.is_err() {
            break;
        }
    }
    let _ = out.flush().await;
}
