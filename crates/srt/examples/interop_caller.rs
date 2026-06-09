//! Interop probe: connect to a remote SRT listener (e.g. the C
//! `srt-live-transmit`) as a caller and send a few tagged messages.
//!
//! Usage: `cargo run -p srt --example interop_caller -- 127.0.0.1:4200 [passphrase]`

use std::time::Duration;

use bytes::Bytes;
use srt::{CipherMode, Config, EncryptionSettings, KeySize, connect};

#[tokio::main]
async fn main() {
    let remote = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4200".to_string());
    let passphrase = std::env::args().nth(2);

    let config = Config {
        latency: Duration::from_millis(120),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: passphrase.map(|p| EncryptionSettings {
            passphrase: p.into_bytes(),
            key_size: KeySize::Aes128,
            cipher: CipherMode::Ctr,
        }),
        max_bw: 0,
        km_refresh_rate: 0,
        fec: None,
    };

    eprintln!("[srtrust] connecting to {remote} ...");
    let stream = match connect(
        "127.0.0.1:0".parse().unwrap(),
        remote.parse().expect("valid addr"),
        config,
    )
    .await
    {
        Ok(s) => {
            eprintln!("[srtrust] connected, handshake complete");
            s
        }
        Err(e) => {
            eprintln!("[srtrust] connect FAILED: {e}");
            std::process::exit(1);
        }
    };

    for i in 0..10u32 {
        let line = format!("srtrust message {i:02}\n");
        if let Err(e) = stream.send(Bytes::from(line)).await {
            eprintln!("[srtrust] send {i} failed: {e}");
            std::process::exit(1);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    eprintln!("[srtrust] sent 10 messages, flushing ...");
    // Give TSBPD + retransmission time to deliver before we tear the socket down.
    tokio::time::sleep(Duration::from_millis(800)).await;
    eprintln!("[srtrust] done");
}
