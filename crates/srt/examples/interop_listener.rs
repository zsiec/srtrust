//! Interop probe: a srtrust listener that accepts one connection and prints the
//! messages it receives (e.g. from the C `srt-live-transmit` caller).
//!
//! Usage: `cargo run -p srt --example interop_listener -- 4200 [passphrase]`

use std::time::Duration;

use srt::{CipherMode, Config, EncryptionSettings, KeySize, SrtListener};

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(4200);
    let passphrase = std::env::args().nth(2);

    let mut config = Config::default().with_flow_window(8192);
    if let Some(p) = passphrase {
        config = config.with_encryption(EncryptionSettings {
            passphrase: p.into_bytes(),
            key_size: KeySize::Aes128,
            cipher: CipherMode::Ctr,
        });
    }

    let mut listener =
        SrtListener::bind(format!("127.0.0.1:{port}").parse().unwrap(), config).expect("bind");
    eprintln!("[srtrust] listening on {}", listener.local_addr());

    let mut stream = match listener.accept().await {
        Ok(s) => {
            eprintln!("[srtrust] accepted a connection");
            s
        }
        Err(e) => {
            eprintln!("[srtrust] accept FAILED: {e}");
            std::process::exit(1);
        }
    };

    let mut count = 0u32;
    while let Ok(Some(message)) = tokio::time::timeout(Duration::from_secs(4), stream.recv()).await
    {
        count += 1;
        eprintln!(
            "[srtrust] received #{count} ({} bytes): {:?}",
            message.len(),
            String::from_utf8_lossy(&message).trim_end()
        );
    }
    eprintln!("[srtrust] done — received {count} messages total");
}
