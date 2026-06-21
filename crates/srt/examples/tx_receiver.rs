//! Live SRT receiver for the Transit-WPT bench: a LISTENER that accepts one caller
//! and writes the recovered MPEG-TS byte stream to stdout. Pairs with `tx_sender`.
//!
//! Usage: `tx_receiver <port> [--latency MS] [--flow-window PKT] [--mtu B]
//!         [--maxbw BYTES_PER_SEC] [--fec GROUP] [--passphrase STR --key-size BITS]`
//!   (built via `cargo build --release --example tx_receiver -p srt`)
//!
//! The bench's per-impl parameter lab drives these flags so the same srtrust leg
//! can be re-armed with different latency/window/bitrate/FEC/encryption settings.
use srt::{CipherMode, Config, EncryptionSettings, FecConfig, KeySize, SrtListener};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, stdout};

/// config_from_flags builds the srtrust Config from the bench's CLI knobs (the
/// `--key value` pairs after the positional port). Unset flags keep defaults.
fn config_from_flags(args: &[String]) -> Config {
    let mut cfg = Config::default();
    let mut passphrase: Option<String> = None;
    let mut key_bits: u32 = 128;
    let mut i = 2;
    while i + 1 < args.len() {
        let (key, val) = (args[i].as_str(), args[i + 1].as_str());
        match key {
            "--latency" => {
                if let Ok(ms) = val.parse::<u64>() {
                    cfg = cfg.with_latency(Duration::from_millis(ms));
                }
            }
            "--flow-window" => {
                if let Ok(p) = val.parse::<u32>() {
                    cfg = cfg.with_flow_window(p);
                }
            }
            "--mtu" => {
                if let Ok(m) = val.parse::<u32>() {
                    cfg = cfg.with_mtu(m);
                }
            }
            "--maxbw" => {
                if let Ok(b) = val.parse::<u64>() {
                    cfg = cfg.with_max_bw(b);
                }
            }
            "--fec" => {
                if let Ok(g) = val.parse::<usize>() {
                    cfg = cfg.with_fec(FecConfig { group_size: g });
                }
            }
            "--passphrase" => passphrase = Some(val.to_string()),
            "--key-size" => {
                if let Ok(b) = val.parse::<u32>() {
                    key_bits = b;
                }
            }
            _ => {}
        }
        i += 2;
    }
    if let Some(pass) = passphrase {
        let key_size = match key_bits {
            192 => KeySize::Aes192,
            256 => KeySize::Aes256,
            _ => KeySize::Aes128,
        };
        cfg = cfg.with_encryption(EncryptionSettings {
            passphrase: pass.into_bytes(),
            key_size,
            cipher: CipherMode::Ctr,
        });
    }
    cfg
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args
        .get(1)
        .expect("usage: tx_receiver <port> [flags]")
        .parse()
        .expect("port must be a number");
    let config = config_from_flags(&args);
    let mut listener =
        SrtListener::bind(format!("127.0.0.1:{port}").parse().unwrap(), config).expect("srt bind");
    eprintln!(
        "[srtrust] tx_receiver listening on {}",
        listener.local_addr()
    );

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
