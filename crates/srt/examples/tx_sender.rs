//! Live SRT sender for the Transit-WPT bench: read an MPEG-TS byte stream from
//! stdin and push it as a CALLER to a listener in ~1316-byte messages. Pairs with
//! `tx_receiver`. An impairment relay can sit between them; SRT's ARQ recovers it.
//!
//! Usage: `tx_sender <host:port> [--latency MS] [--flow-window PKT] [--mtu B]
//!         [--maxbw BYTES_PER_SEC] [--fec GROUP] [--passphrase STR --key-size BITS]`
//!   (built via `cargo build --release --example tx_sender -p srt`)
//!
//! The bench's per-impl parameter lab drives these flags so the same srtrust leg
//! can be re-armed with different latency/window/bitrate/FEC/encryption settings.
use bytes::Bytes;
use srt::{CipherMode, Config, EncryptionSettings, FecConfig, KeySize, connect};
use std::time::Duration;
use tokio::io::{AsyncReadExt, stdin};

/// `config_from_flags` builds the srtrust Config from the bench's CLI knobs (the
/// `--key value` pairs after the positional address). Unset flags keep defaults.
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
    let remote = args
        .get(1)
        .cloned()
        .expect("usage: tx_sender <host:port> [flags]");
    let config = config_from_flags(&args);
    let stream = connect(remote.as_str(), config).await.expect("srt connect");
    eprintln!("[srtrust] tx_sender connected to {remote}");

    let mut input = stdin();
    let mut buf = vec![0u8; 1316];
    loop {
        match input.read(&mut buf).await {
            Ok(0) | Err(_) => break, // EOF or read error: stop
            Ok(n) => {
                if stream
                    .send(Bytes::copy_from_slice(&buf[..n]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}
