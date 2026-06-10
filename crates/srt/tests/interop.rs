//! Interoperability tests against the reference C implementation (libsrt's
//! `srt-live-transmit`). They run only when that binary is installed (like
//! srtgo's `//go:build interop` suite) and skip otherwise, so `cargo test` stays
//! green on a machine without libsrt.
//!
//! Install libsrt to run them: `brew install srt` (macOS) / `apt install srt-tools`.
//!
//! These prove srtrust speaks SRT on the wire — the same handshake, ARQ, TSBPD,
//! and AES-CTR encryption — to a different, independently-developed implementation.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use bytes::Bytes;
use srt::{CipherMode, Config, EncryptionSettings, KeySize, connect};

/// Locates `srt-live-transmit`, or `None` to skip the interop tests.
fn srt_live_transmit() -> Option<String> {
    for candidate in [
        "srt-live-transmit",
        "/opt/homebrew/bin/srt-live-transmit",
        "/usr/local/bin/srt-live-transmit",
        "/usr/bin/srt-live-transmit",
    ] {
        if Command::new(candidate)
            .arg("-version")
            .output()
            .is_ok_and(|o| o.status.success() || !o.stderr.is_empty())
        {
            return Some(candidate.to_string());
        }
    }
    None
}

fn base_config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(120))
        .with_flow_window(8192)
}

/// Spawns a C `srt-live-transmit` listener that forwards received payload as UDP
/// datagrams to `udp_port` (avoids the stdout buffering that a SIGKILL would
/// drop), optionally decrypting with `passphrase`.
fn spawn_c_listener(
    slt: &str,
    srt_port: u16,
    udp_port: u16,
    passphrase: Option<&str>,
    gcm: bool,
) -> Child {
    use std::fmt::Write as _;
    let mut uri = format!("srt://:{srt_port}?mode=listener&latency=120");
    if let Some(p) = passphrase {
        let _ = write!(uri, "&passphrase={p}&pbkeylen=16");
        if gcm {
            // libsrt SRTO_CRYPTOMODE: 1 = AES-CTR (default), 2 = AES-GCM (1.5.3+).
            let _ = write!(uri, "&cryptomode=2");
        }
    }
    Command::new(slt)
        .args([
            "-t",
            "8",
            "-loglevel:error",
            &uri,
            &format!("udp://127.0.0.1:{udp_port}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn srt-live-transmit")
}

/// Runs a srtrust caller against a C listener and asserts the C side received the
/// (decrypted) messages, forwarded back to us over UDP.
async fn caller_to_c(srt_port: u16, udp_port: u16, passphrase: Option<&str>, cipher: CipherMode) {
    caller_to_c_n(srt_port, udp_port, passphrase, cipher, 5, 0).await;
}

/// As [`caller_to_c`] but sends `messages` messages with a key-refresh rate of
/// `km_refresh` (0 = default) — used to exercise mid-stream rekeying against
/// libsrt: if libsrt rejects srtrust's KMREQ, it cannot decrypt the post-rotation
/// packets and the later messages never arrive.
async fn caller_to_c_n(
    srt_port: u16,
    udp_port: u16,
    passphrase: Option<&str>,
    cipher: CipherMode,
    messages: u8,
    km_refresh: u32,
) {
    let Some(slt) = srt_live_transmit() else {
        eprintln!("SKIP: srt-live-transmit not installed (install libsrt to run interop tests)");
        return;
    };

    // Capture what libsrt forwards before it starts (so no datagram is missed).
    let sink = tokio::net::UdpSocket::bind(format!("127.0.0.1:{udp_port}"))
        .await
        .expect("bind udp sink");

    let gcm = matches!(cipher, CipherMode::Gcm);
    let mut child = spawn_c_listener(&slt, srt_port, udp_port, passphrase, gcm);
    tokio::time::sleep(Duration::from_millis(1300)).await; // let the C listener bind

    let mut config = base_config().with_km_refresh_rate(km_refresh);
    if let Some(p) = passphrase {
        config = config.with_encryption(EncryptionSettings {
            passphrase: p.as_bytes().to_vec(),
            key_size: KeySize::Aes128,
            cipher,
        });
    }
    let stream = connect(format!("127.0.0.1:{srt_port}"), config)
        .await
        .expect("srtrust caller connects to the libsrt listener");

    for i in 0..messages {
        stream
            .send(Bytes::from(format!("interop-msg-{i}\n")))
            .await
            .expect("send to libsrt");
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    // Collect the datagrams libsrt forwarded (each received SRT message → one UDP
    // datagram).
    let mut received = Vec::new();
    let mut buf = [0u8; 2048];
    while received.len() < usize::from(messages) {
        match tokio::time::timeout(Duration::from_secs(3), sink.recv(&mut buf)).await {
            Ok(Ok(n)) => received.push(String::from_utf8_lossy(&buf[..n]).to_string()),
            _ => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    let joined = received.join("");
    for i in 0..messages {
        assert!(
            joined.contains(&format!("interop-msg-{i}")),
            "libsrt did not receive message {i}. Received: {received:?}"
        );
    }
}

#[tokio::test]
async fn srtrust_caller_to_libsrt_listener_plaintext() {
    caller_to_c(18801, 18811, None, CipherMode::Ctr).await;
}

#[tokio::test]
async fn srtrust_caller_to_libsrt_listener_encrypted() {
    caller_to_c(18802, 18812, Some("0123456789abcdef"), CipherMode::Ctr).await;
}

#[tokio::test]
async fn srtrust_caller_to_libsrt_listener_gcm() {
    caller_to_c(18803, 18813, Some("0123456789abcdef"), CipherMode::Gcm).await;
}

#[tokio::test]
async fn srtrust_caller_to_libsrt_listener_rekey() {
    // A tiny refresh rate forces srtrust to rotate its SEK mid-stream; libsrt must
    // accept the announced KMREQ to keep decrypting after the switch.
    caller_to_c_n(
        18804,
        18814,
        Some("0123456789abcdef"),
        CipherMode::Ctr,
        24,
        8,
    )
    .await;
}
