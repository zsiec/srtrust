//! Throughput benchmark for the `srt` I/O layer (cf. srtgo's `srt-bench`).
//!
//! Modes:
//!   loopback [secs] [payload]   — sender + receiver in one process (quick)
//!   sender <addr> [secs] [pay]  — connect and push as fast as possible
//!   receiver <port> [secs]      — listen, accept, drain, report
//!
//! Reports MB/s, Mbps, and packets/s.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use srt::{CipherMode, Config, EncryptionSettings, KeySize, SrtListener, connect};

fn config() -> Config {
    // SRT_MAXBW (bytes/sec) paces the sender; 0 = unlimited (floods; the
    // receiver's advertised window is then the only brake).
    let max_bw = std::env::var("SRT_MAXBW")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    // SRT_FC: flow window in packets (cf. libsrt SRTO_FC; srtgo's bench uses
    // 25600). The receiver's advertised window caps steady-state throughput at
    // roughly flow_window/latency packets per second.
    let flow_window = std::env::var("SRT_FC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8192);
    // SRT_PASSPHRASE enables AES-128; SRT_GCM=1 selects GCM over CTR.
    let encryption = std::env::var("SRT_PASSPHRASE")
        .ok()
        .map(|passphrase| EncryptionSettings {
            passphrase: passphrase.into_bytes(),
            key_size: KeySize::Aes128,
            cipher: if std::env::var("SRT_GCM").is_ok_and(|v| v == "1") {
                CipherMode::Gcm
            } else {
                CipherMode::Ctr
            },
        });
    let mut config = Config::default()
        .with_flow_window(flow_window)
        .with_max_bw(max_bw);
    if let Some(enc) = encryption {
        config = config.with_encryption(enc);
    }
    config
}

fn report(label: &str, bytes: u64, elapsed: Duration, payload: usize) {
    let secs = elapsed.as_secs_f64();
    let megabytes = bytes as f64 / 1e6 / secs;
    let megabits = bytes as f64 * 8.0 / 1e6 / secs;
    let packets = (bytes / payload as u64) as f64 / secs;
    println!(
        "{label:<28} {megabytes:>8.1} MB/s  {megabits:>8.0} Mbps  {packets:>10.0} pkt/s   ({bytes} bytes in {secs:.2}s)"
    );
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map_or("loopback", String::as_str);

    match mode {
        // loopback [secs] [payload]
        "loopback" => {
            let secs = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
            let payload = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1316);
            loopback(secs, payload).await;
        }
        // sender <addr> [secs] [payload]
        "sender" => {
            let addr = args.get(2).expect("sender needs <addr>");
            let secs = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
            let payload = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1316);
            sender(addr.parse().expect("valid addr"), secs, payload).await;
        }
        // receiver <port> [secs]
        "receiver" => {
            let port: u16 = args.get(2).expect("receiver needs <port>").parse().unwrap();
            let secs = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
            receiver(port, secs).await;
        }
        other => eprintln!("unknown mode {other:?} (loopback|sender|receiver)"),
    }
}

async fn loopback(secs: u64, payload: usize) {
    let received = Arc::new(AtomicU64::new(0));
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let rx_bytes = received.clone();
    let rx = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("accept");
        while let Some(data) = stream.recv().await {
            rx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
    });

    let stream = connect(addr, config()).await.expect("connect");
    let buf = Bytes::from(vec![0xABu8; payload]);
    let start = Instant::now();
    let mut sent = 0u64;
    while start.elapsed() < Duration::from_secs(secs) {
        if stream.send(buf.clone()).await.is_err() {
            break;
        }
        sent += payload as u64;
    }
    let elapsed = start.elapsed();
    // Let TSBPD + in-flight data drain to the receiver.
    tokio::time::sleep(Duration::from_millis(400)).await;
    rx.abort();

    println!("\nsrtrust loopback ({payload}-byte payloads, {secs}s):");
    report("  submitted (sender)", sent, elapsed, payload);
    report(
        "  delivered (receiver)",
        received.load(Ordering::Relaxed),
        elapsed,
        payload,
    );
}

async fn sender(addr: std::net::SocketAddr, secs: u64, payload: usize) {
    let stream = connect(addr, config()).await.expect("connect");
    let buf = Bytes::from(vec![0xABu8; payload]);
    let start = Instant::now();
    let mut sent = 0u64;
    while start.elapsed() < Duration::from_secs(secs) {
        if stream.send(buf.clone()).await.is_err() {
            break;
        }
        sent += payload as u64;
    }
    let elapsed = start.elapsed();
    // Close gracefully and WAIT: a paced close lingers while the queue drains,
    // and exiting the process first kills the driver before its SHUTDOWN goes
    // out — the receiver then burns its 5 s peer-idle timeout, inflating its
    // measurement window by that tail.
    let _ = stream.close().await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    report("srtrust sender", sent, elapsed, payload);
}

async fn receiver(port: u16, secs: u64) {
    let mut listener =
        SrtListener::bind(format!("0.0.0.0:{port}").parse().unwrap(), config()).unwrap();
    eprintln!("listening on {}", listener.local_addr());
    let mut stream = listener.accept().await.expect("accept");
    let mut bytes = 0u64;
    let mut payload = 1316usize;
    // Measure over the first→last DATA window: a peer that dies without a
    // clean shutdown costs a 5 s peer-idle wait that must not dilute the rate.
    let start = Instant::now();
    let mut first: Option<Instant> = None;
    let mut last = start;
    while let Ok(Some(data)) =
        tokio::time::timeout(Duration::from_secs(secs + 2), stream.recv()).await
    {
        last = Instant::now();
        first.get_or_insert(last);
        payload = data.len();
        bytes += data.len() as u64;
    }
    let window = first.map_or_else(|| start.elapsed(), |f| last - f);
    report("srtrust receiver", bytes, window, payload);
}
