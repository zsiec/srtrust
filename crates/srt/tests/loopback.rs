//! Loopback integration tests for the `srt` I/O layer: real Tokio, real UDP
//! sockets on localhost. These exercise the whole stack — the sans-I/O core
//! driven over an actual socket — end to end.

use std::time::Duration;

use bytes::Bytes;
use srt::{CipherMode, Config, EncryptionSettings, KeySize, SrtListener, connect};

fn config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(120))
        .with_flow_window(8192)
}

fn encrypted_config(passphrase: &[u8]) -> Config {
    config().with_encryption(EncryptionSettings {
        passphrase: passphrase.to_vec(),
        key_size: KeySize::Aes128,
        cipher: CipherMode::Ctr,
    })
}

async fn run_round_trip(make_config: fn() -> Config) {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), make_config()).unwrap();
    let addr = listener.local_addr();

    let caller = tokio::spawn(async move {
        let stream = connect(addr, make_config()).await.expect("caller connects");
        for i in 0..5u8 {
            stream.send(Bytes::from(vec![i; 200])).await.expect("send");
        }
        stream
    });

    let mut server = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept within 5s")
        .expect("accept ok");

    for i in 0..5u8 {
        let message = tokio::time::timeout(Duration::from_secs(5), server.recv())
            .await
            .expect("recv within 5s")
            .expect("a message");
        assert_eq!(&message[..], &vec![i; 200][..], "message {i} round-trips");
    }

    let _caller = caller.await.unwrap();
}

#[tokio::test]
async fn plaintext_data_round_trips_over_loopback() {
    run_round_trip(config).await;
}

#[tokio::test]
async fn one_listener_accepts_many_concurrent_callers() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    // Three independent callers connect to the same listener at once. Each tags
    // its payload with its own id so we can prove the listener demuxes them to
    // separate streams (not one connection stealing another's datagrams).
    let callers: Vec<_> = (0..3u8)
        .map(|id| {
            tokio::spawn(async move {
                let stream = connect(addr, config()).await.expect("caller connects");
                for seq in 0..4u8 {
                    stream
                        .send(Bytes::from(vec![id; (seq as usize + 1) * 50]))
                        .await
                        .expect("send");
                }
                stream
            })
        })
        .collect();

    // Accept all three and drain each; every message must carry the id of the
    // caller whose stream it arrived on.
    let mut servers = Vec::new();
    for _ in 0..3 {
        let server = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("accept within 5s")
            .expect("accept ok");
        servers.push(server);
    }

    for server in &mut servers {
        let first = tokio::time::timeout(Duration::from_secs(5), server.recv())
            .await
            .expect("recv within 5s")
            .expect("a message");
        let id = first[0];
        assert!(id < 3, "message carries a known caller id");
        assert!(
            first.iter().all(|&b| b == id),
            "no cross-talk: the whole message is one caller's id"
        );
        // Remaining three messages from the same caller, all its id, growing.
        for seq in 1..4u8 {
            let message = tokio::time::timeout(Duration::from_secs(5), server.recv())
                .await
                .expect("recv within 5s")
                .expect("a message");
            assert_eq!(message.len(), (seq as usize + 1) * 50);
            assert!(
                message.iter().all(|&b| b == id),
                "still caller {id}'s stream"
            );
        }
    }

    for caller in callers {
        let _ = caller.await.unwrap();
    }
}

#[tokio::test]
async fn encrypted_data_round_trips_over_loopback() {
    run_round_trip(|| encrypted_config(b"loopback-secret")).await;
}

#[tokio::test]
async fn stats_report_the_transfer() {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let caller = tokio::spawn(async move {
        let stream = connect(addr, config()).await.expect("connect");
        for _ in 0..10u8 {
            stream
                .send(Bytes::from(vec![7u8; 300]))
                .await
                .expect("send");
        }
        // Let the data and its ACKs settle before sampling.
        tokio::time::sleep(Duration::from_millis(300)).await;
        stream.stats().await.expect("stats")
    });

    let mut server = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept within 5s")
        .expect("accept ok");
    for _ in 0..10 {
        tokio::time::timeout(Duration::from_secs(5), server.recv())
            .await
            .expect("recv within 5s")
            .expect("a message");
    }
    let server_stats = server.stats().await.expect("server stats");

    let caller_stats = caller.await.unwrap();
    assert_eq!(caller_stats.packets_sent, 10, "sender counted 10 packets");
    assert_eq!(caller_stats.bytes_sent, 10 * 300);
    assert_eq!(server_stats.packets_received, 10, "receiver counted 10");
    assert_eq!(server_stats.bytes_received, 10 * 300);
}

#[tokio::test]
async fn receive_rate_tracks_the_stream_not_burst_speed() {
    // Stream ~700 packets paced ~2 ms apart (~500 pkt/s, just over a one-second
    // averaging window) and check the receiver's reported delivery rate tracks the
    // actual stream rate. Guards both the windowed-throughput estimator and the
    // demux arrival-time plumbing: before those, the estimate read tens of
    // thousands of pps (the core's burst-processing speed) for a few-hundred-pps
    // stream.
    const COUNT: usize = 700;
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();

    let caller = tokio::spawn(async move {
        let stream = connect(addr, config()).await.expect("connect");
        for _ in 0..COUNT {
            stream
                .send(Bytes::from(vec![3u8; 800]))
                .await
                .expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // Hold the stream open well past the server's stats sample so the
        // connection isn't torn down out from under it.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let mut server = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("accept within 10s")
        .expect("accept ok");
    let mut received = 0;
    while received < COUNT {
        match tokio::time::timeout(Duration::from_secs(5), server.recv()).await {
            Ok(Some(_)) => received += 1,
            _ => break,
        }
    }
    let stats = server.stats().await.expect("stats");
    caller.await.unwrap();

    // The windowed estimate lands in the right order of magnitude for the stream —
    // emphatically not the five-figure burst rate the old inter-arrival-median
    // produced. The band is deliberately wide: `tokio::time::sleep` granularity
    // varies by host (macOS rounds up well past 2 ms), so the realized pace ranges
    // from ~100 to ~500 pkt/s — but never the tens of thousands of the old bug.
    let pps = stats.recv_rate_pps;
    assert!(
        (20..=5_000).contains(&pps),
        "recv_rate_pps={pps} should track the stream pace, not burst speed"
    );
    assert!(
        stats.recv_rate_bps > 10_000,
        "recv_rate_bps={} implausibly low for a steady stream",
        stats.recv_rate_bps
    );
}
