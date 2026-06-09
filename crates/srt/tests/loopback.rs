//! Loopback integration tests for the `srt` I/O layer: real Tokio, real UDP
//! sockets on localhost. These exercise the whole stack — the sans-I/O core
//! driven over an actual socket — end to end.

use std::time::Duration;

use bytes::Bytes;
use srt::{CipherMode, Config, EncryptionSettings, KeySize, SrtListener, connect};

fn config() -> Config {
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

fn encrypted_config(passphrase: &[u8]) -> Config {
    Config {
        encryption: Some(EncryptionSettings {
            passphrase: passphrase.to_vec(),
            key_size: KeySize::Aes128,
            cipher: CipherMode::Ctr,
        }),
        ..config()
    }
}

async fn run_round_trip(make_config: fn() -> Config) {
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), make_config()).unwrap();
    let addr = listener.local_addr();

    let caller = tokio::spawn(async move {
        let stream = connect("127.0.0.1:0".parse().unwrap(), addr, make_config())
            .await
            .expect("caller connects");
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
                let stream = connect("127.0.0.1:0".parse().unwrap(), addr, config())
                    .await
                    .expect("caller connects");
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
        let stream = connect("127.0.0.1:0".parse().unwrap(), addr, config())
            .await
            .expect("connect");
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
