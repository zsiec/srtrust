//! Key-rotation tests (spec §6.1.6): an encrypted sender periodically rotates its
//! Stream Encrypting Key (even ↔ odd slots, pre-announced via a KMREQ control
//! packet); the receiver installs the announced key and decrypts each packet by
//! its even/odd flag. The stream must stay intact across rotations — decrypting
//! with the wrong key would corrupt it. Driven through the deterministic
//! [`sim::Pair`].

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{
    CipherMode, Config, Connection, EncryptionSettings, Event, KeySize,
};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config() -> Config {
    Config {
        latency: Duration::from_millis(120),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: Some(EncryptionSettings {
            passphrase: b"rotate-me-please".to_vec(),
            key_size: KeySize::Aes128,
            cipher: CipherMode::Ctr,
        }),
        max_bw: 0,
        // A tiny refresh rate so rotation happens within a short test (the wire
        // mechanism is identical at the 2^24 default).
        km_refresh_rate: 8,
        fec: None,
    }
}

fn connected() -> Pair {
    let now = t0();
    let caller = Connection::connect(
        config(),
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        |b| {
            // Deterministic "randomness" for the initial SEK/salt.
            for (i, x) in b.iter_mut().enumerate() {
                *x = 0x11 ^ u8::try_from(i % 256).unwrap();
            }
        },
    );
    let listener = Listener::new(
        config(),
        SocketId::new(0x22),
        SeqNumber::new(9000),
        0xC0FF_EE12,
        now,
    );
    let mut pair = Pair::new(
        now,
        caller,
        listener,
        LinkConfig::PERFECT,
        LinkConfig::PERFECT,
        1,
    );
    assert!(
        pair.run_until_connected(200),
        "encrypted handshake completes"
    );
    pair
}

#[test]
fn keys_rotate_without_corrupting_the_stream() {
    let mut pair = connected();
    let n = 40u8;
    for i in 0..n {
        // Each payload is filled with its index, so any wrong-key decryption would
        // show up as bytes that are not all equal to the index.
        let payload = vec![i; 120];
        pair.caller_send(&payload);
    }

    assert!(
        pair.run_until(|p| p.accepted_received().len() == usize::from(n), 200_000),
        "every packet is delivered across the rotations (got {})",
        pair.accepted_received().len()
    );

    let received = pair.accepted_received();
    for (i, message) in received.iter().enumerate() {
        let tag = u8::try_from(i).unwrap();
        assert_eq!(message.len(), 120);
        assert!(
            message.iter().all(|&b| b == tag),
            "message {i} decrypted intact (no wrong-key corruption)"
        );
    }

    // The refresh rate (8) guarantees several rotations across 40 packets.
    let rotations = pair
        .caller_events()
        .iter()
        .filter(|e| matches!(e, Event::KeyRefreshNeeded { .. }))
        .count();
    assert!(
        rotations >= 2,
        "the key rotated multiple times, got {rotations}"
    );
}
