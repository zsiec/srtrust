//! End-to-end encryption tests (spec §6): the caller negotiates a wrapped SEK in
//! the handshake (KMREQ/KMRSP), data flows AES-CTR encrypted, and a wrong
//! passphrase is rejected — all through the deterministic [`sim::Pair`].

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{CipherMode, Config, Connection, EncryptionSettings, KeySize};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config(passphrase: &[u8], key_size: KeySize) -> Config {
    cipher_config(passphrase, key_size, CipherMode::Ctr)
}

fn cipher_config(passphrase: &[u8], key_size: KeySize, cipher: CipherMode) -> Config {
    Config::default()
        .with_latency(Duration::from_millis(200))
        .with_flow_window(8192)
        .with_encryption(EncryptionSettings {
            passphrase: passphrase.to_vec(),
            key_size,
            cipher,
        })
}

/// A deterministic fill for the embedder's RNG (test-only): the exact key bytes
/// do not matter for correctness — the caller generates them and the listener
/// recovers the same ones — only that it is reproducible.
fn fill_rng() -> impl FnMut(&mut [u8]) {
    let mut n = 0u8;
    move |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            *b = n;
            n = n.wrapping_add(7);
        }
    }
}

fn connect_with(caller_pass: &[u8], listener_pass: &[u8], key_size: KeySize) -> Pair {
    let now = t0();
    let caller = Connection::connect(
        config(caller_pass, key_size),
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        fill_rng(),
    );
    let listener = Listener::new(
        config(listener_pass, key_size),
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
    pair.run_until_connected(300);
    pair
}

fn connect_cipher(passphrase: &[u8], key_size: KeySize, cipher: CipherMode) -> Pair {
    let now = t0();
    let caller = Connection::connect(
        cipher_config(passphrase, key_size, cipher),
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        fill_rng(),
    );
    // The listener leaves the cipher unset (Ctr) — it adopts the caller's choice
    // from the Key Material (CryptoModeAuto), which this test exercises.
    let listener = Listener::new(
        config(passphrase, key_size),
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
    pair.run_until_connected(300);
    pair
}

#[test]
fn gcm_authenticated_data_round_trips() {
    // The caller chooses AES-GCM; the listener adopts it from the KM (Auto).
    let mut pair = connect_cipher(b"swordfish", KeySize::Aes128, CipherMode::Gcm);
    assert!(pair.both_connected(), "GCM connection established");
    for i in 0..6u8 {
        pair.caller_send(&[i; 64]);
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == 6, 20_000));
    let received = pair.accepted_received();
    for (i, bytes) in received.iter().enumerate() {
        assert_eq!(bytes.len(), 64, "tag stripped on decrypt");
        assert!(
            bytes.iter().all(|&b| usize::from(b) == i),
            "GCM payload {i} authenticated and decrypted"
        );
    }
}

#[test]
fn gcm_recovers_lost_packets_via_retransmit() {
    // GCM authenticates the packet header, which changes on retransmit — so a
    // resend must be re-encrypted, not replayed. Establish on a clean link, then
    // degrade it and confirm every GCM packet still arrives despite loss. A
    // generous latency leaves room for recovery (incl. the reorder-tolerance and
    // EXP delays) inside the play-out budget.
    let now = t0();
    // A wide latency budget so NAK/EXP recovery completes before TLPKTDROP would
    // shed a too-late packet (reorder tolerance delays NAKs, so the budget must be
    // generous — live SRT runs with latency well above the recovery time).
    let cfg = cipher_config(b"swordfish", KeySize::Aes128, CipherMode::Gcm)
        .with_latency(Duration::from_secs(10));
    let listener_cfg = config(b"swordfish", KeySize::Aes128).with_latency(Duration::from_secs(10));
    let caller = Connection::connect(
        cfg,
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        fill_rng(),
    );
    let listener = Listener::new(
        listener_cfg,
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
    assert!(pair.run_until_connected(300));
    assert!(pair.both_connected());
    let lossy = LinkConfig {
        loss: 0.3,
        ..LinkConfig::PERFECT
    };
    pair.degrade_links(lossy, lossy, 0xBEEF);
    for i in 0..12u8 {
        pair.caller_send(&[i; 80]);
    }
    let done = pair.run_until(|p| p.accepted_received().len() == 12, 2_000_000);
    assert!(
        done,
        "GCM retransmits must re-encrypt so the receiver authenticates them"
    );
    let received = pair.accepted_received();
    for (i, bytes) in received.iter().enumerate() {
        assert!(
            bytes.iter().all(|&b| usize::from(b) == i),
            "GCM packet {i} authenticated + decrypted after loss recovery"
        );
    }
}

#[test]
fn encrypted_data_round_trips_aes128() {
    let mut pair = connect_with(b"swordfish", b"swordfish", KeySize::Aes128);
    assert!(
        pair.both_connected(),
        "a matching passphrase establishes the encrypted connection"
    );
    for i in 0..6u8 {
        pair.caller_send(&[i; 64]);
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == 6, 20_000));
    let received = pair.accepted_received();
    for (i, bytes) in received.iter().enumerate() {
        assert_eq!(bytes.len(), 64);
        assert!(
            bytes.iter().all(|&b| usize::from(b) == i),
            "payload {i} decrypted back to its plaintext"
        );
    }
}

#[test]
fn encrypted_data_round_trips_aes256() {
    let mut pair = connect_with(b"hunter2", b"hunter2", KeySize::Aes256);
    assert!(pair.both_connected());
    pair.caller_send(b"top secret broadcast payload");
    assert!(pair.run_until(|p| !p.accepted_received().is_empty(), 20_000));
    assert_eq!(
        pair.accepted_received()[0].as_ref(),
        b"top secret broadcast payload"
    );
}

#[test]
fn a_wrong_passphrase_is_rejected() {
    let pair = connect_with(b"correct horse", b"battery staple", KeySize::Aes128);
    // The listener's KEK cannot unwrap the SEK, so it declines the conclusion and
    // never sends a usable response: the connection does not form.
    assert!(
        !pair.both_connected(),
        "a mismatched passphrase must not connect"
    );
    assert!(!pair.accepted_connected(), "the listener did not accept");
}
