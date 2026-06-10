//! Handshake rejection (spec §4.3, Table 7; libsrt `SRT_REJ_*`): a listener
//! that cannot accept a conclusion answers with a `URQ_FAILURE` handshake
//! (handshake type = 1000 + reason code) instead of silently dropping it, and
//! a caller receiving one fails fast with [`ConnectionError::Rejected`] —
//! rather than burning its whole connect timeout on retries that can never
//! succeed.

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{
    CipherMode, Config, Connection, EncryptionSettings, Event, KeySize,
};
use srt_protocol::error::ConnectionError;
use srt_protocol::handshake::{HandshakeType, RejectReason};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(120))
        .with_flow_window(8192)
}

fn encrypted(passphrase: &[u8]) -> Config {
    config().with_encryption(EncryptionSettings {
        passphrase: passphrase.to_vec(),
        key_size: KeySize::Aes128,
        cipher: CipherMode::Ctr,
    })
}

fn pair(caller_cfg: Config, listener_cfg: Config) -> Pair {
    let now = t0();
    let caller = Connection::connect(
        caller_cfg,
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        |buf| buf.fill(7),
    );
    let listener = Listener::new(
        listener_cfg,
        SocketId::new(0x22),
        SeqNumber::new(9000),
        0xCAFE,
        now,
    );
    Pair::new(
        now,
        caller,
        listener,
        LinkConfig::PERFECT,
        LinkConfig::PERFECT,
        1,
    )
}

/// The caller's rejection reason, if it failed with one.
fn rejected_reason(pair: &Pair) -> Option<RejectReason> {
    pair.caller_events().iter().find_map(|e| match e {
        Event::Failed(ConnectionError::Rejected(reason)) => Some(*reason),
        _ => None,
    })
}

#[test]
fn reject_reason_codes_round_trip_through_the_handshake_type() {
    for reason in [
        RejectReason::BadSecret,
        RejectReason::Unsecure,
        RejectReason::Version,
        RejectReason::Other(2404), // an app-defined code (libsrt user range)
    ] {
        let hs_type = HandshakeType::rejection(reason);
        assert_eq!(
            hs_type.reject_reason(),
            Some(reason),
            "{reason:?} survives the wire encoding"
        );
    }
    // The ordinary handshake types are NOT rejections.
    for hs_type in [
        HandshakeType::INDUCTION,
        HandshakeType::CONCLUSION,
        HandshakeType::AGREEMENT,
        HandshakeType::DONE,
        HandshakeType::WAVEHAND,
    ] {
        assert_eq!(hs_type.reject_reason(), None, "{hs_type:?} is no rejection");
    }
}

#[test]
fn wrong_passphrase_is_rejected_with_bad_secret() {
    let mut pair = pair(
        encrypted(b"correct horse battery"),
        encrypted(b"wrong wrong wrong"),
    );
    pair.run_for(1_000_000); // 1 s: well inside the 3 s connect timeout

    assert_eq!(
        rejected_reason(&pair),
        Some(RejectReason::BadSecret),
        "a passphrase mismatch is rejected as BadSecret, events: {:?}",
        pair.caller_events()
    );
    assert!(!pair.caller_connected(), "the caller must not connect");
}

#[test]
fn plain_caller_to_encrypted_listener_is_rejected_unsecure() {
    let mut pair = pair(config(), encrypted(b"correct horse battery"));
    pair.run_for(1_000_000);

    assert_eq!(
        rejected_reason(&pair),
        Some(RejectReason::Unsecure),
        "an unencrypted caller is rejected as Unsecure by an encrypted listener"
    );
}

#[test]
fn encrypted_caller_to_plain_listener_is_rejected_unsecure() {
    let mut pair = pair(encrypted(b"correct horse battery"), config());
    pair.run_for(1_000_000);

    assert_eq!(
        rejected_reason(&pair),
        Some(RejectReason::Unsecure),
        "an encrypted caller is rejected as Unsecure by a plaintext listener"
    );
}

#[test]
fn matching_passphrases_still_connect() {
    // The guard rails must not break the happy path.
    let mut pair = pair(
        encrypted(b"correct horse battery"),
        encrypted(b"correct horse battery"),
    );
    assert!(pair.run_until_connected(200), "matching keys connect");
}
