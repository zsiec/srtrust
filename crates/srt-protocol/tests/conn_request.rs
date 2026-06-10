//! Deferred accept (cf. libsrt's listener callback, srtgo's `AcceptFunc`): a
//! listener in deferred mode parks each crypto-valid conclusion and surfaces it
//! as a connection request — Stream ID and peer address attached — for the
//! application to accept or reject (spec §3.2.1.3: the Stream ID is exactly the
//! "which resource, which credentials" field this decision needs). Crypto
//! mismatches are still rejected on the spot and never surfaced.

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{
    CipherMode, Config, Connection, EncryptionSettings, Event, KeySize,
};
use srt_protocol::error::ConnectionError;
use srt_protocol::handshake::RejectReason;
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(120))
        .with_flow_window(8192)
}

fn deferred_pair(caller_cfg: Config, listener_cfg: Config) -> Pair {
    let now = t0();
    let caller = Connection::connect(
        caller_cfg,
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        |buf| buf.fill(7),
    );
    let mut listener = Listener::new(
        listener_cfg,
        SocketId::new(0x22),
        SeqNumber::new(9000),
        0xCAFE,
        now,
    );
    listener.defer_accepts();
    Pair::new(
        now,
        caller,
        listener,
        LinkConfig::PERFECT,
        LinkConfig::PERFECT,
        1,
    )
}

#[test]
fn a_deferred_listener_surfaces_the_request_with_stream_id_and_addr() {
    let mut pair = deferred_pair(
        config().with_stream_id("#!::r=live/cam1,m=publish"),
        config(),
    );
    pair.run_for(300_000); // long past the conclusion's arrival

    let request = pair
        .listener_poll_request()
        .expect("the conclusion surfaces a connection request");
    assert_eq!(request.stream_id(), Some("#!::r=live/cam1,m=publish"));
    assert_eq!(request.remote_addr(), Pair::caller_addr());
    assert!(
        !pair.caller_connected(),
        "no decision yet: the handshake must not complete on its own"
    );
}

#[test]
fn accepting_a_pending_request_completes_the_handshake() {
    let mut pair = deferred_pair(config().with_stream_id("abc"), config());
    pair.run_for(300_000);

    let request = pair.listener_poll_request().expect("request surfaces");
    pair.listener_accept_pending(request.remote_addr())
        .expect("the pending conclusion accepts");
    assert!(
        pair.run_until_connected(200),
        "both sides connect after the deferred accept"
    );
}

#[test]
fn rejecting_a_pending_request_fails_the_caller_with_the_reason() {
    let mut pair = deferred_pair(config().with_stream_id("not-authorized"), config());
    pair.run_for(300_000);

    let request = pair.listener_poll_request().expect("request surfaces");
    // An application-defined code (libsrt's user-defined range starts at 2000).
    let reason = RejectReason::Other(2403);
    assert!(pair.listener_reject_pending(request.remote_addr(), reason));
    pair.run_for(300_000);

    assert!(
        pair.caller_events()
            .iter()
            .any(|e| matches!(e, Event::Failed(ConnectionError::Rejected(r)) if *r == reason)),
        "the caller learns the application's rejection reason, events: {:?}",
        pair.caller_events()
    );
}

#[test]
fn retransmitted_conclusions_surface_one_request_only() {
    let mut pair = deferred_pair(config(), config());
    // The undecided caller retransmits its conclusion every 250 ms; run long
    // enough for several retransmissions to hit the listener.
    pair.run_for(1_200_000);

    assert!(pair.listener_poll_request().is_some(), "first request");
    assert!(
        pair.listener_poll_request().is_none(),
        "retransmissions are deduplicated by peer address"
    );
}

#[test]
fn a_wrong_passphrase_caller_is_rejected_and_never_surfaced() {
    let encrypted = |pass: &[u8]| {
        config().with_encryption(EncryptionSettings {
            passphrase: pass.to_vec(),
            key_size: KeySize::Aes128,
            cipher: CipherMode::Ctr,
        })
    };
    let mut pair = deferred_pair(
        encrypted(b"correct horse battery"),
        encrypted(b"wrong wrong wrong"),
    );
    pair.run_for(1_000_000);

    assert!(
        pair.listener_poll_request().is_none(),
        "a crypto-invalid conclusion must not reach the application"
    );
    assert!(
        pair.caller_events().iter().any(|e| matches!(
            e,
            Event::Failed(ConnectionError::Rejected(RejectReason::BadSecret))
        )),
        "the bad caller is rejected on the spot (BadSecret)"
    );
}

#[test]
fn accepting_an_unknown_address_errors() {
    let mut pair = deferred_pair(config(), config());
    pair.run_for(300_000);
    let bogus = "203.0.113.7:9000".parse().expect("addr");
    assert!(
        pair.listener_accept_pending(bogus).is_err(),
        "accepting an address with no pending conclusion must error"
    );
}
