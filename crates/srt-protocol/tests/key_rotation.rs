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
use srt_protocol::control::{ControlBody, ControlType};
use srt_protocol::listener::Listener;
use srt_protocol::packet::{Packet, SocketId};
use srt_protocol::seq::SeqNumber;

/// The SRT command subtypes a rekey Key Material message rides on (spec §6.1.6;
/// `UMSG_EXT` control packets). Mirrors the crate's private constants.
const EXT_KMREQ: u16 = 3;
const EXT_KMRSP: u16 = 4;

/// Whether `datagram` is a `UMSG_EXT` control packet with the given subtype.
fn is_km(datagram: &[u8], wanted: u16) -> bool {
    matches!(
        Packet::decode(datagram),
        Ok(Packet::Control(c)) if matches!(
            c.body,
            ControlBody::Raw { control_type: ControlType::UserDefined, subtype, .. }
                if subtype == wanted
        )
    )
}

fn cipher_config(cipher: CipherMode, km_refresh_rate: u32) -> Config {
    Config {
        latency: Duration::from_millis(120),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: Some(EncryptionSettings {
            passphrase: b"rotate-me-please".to_vec(),
            key_size: KeySize::Aes128,
            cipher,
        }),
        max_bw: 0,
        // A tiny refresh rate so rotation happens within a short test (the wire
        // mechanism is identical at the 2^24 default).
        km_refresh_rate,
        fec: None,
    }
}

fn connected() -> Pair {
    connected_cipher(CipherMode::Ctr, 8)
}

fn connected_cipher(cipher: CipherMode, km_refresh_rate: u32) -> Pair {
    let now = t0();
    let caller = Connection::connect(
        cipher_config(cipher, km_refresh_rate),
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
        cipher_config(cipher, km_refresh_rate),
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
        // show up as bytes that are not all equal to the index. Real time passes
        // between packets: a rotation needs a KMREQ→KMRSP round trip to confirm
        // the peer holds the next key before the sender switches (BUG-06), so a
        // zero-time burst cannot rotate.
        let payload = vec![i; 120];
        pair.caller_send(&payload);
        pair.run_for(20_000);
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

/// BUG-06 (docs/known-issues/06): control packets are not ARQ-protected, so the
/// rekey KMREQ/KMRSP exchange must supply its own reliability. A sender that
/// announces the next key exactly once and then switches unconditionally turns
/// one lost datagram into an undecryptable stream for a whole refresh window.
/// The sender must re-announce until the peer's KMRSP confirms, and only switch
/// after confirmation (libsrt re-sends until `SRT_KM_S_SECURED`; srtgo retries
/// every 1.5×SRTT).
#[test]
fn a_lost_rekey_kmreq_is_resent_and_the_stream_stays_decryptable() {
    let mut pair = connected(); // CTR, km_refresh_rate = 8

    // Drop only the *first* rekey KMREQ.
    let mut dropped_one = false;
    pair.set_c2l_drop_filter(move |datagram| {
        if !dropped_one && is_km(datagram, EXT_KMREQ) {
            dropped_one = true;
            return true;
        }
        false
    });

    // Stream across the rotation point (pre-announce at packet 6, switch due at
    // packet 9) with real time between packets.
    let n = 40u8;
    for i in 0..n {
        pair.caller_send(&[i; 120]);
        pair.run_for(20_000);
    }
    // Settle long enough for the KMREQ re-send (and its KMRSP) to complete.
    pair.run_for(3_000_000);

    // The rotation must eventually complete on the re-announced key: these
    // packets are sent after confirmation, under the new key.
    for i in n..n + 20 {
        pair.caller_send(&[i; 120]);
        pair.run_for(20_000);
    }
    let total = usize::from(n) + 20;

    assert!(
        pair.run_until(|p| p.accepted_received().len() == total, 200_000),
        "every packet decrypts despite the lost KMREQ: expected {total}, got {} \
         (undecryptable: {})",
        pair.accepted_received().len(),
        pair.accepted_stats().map_or(0, |s| s.packets_undecryptable),
    );
    let received = pair.accepted_received();
    for (i, message) in received.iter().enumerate() {
        let tag = u8::try_from(i).expect("fits");
        assert!(
            message.iter().all(|&b| b == tag),
            "message {i} decrypted intact"
        );
    }
    assert_eq!(
        pair.accepted_stats()
            .expect("accepted exists")
            .packets_undecryptable,
        0,
        "no packet was ever sent under an unconfirmed key"
    );
}

/// The dual of the lost-KMREQ case: if the peer's KMRSP never arrives, the
/// sender must keep using the old (still-shared) key — a late rotation is
/// strictly better than an undecryptable stream.
#[test]
fn the_key_switch_waits_for_kmrsp_confirmation() {
    let mut pair = connected();
    // Black-hole every rekey KMRSP from the listener side.
    pair.set_l2c_drop_filter(|datagram| is_km(datagram, EXT_KMRSP));

    let n = 40u8;
    for i in 0..n {
        pair.caller_send(&[i; 120]);
        pair.run_for(20_000);
    }
    assert!(
        pair.run_until(|p| p.accepted_received().len() == usize::from(n), 200_000),
        "unconfirmed rotation must not break the stream: got {} of {n} \
         (undecryptable: {})",
        pair.accepted_received().len(),
        pair.accepted_stats().map_or(0, |s| s.packets_undecryptable),
    );
    assert_eq!(
        pair.accepted_stats()
            .expect("accepted exists")
            .packets_undecryptable,
        0,
        "every packet stays on a key both sides hold"
    );
}

/// BUG-02 (docs/known-issues/02): a GCM packet lost *before* a key rotation is
/// retransmitted *after* it. The retransmission is re-encrypted (GCM stores
/// plaintext and re-encrypts per send), so its key-slot flag must name the key
/// that actually encrypted it — the now-active one — or the receiver decrypts
/// with the stale key and drops the packet forever (spec §6.1.6: the even/odd
/// flag selects the key).
#[test]
fn gcm_packet_lost_before_rotation_recovers_after_it() {
    // km_refresh_rate = 16 makes the 20-packet burst rotate exactly **once**
    // (switch at the 17th send): the active slot at retransmit time (odd) is the
    // opposite of the lost packet's (even). A smaller rate would rotate twice and
    // land back on even, masking the bug.
    let mut pair = connected_cipher(CipherMode::Gcm, 16);

    // Drop only the *first* transmission of seq 1003: it is encrypted under the
    // initial even key, and its NAK-triggered retransmission happens after the
    // sender has rotated to the odd key.
    pair.set_c2l_drop_filter(|datagram| {
        matches!(
            Packet::decode(datagram),
            Ok(Packet::Data(d)) if d.seq == SeqNumber::new(1003) && !d.retransmitted
        )
    });

    let n = 20u8;
    for i in 0..n {
        // Index-tagged payloads make any wrong-key decryption visible.
        pair.caller_send(&[i; 120]);
    }

    assert!(
        pair.run_until(|p| p.accepted_received().len() == usize::from(n), 200_000),
        "the pre-rotation loss is recovered: expected {n} messages, got {} \
         (undecryptable: {})",
        pair.accepted_received().len(),
        pair.accepted_stats().map_or(0, |s| s.packets_undecryptable),
    );
    let received = pair.accepted_received();
    for (i, message) in received.iter().enumerate() {
        let tag = u8::try_from(i).expect("n fits in u8");
        assert!(
            message.iter().all(|&b| b == tag),
            "message {i} decrypted intact across the rotation"
        );
    }
    let stats = pair.accepted_stats().expect("accepted side exists");
    assert_eq!(
        stats.packets_undecryptable, 0,
        "no retransmission was flagged with the wrong key slot"
    );
}
