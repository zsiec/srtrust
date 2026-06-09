//! End-to-end ARQ tests (spec §4.5–§4.8): reliable, in-order delivery over a
//! lossy, reordering link, driven through the deterministic [`sim::Pair`].

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config() -> Config {
    Config {
        // A generous latency so retransmissions (incl. the 300 ms EXP backstop)
        // arrive within the TSBPD play-out budget rather than being dropped as
        // too-late. Live SRT likewise sets latency well above the recovery time.
        latency: Duration::from_secs(1),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: None,
        max_bw: 0,
        km_refresh_rate: 0,
        fec: None,
    }
}

fn caller(now: std::time::Instant) -> Connection {
    Connection::connect(
        config(),
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        |_| {},
    )
}

fn listener(now: std::time::Instant) -> Listener {
    Listener::new(
        config(),
        SocketId::new(0x22),
        SeqNumber::new(9000),
        0xC0FF_EE12,
        now,
    )
}

/// Builds a pair and runs the handshake to completion.
fn connected(c2l: LinkConfig, l2c: LinkConfig, seed: u64) -> Pair {
    let now = t0();
    let mut pair = Pair::new(now, caller(now), listener(now), c2l, l2c, seed);
    assert!(pair.run_until_connected(200), "handshake must complete");
    pair
}

/// A `len`-byte payload whose first byte tags it with index `i`.
fn payload(i: u8, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    v[0] = i;
    v
}

#[test]
fn data_transfers_over_a_perfect_link() {
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 1);
    for i in 0..5u8 {
        pair.caller_send(&payload(i, 100));
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == 5, 10_000));
    let received = pair.accepted_received();
    assert_eq!(received.len(), 5, "all five packets delivered");
    for (i, bytes) in received.iter().enumerate() {
        assert_eq!(usize::from(bytes[0]), i, "delivered in order");
        assert_eq!(bytes.len(), 100);
    }
}

#[test]
fn data_recovers_from_a_lossy_link() {
    let lossy = LinkConfig {
        loss: 0.3,
        ..LinkConfig::PERFECT
    };
    let mut pair = connected(lossy, lossy, 0xBEEF);
    for i in 0..20u8 {
        pair.caller_send(&payload(i, 60));
    }
    let done = pair.run_until(|p| p.accepted_received().len() == 20, 200_000);
    assert!(done, "retransmission must recover every packet");
    let received = pair.accepted_received();
    for (i, bytes) in received.iter().enumerate() {
        assert_eq!(
            usize::from(bytes[0]),
            i,
            "still delivered in order despite loss"
        );
    }
}

#[test]
fn reordered_data_is_delivered_in_order() {
    let jittery = LinkConfig {
        delay: Duration::from_millis(10),
        loss: 0.0,
        jitter: Duration::from_millis(8),
    };
    let mut pair = connected(jittery, jittery, 99);
    for i in 0..16u8 {
        pair.caller_send(&payload(i, 40));
    }
    let done = pair.run_until(|p| p.accepted_received().len() == 16, 200_000);
    assert!(done, "all packets delivered despite reordering");
    let received = pair.accepted_received();
    for (i, bytes) in received.iter().enumerate() {
        assert_eq!(
            usize::from(bytes[0]),
            i,
            "reassembled into the original order"
        );
    }
}

#[test]
fn tail_loss_is_recovered_by_the_exp_timer() {
    // Establish on a clean link, then degrade it: heavy feedback loss means ACKs
    // and NAKs from the receiver mostly never arrive, so NAK-driven retransmission
    // stalls. Only the sender's EXP timer can drive the data through. The data
    // link also drops some packets.
    //
    // A generous latency keeps the play-out budget wide enough that EXP recovery
    // fits inside it — otherwise send-side TLPKTDROP would (correctly) shed a
    // packet whose recovery takes longer than `latency`.
    let now = t0();
    let cfg = Config {
        latency: Duration::from_secs(5),
        ..config()
    };
    let caller = Connection::connect(
        cfg.clone(),
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        |_| {},
    );
    let listener = Listener::new(
        cfg,
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
        7,
    );
    assert!(pair.run_until_connected(200), "handshake completes");
    let c2l = LinkConfig {
        loss: 0.2,
        ..LinkConfig::PERFECT
    };
    let feedback_starved = LinkConfig {
        loss: 0.9,
        ..LinkConfig::PERFECT
    };
    pair.degrade_links(c2l, feedback_starved, 7);
    for i in 0..8u8 {
        pair.caller_send(&payload(i, 30));
    }
    let done = pair.run_until(|p| p.accepted_received().len() == 8, 1_000_000);
    assert!(
        done,
        "the EXP retransmission backstop must deliver the data even when feedback is starved"
    );
}
