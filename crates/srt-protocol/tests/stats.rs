//! Connection-statistics tests: the cumulative counters track real traffic —
//! sends, receives, and (on a lossy link) retransmissions. Driven through the
//! deterministic [`sim::Pair`].

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config() -> Config {
    Config::default()
        .with_latency(Duration::from_secs(1))
        .with_flow_window(8192)
}

fn connected(c2l: LinkConfig, l2c: LinkConfig, seed: u64) -> Pair {
    let now = t0();
    let caller = Connection::connect(
        config(),
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        |_| {},
    );
    let listener = Listener::new(
        config(),
        SocketId::new(0x22),
        SeqNumber::new(9000),
        0xC0FF_EE12,
        now,
    );
    let mut pair = Pair::new(now, caller, listener, c2l, l2c, seed);
    assert!(pair.run_until_connected(200), "handshake completes");
    pair
}

#[test]
fn counters_track_a_clean_transfer() {
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 1);
    let n = 12u8;
    for i in 0..n {
        pair.caller_send(&[i; 100]);
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == usize::from(n), 50_000));

    let caller = pair.caller_stats();
    assert_eq!(caller.packets_sent, u64::from(n), "every send counted");
    assert_eq!(caller.bytes_sent, u64::from(n) * 100);
    assert_eq!(
        caller.packets_retransmitted, 0,
        "no retransmits on a perfect link"
    );

    let accepted = pair.accepted_stats().expect("accepted exists");
    assert_eq!(
        accepted.packets_received,
        u64::from(n),
        "every packet received"
    );
    assert_eq!(accepted.bytes_received, u64::from(n) * 100);
    assert_eq!(
        accepted.packets_dropped, 0,
        "nothing dropped on a clean link"
    );
}

#[test]
fn the_receiver_estimates_its_delivery_rate() {
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 5);
    // Stream a steady sequence for several seconds of fake time — well past the
    // estimator's one-second averaging window, so it finalizes a reading. (The sim
    // advances to the next event per `run_for`, so the arrival cadence follows the
    // link/timer events, not a literal 1 ms; the exact rate is the harness's, the
    // point is that a *sane stream rate* is reported.)
    for _ in 0..300u32 {
        pair.caller_send(&[7u8; 800]);
        pair.run_for(1_000);
    }
    pair.run_for(200_000); // let the tail arrive

    let accepted = pair.accepted_stats().expect("accepted exists");
    // The windowed throughput reports the actual stream rate (cross-checked against
    // libsrt's `mbpsRecvRate`, which reports ~the stream rate — not the orders-of-
    // magnitude-higher intra-burst rate an inter-arrival median produces). These are
    // the numbers a full ACK now carries to the peer (spec §3.2.4).
    assert!(
        (10..=50_000).contains(&accepted.recv_rate_pps),
        "a sane stream rate is reported, got {}",
        accepted.recv_rate_pps
    );
    assert!(
        accepted.recv_rate_bps > 0,
        "byte rate also reported, got {}",
        accepted.recv_rate_bps
    );
    assert!(
        accepted.link_capacity_pps > 0,
        "link-capacity estimate reported, got {}",
        accepted.link_capacity_pps
    );
}

#[test]
fn retransmissions_are_counted_on_a_lossy_link() {
    let lossy = LinkConfig {
        loss: 0.3,
        ..LinkConfig::PERFECT
    };
    let mut pair = connected(lossy, lossy, 0xBEEF);
    let n = 20u8;
    for i in 0..n {
        pair.caller_send(&[i; 60]);
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == usize::from(n), 200_000));

    let caller = pair.caller_stats();
    assert_eq!(caller.packets_sent, u64::from(n), "originals counted once");
    assert!(
        caller.packets_retransmitted > 0,
        "loss forced retransmissions, got {}",
        caller.packets_retransmitted
    );

    // The receiver still accepts exactly n unique packets; duplicates (from
    // retransmits that crossed with recovery) are counted separately, not as data.
    let accepted = pair.accepted_stats().unwrap();
    assert_eq!(
        accepted.packets_received,
        u64::from(n),
        "n unique delivered"
    );
}

#[test]
fn counters_track_acks_naks_and_negotiated_latency() {
    // 30% loss caller→listener: the receiver must NAK, the sender must hear
    // those NAKs, and ACKs flow back the whole time.
    let lossy = LinkConfig {
        loss: 0.3,
        ..LinkConfig::PERFECT
    };
    let mut pair = connected(lossy, LinkConfig::PERFECT, 7);
    let n = 40u8;
    for i in 0..n {
        pair.caller_send(&[i; 100]);
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == usize::from(n), 50_000));

    let caller = pair.caller_stats();
    let accepted = pair.accepted_stats().expect("accepted exists");
    assert!(caller.acks_received >= 1, "the sender heard ACKs");
    assert!(caller.naks_received >= 1, "the sender heard loss reports");
    assert!(accepted.acks_sent >= 1, "the receiver sent ACKs");
    assert!(accepted.naks_sent >= 1, "the receiver sent loss reports");
    assert_eq!(
        caller.acks_received, accepted.acks_sent,
        "every ACK the receiver sent arrived (the l2c link is perfect)"
    );

    // Both sides advertised 1 s, so both negotiated 1 s (spec §4.3.1.2).
    assert_eq!(caller.latency_ms, 1000);
    assert_eq!(accepted.latency_ms, 1000);
}

#[test]
fn send_buffer_gauge_tracks_the_unacknowledged_backlog() {
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 1);

    // Cut both links: sends queue up with no way to be acknowledged.
    let dead = LinkConfig {
        loss: 1.0,
        ..LinkConfig::PERFECT
    };
    pair.degrade_links(dead, dead, 9);
    for i in 0..5u8 {
        pair.caller_send(&[i; 100]);
    }
    assert!(
        pair.caller_stats().send_buffer_packets >= 5,
        "unacknowledged data shows in the send-buffer gauge, got {}",
        pair.caller_stats().send_buffer_packets
    );

    // Heal the links and let everything deliver + acknowledge: gauge drains.
    pair.degrade_links(LinkConfig::PERFECT, LinkConfig::PERFECT, 10);
    assert!(pair.run_until(|p| p.caller_stats().send_buffer_packets == 0, 50_000));
}
