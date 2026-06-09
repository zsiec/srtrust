//! TSBPD (timestamp-based packet delivery) and TLPKTDROP tests (spec §4.5–§4.6),
//! driven through the deterministic [`sim::Pair`].

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config(latency_ms: u64) -> Config {
    Config {
        latency: Duration::from_millis(latency_ms),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: None,
        max_bw: 0,
        km_refresh_rate: 0,
        fec: None,
    }
}

fn connected(c2l: LinkConfig, l2c: LinkConfig, seed: u64, latency_ms: u64) -> Pair {
    let now = t0();
    let cfg = config(latency_ms);
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
    let mut pair = Pair::new(now, caller, listener, c2l, l2c, seed);
    assert!(pair.run_until_connected(200), "handshake must complete");
    pair
}

/// A 50-byte payload tagged with index `i`.
fn payload(i: u8) -> Vec<u8> {
    let mut v = vec![0u8; 50];
    v[0] = i;
    v
}

/// The index tags of what the receiver delivered, in delivery order.
fn delivered_indices(pair: &Pair) -> Vec<u8> {
    pair.accepted_received().iter().map(|b| b[0]).collect()
}

#[test]
fn delivery_is_held_until_the_play_time() {
    let latency_ms = 200;
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 1, latency_ms);

    let sent_at = pair.fake_micros();
    pair.caller_send(&payload(0));

    // Well before the play time, the packet is buffered, not delivered.
    pair.run_for(100_000); // 100 ms < 200 ms latency
    assert!(
        pair.accepted_received().is_empty(),
        "the packet must be held until its play time"
    );

    // It is delivered roughly `latency` after it arrived (one-way delay + latency).
    assert!(pair.run_until(|p| !p.accepted_received().is_empty(), 10_000));
    let elapsed = pair.fake_micros() - sent_at;
    assert!(
        (200_000..=230_000).contains(&elapsed),
        "delivered ~latency after send (10 ms link + 200 ms latency), got {elapsed} us"
    );
}

#[test]
fn clean_link_delivers_everything_in_order() {
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 3, 100);
    for i in 0..10u8 {
        pair.caller_send(&payload(i));
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == 10, 20_000));
    assert_eq!(delivered_indices(&pair), (0..10).collect::<Vec<u8>>());
}

#[test]
fn tlpktdrop_skips_unrecoverable_packets_but_keeps_the_stream_flowing() {
    // Establish on a clean link, then degrade: a short latency, lossy data, and
    // *fully* lost feedback. NAK-based recovery is impossible (no NAK reaches the
    // sender), and the only retransmit source — the 300 ms EXP backstop — always
    // arrives long after the 40 ms play time. So every first-transmit loss is
    // unrecoverable: TLPKTDROP must drop it and keep delivering the rest in order.
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 7, 40);
    let lossy_data = LinkConfig {
        loss: 0.4,
        ..LinkConfig::PERFECT
    };
    let dead_feedback = LinkConfig {
        loss: 1.0,
        ..LinkConfig::PERFECT
    };
    pair.degrade_links(lossy_data, dead_feedback, 7);

    for i in 0..30u8 {
        pair.caller_send(&payload(i));
    }
    // Let every packet's play time pass so all fates (deliver or drop) are decided.
    pair.run_for(2_000_000);

    let indices = delivered_indices(&pair);
    assert!(!indices.is_empty(), "some packets were delivered");
    assert!(
        indices.len() < 30,
        "TLPKTDROP dropped unrecoverable packets, got {} of 30",
        indices.len()
    );
    assert!(
        indices.windows(2).all(|w| w[0] < w[1]),
        "delivery stays strictly in order across drops: {indices:?}"
    );
    assert!(
        *indices.last().unwrap() >= 20,
        "delivery progressed near the tail rather than stalling on a gap: {indices:?}"
    );
}
