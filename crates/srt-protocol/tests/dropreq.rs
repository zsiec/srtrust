//! DROPREQ end-to-end tests (spec §3.2.9): a sender that gives up on packets too
//! old to ever play in time announces the drop so the receiver advances cleanly
//! instead of `NAK`-ing forever for data that will never come. Driven through the
//! deterministic [`sim::Pair`].

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

/// A short latency so the play-out budget is tight: packets that loss keeps from
/// arriving quickly become too late, triggering send-side TLPKTDROP + DROPREQ.
fn config() -> Config {
    Config {
        latency: Duration::from_millis(80),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: None,
        max_bw: 0,
        km_refresh_rate: 0,
        fec: None,
    }
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
    // Handshake on a clean link, then degrade for the data phase.
    let mut pair = Pair::new(
        now,
        caller,
        listener,
        LinkConfig::PERFECT,
        LinkConfig::PERFECT,
        seed,
    );
    assert!(pair.run_until_connected(200), "handshake completes");
    pair.degrade_links(c2l, l2c, seed);
    pair
}

#[test]
fn too_late_packets_are_dropped_and_announced() {
    // Lossy data link, heavily-starved feedback: NAK/ACK rarely get back, so the
    // sender cannot recover everything inside the 80 ms budget and must shed the
    // stragglers — announcing each via DROPREQ.
    let lossy = LinkConfig {
        loss: 0.4,
        ..LinkConfig::PERFECT
    };
    let starved = LinkConfig {
        loss: 0.9,
        ..LinkConfig::PERFECT
    };
    let mut pair = connected(lossy, starved, 11);

    for i in 0..40u8 {
        pair.caller_send(&[i; 60]);
        pair.run_for(20_000); // 20 ms between packets
    }
    // Let everything settle: in-flight data drains, drops are announced.
    pair.run_for(2_000_000);

    // The sender shed at least one too-late packet (send-side TLPKTDROP).
    assert!(
        pair.caller_dropreqs() >= 1,
        "the sender announces dropped packets, got {}",
        pair.caller_dropreqs()
    );

    // Whatever the receiver delivered came in strictly increasing order — the
    // dropped packets are skipped, never delivered out of order or duplicated.
    let received = pair.accepted_received();
    assert!(
        !received.is_empty(),
        "the receiver still delivers the stream"
    );
    let tags: Vec<u8> = received.iter().map(|m| m[0]).collect();
    assert!(
        tags.windows(2).all(|w| w[0] < w[1]),
        "delivered packets are strictly increasing (in order, no dupes): {tags:?}"
    );

    // The connection made progress to the end of the stream rather than stalling
    // on a permanent gap: the last delivered packet is near the end.
    assert!(
        *tags.last().unwrap() >= 30,
        "delivery reached the tail of the stream, last={}",
        tags.last().unwrap()
    );
}
