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
    Config::default()
        .with_latency(Duration::from_millis(80))
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
    // A usable data link but a DEAD feedback link: no ACK ever returns, so the
    // sender can never confirm delivery and — once a packet outlives libsrt's
    // send-side TLPKTDROP window (max(latency, 1000 ms) + 2·SYN ≈ 1020 ms) — sheds
    // it and announces the drop via DROPREQ. (A merely-lossy link no longer forces a
    // drop: the corrected window lets ARQ recover the stragglers rather than
    // abandoning them at the bare 80 ms playout latency — the point of the fix.)
    let data = LinkConfig {
        loss: 0.1,
        ..LinkConfig::PERFECT
    };
    let dead_feedback = LinkConfig {
        loss: 1.0,
        ..LinkConfig::PERFECT
    };
    let mut pair = connected(data, dead_feedback, 11);

    for i in 0..40u8 {
        pair.caller_send(&[i; 60]);
        pair.run_for(20_000); // 20 ms between packets
    }
    // Settle well past the ~1020 ms drop threshold so the un-acked tail ages out.
    pair.run_for(2_500_000);

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
