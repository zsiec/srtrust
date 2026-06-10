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
    Config::default()
        .with_latency(Duration::from_millis(latency_ms))
        .with_flow_window(8192)
}

fn connected(c2l: LinkConfig, l2c: LinkConfig, seed: u64, latency_ms: u64) -> Pair {
    connected_asymmetric(c2l, l2c, seed, latency_ms, latency_ms)
}

fn connected_asymmetric(
    c2l: LinkConfig,
    l2c: LinkConfig,
    seed: u64,
    caller_latency_ms: u64,
    listener_latency_ms: u64,
) -> Pair {
    let now = t0();
    let caller = Connection::connect(
        config(caller_latency_ms),
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        |_| {},
    );
    let listener = Listener::new(
        config(listener_latency_ms),
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

/// BUG-03 (docs/known-issues/03): packet timestamps are 32-bit microseconds, and
/// a single circular diff against the frozen first-packet anchor is only
/// unambiguous within ±2^31 µs (~35.8 min). Past that, the computed play time
/// lands in the past and TSBPD degenerates into deliver-immediately. The time
/// base must advance across the wrap (spec §4.5.1.1 case 1). The stream here is
/// continuous (a packet every 10 s), as live streams are — wrap tracking keys
/// on the data stream itself.
#[test]
fn delivery_is_still_held_after_the_timestamp_wrap_window() {
    let latency_ms = 200;
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 11, latency_ms);

    // Stream one packet every 10 fake seconds until sender timestamps are well
    // past anchor + 2^31 µs (~35.8 min → 220 packets ≈ 36.7 min).
    let across = 220u32;
    for i in 0..across {
        pair.caller_send(&payload(u8::try_from(i % 200).expect("fits")));
        pair.run_for(10_000_000);
    }
    assert_eq!(
        pair.accepted_received().len(),
        across as usize,
        "the steady stream is delivered throughout"
    );

    // A packet sent now — past the ±2^31 µs window from the anchor — must still
    // be held for `latency`, not played out immediately.
    let sent_at = pair.fake_micros();
    assert!(
        sent_at > (1 << 31),
        "the test must actually cross the wrap window, at {sent_at} us"
    );
    pair.caller_send(&payload(255));
    pair.run_for(100_000); // 100 ms < the 200 ms latency
    assert_eq!(
        pair.accepted_received().len(),
        across as usize,
        "a packet sent past the wrap window must still be held for `latency`"
    );
    assert!(pair.run_until(
        |p| p.accepted_received().len() == across as usize + 1,
        20_000
    ));
    let elapsed = pair.fake_micros() - sent_at;
    assert!(
        (200_000..=230_000).contains(&elapsed),
        "played ~latency after send even across the wrap, got {elapsed} us"
    );
}

/// Latency is **negotiated**: each side advertises its configured value and the
/// connection uses the larger (spec §4.3.1.2; libsrt `SRTO_RCVLATENCY` /
/// `SRTO_PEERLATENCY` semantics). A receiver configured low must still hold
/// packets for the higher latency the *sender* advertised — and the sender's
/// too-late drop budget must use the same negotiated value. Found live: srtrust
/// computed and advertised the negotiated value, then used its local config
/// everywhere.
#[test]
fn the_negotiated_latency_binds_a_low_latency_receiver() {
    // Caller (the sender) wants 400 ms; the listener (the receiver) only 100 ms.
    // Negotiated: 400 ms — the receiver must hold packets that long.
    let mut pair = connected_asymmetric(LinkConfig::PERFECT, LinkConfig::PERFECT, 17, 400, 100);

    let sent_at = pair.fake_micros();
    pair.caller_send(&payload(0));

    pair.run_for(250_000); // 250 ms: past the receiver's own 100 ms config
    assert!(
        pair.accepted_received().is_empty(),
        "the packet must be held for the negotiated 400 ms, not the local 100 ms"
    );
    assert!(pair.run_until(|p| !p.accepted_received().is_empty(), 10_000));
    let elapsed = pair.fake_micros() - sent_at;
    assert!(
        (400_000..=440_000).contains(&elapsed),
        "delivered ~negotiated latency after send (10 ms link + 400 ms), got {elapsed} us"
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
