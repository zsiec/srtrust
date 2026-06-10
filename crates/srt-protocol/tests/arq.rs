//! End-to-end ARQ tests (spec §4.5–§4.8): reliable, in-order delivery over a
//! lossy, reordering link, driven through the deterministic [`sim::Pair`].

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection};
use srt_protocol::listener::Listener;
use srt_protocol::packet::{Packet, SocketId};
use srt_protocol::seq::SeqNumber;

fn config() -> Config {
    // A generous latency so retransmissions (incl. the 300 ms EXP backstop)
    // arrive within the TSBPD play-out budget rather than being dropped as
    // too-late. Live SRT likewise sets latency well above the recovery time.
    Config::default()
        .with_latency(Duration::from_secs(1))
        .with_flow_window(8192)
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

/// BUG-01 (docs/known-issues/01): one lost packet must produce (about) one
/// retransmission, not `RTT / NAK_interval` of them. The sender keeps a
/// per-packet retransmit timing-gate (libsrt's `checkRexmitRightTime`; spec
/// §4.8.2 — packets "are not retransmitted unnecessarily"), and the receiver's
/// periodic NAK backs off instead of re-reporting the same loss every interval.
#[test]
fn a_single_loss_is_retransmitted_once_not_once_per_nak() {
    // A long link (RTT 200 ms) gives many NAK intervals between the first
    // retransmission and its arrival — exactly where the duplicates came from.
    let long = LinkConfig {
        delay: Duration::from_millis(100),
        loss: 0.0,
        jitter: Duration::ZERO,
    };
    let mut pair = connected(long, long, 5);

    // Warm up: 20 packets at a 5 ms cadence, no loss, so RTT estimates converge.
    for i in 0..20u8 {
        pair.caller_send(&payload(i, 60));
        pair.run_for(5_000);
    }

    // Now lose exactly one packet (the 26th, seq 1025), first transmission only.
    pair.set_c2l_drop_filter(|datagram| {
        matches!(
            Packet::decode(datagram),
            Ok(Packet::Data(d)) if d.seq == SeqNumber::new(1025) && !d.retransmitted
        )
    });
    for i in 20..40u8 {
        pair.caller_send(&payload(i, 60));
        pair.run_for(5_000);
    }

    assert!(
        pair.run_until(|p| p.accepted_received().len() == 40, 200_000),
        "the loss is recovered (got {})",
        pair.accepted_received().len()
    );
    // Let any late duplicates and straggler NAK responses arrive.
    pair.run_for(1_000_000);

    let recv = pair.accepted_stats().expect("accepted side exists");
    assert_eq!(
        recv.packets_duplicate, 0,
        "no duplicate ever reaches the receiver for a single loss"
    );
    assert_eq!(
        pair.caller_stats().packets_retransmitted,
        1,
        "exactly one retransmission for one lost packet"
    );
    assert!(
        pair.accepted_naks() <= 2,
        "the loss is NAK'd once (plus at most one RTO-aged re-NAK), got {}",
        pair.accepted_naks()
    );
}

/// 5c (docs/known-issues/05): the reorder tolerance adapts to the link instead
/// of staying a fixed constant. On a jittery-but-lossless link whose reorder
/// depth exceeds the old fixed tolerance, the receiver initially NAKs
/// reordered-in-flight packets — but once it *observes* that depth (belated
/// originals arriving, libsrt's `SRTO_LOSSMAXTTL` adaptation) it must stop
/// mistaking reordering for loss.
#[test]
fn reorder_tolerance_adapts_to_a_jittery_link() {
    // 20 ms of jitter at a 1 ms send cadence → reorder depth up to ~20, far
    // beyond the old fixed tolerance of 5, so several packets routinely
    // overtake a merely-delayed one.
    let jittery = LinkConfig {
        delay: Duration::from_millis(10),
        loss: 0.0,
        jitter: Duration::from_millis(20),
    };
    let mut pair = connected(jittery, jittery, 21);

    // Learning phase: the receiver may NAK while it discovers the reorder depth.
    for i in 0..150u8 {
        pair.caller_send(&payload(i, 60));
        pair.run_for(1_000);
    }
    pair.run_for(500_000); // settle: everything delivered, no gaps outstanding
    let learned_naks = pair.accepted_naks();

    // Adapted phase: same jitter, zero loss — no more spurious NAKs.
    for i in 150..=255u8 {
        pair.caller_send(&payload(i, 60));
        pair.run_for(1_000);
    }
    // Long enough for the tail to clear the 1 s TSBPD latency and play out.
    pair.run_for(1_500_000);

    assert_eq!(
        pair.accepted_received().len(),
        256,
        "everything is delivered on the lossless link"
    );
    // A residual trickle is allowed: the tolerance decays on sustained order
    // (so it must occasionally re-learn) and a never-before-seen reorder depth
    // can still first appear here. What must be gone is the steady spurious
    // NAK-ing a *fixed* tolerance produces on every deep reorder.
    let adapted_naks = pair.accepted_naks() - learned_naks;
    assert!(
        adapted_naks <= learned_naks / 4,
        "once adapted, spurious NAKs nearly vanish: {adapted_naks} new \
         (vs {learned_naks} while learning)"
    );
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
    let cfg = config().with_latency(Duration::from_secs(5));
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
