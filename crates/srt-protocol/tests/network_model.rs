//! Determinism tests for the network-simulator primitives ([`sim::Rng`],
//! [`sim::Link`], [`sim::TimerWheel`]). The whole harness must be reproducible
//! from a seed and produce no surprises from the fake clock — that is what makes
//! the protocol tests flake-free.

mod sim;

use std::time::Duration;

use bytes::Bytes;
use sim::{Link, LinkConfig, Rng, TimerWheel};
use srt_protocol::connection::TimerId;

fn dg(n: u8) -> Bytes {
    Bytes::from(vec![n; 4])
}

// ---- Rng -------------------------------------------------------------------

#[test]
fn rng_is_reproducible_from_seed() {
    let mut a = Rng::new(0xDEAD_BEEF);
    let mut b = Rng::new(0xDEAD_BEEF);
    let seq_a: Vec<u64> = (0..16).map(|_| a.next_u64()).collect();
    let seq_b: Vec<u64> = (0..16).map(|_| b.next_u64()).collect();
    assert_eq!(seq_a, seq_b, "same seed must yield the same stream");
}

#[test]
fn rng_distinct_seeds_diverge() {
    let mut a = Rng::new(1);
    let mut b = Rng::new(2);
    assert_ne!(a.next_u64(), b.next_u64());
}

#[test]
fn rng_unit_is_in_range() {
    let mut r = Rng::new(7);
    for _ in 0..10_000 {
        let u = r.next_unit();
        assert!((0.0..1.0).contains(&u), "unit {u} out of [0,1)");
    }
}

#[test]
fn rng_below_is_bounded() {
    let mut r = Rng::new(99);
    for _ in 0..10_000 {
        assert!(r.below(10) < 10);
    }
}

// ---- Link ------------------------------------------------------------------

#[test]
fn perfect_link_delivers_all_in_order_after_delay() {
    let mut link = Link::new(LinkConfig::PERFECT, 0);
    // Send four datagrams 1 ms apart starting at t = 0.
    for i in 0..4u8 {
        link.send(u64::from(i) * 1_000, dg(i));
    }
    // Nothing is due before the 10 ms propagation delay elapses.
    assert!(link.drain_due(9_000).is_empty());
    assert_eq!(link.dropped(), 0);
    // By t = 13 ms every datagram (last sent at 3 ms, due at 13 ms) has arrived,
    // in send order.
    let arrived: Vec<Bytes> = link.drain_due(13_000);
    assert_eq!(arrived, vec![dg(0), dg(1), dg(2), dg(3)]);
    assert!(link.next_deadline().is_none());
}

#[test]
fn link_total_loss_drops_everything() {
    let cfg = LinkConfig {
        loss: 1.0,
        ..LinkConfig::PERFECT
    };
    let mut link = Link::new(cfg, 42);
    for i in 0..20u8 {
        link.send(0, dg(i));
    }
    assert_eq!(link.dropped(), 20);
    assert!(link.next_deadline().is_none());
    assert!(link.drain_due(1_000_000).is_empty());
}

#[test]
fn link_zero_loss_drops_nothing() {
    let mut link = Link::new(LinkConfig::PERFECT, 123);
    for i in 0..20u8 {
        link.send(0, dg(i));
    }
    assert_eq!(link.dropped(), 0);
}

#[test]
fn link_loss_pattern_is_reproducible() {
    let cfg = LinkConfig {
        loss: 0.5,
        ..LinkConfig::PERFECT
    };
    let run = || {
        let mut link = Link::new(cfg, 0xABCD);
        for i in 0..64u8 {
            link.send(0, dg(i));
        }
        // Which datagrams survived, in delivery order, plus the drop count.
        (link.drain_due(1_000_000), link.dropped())
    };
    let (survived_a, dropped_a) = run();
    let (survived_b, dropped_b) = run();
    assert_eq!(
        survived_a, survived_b,
        "loss pattern must replay identically"
    );
    assert_eq!(dropped_a, dropped_b);
    // A 50% link over 64 datagrams must drop some but not all (sanity, not flake:
    // the seed is fixed so this is a deterministic assertion).
    assert!(dropped_a > 0 && dropped_a < 64);
    assert_eq!(survived_a.len() as u64 + dropped_a, 64);
}

#[test]
fn link_jitter_stays_in_bounds_and_replays() {
    let cfg = LinkConfig {
        delay: Duration::from_millis(10),
        loss: 0.0,
        jitter: Duration::from_millis(5),
    };
    let order = |seed: u64| {
        let mut link = Link::new(cfg, seed);
        for i in 0..16u8 {
            link.send(0, dg(i)); // all sent at t = 0
        }
        // Every delivery time must fall within [delay, delay+jitter].
        let mut times = Vec::new();
        while let Some(at) = link.next_deadline() {
            assert!((10_000..=15_000).contains(&at), "delivery {at} out of band");
            // Drain exactly the datagrams due at this instant.
            let _ = link.drain_due(at);
            times.push(at);
        }
        times
    };
    assert_eq!(
        order(555),
        order(555),
        "jitter schedule must replay identically"
    );
}

// ---- TimerWheel ------------------------------------------------------------

#[test]
fn timer_wheel_reports_earliest_deadline() {
    let mut w = TimerWheel::new();
    assert_eq!(w.next_deadline(), None);
    w.set(TimerId::Handshake, 5_000);
    assert_eq!(w.next_deadline(), Some(5_000));
}

#[test]
fn timer_wheel_set_reschedules_same_id() {
    let mut w = TimerWheel::new();
    w.set(TimerId::Handshake, 5_000);
    w.set(TimerId::Handshake, 2_000); // re-arm moves the deadline
    assert_eq!(w.next_deadline(), Some(2_000));
}

#[test]
fn timer_wheel_clear_removes_timer() {
    let mut w = TimerWheel::new();
    w.set(TimerId::Handshake, 5_000);
    w.clear(TimerId::Handshake);
    assert_eq!(w.next_deadline(), None);
    w.clear(TimerId::Handshake); // clearing an unarmed timer is a no-op
}

#[test]
fn timer_wheel_pop_due_fires_and_removes() {
    let mut w = TimerWheel::new();
    w.set(TimerId::Handshake, 5_000);
    assert!(w.pop_due(4_999).is_empty(), "not yet due");
    assert_eq!(w.pop_due(5_000), vec![TimerId::Handshake]);
    assert!(w.pop_due(5_000).is_empty(), "fired timers are removed");
    assert_eq!(w.next_deadline(), None);
}
