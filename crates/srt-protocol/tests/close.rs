//! Graceful-close tests (spec §3.2.7, SHUTDOWN): a closing sender lingers until
//! its outstanding data is acknowledged before tearing down, and a receiver
//! flushes the data it still holds when the SHUTDOWN arrives — so an orderly
//! close never truncates the stream. Driven through the deterministic
//! [`sim::Pair`].

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection, Event};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config() -> Config {
    Config {
        // A long TSBPD latency means freshly-received data sits in the receive
        // buffer (not yet played) for a while — so an abrupt SHUTDOWN that did
        // not flush it would visibly drop the tail. That is exactly what the
        // graceful path must prevent.
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

fn connected(seed: u64) -> Pair {
    let now = t0();
    let mut pair = Pair::new(
        now,
        caller(now),
        listener(now),
        LinkConfig::PERFECT,
        LinkConfig::PERFECT,
        seed,
    );
    assert!(pair.run_until_connected(200), "handshake must complete");
    pair
}

fn payload(i: u8, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    v[0] = i;
    v
}

#[test]
fn graceful_close_delivers_all_buffered_data_then_closes() {
    let mut pair = connected(7);
    for i in 0..10u8 {
        pair.caller_send(&payload(i, 100));
    }
    // Close immediately after submitting — long before TSBPD would have played
    // the data out on its own.
    pair.caller_close();

    assert!(
        pair.run_until(Pair::accepted_closed, 100_000),
        "the accepted side eventually closes"
    );

    let received = pair.accepted_received();
    assert_eq!(
        received.len(),
        10,
        "every submitted message is delivered before the close (no tail drop)"
    );
    for (i, msg) in received.iter().enumerate() {
        assert_eq!(
            u32::from(msg[0]),
            u32::try_from(i).unwrap(),
            "message {i} delivered in order"
        );
    }

    // The flush ordering matters: all data must be delivered *before* Closed.
    let events = pair.accepted_events();
    let closed_at = events
        .iter()
        .position(|e| matches!(e, Event::Closed))
        .expect("a Closed event");
    let last_data = events
        .iter()
        .rposition(|e| matches!(e, Event::DataReceived(_)))
        .expect("at least one DataReceived");
    assert!(
        last_data < closed_at,
        "buffered data is flushed before Closed"
    );
}

#[test]
fn closing_an_idle_connection_closes_immediately() {
    // With nothing outstanding, close need not linger: the caller emits Closed
    // right away.
    let mut pair = connected(3);
    pair.caller_close();
    assert!(
        pair.caller_closed(),
        "an idle close completes synchronously"
    );
}
