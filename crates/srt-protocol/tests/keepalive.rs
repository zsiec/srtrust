//! Keepalive tests (spec §3.2.6): an established connection that goes idle must
//! still send periodic KEEPALIVE control packets, so a peer enforcing an idle
//! timeout (libsrt's `PeerIdleTimeout`) does not tear the connection down.

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection, Event};
use srt_protocol::error::ConnectionError;
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(120))
        .with_flow_window(8192)
}

fn connected() -> Pair {
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
        0xCAFE,
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
    assert!(pair.run_until_connected(200), "handshake completes");
    pair
}

#[test]
fn an_idle_connection_emits_periodic_keepalives() {
    let mut pair = connected();
    assert_eq!(pair.caller_keepalives(), 0, "none yet right after connect");

    // No data flows for several seconds; both ends are idle.
    pair.run_for(3_500_000); // 3.5 s of fake time

    // libsrt's keepalive period is 1 s, so ~3 should have gone out each way.
    assert!(
        pair.caller_keepalives() >= 2,
        "the idle caller keeps the connection alive, got {}",
        pair.caller_keepalives()
    );
    assert!(
        pair.accepted_keepalives() >= 2,
        "the idle acceptor keeps the connection alive, got {}",
        pair.accepted_keepalives()
    );
}

#[test]
fn a_dead_peer_times_the_connection_out() {
    let mut pair = connected();
    // Cut the acceptor→caller link entirely: the caller now hears nothing (its own
    // keepalives still reach the acceptor over the other link).
    let dead = LinkConfig {
        loss: 1.0,
        ..LinkConfig::PERFECT
    };
    pair.degrade_links(LinkConfig::PERFECT, dead, 1);

    // Past the 5 s idle timeout, the caller declares the peer gone.
    pair.run_for(6_000_000);

    assert!(
        pair.caller_events()
            .iter()
            .any(|e| matches!(e, Event::Failed(ConnectionError::Timeout))),
        "the caller times out a silent peer"
    );
    // The acceptor still receives the caller's keepalives, so it stays up.
    assert!(
        !pair
            .accepted_events()
            .iter()
            .any(|e| matches!(e, Event::Failed(_))),
        "the acceptor, still hearing keepalives, does not time out"
    );
}

#[test]
fn keepalives_keep_an_idle_connection_alive() {
    // The complement of the timeout test: with both links healthy, the periodic
    // keepalives reset each side's idle timer, so a long idle does NOT time out.
    let mut pair = connected();
    pair.run_for(8_000_000); // 8 s idle, well past the 5 s timeout
    assert!(
        !pair
            .caller_events()
            .iter()
            .any(|e| matches!(e, Event::Failed(_))),
        "keepalives hold the connection open through a long idle"
    );
}

#[test]
fn sending_data_suppresses_keepalives() {
    let mut pair = connected();
    // Keep data flowing every 200 ms for ~2 s; the sender never goes idle long
    // enough to need a keepalive.
    for _ in 0..10 {
        pair.caller_send(&[0u8; 200]);
        pair.run_for(200_000);
    }
    assert_eq!(
        pair.caller_keepalives(),
        0,
        "an actively-sending caller emits no keepalives"
    );
}
