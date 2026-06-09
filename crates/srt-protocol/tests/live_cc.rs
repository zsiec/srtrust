//! `LiveCC` pacing tests (spec §5.1): the sender spaces packets by the send period
//! derived from the configured maximum bandwidth, driven through [`sim::Pair`].

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

/// Target send period: 10 ms.
const PERIOD_US: u64 = 10_000;
/// SRT packet size for a full payload: 1456 payload + 16 header.
const PKT_SIZE: u64 = 1472;
/// Maximum bandwidth chosen so a full packet takes exactly `PERIOD_US`.
const MAX_BW: u64 = PKT_SIZE * 1_000_000 / PERIOD_US; // 147_200 bytes/s

fn config(max_bw: u64) -> Config {
    Config {
        latency: Duration::from_millis(300),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: None,
        max_bw,
        km_refresh_rate: 0,
        fec: None,
    }
}

fn connected(max_bw: u64) -> Pair {
    let now = t0();
    let caller = Connection::connect(
        config(max_bw),
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        |_| {},
    );
    let listener = Listener::new(
        config(max_bw),
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
        1,
    );
    assert!(pair.run_until_connected(200), "handshake must complete");
    pair
}

#[test]
fn pacing_spaces_packets_by_the_send_period() {
    let mut pair = connected(MAX_BW);
    // Submit eight full-size packets in one burst; `LiveCC` must pace them out at
    // one send period apart (so delivery is likewise spaced).
    for _ in 0..8 {
        pair.caller_send(&[0xAB; 1456]);
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == 8, 200_000));

    let times = pair.accepted_data_times();
    assert_eq!(times.len(), 8);
    for window in times.windows(2) {
        assert_eq!(
            window[1] - window[0],
            PERIOD_US,
            "consecutive packets are delivered exactly one send period apart"
        );
    }
}

#[test]
fn unlimited_bandwidth_does_not_pace() {
    let mut pair = connected(0); // max_bw = 0 disables pacing
    for _ in 0..8 {
        pair.caller_send(&[0xCD; 1456]);
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == 8, 200_000));

    let times = pair.accepted_data_times();
    assert_eq!(times.len(), 8);
    // All eight leave at once, so they share a play time and arrive together.
    assert!(
        times.windows(2).all(|w| w[1] == w[0]),
        "without pacing the burst is delivered together, got {times:?}"
    );
}
