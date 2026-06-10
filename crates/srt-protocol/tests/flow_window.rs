//! Flow-window / backpressure tests (spec §4.8, BUG-04 in docs/known-issues/04):
//! the sender's backpressure signal must bound *sent-but-unacknowledged* data in
//! every configuration — including the default unpaced one (`max_bw = 0`), where
//! sends bypass the pacer queue and go straight into the retransmission buffer.

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config(flow_window: u32, latency_ms: u64) -> Config {
    // max_bw stays at the default 0: the unpaced path.
    Config::default()
        .with_latency(Duration::from_millis(latency_ms))
        .with_flow_window(flow_window)
}

fn connected(flow_window: u32, latency_ms: u64) -> Pair {
    let now = t0();
    let cfg = config(flow_window, latency_ms);
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
        1,
    );
    assert!(pair.run_until_connected(200), "handshake must complete");
    pair
}

/// The backpressure signal must close once `flow_window` packets are in flight
/// (sent, unacknowledged) on the **unpaced** default path — not just when the
/// pacer queue fills (spec §4.8: the sender respects the flow window). It
/// reopens once the peer has both acknowledged the packets *and* freed its
/// receive buffer (TSBPD-held data still occupies the peer's window).
#[test]
fn unpaced_sends_close_the_window_until_acknowledged() {
    let mut pair = connected(4, 50);

    assert!(
        pair.caller_send_window_available(),
        "window open before any sends"
    );
    // Four un-ACKed sends at the same instant fill the window of 4.
    for i in 0..4u8 {
        pair.caller_send(&[i; 100]);
    }
    assert!(
        !pair.caller_send_window_available(),
        "window must close with flow_window packets sent and unacknowledged"
    );

    // ACKs arrive (~10 ms cadence + RTT) and, once the 50 ms play time passes,
    // the peer's buffer drains and its advertised window recovers.
    pair.run_for(200_000);
    assert!(
        pair.caller_send_window_available(),
        "the window reopens once the peer acknowledges and frees its buffer"
    );
}

/// Send-side TLPKTDROP must be *visible*: every packet `drop_too_late` sheds is
/// counted (libsrt's `sndDropTotal`). A sender silently discarding data while
/// reporting clean stats hides the loss from the application.
#[test]
fn send_side_drops_are_counted_in_stats() {
    // Feedback fully dead: nothing is ever acknowledged, so once packets age
    // past the latency budget the sender sheds them (TLPKTDROP + DROPREQ).
    let mut pair = connected(8192, 50);
    let dead_feedback = LinkConfig {
        loss: 1.0,
        ..LinkConfig::PERFECT
    };
    pair.degrade_links(LinkConfig::PERFECT, dead_feedback, 9);

    for i in 0..10u8 {
        pair.caller_send(&[i; 100]);
    }
    // Run past the 50 ms latency budget and the 300 ms EXP firing that triggers
    // the shedding.
    pair.run_for(1_000_000);

    let stats = pair.caller_stats();
    assert!(
        stats.packets_dropped_sent >= 10,
        "every shed packet is counted (sent 10, counted {})",
        stats.packets_dropped_sent
    );
}
