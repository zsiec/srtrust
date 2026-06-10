//! Receive-side flow control against a window-ignoring peer: the receiver
//! advertises its free buffer in every ACK (spec §3.2.4), and a compliant
//! sender stops at zero — but a flooding or buggy peer keeps sending. The
//! receiver must then enforce its own window locally, dropping the excess
//! instead of buffering without bound: a stalled application costs a bounded
//! amount of memory, never an OOM.

use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use srt_protocol::connection::{Config, Connection, Event};
use srt_protocol::listener::Listener;
use srt_protocol::packet::{DataPacket, Encryption, MsgNumber, Packet, PacketPosition, SocketId};
use srt_protocol::seq::SeqNumber;
use srt_protocol::timestamp::Timestamp;

const FLOW_WINDOW: u32 = 64;
const CALLER_ISN: u32 = 1000;

fn config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(120))
        .with_flow_window(FLOW_WINDOW)
}

/// Performs the caller↔listener handshake by hand and returns the accepted
/// (listener-side) connection — so the test owns event draining completely.
fn accepted_connection(now: Instant) -> Connection {
    let mut caller = Connection::connect(
        config(),
        SocketId::new(0x11),
        SeqNumber::new(CALLER_ISN),
        now,
        |_| {},
    );
    let mut listener = Listener::new(
        config(),
        SocketId::new(0x22),
        SeqNumber::new(9000),
        0xCAFE,
        now,
    );
    let from = "127.0.0.1:5000".parse().expect("addr");

    // induction → response → conclusion → accept
    let induction = next_datagram(&mut caller).expect("caller sends induction");
    listener.feed_recv_buf(&induction, from, now);
    let (_, response) = listener.poll_response().expect("induction response");
    caller.feed_recv_buf(&response, now);
    let conclusion = next_datagram(&mut caller).expect("caller sends conclusion");
    listener.feed_recv_buf(&conclusion, from, now);
    listener.poll_accept().expect("conclusion accepted")
}

/// Drains the connection's outputs, returning the first datagram found.
fn next_datagram(conn: &mut Connection) -> Option<Bytes> {
    use srt_protocol::connection::Output;
    let mut found = None;
    while let Some(output) = conn.poll_output() {
        if let Output::SendDatagram(bytes) = output
            && found.is_none()
        {
            found = Some(bytes);
        }
    }
    found
}

/// One flood packet from the (window-ignoring) caller.
fn flood_packet(index: u32) -> Bytes {
    let packet = Packet::Data(DataPacket {
        seq: SeqNumber::new(CALLER_ISN + index),
        position: PacketPosition::Single,
        in_order: true,
        encryption: Encryption::None,
        retransmitted: false,
        message_number: MsgNumber::new(1 + index),
        timestamp: Timestamp::from_micros(index * 100),
        dest_socket_id: SocketId::new(0x22),
        payload: Bytes::from(vec![0xAB; 1000]),
    });
    let mut out = BytesMut::new();
    packet.encode(&mut out);
    out.freeze()
}

#[test]
fn a_flood_against_a_stalled_app_is_bounded_by_the_flow_window() {
    let t0 = Instant::now();
    let mut conn = accepted_connection(t0);

    // The application never drains events; the peer ignores the advertised
    // window and floods 50× more than the window holds. Time advances so
    // TSBPD keeps moving packets from the buffer into the (undrained) event
    // queue — both count against the window.
    let flood: u32 = FLOW_WINDOW * 50;
    for i in 0..flood {
        let now = t0 + Duration::from_micros(u64::from(i) * 100);
        conn.feed_recv_buf(&flood_packet(i), now);
        // The I/O layer still ships outgoing ACKs/NAKs; it just never reads
        // data. Draining outputs must not unbound the receive side.
        while conn.poll_output().is_some() {}
    }

    let stats = conn.stats();
    assert!(
        stats.packets_received <= u64::from(FLOW_WINDOW),
        "held data is bounded by the flow window: accepted {} of {flood} (window {FLOW_WINDOW})",
        stats.packets_received,
    );
    assert!(
        stats.packets_dropped_full >= u64::from(flood - FLOW_WINDOW * 2),
        "the excess is dropped, not buffered: dropped_full={}",
        stats.packets_dropped_full,
    );
}

#[test]
fn a_compliant_burst_within_the_window_is_untouched() {
    // The cap must not bite normal traffic: a burst smaller than the window
    // is fully accepted even before the app drains anything.
    let t0 = Instant::now();
    let mut conn = accepted_connection(t0);

    let burst = FLOW_WINDOW / 2;
    for i in 0..burst {
        let now = t0 + Duration::from_micros(u64::from(i) * 100);
        conn.feed_recv_buf(&flood_packet(i), now);
        while conn.poll_output().is_some() {}
    }
    let stats = conn.stats();
    assert_eq!(stats.packets_received, u64::from(burst), "all accepted");
    assert_eq!(stats.packets_dropped_full, 0, "nothing dropped");

    // And once the app drains, delivery is intact and in order.
    let now = t0 + Duration::from_secs(2);
    conn.handle_timer(srt_protocol::connection::TimerId::Tsbpd, now);
    let mut delivered = 0;
    while let Some(event) = conn.poll_event() {
        if matches!(event, Event::DataReceived(_)) {
            delivered += 1;
        }
    }
    assert_eq!(delivered, burst, "every buffered packet plays out");
}
