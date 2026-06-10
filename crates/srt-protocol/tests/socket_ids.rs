//! Per-connection socket ids: the listener mints a unique local socket id for
//! every connection it accepts (cf. libsrt, where each accepted socket gets
//! its own id). The id travels to the caller in the conclusion response's
//! `srt_socket_id` field, so every subsequent packet's destination-socket-id
//! identifies the connection — which is what lets an I/O layer demux by id
//! and survive a peer whose source address changes mid-stream (NAT rebind).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use srt_protocol::connection::{Config, Connection, Output};
use srt_protocol::control::ControlBody;
use srt_protocol::listener::Listener;
use srt_protocol::packet::{Packet, SocketId};
use srt_protocol::seq::SeqNumber;

const LISTENER_ID: u32 = 0x2222_0000;

fn config() -> Config {
    Config::default().with_latency(Duration::from_millis(120))
}

fn next_datagram(conn: &mut Connection) -> Option<Bytes> {
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

/// Walks one caller through the full handshake against `listener`, returning
/// the accepted connection and the `srt_socket_id` its conclusion response
/// advertised to the caller.
fn accept_one(
    listener: &mut Listener,
    caller_id: u32,
    caller_isn: u32,
    from: SocketAddr,
    now: Instant,
) -> (Connection, SocketId) {
    let mut caller = Connection::connect(
        config(),
        SocketId::new(caller_id),
        SeqNumber::new(caller_isn),
        now,
        |_| {},
    );
    let induction = next_datagram(&mut caller).expect("induction");
    listener.feed_recv_buf(&induction, from, now);
    let (_, response) = listener.poll_response().expect("induction response");
    caller.feed_recv_buf(&response, now);
    let conclusion = next_datagram(&mut caller).expect("conclusion");
    listener.feed_recv_buf(&conclusion, from, now);
    let mut accepted = listener.poll_accept().expect("accepted");

    // The conclusion response (HSRSP) the accepted side queued carries the id
    // the caller will address from now on.
    let hsrsp = next_datagram(&mut accepted).expect("conclusion response");
    let Ok(Packet::Control(ctrl)) = Packet::decode(&hsrsp) else {
        panic!("the conclusion response decodes as a control packet");
    };
    let ControlBody::Handshake(hs) = ctrl.body else {
        panic!("the conclusion response is a handshake");
    };
    (accepted, hs.srt_socket_id)
}

#[test]
fn each_accepted_connection_gets_its_own_socket_id() {
    let now = Instant::now();
    let mut listener = Listener::new(
        config(),
        SocketId::new(LISTENER_ID),
        SeqNumber::new(9000),
        0xCAFE,
        now,
    );

    let (conn_a, advertised_a) = accept_one(
        &mut listener,
        0x11,
        1000,
        "127.0.0.1:5000".parse().expect("addr"),
        now,
    );
    let (conn_b, advertised_b) = accept_one(
        &mut listener,
        0x12,
        2000,
        "127.0.0.1:5001".parse().expect("addr"),
        now,
    );

    let id_a = conn_a.local_socket_id();
    let id_b = conn_b.local_socket_id();
    assert_ne!(id_a, id_b, "two connections, two ids");
    assert_ne!(id_a.value(), LISTENER_ID, "distinct from the listener's id");
    assert_ne!(id_b.value(), LISTENER_ID, "distinct from the listener's id");
    assert_ne!(
        id_a.value(),
        0,
        "zero routes to the listener — never minted"
    );
    assert_ne!(
        id_b.value(),
        0,
        "zero routes to the listener — never minted"
    );

    // The caller addresses the id we advertised — they must agree.
    assert_eq!(advertised_a, id_a, "HSRSP advertises connection A's own id");
    assert_eq!(advertised_b, id_b, "HSRSP advertises connection B's own id");
}
