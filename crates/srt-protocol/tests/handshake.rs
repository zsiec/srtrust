//! End-to-end caller↔listener handshake tests (spec §4.3.1), driven through the
//! deterministic [`sim::Pair`] harness — no sockets, no sleeps, no flake.

mod sim;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::BytesMut;
use sim::LinkConfig;
use sim::{Pair, t0};
use srt_protocol::connection::{Config, Connection, Event, Output};
use srt_protocol::control::ControlBody;
use srt_protocol::handshake::{
    EncryptionField, Handshake, HandshakeExtension, HandshakeType, SrtFlags, SrtHandshake,
};
use srt_protocol::listener::Listener;
use srt_protocol::packet::{ControlPacket, Packet, SocketId};
use srt_protocol::seq::SeqNumber;
use srt_protocol::timestamp::Timestamp;

const CALLER_ID: u32 = 0x1111_1111;
const LISTENER_ID: u32 = 0x2222_2222;
const CALLER_ISN: u32 = 1000;
const LISTENER_ISN: u32 = 9000;
const COOKIE_SECRET: u64 = 0xC0FF_EE00_1234_5678;
const LATENCY_MS: u64 = 120;

fn live_config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(LATENCY_MS))
        .with_flow_window(8192)
}

fn caller(now: std::time::Instant) -> Connection {
    Connection::connect(
        live_config(),
        SocketId::new(CALLER_ID),
        SeqNumber::new(CALLER_ISN),
        now,
        |_| {},
    )
}

fn listener(now: std::time::Instant) -> Listener {
    Listener::new(
        live_config(),
        SocketId::new(LISTENER_ID),
        SeqNumber::new(LISTENER_ISN),
        COOKIE_SECRET,
        now,
    )
}

/// Drains a connection's outputs, returning the first sent datagram decoded as a
/// packet plus whether a `Handshake` retransmit timer was armed.
fn first_sent_packet(conn: &mut Connection) -> (Packet, bool) {
    let mut packet = None;
    let mut armed_timer = false;
    while let Some(output) = conn.poll_output() {
        match output {
            Output::SendDatagram(bytes) if packet.is_none() => {
                packet = Some(Packet::decode(&bytes).expect("a valid packet"));
            }
            Output::SetTimer { .. } => armed_timer = true,
            _ => {}
        }
    }
    (packet.expect("the connection sent a datagram"), armed_timer)
}

fn as_handshake(packet: &Packet) -> &srt_protocol::handshake::Handshake {
    match packet {
        Packet::Control(c) => match &c.body {
            ControlBody::Handshake(hs) => hs,
            other => panic!("expected a handshake body, got {other:?}"),
        },
        Packet::Data(_) => panic!("expected a control packet, got data"),
    }
}

#[test]
fn caller_connect_emits_induction_and_arms_timer() {
    let now = t0();
    let mut caller = caller(now);
    let (packet, armed) = first_sent_packet(&mut caller);

    // The induction packet is addressed to socket id 0 (a connection request).
    let dest = match &packet {
        Packet::Control(c) => c.dest_socket_id,
        Packet::Data(_) => unreachable!(),
    };
    assert_eq!(dest, SocketId::new(0));

    let hs = as_handshake(&packet);
    assert_eq!(
        hs.version, 4,
        "induction advertises UDT version 4 (§4.3.1.1)"
    );
    assert_eq!(
        hs.extension_field, 2,
        "caller induction extension field is 2"
    );
    assert_eq!(hs.handshake_type, HandshakeType::INDUCTION);
    assert_eq!(hs.syn_cookie, 0, "caller induction carries no cookie yet");
    assert_eq!(hs.srt_socket_id, SocketId::new(CALLER_ID));
    assert!(armed, "the handshake retransmit timer must be armed");
}

#[test]
fn handshake_completes_over_a_perfect_link() {
    let now = t0();
    let mut pair = Pair::new(
        now,
        caller(now),
        listener(now),
        LinkConfig::PERFECT,
        LinkConfig::PERFECT,
        1,
    );
    assert!(
        pair.run_until_connected(100),
        "both sides must reach Connected over a lossless link"
    );

    // The caller learned the listener's identity and the negotiated latency.
    let connected = pair
        .caller_events()
        .iter()
        .find_map(|e| match e {
            Event::Connected(n) => Some(n),
            _ => None,
        })
        .expect("caller Connected");
    assert_eq!(connected.peer_socket_id, SocketId::new(LISTENER_ID));
    // HSv5 is a single-ISN model: the acceptor ADOPTS the caller's ISN for its
    // own sending and echoes it in the conclusion response (libsrt
    // `acceptAndRespond`: "use peer's ISN and send it back for security
    // check"). A blocking-connect libsrt caller REJECTS a response whose ISN
    // is not its own (`startConnect`: `m_ConnRes.m_iISN != m_iISN` →
    // MN_SECURITY) — found live via srt-cbench; `srt-live-transmit` masked it
    // by connecting non-blockingly.
    assert_eq!(connected.peer_initial_seq, SeqNumber::new(CALLER_ISN));
    assert_eq!(connected.latency, Duration::from_millis(LATENCY_MS));

    // The accepted side learned the caller's identity.
    let accepted = pair
        .accepted_events()
        .iter()
        .find_map(|e| match e {
            Event::Connected(n) => Some(n),
            _ => None,
        })
        .expect("accepted Connected");
    assert_eq!(accepted.peer_socket_id, SocketId::new(CALLER_ID));
    assert_eq!(accepted.peer_initial_seq, SeqNumber::new(CALLER_ISN));
}

#[test]
fn caller_addresses_the_conclusion_to_socket_id_zero() {
    // libsrt routes only a zero-destination handshake to the listener, so the
    // caller's conclusion must keep destination id 0 (interop regression guard;
    // see Connection::send_conclusion). The literal spec says use the induction
    // socket id, but that does not interoperate with libsrt.
    let now = t0();
    let mut caller = caller(now);
    while caller.poll_output().is_some() {} // drain the induction

    // Feed a listener-style induction response (version 5, SRT magic, a non-zero
    // listener socket id) and capture the conclusion the caller emits.
    let response = Handshake {
        version: 5,
        encryption: EncryptionField::None,
        extension_field: 0x4A17,
        initial_seq: SeqNumber::new(7000),
        mtu: 1500,
        max_flow_window: 8192,
        handshake_type: HandshakeType::INDUCTION,
        srt_socket_id: SocketId::new(LISTENER_ID),
        syn_cookie: 0xDEAD_BEEF,
        peer_ip: [0; 16],
        extensions: Vec::new(),
    };
    caller.feed_recv_buf(&encode_handshake(response, SocketId::new(CALLER_ID)), now);

    let (packet, _) = first_sent_packet(&mut caller);
    let dest = match &packet {
        Packet::Control(c) => c.dest_socket_id,
        Packet::Data(_) => panic!("expected a control packet"),
    };
    assert_eq!(
        as_handshake(&packet).handshake_type,
        HandshakeType::CONCLUSION
    );
    assert_eq!(
        dest,
        SocketId::new(0),
        "the conclusion must be addressed to socket id 0, not the listener's id"
    );
}

#[test]
fn handshake_recovers_from_a_lossy_link() {
    let now = t0();
    // 40% loss each way; the handshake retransmit timer must drive it to
    // completion. Seed is fixed, so this is deterministic, not flaky.
    let lossy = LinkConfig {
        loss: 0.4,
        ..LinkConfig::PERFECT
    };
    let mut pair = Pair::new(now, caller(now), listener(now), lossy, lossy, 0xBEEF);
    assert!(
        pair.run_until_connected(10_000),
        "retransmission must complete the handshake despite loss"
    );
}

/// Encodes a handshake control packet into a datagram addressed to `dest`.
fn encode_handshake(hs: Handshake, dest: SocketId) -> Vec<u8> {
    let mut buf = BytesMut::new();
    Packet::Control(ControlPacket {
        timestamp: Timestamp::from_micros(0),
        dest_socket_id: dest,
        body: ControlBody::Handshake(hs),
    })
    .encode(&mut buf);
    buf.to_vec()
}

#[test]
fn listener_rejects_a_forged_syn_cookie() {
    let now = t0();
    let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
    let mut listener = listener(now);

    // Induce to obtain a genuine cookie.
    let induction = Handshake {
        version: 4,
        encryption: EncryptionField::None,
        extension_field: 2,
        initial_seq: SeqNumber::new(CALLER_ISN),
        mtu: 1500,
        max_flow_window: 8192,
        handshake_type: HandshakeType::INDUCTION,
        srt_socket_id: SocketId::new(CALLER_ID),
        syn_cookie: 0,
        peer_ip: [0; 16],
        extensions: Vec::new(),
    };
    listener.feed_recv_buf(&encode_handshake(induction, SocketId::new(0)), from, now);
    let (_addr, response) = listener.poll_response().expect("induction response");
    let cookie = as_handshake(&Packet::decode(&response).unwrap()).syn_cookie;
    assert_ne!(cookie, 0, "the listener must mint a non-zero cookie");

    let conclusion = |cookie: u32| Handshake {
        version: 5,
        encryption: EncryptionField::None,
        extension_field: 1,
        initial_seq: SeqNumber::new(CALLER_ISN),
        mtu: 1500,
        max_flow_window: 8192,
        handshake_type: HandshakeType::CONCLUSION,
        srt_socket_id: SocketId::new(CALLER_ID),
        syn_cookie: cookie,
        peer_ip: [0; 16],
        extensions: vec![HandshakeExtension::HsReq(SrtHandshake {
            srt_version: 0x0001_0501,
            flags: SrtFlags::from_bits(0),
            recv_tsbpd_delay: 120,
            send_tsbpd_delay: 120,
        })],
    };

    // A forged cookie must allocate nothing (the anti-DoS guarantee, §4.3.1.1).
    let forged = encode_handshake(conclusion(cookie ^ 0xDEAD_BEEF), SocketId::new(LISTENER_ID));
    listener.feed_recv_buf(&forged, from, now);
    assert!(
        listener.poll_accept().is_none(),
        "a forged cookie must not produce an accepted connection"
    );

    // The genuine cookie is accepted.
    let valid = encode_handshake(conclusion(cookie), SocketId::new(LISTENER_ID));
    listener.feed_recv_buf(&valid, from, now);
    assert!(
        listener.poll_accept().is_some(),
        "the genuine cookie must be accepted"
    );
}

#[test]
fn caller_times_out_when_listener_is_unreachable() {
    let now = t0();
    // Every caller→listener datagram is dropped: the listener never hears the
    // caller, so the caller must give up after the connect timeout.
    let black_hole = LinkConfig {
        loss: 1.0,
        ..LinkConfig::PERFECT
    };
    let mut pair = Pair::new(
        now,
        caller(now),
        listener(now),
        black_hole,
        LinkConfig::PERFECT,
        7,
    );
    pair.run(10_000);
    assert!(
        pair.caller_events()
            .iter()
            .any(|e| matches!(e, Event::Failed(_))),
        "the caller must emit Failed after the handshake times out"
    );
    assert!(!pair.caller_connected());
}
