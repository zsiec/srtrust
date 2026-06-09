//! Message-mode framing tests (spec §3.2.1): an application message larger than
//! one packet is split into First/Middle/Last fragments on the wire and
//! reassembled into a single message at the receiver — never delivered as
//! fragments, and never as one over-MTU datagram. Driven through [`sim::Pair`].

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

fn config() -> Config {
    Config {
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

fn connected(c2l: LinkConfig, l2c: LinkConfig, seed: u64) -> Pair {
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
        0xC0FF_EE12,
        now,
    );
    let mut pair = Pair::new(now, caller, listener, c2l, l2c, seed);
    assert!(pair.run_until_connected(200), "handshake completes");
    pair
}

/// A `len`-byte payload with a recognisable, position-dependent pattern.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

#[test]
fn a_large_message_is_fragmented_and_reassembled() {
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 1);
    // 4000 bytes > one 1500-MTU packet → 3 fragments (First, Middle, Last).
    let message = pattern(4000);
    pair.caller_send(&message);
    assert!(pair.run_until(|p| !p.accepted_received().is_empty(), 20_000));

    let received = pair.accepted_received();
    assert_eq!(received.len(), 1, "delivered as ONE reassembled message");
    assert_eq!(
        &received[0][..],
        &message[..],
        "the message is intact and in order"
    );

    // It really was fragmented: no datagram exceeded the MTU.
    assert!(
        pair.caller_max_datagram() <= 1500,
        "fragments respect the MTU, max datagram was {}",
        pair.caller_max_datagram()
    );
}

#[test]
fn small_messages_stay_single_packets() {
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 2);
    for i in 0..4u8 {
        pair.caller_send(&[i; 100]); // each fits one packet
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == 4, 20_000));
    let received = pair.accepted_received();
    // Four messages in, four messages out — small messages are not coalesced.
    assert_eq!(received.len(), 4);
    for (i, msg) in received.iter().enumerate() {
        assert_eq!(msg.len(), 100);
        assert!(msg.iter().all(|&b| usize::from(b) == i));
    }
}

#[test]
fn fragments_reassemble_across_loss_recovery() {
    // A lossy link: lost fragments are retransmitted, and the receiver still
    // reassembles each multi-packet message exactly (the contiguity check tolerates
    // the eventual in-order delivery that retransmission restores).
    let lossy = LinkConfig {
        loss: 0.2,
        ..LinkConfig::PERFECT
    };
    let mut pair = connected(lossy, lossy, 7);
    let messages: Vec<Vec<u8>> = (0..4).map(|i| pattern(3000 + i * 200)).collect();
    for m in &messages {
        pair.caller_send(m);
    }
    assert!(
        pair.run_until(|p| p.accepted_received().len() == 4, 200_000),
        "all messages recovered and reassembled"
    );
    let received = pair.accepted_received();
    for (i, msg) in received.iter().enumerate() {
        assert_eq!(&msg[..], &messages[i][..], "message {i} reassembled intact");
    }
}
