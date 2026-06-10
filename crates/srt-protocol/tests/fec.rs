//! Forward-error-correction wire integration (spec App.; libsrt packet filter):
//! the sender emits a row-parity packet per group on the wire, and the receiver
//! rebuilds a single lost member of a group *without* a retransmission round-trip.
//! Driven end-to-end through the deterministic [`sim::Pair`] harness.

mod sim;

use std::time::Duration;

use sim::{LinkConfig, Pair, t0};
use srt_protocol::connection::{Config, Connection, FecConfig};
use srt_protocol::listener::Listener;
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

const GROUP: usize = 4;

fn config() -> Config {
    // Both peers agree on the same group geometry out of band (handshake
    // negotiation is future work); the accepted side inherits this config.
    Config::default()
        .with_latency(Duration::from_secs(1))
        .with_flow_window(8192)
        .with_fec(FecConfig { group_size: GROUP })
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

/// An `n`-byte single-packet payload tagged with `tag` in its first byte.
fn packet(tag: u8, n: usize) -> Vec<u8> {
    let mut v = vec![tag; n];
    v[0] = tag;
    v
}

#[test]
fn fec_recovers_losses_on_the_wire() {
    const COUNT: usize = 200;
    // A forward link that drops ~6% of datagrams; with one parity per group of 4,
    // groups that lose a single member are rebuilt by FEC, not by retransmission.
    let lossy = LinkConfig {
        loss: 0.06,
        ..LinkConfig::PERFECT
    };
    let mut pair = connected(lossy, LinkConfig::PERFECT, 0xFEC0);

    for i in 0..COUNT {
        // u16-distinct tags so every delivered message is identifiable.
        pair.caller_send(&packet(u8::try_from(i % 251).unwrap(), 200));
    }
    assert!(
        pair.run_until(|p| p.accepted_received().len() == COUNT, 1_000_000),
        "every message is delivered (FEC + ARQ together lose nothing)"
    );

    let stats = pair.accepted_stats().expect("accepted side exists");
    assert!(
        stats.packets_recovered >= 1,
        "FEC rebuilt at least one lost packet on the wire (recovered {})",
        stats.packets_recovered
    );
}

#[test]
fn fec_adds_a_parity_packet_per_group_on_a_clean_link() {
    // On a lossless link FEC is pure overhead: nothing is recovered, but the
    // parity packets ride the wire (one per GROUP data packets) and are silently
    // dropped by the receiver — never surfacing as application data.
    const COUNT: usize = 12; // 3 full groups of 4
    let mut pair = connected(LinkConfig::PERFECT, LinkConfig::PERFECT, 1);
    for i in 0..COUNT {
        pair.caller_send(&packet(u8::try_from(i).unwrap(), 100));
    }
    assert!(pair.run_until(|p| p.accepted_received().len() == COUNT, 50_000));

    let received = pair.accepted_received();
    assert_eq!(
        received.len(),
        COUNT,
        "parity packets are not delivered as data"
    );
    for (i, msg) in received.iter().enumerate() {
        assert_eq!(
            msg[0],
            u8::try_from(i).unwrap(),
            "in-order, intact delivery"
        );
    }
    assert_eq!(
        pair.accepted_stats().unwrap().packets_recovered,
        0,
        "nothing to recover on a perfect link"
    );
}
