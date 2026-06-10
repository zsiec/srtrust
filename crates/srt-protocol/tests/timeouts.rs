//! Configurable timeouts: `connect_timeout`, `peer_idle_timeout`, and `linger`
//! are [`Config`] fields (cf. libsrt's `SRTO_CONNTIMEO`, `SRTO_PEERIDLETIMEO`,
//! `SRTO_LINGER`), not hardcoded constants — a relay that must fail over fast
//! cannot wait 3 s to learn a connect attempt is dead.

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

fn pair_with(caller_cfg: Config, listener_cfg: Config, c2l: LinkConfig, l2c: LinkConfig) -> Pair {
    let now = t0();
    let caller = Connection::connect(
        caller_cfg,
        SocketId::new(0x11),
        SeqNumber::new(1000),
        now,
        |_| {},
    );
    let listener = Listener::new(
        listener_cfg,
        SocketId::new(0x22),
        SeqNumber::new(9000),
        0xCAFE,
        now,
    );
    Pair::new(now, caller, listener, c2l, l2c, 1)
}

const DEAD: LinkConfig = LinkConfig {
    loss: 1.0,
    ..LinkConfig::PERFECT
};

#[test]
fn connect_timeout_is_configurable() {
    // The listener never hears the caller; with a 500 ms connect timeout the
    // caller gives up well before the 3 s default would.
    let cfg = config().with_connect_timeout(Duration::from_millis(500));
    let mut pair = pair_with(cfg, config(), DEAD, LinkConfig::PERFECT);
    pair.run_for(700_000); // 0.7 s of fake time
    assert!(
        pair.caller_events()
            .iter()
            .any(|e| matches!(e, Event::Failed(ConnectionError::HandshakeTimeout))),
        "a 500 ms connect timeout fails the handshake within 0.7 s"
    );
}

#[test]
fn default_connect_timeout_still_retries_at_700ms() {
    // The complement: at the 3 s default, 0.7 s of silence is not yet fatal.
    let mut pair = pair_with(config(), config(), DEAD, LinkConfig::PERFECT);
    pair.run_for(700_000);
    assert!(
        !pair
            .caller_events()
            .iter()
            .any(|e| matches!(e, Event::Failed(_))),
        "the 3 s default keeps retrying at 0.7 s"
    );
}

#[test]
fn peer_idle_timeout_is_configurable() {
    // Connect normally, then cut the acceptor→caller link: with a 2 s peer-idle
    // timeout the caller declares the peer dead before the 5 s default would.
    let cfg = config().with_peer_idle_timeout(Duration::from_secs(2));
    let mut pair = pair_with(cfg, config(), LinkConfig::PERFECT, LinkConfig::PERFECT);
    assert!(pair.run_until_connected(200), "handshake completes");

    pair.degrade_links(LinkConfig::PERFECT, DEAD, 1);
    pair.run_for(2_500_000); // 2.5 s of silence

    assert!(
        pair.caller_events()
            .iter()
            .any(|e| matches!(e, Event::Failed(ConnectionError::Timeout))),
        "a 2 s peer-idle timeout fires within 2.5 s of silence"
    );
}

#[test]
fn linger_is_configurable() {
    // Close with unacknowledged data while the peer link is dead: nothing can
    // be flushed, so the close completes when linger expires. With a 1 s linger
    // the caller reports Closed well before the 3 s default would.
    let cfg = config().with_linger(Duration::from_secs(1));
    let mut pair = pair_with(cfg, config(), LinkConfig::PERFECT, LinkConfig::PERFECT);
    assert!(pair.run_until_connected(200), "handshake completes");

    pair.degrade_links(DEAD, DEAD, 1);
    pair.caller_send(&[0u8; 200]); // now unacknowledgeable
    pair.caller_close();
    pair.run_for(1_500_000); // 1.5 s

    assert!(
        pair.caller_closed(),
        "a 1 s linger completes the close within 1.5 s"
    );
}
