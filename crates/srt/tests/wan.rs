//! WAN-profile tests: the full real-socket stack (tokio drivers, timer
//! wheels, UDP) under conditions loopback never shows — 80 ms of round-trip
//! time, random loss in both directions, and jitter large enough to reorder.
//! The deterministic simulator already proves the *protocol* under these
//! conditions; these tests prove the *I/O layer*: real timers driving
//! retransmission across a real RTT, and the RTT estimator converging on the
//! actual path delay.
//!
//! The rust↔rust test always runs; the libsrt one is gated like the rest of
//! the interop suite.

mod interop_util;

use std::time::Duration;

use bytes::Bytes;
use interop_util::*;
use srt::{CipherMode, SrtListener, connect};

/// srtrust → srtrust over an 80 ms RTT path with 2% loss each way and enough
/// jitter to reorder, encrypted: everything arrives, in order; the
/// retransmission machinery demonstrably ran; and the RTT estimate reflects
/// the real path, not a loopback fantasy.
#[tokio::test]
async fn wan_profile_delivers_everything_in_order() {
    let (front, backend) = (19500, 19501);
    let total: u32 = 300;

    let config = encrypted(CipherMode::Ctr, 0).with_latency(Duration::from_millis(600));
    let mut listener = SrtListener::bind(
        format!("127.0.0.1:{backend}").parse().unwrap(),
        config.clone(),
    )
    .unwrap();

    // 5% loss on the data-heavy direction: ~15 of the 300 data packets drop
    // (P(none) ≈ 2e-7), so the retransmission assertion below cannot flake.
    let cfg = ProxyCfg {
        c2l_loss: 0.05,
        l2c_loss: 0.02,
        seed: 42,
        delay: Duration::from_millis(40), // 80 ms RTT
        jitter: Duration::from_millis(8), // > the 5 ms send pace: reorders
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    let (stream, server) = tokio::join!(
        connect(format!("127.0.0.1:{front}"), config),
        listener.accept(),
    );
    let (stream, mut server) = (
        stream.expect("connect across 80 ms RTT"),
        server.expect("accept"),
    );

    let sender = tokio::spawn(async move {
        for i in 0..total {
            stream.send(Bytes::from(msg(i, 188))).await.expect("send");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        stream // keep the connection open while ARQ finishes the tail
    });

    let received = recv_indices(&mut server, total, Duration::from_secs(10)).await;
    let stream = sender.await.expect("sender task");

    assert_all_in_order(&received, total, "WAN profile rust→rust");
    assert!(
        WireCounts::get(&counts.dropped) >= 1,
        "the loss impairment actually dropped something"
    );

    let stats = stream.stats().await.expect("stats");
    assert!(
        stats.packets_retransmitted >= 1,
        "loss recovery ran (retransmitted={})",
        stats.packets_retransmitted
    );
    // The smoothed RTT must reflect the real ~80 ms path (loopback would read
    // well under a millisecond) without drifting wildly above it.
    assert!(
        (60_000..400_000).contains(&stats.rtt_us),
        "the RTT estimate tracks the real path: {} µs",
        stats.rtt_us
    );
    drop(stream);
}

/// libsrt → srtrust across the same WAN profile (gated on the libsrt tools):
/// the reference implementation's timing interacts with ours across a real
/// RTT, with loss in both directions.
#[tokio::test]
async fn wan_profile_libsrt_to_srtrust() {
    let slt = require_libsrt!();
    let (front, backend, in_port) = (19510, 19511, 19512);
    let total: u32 = 100;

    let config = base_config().with_latency(Duration::from_millis(600));
    let mut listener =
        SrtListener::bind(format!("127.0.0.1:{backend}").parse().unwrap(), config).unwrap();

    let cfg = ProxyCfg {
        c2l_loss: 0.02,
        l2c_loss: 0.02,
        seed: 7,
        delay: Duration::from_millis(40),
        jitter: Duration::from_millis(8),
        ..ProxyCfg::default()
    };
    let _counts = spawn_proxy(front, backend, cfg).await;

    let mut child = spawn_slt(
        &slt,
        &format!("udp://127.0.0.1:{in_port}"),
        &format!("srt://127.0.0.1:{front}?latency=600"),
    );
    let mut server = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("libsrt connects across the WAN profile")
        .expect("accept");
    // Our accept resolves when the conclusion is answered; the libsrt caller
    // only learns that ~RTT/2 later. Let it finish before feeding its UDP
    // input, or it drops the first messages as "not connected yet".
    tokio::time::sleep(Duration::from_millis(500)).await;
    let feeder = tokio::spawn(feed_libsrt_input(
        in_port,
        total,
        Duration::from_millis(10),
        188,
    ));
    let received = recv_indices(&mut server, total, Duration::from_secs(10)).await;
    let _ = feeder.await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, total, "WAN profile libsrt→srtrust");
}
