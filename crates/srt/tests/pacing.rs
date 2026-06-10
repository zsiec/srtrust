//! Paced-sender fidelity: a sender configured with `max_bw` must put data on
//! the wire at that rate — submission throttled to the pace by the send
//! window, delivery unstretched, every byte arriving.
//!
//! Born of a benchmark scare (docs/bench.md): a two-process bench measured
//! ~55 % of the configured pace, which this test helped prove was a *harness*
//! artifact (the bench process exited before its graceful close finished, so
//! the receiver's measurement window absorbed a 5 s peer-idle tail). The test
//! stays as the regression pin that pacing really is faithful — its producer
//! runs on a dedicated OS thread so driver/producer scheduling matches a real
//! application rather than masking contention.

#![allow(clippy::cast_precision_loss)] // bench-style rate math on small totals

use std::time::{Duration, Instant};

use bytes::Bytes;
use srt::{Config, SrtListener, connect};

fn paced_config() -> Config {
    Config {
        latency: Duration::from_millis(120),
        mtu: 1500,
        flow_window: 25600,
        stream_id: None,
        encryption: None,
        max_bw: 100_000_000, // 800 Mbps
        km_refresh_rate: 0,
        fec: None,
    }
}

/// Flood-submit against an 800 Mbps pace for 3 s and compare the *wire* window
/// (first byte to last byte at the receiver) with the submission window: the
/// stream must not stretch. Every submitted byte must also arrive.
#[tokio::test]
async fn paced_stream_is_not_stretched_on_the_wire() {
    if cfg!(debug_assertions) {
        // Debug builds cannot reach the pace (the per-packet path is ~10×
        // slower) and legitimately shed under full-suite load — the fidelity
        // contract is meaningful only for optimized builds.
        eprintln!("SKIP: pacing fidelity is asserted in release builds only");
        return;
    }
    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), paced_config()).unwrap();
    let addr = listener.local_addr();

    let stream = connect("127.0.0.1:0".parse().unwrap(), addr, paced_config())
        .await
        .expect("connect");
    let mut server = listener.accept().await.expect("accept");

    let receiver = tokio::spawn(async move {
        let mut first: Option<Instant> = None;
        let mut last = Instant::now();
        let mut bytes = 0u64;
        while let Some(data) = server.recv().await {
            let now = Instant::now();
            first.get_or_insert(now);
            last = now;
            bytes += data.len() as u64;
        }
        (first, last, bytes)
    });

    // The producer runs on its OWN OS thread with its own runtime, like a
    // real application feeding a stream — sharing the drivers' workers would
    // soften scheduling contention and weaken the test.
    let producer = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("producer runtime");
        rt.block_on(async move {
            let payload = Bytes::from(vec![0xABu8; 1316]);
            let started = Instant::now();
            let mut submitted = 0u64;
            while started.elapsed() < Duration::from_secs(3) {
                stream.send(payload.clone()).await.expect("send");
                submitted += payload.len() as u64;
            }
            (submitted, started.elapsed())
            // `stream` drops here: graceful close; the driver drains the queue.
        })
    });
    let (submitted, submission_window) =
        tokio::task::spawn_blocking(move || producer.join().expect("producer thread"))
            .await
            .expect("join");

    let (first, last, bytes) = receiver.await.expect("receiver");
    let wire_window = last - first.expect("data arrived");

    assert_eq!(bytes, submitted, "every submitted byte arrives");
    let stretch = wire_window.as_secs_f64() / submission_window.as_secs_f64();
    eprintln!(
        "PROBE submitted={} window={:?} wire={:?} stretch={:.2} rate={:.0}Mbps",
        submitted,
        submission_window,
        wire_window,
        stretch,
        submitted as f64 * 8.0 / 1e6 / submission_window.as_secs_f64()
    );
    assert!(
        stretch < 1.30,
        "the wire must carry the stream at the configured pace: \
         {submitted} bytes submitted in {submission_window:?}, \
         delivered over {wire_window:?} (stretch {stretch:.2}x)"
    );
    // And the pace must actually be respected (not just unpaced flooding):
    // 3 s at 800 Mbps ≈ 300 MB; an unpaced flood would push far more.
    let rate_mbps = bytes as f64 * 8.0 / 1e6 / submission_window.as_secs_f64();
    assert!(
        (500.0..1000.0).contains(&rate_mbps),
        "submission throttled near the configured 800 Mbps pace, got {rate_mbps:.0}"
    );
}
