//! Intense interoperability exploration against the reference C implementation
//! (libsrt, preferring the `~/dev/srt` checkout build — v1.5.5 plus its
//! KMREQ/KMRSP/LOSSREPORT/DROPREQ parser-hardening commits).
//!
//! Beyond the smoke tests in `interop.rs`, this suite drives the *protocol
//! dynamics* both ways through a wire-spy UDP proxy that decodes every datagram
//! with srtrust's own codec: it counts control types and key-slot flags, and can
//! drop targeted packets (a specific KMREQ, the Nth data packet), apply seeded
//! random loss, and add link delay. That makes externally-invisible behaviors —
//! "did the key rotation actually complete?", "was the lost KMREQ re-sent?" —
//! assertable against the real libsrt.
//!
//! Every test skips cleanly when no `srt-live-transmit` binary is found.

mod interop_util;

use std::time::{Duration, Instant};

use interop_util::*;
use srt::{CipherMode, Config, SrtListener};
use srt_protocol::control::{ControlBody, ControlType};
use srt_protocol::packet::Packet;
use tokio::net::UdpSocket;

// ---- libsrt caller → srtrust listener (direction missing from interop.rs) ----

async fn libsrt_caller_into_srtrust(
    srt_port: u16,
    in_port: u16,
    cipher: Option<CipherMode>,
    rekey: Option<(u32, u32)>,
    messages: u32,
) {
    let slt = require_libsrt!();
    let config = match cipher {
        None => base_config(),
        Some(c) => encrypted(c, 0),
    };
    let mut listener =
        SrtListener::bind(format!("127.0.0.1:{srt_port}").parse().unwrap(), config).unwrap();

    let gcm = matches!(cipher, Some(CipherMode::Gcm));
    let query = libsrt_query(120, cipher.map(|_| PASSPHRASE), gcm, rekey);
    let mut child = spawn_slt(
        &slt,
        &format!("udp://127.0.0.1:{in_port}"),
        &format!("srt://127.0.0.1:{srt_port}?{query}"),
    );

    let mut server = tokio::time::timeout(Duration::from_secs(8), listener.accept())
        .await
        .expect("libsrt caller connects within 8s")
        .expect("accept");

    let feeder = tokio::spawn(feed_libsrt_input(
        in_port,
        messages,
        Duration::from_millis(5),
        64,
    ));
    let received = recv_indices(&mut server, messages, Duration::from_secs(3)).await;
    let _ = feeder.await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, messages, "libsrt→srtrust");
}

#[tokio::test]
async fn libsrt_caller_to_srtrust_listener_plaintext() {
    libsrt_caller_into_srtrust(19110, 19111, None, None, 50).await;
}

#[tokio::test]
async fn libsrt_caller_to_srtrust_listener_ctr() {
    libsrt_caller_into_srtrust(19120, 19121, Some(CipherMode::Ctr), None, 50).await;
}

#[tokio::test]
async fn libsrt_caller_to_srtrust_listener_gcm() {
    libsrt_caller_into_srtrust(19130, 19131, Some(CipherMode::Gcm), None, 50).await;
}

/// libsrt drives the rotation: its periodic KMREQ must be installed and echoed
/// by srtrust, and srtrust must decrypt across every switch (dual key slots).
#[tokio::test]
async fn libsrt_rekey_into_srtrust_listener() {
    libsrt_caller_into_srtrust(19140, 19141, Some(CipherMode::Ctr), Some((64, 16)), 250).await;
}

// ---- rekey proof + lost KMREQ, srtrust → libsrt through the wire spy ----

/// The smoke test in `interop.rs` cannot tell whether the rotation *happened* —
/// staying on the old key forever also delivers every message. The wire spy
/// proves it: libsrt's KMRSP is observed, and odd-slot data flows afterwards.
#[tokio::test]
async fn srtrust_rekey_completes_against_libsrt() {
    let slt = require_libsrt!();
    let (front, backend, sink_port) = (19150, 19151, 19152);

    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{backend}?mode=listener&{}",
            libsrt_query(120, Some(PASSPHRASE), false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let counts = spawn_proxy(front, backend, ProxyCfg::default()).await;

    let received = srtrust_sender_run(
        encrypted(CipherMode::Ctr, 16),
        front,
        &sink,
        64,
        Duration::from_millis(30),
        64,
        Duration::from_secs(4),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 64, "rekey stream");
    assert!(
        WireCounts::get(&counts.kmreq) >= 1,
        "a rekey KMREQ crossed the wire"
    );
    assert!(
        WireCounts::get(&counts.kmrsp) >= 1,
        "libsrt confirmed the rekey with a KMRSP (kmreq={})",
        WireCounts::get(&counts.kmreq)
    );
    assert!(
        WireCounts::get(&counts.data_odd) >= 1,
        "the switch actually happened: odd-slot data on the wire \
         (even={}, odd={})",
        WireCounts::get(&counts.data_even),
        WireCounts::get(&counts.data_odd)
    );
}

/// BUG-06 against the real reference: drop the first rekey KMREQ on the wire.
/// srtrust must re-announce (keepalive cadence), libsrt must accept the late
/// KMREQ, and the rotation must still complete with zero loss.
#[tokio::test]
async fn srtrust_rekey_survives_a_lost_kmreq_against_libsrt() {
    let slt = require_libsrt!();
    let (front, backend, sink_port) = (19160, 19161, 19162);

    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{backend}?mode=listener&{}",
            libsrt_query(120, Some(PASSPHRASE), false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let mut dropped_one = false;
    let cfg = ProxyCfg {
        c2l_drop: Some(Box::new(move |datagram: &[u8]| {
            if dropped_one {
                return false;
            }
            let is_kmreq = matches!(
                Packet::decode(datagram),
                Ok(Packet::Control(c)) if matches!(
                    c.body,
                    ControlBody::Raw { control_type: ControlType::UserDefined, subtype, .. }
                        if subtype == EXT_KMREQ
                )
            );
            if is_kmreq {
                dropped_one = true;
            }
            is_kmreq
        })),
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    // 100 messages at 30 ms ≈ 3 s: announce ~0.4 s in, retry at the ~1 s
    // keepalive, confirm, then switch — all inside the stream.
    let received = srtrust_sender_run(
        encrypted(CipherMode::Ctr, 16),
        front,
        &sink,
        100,
        Duration::from_millis(30),
        64,
        Duration::from_secs(5),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 100, "lost-KMREQ rekey stream");
    assert!(
        WireCounts::get(&counts.kmreq) >= 2,
        "the dropped KMREQ was re-announced (saw {})",
        WireCounts::get(&counts.kmreq)
    );
    assert!(
        WireCounts::get(&counts.kmrsp) >= 1,
        "libsrt confirmed the re-announced key"
    );
    assert!(
        WireCounts::get(&counts.data_odd) >= 1,
        "the rotation completed on the re-announced key"
    );
}

// ---- loss / reorder stress ----

async fn lossy_srtrust_to_libsrt(front: u16, backend: u16, sink_port: u16, cipher: CipherMode) {
    let slt = require_libsrt!();
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let gcm = matches!(cipher, CipherMode::Gcm);
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{backend}?mode=listener&{}",
            libsrt_query(1000, Some(PASSPHRASE), gcm, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let cfg = ProxyCfg {
        c2l_loss: 0.05,
        l2c_loss: 0.05,
        seed: 0xBEEF,
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    let config = Config {
        latency: Duration::from_millis(1000),
        ..encrypted(cipher, 0)
    };
    let received = srtrust_sender_run(
        config,
        front,
        &sink,
        200,
        Duration::from_millis(10),
        64,
        Duration::from_secs(6),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 200, "lossy srtrust→libsrt");
    assert!(
        WireCounts::get(&counts.retransmits) >= 1,
        "loss actually exercised the ARQ path (dropped {})",
        WireCounts::get(&counts.dropped)
    );
}

/// 5% loss each way: libsrt NAKs srtrust; srtrust's gated retransmissions must
/// recover everything within the latency budget.
#[tokio::test]
async fn lossy_ctr_srtrust_to_libsrt() {
    lossy_srtrust_to_libsrt(19170, 19171, 19172, CipherMode::Ctr).await;
}

/// Same under AES-GCM: every retransmission is *re-encrypted* by srtrust and
/// must still authenticate at libsrt (header AAD rebuilt from the wire).
#[tokio::test]
async fn lossy_gcm_srtrust_to_libsrt() {
    lossy_srtrust_to_libsrt(19180, 19181, 19182, CipherMode::Gcm).await;
}

/// The reverse: srtrust is the receiver on a lossy link — its NAKs (and its
/// adaptive reorder tolerance) drive libsrt's retransmissions.
#[tokio::test]
async fn lossy_libsrt_to_srtrust() {
    let slt = require_libsrt!();
    let (front, backend, in_port) = (19190, 19191, 19192);

    let config = Config {
        latency: Duration::from_millis(1000),
        ..encrypted(CipherMode::Ctr, 0)
    };
    let mut listener =
        SrtListener::bind(format!("127.0.0.1:{backend}").parse().unwrap(), config).unwrap();

    let cfg = ProxyCfg {
        c2l_loss: 0.05,
        l2c_loss: 0.05,
        seed: 0xFEED,
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    let mut child = spawn_slt(
        &slt,
        &format!("udp://127.0.0.1:{in_port}"),
        &format!(
            "srt://127.0.0.1:{front}?{}",
            libsrt_query(1000, Some(PASSPHRASE), false, None)
        ),
    );

    let mut server = tokio::time::timeout(Duration::from_secs(8), listener.accept())
        .await
        .expect("libsrt connects through the lossy proxy")
        .expect("accept");
    let feeder = tokio::spawn(feed_libsrt_input(
        in_port,
        200,
        Duration::from_millis(10),
        64,
    ));
    let received = recv_indices(&mut server, 200, Duration::from_secs(3)).await;
    let _ = feeder.await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 200, "lossy libsrt→srtrust");
    assert!(
        WireCounts::get(&counts.naks) >= 1,
        "srtrust reported loss to libsrt (dropped {})",
        WireCounts::get(&counts.dropped)
    );
}

/// BUG-02 against the real reference: a GCM packet lost *before* srtrust's key
/// rotation is retransmitted *after* it. The proxy's 80 ms one-way delay makes
/// the NAK round trip slower than the rotation, forcing the retransmission to
/// cross the boundary; libsrt must authenticate and decrypt it under the new
/// slot flag.
#[tokio::test]
async fn gcm_retransmit_across_rotation_against_libsrt() {
    let slt = require_libsrt!();
    let (front, backend, sink_port) = (19200, 19201, 19202);

    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{backend}?mode=listener&{}",
            libsrt_query(800, Some(PASSPHRASE), true, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    // Drop the 14th original (non-retransmitted) data packet: sent under the
    // pre-rotation even key (switch is due at the 17th), recovered after the
    // switch thanks to the 160 ms round trip.
    let mut originals = 0u32;
    let cfg = ProxyCfg {
        delay: Duration::from_millis(80),
        c2l_drop: Some(Box::new(move |datagram: &[u8]| {
            if let Ok(Packet::Data(d)) = Packet::decode(datagram)
                && !d.retransmitted
            {
                originals += 1;
                return originals == 14;
            }
            false
        })),
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    let config = Config {
        latency: Duration::from_millis(800),
        ..encrypted(CipherMode::Gcm, 16)
    };
    let received = srtrust_sender_run(
        config,
        front,
        &sink,
        64,
        Duration::from_millis(20),
        64,
        Duration::from_secs(6),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 64, "GCM loss-across-rotation");
    assert!(
        WireCounts::get(&counts.retransmits) >= 1,
        "the dropped packet was retransmitted"
    );
    assert!(
        WireCounts::get(&counts.data_odd) >= 1,
        "the rotation happened during the stream"
    );
}

// ---- flow control / throughput ----

/// A deliberately slow (but not stalled) srtrust reader: our full ACKs now
/// advertise *real* receive-buffer availability, which libsrt's sender uses as
/// its flow window. libsrt must keep flowing against those numbers — a
/// misencoded or wild value would stall or kill the stream.
#[tokio::test]
async fn slow_srtrust_reader_throttles_libsrt_sender() {
    let slt = require_libsrt!();
    let (srt_port, in_port) = (19210, 19211);

    let config = Config {
        flow_window: 1024,
        ..base_config()
    };
    let mut listener =
        SrtListener::bind(format!("127.0.0.1:{srt_port}").parse().unwrap(), config).unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!("udp://127.0.0.1:{in_port}"),
        &format!(
            "srt://127.0.0.1:{srt_port}?{}",
            libsrt_query(120, None, false, None)
        ),
    );
    let mut server = tokio::time::timeout(Duration::from_secs(8), listener.accept())
        .await
        .expect("libsrt connects")
        .expect("accept");

    let feeder = tokio::spawn(feed_libsrt_input(
        in_port,
        500,
        Duration::from_millis(5),
        64,
    ));
    let mut got = Vec::new();
    while got.len() < 500 {
        match tokio::time::timeout(Duration::from_secs(3), server.recv()).await {
            Ok(Some(m)) => {
                if let Some(i) = msg_index(&m) {
                    got.push(i);
                }
                // Read slower than the input pace would like, so the advertised
                // window genuinely dips.
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            _ => break,
        }
    }
    let _ = feeder.await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&got, 500, "slow-reader stream");
}

/// Throughput sanity: 2000 full-size messages, unpaced, must cross to libsrt
/// well inside a loose wall-clock bound — catches a gross regression from the
/// flow-window changes (the window must keep reopening on libsrt's ACK cadence).
#[tokio::test]
async fn srtrust_to_libsrt_throughput_sanity() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19220, 19221);

    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query(120, None, false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let started = Instant::now();
    let received = srtrust_sender_run(
        base_config(),
        srt_port,
        &sink,
        2000,
        Duration::ZERO,
        1316,
        Duration::from_secs(12),
    )
    .await;
    let elapsed = started.elapsed();
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 2000, "throughput stream");
    assert!(
        elapsed < Duration::from_secs(12),
        "2000 full-size messages should cross quickly, took {elapsed:?}"
    );
}

/// The Stream ID extension (spec §3.2.1.3): libsrt must parse and accept a
/// caller-supplied stream id.
#[tokio::test]
async fn stream_id_is_accepted_by_libsrt() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19230, 19231);

    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query(120, None, false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let config = Config {
        stream_id: Some("#!::r=interop/probe,m=publish".to_string()),
        ..base_config()
    };
    let received = srtrust_sender_run(
        config,
        srt_port,
        &sink,
        10,
        Duration::from_millis(20),
        64,
        Duration::from_secs(3),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 10, "stream-id stream");
}
