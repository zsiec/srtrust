//! Edge-case interoperability against libsrt (`~/dev/srt` build): the Tier-1/2
//! matrix beyond `interop_intense.rs` — burst-loss range NAKs, DROPREQ on the
//! wire, encryption mismatches, AES-192/256, idle/shutdown semantics,
//! multi-client, payload-size edges, duplex on one connection, stats
//! cross-validation, handshake-loss torture, and a gated timestamp-wrap soak.
//!
//! Every test skips cleanly when the libsrt binaries are not found.

mod interop_util;

use std::time::Duration;

use bytes::Bytes;
use interop_util::*;
use srt::{CipherMode, Config, EncryptionSettings, KeySize, SrtListener, connect};
use srt_protocol::handshake::HandshakeType;
use srt_protocol::packet::Packet;
use tokio::net::UdpSocket;

/// A targeted filter dropping the `range`-indexed *original* (non-retransmitted)
/// data packets — consecutive sequence numbers, i.e. a loss burst.
fn drop_original_burst(range: std::ops::Range<u32>) -> DropFilter {
    let mut originals = 0u32;
    Box::new(move |datagram: &[u8]| {
        if let Ok(Packet::Data(d)) = Packet::decode(datagram)
            && !d.retransmitted
        {
            originals += 1;
            return range.contains(&(originals - 1));
        }
        false
    })
}

/// A targeted filter black-holing one packet *forever*: it captures the
/// sequence number of the `nth` original and drops every transmission of it.
fn black_hole_nth_original(nth: u32) -> DropFilter {
    let mut originals = 0u32;
    let mut doomed: Option<u32> = None;
    Box::new(move |datagram: &[u8]| {
        if let Ok(Packet::Data(d)) = Packet::decode(datagram) {
            if doomed == Some(d.seq.value()) {
                return true;
            }
            if !d.retransmitted {
                if originals == nth {
                    doomed = Some(d.seq.value());
                    originals += 1;
                    return true;
                }
                originals += 1;
            }
        }
        false
    })
}

// ---- 1. burst loss: range NAKs both ways ----

/// 12 consecutive losses of srtrust's data: libsrt reports them as a *range*
/// LOSSREPORT, which srtrust must parse and retransmit en bloc.
#[tokio::test]
async fn burst_loss_of_srtrust_data_recovers_via_libsrt_range_nak() {
    let slt = require_libsrt!();
    let (front, backend, sink_port) = (19300, 19301, 19302);
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{backend}?mode=listener&{}",
            libsrt_query(1500, Some(PASSPHRASE), false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let cfg = ProxyCfg {
        c2l_drop: Some(drop_original_burst(20..32)),
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    let config = Config {
        latency: Duration::from_millis(1500),
        ..encrypted(CipherMode::Ctr, 0)
    };
    let received = srtrust_sender_run(
        config,
        front,
        &sink,
        100,
        Duration::from_millis(10),
        64,
        Duration::from_secs(5),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 100, "burst loss srtrust→libsrt");
    assert!(
        WireCounts::get(&counts.nak_ranges) >= 1,
        "libsrt compressed the burst into a range LOSSREPORT (naks={})",
        WireCounts::get(&counts.naks)
    );
    assert!(
        WireCounts::get(&counts.retransmits) >= 12,
        "the whole burst was retransmitted (got {})",
        WireCounts::get(&counts.retransmits)
    );
}

/// The reverse: 12 consecutive losses of libsrt's data — srtrust's NAK encodes
/// the burst as a range, and libsrt's (newly hardened) LOSSREPORT parser must
/// accept it and retransmit everything.
#[tokio::test]
async fn burst_loss_of_libsrt_data_recovers_via_srtrust_range_nak() {
    let slt = require_libsrt!();
    let (front, backend, in_port) = (19310, 19311, 19312);

    let config = Config {
        latency: Duration::from_millis(1500),
        ..encrypted(CipherMode::Ctr, 0)
    };
    let mut listener =
        SrtListener::bind(format!("127.0.0.1:{backend}").parse().unwrap(), config).unwrap();

    let cfg = ProxyCfg {
        c2l_drop: Some(drop_original_burst(20..32)),
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    let mut child = spawn_slt(
        &slt,
        &format!("udp://127.0.0.1:{in_port}"),
        &format!(
            "srt://127.0.0.1:{front}?{}",
            libsrt_query(1500, Some(PASSPHRASE), false, None)
        ),
    );
    let mut server = tokio::time::timeout(Duration::from_secs(8), listener.accept())
        .await
        .expect("libsrt connects")
        .expect("accept");
    let feeder = tokio::spawn(feed_libsrt_input(
        in_port,
        100,
        Duration::from_millis(10),
        64,
    ));
    let received = recv_indices(&mut server, 100, Duration::from_secs(3)).await;
    let _ = feeder.await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 100, "burst loss libsrt→srtrust");
    assert!(
        WireCounts::get(&counts.nak_ranges) >= 1,
        "srtrust compressed the burst into a range NAK, and libsrt accepted it \
         (naks={} dropped={} plain={} rexmit={})",
        WireCounts::get(&counts.naks),
        WireCounts::get(&counts.dropped),
        WireCounts::get(&counts.data_plain),
        WireCounts::get(&counts.retransmits),
    );
}

// ---- 2. DROPREQ on the wire, both directions ----

/// One of srtrust's packets is black-holed forever under a tight latency:
/// send-side TLPKTDROP must shed it and announce a DROPREQ that libsrt's
/// hardened parser accepts — the stream continues with exactly one gap.
#[tokio::test]
async fn srtrust_dropreq_skips_cleanly_at_libsrt() {
    let slt = require_libsrt!();
    let (front, backend, sink_port) = (19320, 19321, 19322);
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{backend}?mode=listener&{}",
            libsrt_query(120, None, false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    // 100 ms each way: the receiver's local give-up (and the ACK advancing past
    // the gap) takes a full RTT to reach the sender, so the sender's own
    // too-late shed fires first and the DROPREQ crosses the wire.
    let cfg = ProxyCfg {
        c2l_drop: Some(black_hole_nth_original(9)),
        delay: Duration::from_millis(100),
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    let received = srtrust_sender_run(
        base_config(),
        front,
        &sink,
        50,
        Duration::from_millis(20),
        64,
        Duration::from_secs(5),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_but_one(&received, 50, 9, "srtrust DROPREQ → libsrt");
    assert!(
        WireCounts::get(&counts.dropreqs) >= 1,
        "srtrust announced the shed packet with a DROPREQ"
    );
}

/// The reverse: one of libsrt's packets is black-holed under a tight latency.
/// srtrust's receiver must give the gap up at play time (TLPKTDROP) and keep
/// delivering — exactly one message missing, in order, no stall.
///
/// Note what is *not* asserted: a DROPREQ from libsrt. On a same-latency
/// loopback link the receiver's local give-up always beats the sender's
/// drop-plus-DROPREQ by a round trip, so libsrt rarely emits one here —
/// srtrust's DROPREQ *parsing* is covered by the sim suite (`dropreq.rs`), and
/// srtrust's DROPREQ *encoding* against libsrt by the test above.
#[tokio::test]
async fn blackholed_libsrt_packet_is_skipped_cleanly_by_srtrust() {
    let slt = require_libsrt!();
    let (front, backend, in_port) = (19330, 19331, 19332);

    let mut listener = SrtListener::bind(
        format!("127.0.0.1:{backend}").parse().unwrap(),
        base_config(),
    )
    .unwrap();

    // Same 100 ms-per-way rationale as the srtrust-sender variant: libsrt's
    // sender-side drop must fire before our receiver's advance reaches it.
    let cfg = ProxyCfg {
        c2l_drop: Some(black_hole_nth_original(9)),
        delay: Duration::from_millis(100),
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    let mut child = spawn_slt(
        &slt,
        &format!("udp://127.0.0.1:{in_port}"),
        &format!(
            "srt://127.0.0.1:{front}?{}",
            libsrt_query(120, None, false, None)
        ),
    );
    let mut server = tokio::time::timeout(Duration::from_secs(8), listener.accept())
        .await
        .expect("libsrt connects")
        .expect("accept");
    // srt-live-transmit binds its UDP input only after `srt_connect` completes
    // (slowed here by the 100 ms proxy delay); datagrams fed earlier are lost
    // before they ever become SRT packets.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let feeder = tokio::spawn(feed_libsrt_input(
        in_port,
        50,
        Duration::from_millis(20),
        64,
    ));
    let received = recv_indices(&mut server, 49, Duration::from_secs(3)).await;
    let stats = server.stats().await;
    let _ = feeder.await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_but_one(&received, 50, 9, "black-holed libsrt packet");
    let stats = stats.expect("stats");
    assert!(
        stats.packets_dropped >= 1,
        "the receiver counted its TLPKTDROP skip (dropped={}, wire dropreqs={})",
        stats.packets_dropped,
        WireCounts::get(&counts.dropreqs)
    );
}

// ---- 3. encryption mismatch matrix ----

/// Wrong passphrase, libsrt's default `enforcedencryption=yes`: the handshake
/// must fail cleanly and promptly — never hang.
#[tokio::test]
async fn wrong_passphrase_fails_cleanly() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19340, 19341);
    let _sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query(120, Some("aaaaaaaaaaaaaaaa"), false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let outcome = tokio::time::timeout(
        Duration::from_secs(6),
        connect(
            "127.0.0.1:0".parse().unwrap(),
            format!("127.0.0.1:{srt_port}").parse().unwrap(),
            encrypted(CipherMode::Ctr, 0),
        ),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    let completed = outcome.expect("must resolve within 6s, not hang");
    assert!(
        completed.is_err(),
        "a wrong passphrase must fail the handshake"
    );
}

/// Unencrypted caller against an encrypted libsrt listener (enforced, the
/// default): rejected cleanly.
#[tokio::test]
async fn plain_caller_rejected_by_enforced_encrypted_libsrt() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19342, 19343);
    let _sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query(120, Some(PASSPHRASE), false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let outcome = tokio::time::timeout(
        Duration::from_secs(6),
        connect(
            "127.0.0.1:0".parse().unwrap(),
            format!("127.0.0.1:{srt_port}").parse().unwrap(),
            base_config(),
        ),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        outcome.expect("must resolve, not hang").is_err(),
        "an unencrypted caller must be rejected by an enforced encrypted listener"
    );
}

/// Encrypted caller against an unencrypted libsrt listener with
/// `enforcedencryption=no`: libsrt accepts the connection but cannot decrypt —
/// the defined outcome is "connects, nothing delivered", not a hang or crash.
#[tokio::test]
async fn encrypted_caller_to_plain_unenforced_libsrt_delivers_nothing() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19344, 19345);
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!("srt://:{srt_port}?mode=listener&latency=120&enforcedencryption=no"),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let stream = connect(
        "127.0.0.1:0".parse().unwrap(),
        format!("127.0.0.1:{srt_port}").parse().unwrap(),
        encrypted(CipherMode::Ctr, 0),
    )
    .await
    .expect("unenforced libsrt accepts the mismatched connection");
    for i in 0..5u32 {
        stream.send(Bytes::from(msg(i, 64))).await.expect("send");
    }
    let received = collect_sink(&sink, 5, Duration::from_secs(2)).await;
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        received.is_empty(),
        "libsrt has no key: encrypted payloads must be dropped, got {received:?}"
    );
}

/// A libsrt caller with the wrong passphrase is declined by the srtrust
/// listener — and the listener stays healthy for a correct caller right after.
#[tokio::test]
async fn libsrt_wrong_passphrase_declined_and_listener_survives() {
    let slt = require_libsrt!();
    let (srt_port, in_bad, in_good) = (19346, 19347, 19348);

    let mut listener = SrtListener::bind(
        format!("127.0.0.1:{srt_port}").parse().unwrap(),
        encrypted(CipherMode::Ctr, 0),
    )
    .unwrap();

    let mut bad = spawn_slt(
        &slt,
        &format!("udp://127.0.0.1:{in_bad}"),
        &format!(
            "srt://127.0.0.1:{srt_port}?{}",
            libsrt_query(120, Some("aaaaaaaaaaaaaaaa"), false, None)
        ),
    );
    // The bad caller must never be surfaced to the application.
    let declined = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await;
    assert!(
        declined.is_err(),
        "a wrong-passphrase caller must be declined, not accepted"
    );
    let _ = bad.kill();
    let _ = bad.wait();

    // A correct caller connects and delivers through the same listener.
    let mut good = spawn_slt(
        &slt,
        &format!("udp://127.0.0.1:{in_good}"),
        &format!(
            "srt://127.0.0.1:{srt_port}?{}",
            libsrt_query(120, Some(PASSPHRASE), false, None)
        ),
    );
    let mut server = tokio::time::timeout(Duration::from_secs(8), listener.accept())
        .await
        .expect("the good caller connects")
        .expect("accept");
    let feeder = tokio::spawn(feed_libsrt_input(
        in_good,
        10,
        Duration::from_millis(10),
        64,
    ));
    let received = recv_indices(&mut server, 10, Duration::from_secs(3)).await;
    let _ = feeder.await;
    let _ = good.kill();
    let _ = good.wait();
    assert_all_in_order(&received, 10, "good caller after declined caller");
}

// ---- 4. AES-192 / AES-256 ----

async fn aes_size_run(srt_port: u16, sink_port: u16, key_size: KeySize, cipher: CipherMode) {
    let slt = require_libsrt!();
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let pbkeylen = u8::try_from(key_size.bytes()).expect("16/24/32");
    let gcm = matches!(cipher, CipherMode::Gcm);
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query_sized(120, Some(PASSPHRASE), pbkeylen, gcm, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let config = Config {
        encryption: Some(EncryptionSettings {
            passphrase: PASSPHRASE.as_bytes().to_vec(),
            key_size,
            cipher,
        }),
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
    assert_all_in_order(&received, 10, "AES key-size interop");
}

#[tokio::test]
async fn aes192_ctr_interops() {
    aes_size_run(19350, 19351, KeySize::Aes192, CipherMode::Ctr).await;
}

#[tokio::test]
async fn aes256_ctr_interops() {
    aes_size_run(19352, 19353, KeySize::Aes256, CipherMode::Ctr).await;
}

#[tokio::test]
async fn aes192_gcm_interops() {
    aes_size_run(19354, 19355, KeySize::Aes192, CipherMode::Gcm).await;
}

#[tokio::test]
async fn aes256_gcm_interops() {
    aes_size_run(19356, 19357, KeySize::Aes256, CipherMode::Gcm).await;
}

// ---- 5. idle survival + shutdown semantics ----

/// 12 s of data silence: srtrust's keepalives must hold the connection open
/// past libsrt's 5 s peer-idle timeout, and the stream resumes intact.
#[tokio::test]
async fn idle_connection_survives_libsrt_peer_idle_timeout() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19360, 19361);
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt_args(
        &slt,
        &["-t", "60"],
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query(120, None, false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let stream = connect(
        "127.0.0.1:0".parse().unwrap(),
        format!("127.0.0.1:{srt_port}").parse().unwrap(),
        base_config(),
    )
    .await
    .expect("connect");
    for i in 0..3u32 {
        stream.send(Bytes::from(msg(i, 64))).await.expect("send");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_secs(12)).await; // keepalives only
    for i in 3..6u32 {
        stream
            .send(Bytes::from(msg(i, 64)))
            .await
            .expect("send after the idle period (connection still alive)");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let received = collect_sink(&sink, 6, Duration::from_secs(4)).await;
    let _ = child.kill();
    let _ = child.wait();
    assert_all_in_order(&received, 6, "idle-survival stream");
}

/// A graceful srtrust close is seen by libsrt as a clean connection end:
/// with auto-reconnect off, `srt-live-transmit` exits promptly.
#[tokio::test]
async fn srtrust_graceful_close_ends_libsrt_promptly() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19362, 19363);
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt_args(
        &slt,
        &["-t", "60", "-a", "no"],
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query(120, None, false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let stream = connect(
        "127.0.0.1:0".parse().unwrap(),
        format!("127.0.0.1:{srt_port}").parse().unwrap(),
        base_config(),
    )
    .await
    .expect("connect");
    for i in 0..5u32 {
        stream.send(Bytes::from(msg(i, 64))).await.expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let received = collect_sink(&sink, 5, Duration::from_secs(3)).await;
    assert_all_in_order(&received, 5, "pre-close stream");

    stream.close().await.expect("graceful close");
    let mut exited = false;
    for _ in 0..40 {
        if child.try_wait().expect("try_wait").is_some() {
            exited = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert!(
        exited,
        "libsrt (auto-reconnect off) exits promptly on srtrust's clean shutdown"
    );
}

/// libsrt's side ends (its source-idle timeout closes the connection): srtrust's
/// receiver must observe the end promptly — via SHUTDOWN on the wire, not a
/// peer-idle timeout.
#[tokio::test]
async fn libsrt_termination_ends_srtrust_recv() {
    let slt = require_libsrt!();
    let (front, backend, in_port) = (19364, 19365, 19366);

    let mut listener = SrtListener::bind(
        format!("127.0.0.1:{backend}").parse().unwrap(),
        base_config(),
    )
    .unwrap();
    let counts = spawn_proxy(front, backend, ProxyCfg::default()).await;

    // Source-idle timeout of 2 s: once the UDP feed stops, libsrt closes.
    let mut child = spawn_slt_args(
        &slt,
        &["-t", "2", "-a", "no"],
        &format!("udp://127.0.0.1:{in_port}"),
        &format!(
            "srt://127.0.0.1:{front}?{}",
            libsrt_query(120, None, false, None)
        ),
    );
    let mut server = tokio::time::timeout(Duration::from_secs(8), listener.accept())
        .await
        .expect("libsrt connects")
        .expect("accept");
    feed_libsrt_input(in_port, 5, Duration::from_millis(20), 64).await;
    let received = recv_indices(&mut server, 5, Duration::from_secs(3)).await;
    assert_all_in_order(&received, 5, "pre-termination stream");

    // After the feed stops, libsrt times out and closes; our recv must end.
    let ended = tokio::time::timeout(Duration::from_secs(8), server.recv()).await;
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        matches!(ended, Ok(None)),
        "recv ends when libsrt closes (got timeout/hang instead)"
    );
    assert!(
        WireCounts::get(&counts.shutdowns) >= 1,
        "the end arrived as an SRT SHUTDOWN on the wire"
    );
}

// ---- 6. multi-client ----

/// Four concurrent libsrt callers into one srtrust listener, all encrypted:
/// demux and per-connection crypto under contention; each stream arrives
/// intact and isolated.
#[tokio::test]
async fn four_libsrt_callers_into_one_srtrust_listener() {
    let slt = require_libsrt!();
    let srt_port = 19370;
    let in_ports = [19371u16, 19372, 19373, 19374];

    let mut listener = SrtListener::bind(
        format!("127.0.0.1:{srt_port}").parse().unwrap(),
        encrypted(CipherMode::Ctr, 0),
    )
    .unwrap();

    let mut children: Vec<_> = in_ports
        .iter()
        .map(|in_port| {
            spawn_slt(
                &slt,
                &format!("udp://127.0.0.1:{in_port}"),
                &format!(
                    "srt://127.0.0.1:{srt_port}?{}",
                    libsrt_query(120, Some(PASSPHRASE), false, None)
                ),
            )
        })
        .collect();

    // Accept all four before feeding, then stream concurrently.
    let mut servers = Vec::new();
    for _ in 0..4 {
        servers.push(
            tokio::time::timeout(Duration::from_secs(8), listener.accept())
                .await
                .expect("каller connects")
                .expect("accept"),
        );
    }
    let feeders: Vec<_> = in_ports
        .iter()
        .enumerate()
        .map(|(k, &in_port)| {
            tokio::spawn(feed_libsrt_input_from(
                in_port,
                (u32::try_from(k).expect("4 clients") + 1) * 1000,
                40,
                Duration::from_millis(10),
                64,
            ))
        })
        .collect();
    let collectors: Vec<_> = servers
        .into_iter()
        .map(|mut server| {
            tokio::spawn(async move { recv_indices(&mut server, 40, Duration::from_secs(3)).await })
        })
        .collect();
    let mut streams = Vec::new();
    for c in collectors {
        streams.push(c.await.expect("collector"));
    }
    for f in feeders {
        let _ = f.await;
    }
    for child in &mut children {
        let _ = child.kill();
        let _ = child.wait();
    }

    // Identify each stream by its tag base; every client's 40 messages arrive
    // in order with no cross-contamination.
    let mut bases: Vec<u32> = Vec::new();
    for got in &streams {
        assert_eq!(got.len(), 40, "a client's stream is complete: {got:?}");
        let base = (got[0] / 1000) * 1000;
        bases.push(base);
        for (i, &v) in got.iter().enumerate() {
            assert_eq!(
                v,
                base + u32::try_from(i).expect("40 messages"),
                "client {base}: in-order, no cross-stream leakage"
            );
        }
    }
    bases.sort_unstable();
    assert_eq!(bases, vec![1000, 2000, 3000, 4000], "all four clients seen");
}

// ---- 7. payload-size edges ----

/// Exactly libsrt's default `payloadsize` (1316) under CTR: byte-perfect.
#[tokio::test]
async fn ctr_payload_exactly_1316_round_trips() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19380, 19381);
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query(120, Some(PASSPHRASE), false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let stream = connect(
        "127.0.0.1:0".parse().unwrap(),
        format!("127.0.0.1:{srt_port}").parse().unwrap(),
        encrypted(CipherMode::Ctr, 0),
    )
    .await
    .expect("connect");
    for i in 0..3u32 {
        stream
            .send(Bytes::from(msg(i, 1316)))
            .await
            .expect("send max payload");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut buf = [0u8; 2048];
    let mut got = 0u32;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while got < 3 {
        let Ok(Ok(n)) = tokio::time::timeout_at(deadline, sink.recv(&mut buf)).await else {
            break;
        };
        assert_eq!(&buf[..n], &msg(got, 1316)[..], "payload byte-perfect");
        got += 1;
    }
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(got, 3, "all max-size payloads arrived");
}

/// GCM's 16-byte tag rides *inside* the wire payload, so against libsrt's
/// default `payloadsize` (1316) the largest application payload is 1300.
#[tokio::test]
async fn gcm_payload_1300_is_the_max_against_default_libsrt() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19382, 19383);
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query(120, Some(PASSPHRASE), true, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let received = srtrust_sender_run(
        encrypted(CipherMode::Gcm, 0),
        srt_port,
        &sink,
        3,
        Duration::from_millis(20),
        1300,
        Duration::from_secs(3),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();
    assert_all_in_order(&received, 3, "1300-byte GCM payloads");
}

/// Past the documented edges, pinned empirically: srtrust fragments a
/// 5000-byte message into four 1456-byte-max packets; live-mode libsrt treats
/// packet == message, and `srt-live-transmit` (receive buffer = its 1316-byte
/// `payloadsize`) **discards** every fragment larger than that with
/// `SRT_ELARGEMSG` — only the small tail fragment squeaks through as its own
/// message. The connection itself keeps flowing. The interop guidance this
/// pins (docs/interop.md): never send messages larger than the peer's
/// payload size to live-mode libsrt — the data is silently and *partially*
/// lost, the worst of the outcomes.
#[tokio::test]
async fn oversize_message_is_partially_lost_at_libsrt_but_connection_survives() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19384, 19385);
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query(120, Some(PASSPHRASE), false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let stream = connect(
        "127.0.0.1:0".parse().unwrap(),
        format!("127.0.0.1:{srt_port}").parse().unwrap(),
        encrypted(CipherMode::Ctr, 0),
    )
    .await
    .expect("connect");

    stream
        .send(Bytes::from(msg(0, 5000)))
        .await
        .expect("oversize send");
    tokio::time::sleep(Duration::from_millis(50)).await;
    for i in 1..4u32 {
        stream.send(Bytes::from(msg(i, 64))).await.expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut buf = vec![0u8; 16384];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    loop {
        let Ok(Ok(n)) = tokio::time::timeout_at(deadline, sink.recv(&mut buf)).await else {
            break;
        };
        datagrams.push(buf[..n].to_vec());
        if datagrams.iter().filter(|d| d.len() == 64).count() == 3 {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    // The connection survives: the three small messages arrive in order.
    let smalls: Vec<&Vec<u8>> = datagrams.iter().filter(|d| d.len() == 64).collect();
    assert_eq!(
        smalls.len(),
        3,
        "the stream continues after the oversize message"
    );
    for (i, d) in smalls.iter().enumerate() {
        assert_eq!(
            *d,
            &msg(u32::try_from(i + 1).expect("small"), 64),
            "post-oversize message {} byte-perfect",
            i + 1
        );
    }
    // The oversize message does NOT arrive intact — and not even completely:
    // libsrt discarded the over-buffer fragments.
    assert!(
        !datagrams.iter().any(|d| d == &msg(0, 5000)),
        "live-mode libsrt cannot deliver the message whole"
    );
    let big_bytes: usize = datagrams
        .iter()
        .filter(|d| d.len() != 64)
        .map(Vec::len)
        .sum();
    assert!(
        big_bytes < 5000,
        "fragments above the peer payload size are discarded (got {big_bytes} of 5000 bytes)"
    );
}

// ---- 8. duplex on one connection (libsrt message-mode echo) ----

/// Compiles `tests/helpers/srt_echo.c` against the `~/dev/srt/_build` library —
/// a minimal libsrt **message-mode** echo. (`srt-tunnel` cannot serve here: it
/// is stream-API only and rejects message-API peers, including libsrt's own
/// `srt-live-transmit`.) Returns `None` (skip) when `cc` or the library is
/// unavailable.
fn build_srt_echo() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let build_dir = format!("{home}/dev/srt/_build");
    if !std::path::Path::new(&format!("{build_dir}/srt-live-transmit")).exists() {
        return None;
    }
    let out = std::env::temp_dir().join("srtrust-interop-srt-echo");
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/helpers/srt_echo.c");
    let status = std::process::Command::new("cc")
        .arg(src)
        .args([
            &format!("-I{home}/dev/srt/srtcore"),
            &format!("-I{build_dir}"),
            &format!("-L{build_dir}"),
            "-lsrt",
            &format!("-Wl,-rpath,{build_dir}"),
            "-o",
        ])
        .arg(&out)
        .status()
        .ok()?;
    status.success().then_some(out)
}

/// True bidirectional data on a single SRT connection against libsrt: a
/// message-mode libsrt echo server returns every message on the same
/// connection, so srtrust sends and receives simultaneously — data, ACKs, and
/// ACKACKs interleave in both directions, and message boundaries are
/// preserved.
#[tokio::test]
async fn duplex_echo_against_libsrt_message_echo() {
    let Some(echo_bin) = build_srt_echo() else {
        eprintln!("SKIP: cc or the ~/dev/srt build is unavailable for the echo helper");
        return;
    };
    let srt_port = 19390;
    let mut child = KillOnDrop(
        std::process::Command::new(&echo_bin)
            .arg(srt_port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn srt echo"),
    );
    tokio::time::sleep(Duration::from_millis(800)).await;

    let mut stream = connect(
        "127.0.0.1:0".parse().unwrap(),
        format!("127.0.0.1:{srt_port}").parse().unwrap(),
        base_config(),
    )
    .await
    .expect("srtrust connects to the libsrt echo");

    let total = 30u32;
    let mut echoed: Vec<Vec<u8>> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    for i in 0..total {
        stream
            .send(Bytes::from(msg(i, 64)))
            .await
            .expect("send to the echo");
        // Interleave receives with sends — the duplex part.
        while echoed.len() < i as usize {
            match tokio::time::timeout_at(deadline, stream.recv()).await {
                Ok(Some(back)) => echoed.push(back.to_vec()),
                _ => break,
            }
        }
    }
    while echoed.len() < total as usize {
        match tokio::time::timeout_at(deadline, stream.recv()).await {
            Ok(Some(back)) => echoed.push(back.to_vec()),
            _ => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(
        echoed.len(),
        total as usize,
        "every message came back over the same SRT connection"
    );
    for (i, back) in echoed.iter().enumerate() {
        assert_eq!(
            back,
            &msg(u32::try_from(i).expect("fits"), 64),
            "echoed message {i} byte-perfect, boundary preserved"
        );
    }
}

// ---- 10. stats cross-validation ----

/// libsrt's own JSON statistics must reconcile with what the wire spy (and our
/// sender) saw: it received the stream, observed the retransmissions, and
/// measured a sane RTT.
#[tokio::test]
async fn libsrt_stats_reconcile_with_ours() {
    let slt = require_libsrt!();
    let (front, backend, sink_port) = (19400, 19401, 19402);
    let stats_path = std::env::temp_dir().join("srtrust-interop-stats.json");
    let _ = std::fs::remove_file(&stats_path);

    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt_args(
        &slt,
        &[
            "-t",
            "10",
            "-a",
            "no",
            "-s:100",
            "-pf:json",
            &format!("-statsout:{}", stats_path.display()),
        ],
        &format!(
            "srt://:{backend}?mode=listener&{}",
            libsrt_query(300, None, false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    // Seeded 3% loss on the originals, EXEMPTING the stream tail: a loss of
    // the final packets is recovered only by the EXP backstop, whose first
    // firing races the 300 ms TLPKTDROP budget — correct live-mode shedding,
    // but it would make the 200/200 assertion timing-dependent.
    let mut rng = Rng(0xC0DE);
    let mut originals = 0u32;
    let cfg = ProxyCfg {
        c2l_drop: Some(Box::new(move |datagram: &[u8]| {
            if let Ok(Packet::Data(d)) = Packet::decode(datagram)
                && !d.retransmitted
            {
                originals += 1;
                return originals < 190 && rng.next_unit() < 0.03;
            }
            false
        })),
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    let config = Config {
        latency: Duration::from_millis(300),
        ..base_config()
    };
    let received = srtrust_sender_run(
        config,
        front,
        &sink,
        200,
        Duration::from_millis(10),
        64,
        Duration::from_secs(5),
    )
    .await;
    // `srtrust_sender_run` dropped the stream at return: the driver closes the
    // connection gracefully, and slt (auto-reconnect off) exits and flushes its
    // stats file. Wait for that rather than killing it mid-write.
    for _ in 0..50 {
        if child.try_wait().expect("try_wait").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    assert_all_in_order(&received, 200, "stats run");

    let stats = std::fs::read_to_string(&stats_path).expect("libsrt wrote stats");
    // libsrt's JSON stats nest counters under "recv", and `srt-live-transmit`
    // reports per-interval *deltas* (observed empirically: two snapshots of
    // 124 + 76 packets for a 200-message run) — so reconcile against the SUM
    // across every snapshot.
    let (mut pkt_recv, mut pkt_retrans) = (0u64, 0u64);
    for line in stats.lines() {
        let Some(at) = line.find("\"recv\":{") else {
            continue;
        };
        let recv_obj = &line[at + 8..];
        pkt_recv += json_u64(recv_obj, "packets").unwrap_or(0);
        pkt_retrans += json_u64(recv_obj, "packetsRetransmitted").unwrap_or(0);
    }

    let wire_retrans = u64::from(WireCounts::get(&counts.retransmits));
    let wire_dropped = u64::from(WireCounts::get(&counts.dropped));
    assert!(
        pkt_recv >= 195,
        "libsrt counted the whole stream (sum of recv.packets = {pkt_recv})"
    );
    assert!(
        pkt_retrans >= 1,
        "libsrt saw the loss-driven retransmissions (sum = {pkt_retrans})"
    );
    assert!(
        pkt_retrans <= wire_retrans,
        "libsrt cannot receive more retransmissions ({pkt_retrans}) than crossed \
         the wire ({wire_retrans}, of which some of {wire_dropped} drops)"
    );
}

/// Extracts an integer field from a flat JSON stats line without a JSON parser.
fn json_u64(line: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\":");
    let start = line.find(&pat)? + pat.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

// ---- 11. handshake-loss torture ----

/// Drops one specific handshake packet (per scenario) and asserts the
/// handshake still converges against libsrt via retransmission.
async fn handshake_loss_run(front: u16, backend: u16, sink_port: u16, scenario: HsDrop) {
    let slt = require_libsrt!();
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{backend}?mode=listener&{}",
            libsrt_query(120, None, false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let mut cfg = ProxyCfg::default();
    let filter = hs_drop_filter(scenario.kind);
    match scenario.direction {
        Direction::CallerToListener => cfg.c2l_drop = Some(filter),
        Direction::ListenerToCaller => cfg.l2c_drop = Some(filter),
    }
    let counts = spawn_proxy(front, backend, cfg).await;

    let received = srtrust_sender_run(
        base_config(),
        front,
        &sink,
        3,
        Duration::from_millis(20),
        64,
        Duration::from_secs(3),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 3, "post-handshake stream");
    assert!(
        WireCounts::get(&counts.handshakes) >= 5,
        "a retransmission converged the handshake (saw {} handshake packets, \
         baseline is 4)",
        WireCounts::get(&counts.handshakes)
    );
}

#[derive(Clone, Copy)]
enum Direction {
    CallerToListener,
    ListenerToCaller,
}
#[derive(Clone, Copy)]
enum HsKind {
    FirstAny,        // the induction (first handshake in that direction)
    FirstConclusion, // the first CONCLUSION in that direction
}
#[derive(Clone, Copy)]
struct HsDrop {
    direction: Direction,
    kind: HsKind,
}

fn hs_drop_filter(kind: HsKind) -> DropFilter {
    let mut dropped = false;
    Box::new(move |datagram: &[u8]| {
        if dropped {
            return false;
        }
        let Ok(Packet::Control(c)) = Packet::decode(datagram) else {
            return false;
        };
        let srt_protocol::control::ControlBody::Handshake(hs) = c.body else {
            return false;
        };
        let hit = match kind {
            HsKind::FirstAny => true,
            HsKind::FirstConclusion => hs.handshake_type == HandshakeType::CONCLUSION,
        };
        if hit {
            dropped = true;
        }
        hit
    })
}

#[tokio::test]
async fn handshake_survives_lost_induction_request() {
    handshake_loss_run(
        19410,
        19411,
        19412,
        HsDrop {
            direction: Direction::CallerToListener,
            kind: HsKind::FirstAny,
        },
    )
    .await;
}

#[tokio::test]
async fn handshake_survives_lost_induction_response() {
    handshake_loss_run(
        19413,
        19414,
        19415,
        HsDrop {
            direction: Direction::ListenerToCaller,
            kind: HsKind::FirstAny,
        },
    )
    .await;
}

#[tokio::test]
async fn handshake_survives_lost_conclusion_request() {
    handshake_loss_run(
        19416,
        19417,
        19418,
        HsDrop {
            direction: Direction::CallerToListener,
            kind: HsKind::FirstConclusion,
        },
    )
    .await;
}

/// A lost conclusion *response* with libsrt as the caller: libsrt retransmits
/// its conclusion and the **srtrust listener** must re-answer the repeated
/// handshake (spec §4.3.1.2) — proven here against the real caller.
#[tokio::test]
async fn srtrust_listener_reanswers_libsrt_repeated_conclusion() {
    let slt = require_libsrt!();
    let (front, backend, in_port) = (19419, 19420, 19421);

    let mut listener = SrtListener::bind(
        format!("127.0.0.1:{backend}").parse().unwrap(),
        base_config(),
    )
    .unwrap();
    let cfg = ProxyCfg {
        l2c_drop: Some(hs_drop_filter(HsKind::FirstConclusion)),
        ..ProxyCfg::default()
    };
    let counts = spawn_proxy(front, backend, cfg).await;

    let mut child = spawn_slt(
        &slt,
        &format!("udp://127.0.0.1:{in_port}"),
        &format!(
            "srt://127.0.0.1:{front}?{}",
            libsrt_query(120, None, false, None)
        ),
    );
    let mut server = tokio::time::timeout(Duration::from_secs(8), listener.accept())
        .await
        .expect("libsrt converges despite the lost conclusion response")
        .expect("accept");
    // Our accept() returns at the FIRST conclusion; libsrt only finishes after
    // its retransmitted conclusion is re-answered (~250 ms later) and binds its
    // UDP input then — feed after it has converged.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let feeder = tokio::spawn(feed_libsrt_input(in_port, 3, Duration::from_millis(20), 64));
    let received = recv_indices(&mut server, 3, Duration::from_secs(3)).await;
    let _ = feeder.await;
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, 3, "post-handshake stream");
    assert!(
        WireCounts::get(&counts.handshakes) >= 5,
        "the repeated conclusion was re-answered (saw {})",
        WireCounts::get(&counts.handshakes)
    );
}

/// The same loss with srtrust as the caller against `srt-live-transmit` is
/// **unrecoverable by design of the app**: slt closes its listening socket
/// immediately after the single accept (`apps/transmitmedia.cpp`: "we do one
/// client connection at a time, so close the listener"), so nobody is left to
/// re-answer the retransmitted conclusion. srtrust's defined behavior: keep
/// retrying on the SYN cadence, then fail cleanly with a handshake timeout —
/// never hang. (Against a multi-accept libsrt listener the repeated conclusion
/// *is* re-answered by `processConnectRequest`.)
#[tokio::test]
async fn lost_conclusion_response_fails_cleanly_against_single_accept_libsrt() {
    let slt = require_libsrt!();
    let (front, backend, sink_port) = (19422, 19423, 19424);
    let _sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    let mut child = spawn_slt(
        &slt,
        &format!(
            "srt://:{backend}?mode=listener&{}",
            libsrt_query(120, None, false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let counts = spawn_proxy(
        front,
        backend,
        ProxyCfg {
            l2c_drop: Some(hs_drop_filter(HsKind::FirstConclusion)),
            ..ProxyCfg::default()
        },
    )
    .await;

    let outcome = tokio::time::timeout(
        Duration::from_secs(6),
        connect(
            "127.0.0.1:0".parse().unwrap(),
            format!("127.0.0.1:{front}").parse().unwrap(),
            base_config(),
        ),
    )
    .await;
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        outcome.expect("resolves within 6s, never hangs").is_err(),
        "with the responder gone, the caller must fail cleanly"
    );
    assert!(
        WireCounts::get(&counts.handshakes) >= 8,
        "the caller retried on the SYN cadence before giving up (saw {})",
        WireCounts::get(&counts.handshakes)
    );
}

// ---- 9. timestamp-wrap soak (gated; ~46 minutes) ----

/// 45 minutes of continuous live streaming against libsrt — crosses the
/// ±2^31 µs TSBPD wrap window with real clocks (covers drift too). Run with:
/// `cargo test -p srt --test interop_edge -- --ignored soak --nocapture`
#[tokio::test]
#[ignore = "45-minute soak; run explicitly"]
async fn soak_45_minutes_across_the_timestamp_wrap() {
    let slt = require_libsrt!();
    let (srt_port, sink_port) = (19430, 19431);
    let sink = UdpSocket::bind(("127.0.0.1", sink_port)).await.unwrap();
    // No `-t`: it is an exit timer since app START (not idle), and it would
    // kill the listener mid-soak. KillOnDrop guarantees cleanup instead.
    let mut child = spawn_slt_args(
        &slt,
        &["-a", "no"],
        &format!(
            "srt://:{srt_port}?mode=listener&{}",
            libsrt_query(120, Some(PASSPHRASE), false, None)
        ),
        &format!("udp://127.0.0.1:{sink_port}"),
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let stream = connect(
        "127.0.0.1:0".parse().unwrap(),
        format!("127.0.0.1:{srt_port}").parse().unwrap(),
        encrypted(CipherMode::Ctr, 0),
    )
    .await
    .expect("connect");

    // 45 min at 20 msg/s = 54_000 messages; collect concurrently so the UDP
    // sink never backs up. The collector budget must never race the sender —
    // the first soak run was cut by exactly that (`sleep(50ms)` drifts ~2 ms
    // per tick, stretching the sends to ~46.6 min past a 46-min deadline); an
    // `interval` paces drift-free and the collector returns as soon as `total`
    // arrive anyway.
    let total: u32 = 54_000;
    let collector =
        tokio::spawn(async move { collect_sink(&sink, total, Duration::from_secs(55 * 60)).await });
    let mut pace = tokio::time::interval(Duration::from_millis(50));
    for i in 0..total {
        pace.tick().await;
        stream
            .send(Bytes::from(msg(i, 64)))
            .await
            .expect("send during soak");
        if i % 6000 == 0 {
            eprintln!("soak: sent {i}/{total} (~{} min)", i / 1200);
        }
    }
    let received = collector.await.expect("collector");
    let _ = child.kill();
    let _ = child.wait();

    assert_all_in_order(&received, total, "45-minute soak across the wrap");
}
