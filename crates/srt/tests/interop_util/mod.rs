//! Shared infrastructure for the libsrt interoperability suites
//! (`interop_intense.rs`, `interop_edge.rs`): binary discovery, libsrt process
//! spawning, tagged message framing, and the **wire-spy UDP proxy** — a relay
//! that decodes every datagram with srtrust's own codec to count control types
//! and key-slot flags, and can apply seeded random loss, targeted drops, and
//! fixed link delay in either direction.
//!
//! Shared across test binaries; not every binary uses every helper, hence the
//! module-level `dead_code` allow.
#![allow(dead_code, unreachable_pub)]

use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use srt::{CipherMode, Config, EncryptionSettings, KeySize, connect};
use srt_protocol::control::{ControlBody, ControlType};
use srt_protocol::packet::{Encryption, Packet};
use tokio::net::UdpSocket;

/// SRT command subtypes for rekey Key Material (spec §6.1.6, `UMSG_EXT`).
pub const EXT_KMREQ: u16 = 3;
pub const EXT_KMRSP: u16 = 4;

pub const PASSPHRASE: &str = "0123456789abcdef";

/// Locates `srt-live-transmit`: `$SRT_LIVE_TRANSMIT`, then the `~/dev/srt`
/// checkout build, then the installed candidates. `None` skips the test.
pub fn srt_live_transmit() -> Option<String> {
    find_binary("SRT_LIVE_TRANSMIT", "srt-live-transmit")
}

/// Locates `srt-tunnel` the same way (`$SRT_TUNNEL` overrides).
pub fn srt_tunnel() -> Option<String> {
    find_binary("SRT_TUNNEL", "srt-tunnel")
}

fn find_binary(env: &str, name: &str) -> Option<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(v) = std::env::var(env) {
        candidates.push(v);
    }
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(format!("{home}/dev/srt/_build/{name}"));
    }
    candidates.push(name.to_string());
    for prefix in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        candidates.push(format!("{prefix}/{name}"));
    }
    candidates.into_iter().find(|candidate| {
        Command::new(candidate)
            .arg("-version")
            .output()
            .is_ok_and(|o| o.status.success() || !o.stderr.is_empty())
    })
}

macro_rules! require_libsrt {
    () => {
        match $crate::interop_util::srt_live_transmit() {
            Some(slt) => slt,
            None => {
                eprintln!(
                    "SKIP: srt-live-transmit not found (build ~/dev/srt or brew install srt)"
                );
                return;
            }
        }
    };
}
pub(crate) use require_libsrt;

pub fn base_config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(120))
        .with_flow_window(8192)
}

pub fn encrypted(cipher: CipherMode, km_refresh_rate: u32) -> Config {
    encrypted_sized(cipher, km_refresh_rate, KeySize::Aes128)
}

pub fn encrypted_sized(cipher: CipherMode, km_refresh_rate: u32, key_size: KeySize) -> Config {
    base_config()
        .with_encryption(EncryptionSettings {
            passphrase: PASSPHRASE.as_bytes().to_vec(),
            key_size,
            cipher,
        })
        .with_km_refresh_rate(km_refresh_rate)
}

/// A spawned helper process that is killed when dropped, so a panicking test
/// cannot orphan it — an orphan keeps its UDP port bound and poisons every
/// later run of the suite.
pub struct KillOnDrop(pub Child);

impl KillOnDrop {
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.0.kill()
    }
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.wait()
    }
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.0.try_wait()
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawns `srt-live-transmit` with a 10 s activity timeout.
pub fn spawn_slt(slt: &str, input: &str, output: &str) -> KillOnDrop {
    spawn_slt_args(slt, &["-t", "10"], input, output)
}

/// Spawns `srt-live-transmit` with caller-controlled extra arguments (timeout,
/// auto-reconnect, stats output, …).
pub fn spawn_slt_args(slt: &str, extra: &[&str], input: &str, output: &str) -> KillOnDrop {
    KillOnDrop(
        Command::new(slt)
            .args(extra)
            .args(["-loglevel:error", input, output])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn srt-live-transmit"),
    )
}

/// URI query string for a libsrt endpoint with optional encryption/rekey knobs.
pub fn libsrt_query(
    latency_ms: u32,
    passphrase: Option<&str>,
    gcm: bool,
    rekey: Option<(u32, u32)>,
) -> String {
    libsrt_query_sized(latency_ms, passphrase, 16, gcm, rekey)
}

/// As [`libsrt_query`] with an explicit `pbkeylen` (16 / 24 / 32).
pub fn libsrt_query_sized(
    latency_ms: u32,
    passphrase: Option<&str>,
    pbkeylen: u8,
    gcm: bool,
    rekey: Option<(u32, u32)>,
) -> String {
    use std::fmt::Write as _;
    let mut q = format!("latency={latency_ms}");
    if let Some(p) = passphrase {
        let _ = write!(q, "&passphrase={p}&pbkeylen={pbkeylen}");
        if gcm {
            let _ = write!(q, "&cryptomode=2");
        }
    }
    if let Some((rate, pre)) = rekey {
        let _ = write!(q, "&kmrefreshrate={rate}&kmpreannounce={pre}");
    }
    q
}

// ---- wire spy / impairment proxy ----

/// Counters over everything the proxy saw (both directions), classified with
/// srtrust's own wire codec.
#[derive(Debug, Default)]
pub struct WireCounts {
    pub data_even: AtomicU32,
    pub data_odd: AtomicU32,
    pub data_plain: AtomicU32,
    pub retransmits: AtomicU32,
    pub naks: AtomicU32,
    /// NAKs whose loss list contains at least one multi-sequence *range* —
    /// the compressed form only burst loss produces.
    pub nak_ranges: AtomicU32,
    pub dropreqs: AtomicU32,
    pub handshakes: AtomicU32,
    pub shutdowns: AtomicU32,
    pub kmreq: AtomicU32,
    pub kmrsp: AtomicU32,
    pub dropped: AtomicU32,
}

impl WireCounts {
    pub fn classify(&self, datagram: &[u8]) {
        match Packet::decode(datagram) {
            Ok(Packet::Data(d)) => {
                match d.encryption {
                    Encryption::Even => self.data_even.fetch_add(1, Ordering::Relaxed),
                    Encryption::Odd => self.data_odd.fetch_add(1, Ordering::Relaxed),
                    Encryption::None => self.data_plain.fetch_add(1, Ordering::Relaxed),
                };
                if d.retransmitted {
                    self.retransmits.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(Packet::Control(c)) => match c.body {
                ControlBody::Nak { ref loss } => {
                    self.naks.fetch_add(1, Ordering::Relaxed);
                    if loss.iter().any(|r| !r.is_single()) {
                        self.nak_ranges.fetch_add(1, Ordering::Relaxed);
                    }
                }
                ControlBody::DropReq { .. } => {
                    self.dropreqs.fetch_add(1, Ordering::Relaxed);
                }
                ControlBody::Handshake(_) => {
                    self.handshakes.fetch_add(1, Ordering::Relaxed);
                }
                ControlBody::Shutdown => {
                    self.shutdowns.fetch_add(1, Ordering::Relaxed);
                }
                ControlBody::Raw {
                    control_type: ControlType::UserDefined,
                    subtype,
                    ..
                } => {
                    if subtype == EXT_KMREQ {
                        self.kmreq.fetch_add(1, Ordering::Relaxed);
                    } else if subtype == EXT_KMRSP {
                        self.kmrsp.fetch_add(1, Ordering::Relaxed);
                    }
                }
                _ => {}
            },
            Err(_) => {}
        }
    }

    pub fn get(c: &AtomicU32) -> u32 {
        c.load(Ordering::Relaxed)
    }
}

/// A deterministic `SplitMix64` for seeded loss (mirrors the sim harness).
pub struct Rng(pub u64);
impl Rng {
    pub fn next_unit(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        #[allow(clippy::cast_precision_loss)]
        let unit = ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64;
        unit
    }
}

pub type DropFilter = Box<dyn FnMut(&[u8]) -> bool + Send>;

/// Impairments for one proxy instance.
pub struct ProxyCfg {
    /// Independent drop probability per datagram, caller→listener / reverse.
    pub c2l_loss: f64,
    pub l2c_loss: f64,
    pub seed: u64,
    /// Fixed extra one-way delay applied to every forwarded datagram.
    pub delay: Duration,
    /// Targeted drop on the caller→listener direction (`true` = drop).
    pub c2l_drop: Option<DropFilter>,
    /// Targeted drop on the listener→caller direction (`true` = drop).
    pub l2c_drop: Option<DropFilter>,
}

impl Default for ProxyCfg {
    fn default() -> Self {
        ProxyCfg {
            c2l_loss: 0.0,
            l2c_loss: 0.0,
            seed: 1,
            delay: Duration::ZERO,
            c2l_drop: None,
            l2c_drop: None,
        }
    }
}

/// Starts a UDP relay on `front_port` forwarding to `backend_port` (localhost),
/// classifying every datagram into the returned [`WireCounts`] and applying the
/// configured impairments. The caller (whichever implementation it is) connects
/// to `front_port`; its address is learned from its first datagram.
pub async fn spawn_proxy(front_port: u16, backend_port: u16, mut cfg: ProxyCfg) -> Arc<WireCounts> {
    let counts = Arc::new(WireCounts::default());
    let task_counts = counts.clone();
    let front = UdpSocket::bind(("127.0.0.1", front_port))
        .await
        .expect("bind proxy front");
    let back = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .expect("bind proxy back");
    back.connect(("127.0.0.1", backend_port))
        .await
        .expect("connect proxy back");

    tokio::spawn(async move {
        let front = Arc::new(front);
        let back = Arc::new(back);
        let mut caller: Option<std::net::SocketAddr> = None;
        let mut buf_f = vec![0u8; 2048];
        let mut buf_b = vec![0u8; 2048];
        let mut rng = Rng(cfg.seed);
        loop {
            tokio::select! {
                r = front.recv_from(&mut buf_f) => {
                    let Ok((n, from)) = r else { break };
                    caller = Some(from);
                    let datagram = buf_f[..n].to_vec();
                    task_counts.classify(&datagram);
                    let targeted = cfg.c2l_drop.as_mut().is_some_and(|f| f(&datagram));
                    if targeted || (cfg.c2l_loss > 0.0 && rng.next_unit() < cfg.c2l_loss) {
                        task_counts.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if cfg.delay.is_zero() {
                        let _ = back.send(&datagram).await;
                    } else {
                        let back = back.clone();
                        let delay = cfg.delay;
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = back.send(&datagram).await;
                        });
                    }
                }
                r = back.recv(&mut buf_b) => {
                    let Ok(n) = r else { break };
                    let Some(to) = caller else { continue };
                    let datagram = buf_b[..n].to_vec();
                    task_counts.classify(&datagram);
                    let targeted = cfg.l2c_drop.as_mut().is_some_and(|f| f(&datagram));
                    if targeted || (cfg.l2c_loss > 0.0 && rng.next_unit() < cfg.l2c_loss) {
                        task_counts.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if cfg.delay.is_zero() {
                        let _ = front.send_to(&datagram, to).await;
                    } else {
                        let front = front.clone();
                        let delay = cfg.delay;
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = front.send_to(&datagram, to).await;
                        });
                    }
                }
            }
        }
    });
    counts
}

// ---- shared drivers ----

/// A tagged, fixed-size message body.
pub fn msg(i: u32, len: usize) -> Vec<u8> {
    let mut v = format!("imsg-{i:05}-").into_bytes();
    v.resize(len.max(11), b'.');
    v
}

/// Extracts the tag index from a forwarded message.
pub fn msg_index(bytes: &[u8]) -> Option<u32> {
    let s = std::str::from_utf8(bytes).ok()?;
    s.strip_prefix("imsg-")?.get(0..5)?.parse().ok()
}

/// Drives a srtrust caller through `target_port` (a libsrt listener or a proxy
/// front) and collects what the libsrt listener forwarded to the UDP sink.
/// Returns the received message indices, in arrival order.
pub async fn srtrust_sender_run(
    config: Config,
    target_port: u16,
    sink: &UdpSocket,
    messages: u32,
    pace: Duration,
    len: usize,
    settle: Duration,
) -> Vec<u32> {
    let stream = connect(format!("127.0.0.1:{target_port}"), config)
        .await
        .expect("srtrust caller connects to libsrt");

    for i in 0..messages {
        stream
            .send(Bytes::from(msg(i, len)))
            .await
            .expect("send to libsrt");
        if !pace.is_zero() {
            tokio::time::sleep(pace).await;
        }
    }
    collect_sink(sink, messages, settle).await
}

/// Collects tagged messages from a UDP sink until `expected` arrive or
/// `settle` elapses.
pub async fn collect_sink(sink: &UdpSocket, expected: u32, settle: Duration) -> Vec<u32> {
    let mut received = Vec::new();
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + settle;
    while received.len() < expected as usize {
        match tokio::time::timeout_at(deadline, sink.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if let Some(i) = msg_index(&buf[..n]) {
                    received.push(i);
                }
            }
            _ => break,
        }
    }
    received
}

/// Feeds `messages` UDP datagrams into a libsrt caller's input port at `pace`.
pub async fn feed_libsrt_input(in_port: u16, messages: u32, pace: Duration, len: usize) {
    let tx = UdpSocket::bind("127.0.0.1:0").await.expect("bind feeder");
    for i in 0..messages {
        let _ = tx.send_to(&msg(i, len), ("127.0.0.1", in_port)).await;
        tokio::time::sleep(pace).await;
    }
}

/// As [`feed_libsrt_input`] starting from an arbitrary tag base (multi-client
/// streams stay distinguishable).
pub async fn feed_libsrt_input_from(
    in_port: u16,
    base: u32,
    messages: u32,
    pace: Duration,
    len: usize,
) {
    let tx = UdpSocket::bind("127.0.0.1:0").await.expect("bind feeder");
    for i in 0..messages {
        let _ = tx
            .send_to(&msg(base + i, len), ("127.0.0.1", in_port))
            .await;
        tokio::time::sleep(pace).await;
    }
}

/// Receives until `expected` messages arrive (or `per_msg` elapses without one),
/// returning the indices in arrival order.
pub async fn recv_indices(
    server: &mut srt::SrtStream,
    expected: u32,
    per_msg: Duration,
) -> Vec<u32> {
    let mut got = Vec::new();
    while got.len() < expected as usize {
        match tokio::time::timeout(per_msg, server.recv()).await {
            Ok(Some(m)) => {
                if let Some(i) = msg_index(&m) {
                    got.push(i);
                }
            }
            _ => break,
        }
    }
    got
}

pub fn assert_all_in_order(received: &[u32], expected: u32, what: &str) {
    assert_eq!(
        received.len(),
        expected as usize,
        "{what}: expected {expected} messages, got {} (first missing: {:?})",
        received.len(),
        (0..expected).find(|i| !received.contains(i)),
    );
    assert!(
        received.windows(2).all(|w| w[0] < w[1]),
        "{what}: delivery must be strictly in order"
    );
}

/// Asserts an exactly-one-gap delivery: everything in `0..expected` except
/// `missing` arrived, in order.
pub fn assert_all_but_one(received: &[u32], expected: u32, missing: u32, what: &str) {
    assert_eq!(
        received.len(),
        expected as usize - 1,
        "{what}: expected {} messages (all but #{missing}), got {} (missing: {:?})",
        expected - 1,
        received.len(),
        (0..expected)
            .filter(|i| !received.contains(i))
            .collect::<Vec<_>>(),
    );
    assert!(
        !received.contains(&missing),
        "{what}: #{missing} was black-holed and must not arrive"
    );
    assert!(
        received.windows(2).all(|w| w[0] < w[1]),
        "{what}: delivery stays strictly in order across the drop"
    );
}
