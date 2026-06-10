//! Embedder-supplied configuration and handshake-negotiated parameters.
//!
//! These are the plain data types at the edges of a [`Connection`](super::Connection):
//! [`Config`] (and its [`FecConfig`]/[`EncryptionSettings`]/[`KeySize`] parts) goes
//! *in* when the connection is created; [`Negotiated`] comes *out* when the
//! handshake completes. None of them touch connection state, so they live apart
//! from the state machine.

use std::time::Duration;

use crate::crypto::CipherMode;
use crate::error::ConfigError;
use crate::handshake::EncryptionField;
use crate::packet::SocketId;
use crate::seq::SeqNumber;

/// Immutable per-connection configuration supplied by the embedder.
///
/// Build one from [`Config::default`] (deployment-ready values) and refine it
/// with the `with_*` builders; [`Config::validate`] is the gate the `srt` I/O
/// crate applies at `connect`/`bind`, enforcing the limits libsrt enforces on
/// *its* side — a locally-accepted but peer-rejected value (a 5-character
/// passphrase, say) otherwise surfaces as a silent handshake timeout.
///
/// `#[non_exhaustive]`: construct via `Config::default()` + builders (or field
/// mutation); new knobs can then be added without breaking embedders.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// TSBPD latency to advertise. Sent on the wire as whole milliseconds
    /// (spec §3.2.1.1, the receiver/sender TSBPD delay fields). The connection
    /// uses the **negotiated** latency — the larger of the two advertised
    /// values (spec §4.3.1.2).
    pub latency: Duration,
    /// Maximum transmission unit, bytes (spec §3.2.1, the MTU field).
    pub mtu: u32,
    /// Maximum flow-window size, packets (spec §3.2.1). Steady-state
    /// throughput caps near `flow_window / latency` packets per second; size
    /// it at least `2 × rate × latency` (see `docs/bench.md`).
    pub flow_window: u32,
    /// Stream ID to advertise on the caller side, if any (spec §3.2.1.3).
    pub stream_id: Option<String>,
    /// Encryption settings (spec §6); `None` for an unencrypted connection.
    pub encryption: Option<EncryptionSettings>,
    /// Maximum sending bandwidth in bytes per second for `LiveCC` pacing (`MAX_BW`,
    /// spec §5.1). `0` disables pacing (send as fast as submitted).
    pub max_bw: u64,
    /// Packets to send under one Stream Encrypting Key before rotating to a fresh
    /// one (libsrt's `SRTO_KMREFRESHRATE`, spec §6.1.6). `0` selects the default
    /// ([`KM_REFRESH_DEFAULT`](super::KM_REFRESH_DEFAULT)). Only relevant for an
    /// encrypted connection.
    pub km_refresh_rate: u32,
    /// Forward-error-correction settings (libsrt's `SRTO_PACKETFILTER`); `None`
    /// disables FEC. v1 emits and decodes **row** parity only. Both peers must
    /// agree on the group geometry out of band (handshake negotiation is future
    /// work), and FEC is incompatible with AES-GCM (the XOR clip breaks the auth
    /// tag — use AES-CTR or plaintext).
    pub fec: Option<FecConfig>,
    /// How long a caller keeps retrying the handshake before giving up
    /// (libsrt's `SRTO_CONNTIMEO`).
    pub connect_timeout: Duration,
    /// How long an established connection tolerates total silence from the
    /// peer before failing (libsrt's `SRTO_PEERIDLETIMEO`). Keepalives flow
    /// every second, so a healthy peer never approaches this.
    pub peer_idle_timeout: Duration,
    /// How long a closing connection lingers to drain unacknowledged data
    /// before sending SHUTDOWN regardless (cf. libsrt's `SRTO_LINGER`).
    pub linger: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            latency: Duration::from_millis(120),
            mtu: 1500,
            // Bench-informed (docs/bench.md): 8192 at the default latency caps
            // loopback throughput well below the transport's capability.
            flow_window: 25600,
            stream_id: None,
            encryption: None,
            max_bw: 0,
            km_refresh_rate: 0,
            fec: None,
            connect_timeout: Duration::from_secs(3),
            peer_idle_timeout: Duration::from_secs(5),
            linger: Duration::from_secs(3),
        }
    }
}

// Validation limits (libsrt-aligned where libsrt enforces one).
const MIN_LATENCY: Duration = Duration::from_millis(20);
const MIN_MTU: u32 = 76; // IP + UDP + SRT headers
const MAX_MTU: u32 = 1500;
const MIN_FLOW_WINDOW: u32 = 32;
const MIN_PASSPHRASE: usize = 10; // libsrt HAICRYPT secret limits
const MAX_PASSPHRASE: usize = 79;
const MIN_CONNECT_TIMEOUT: Duration = Duration::from_millis(100);
const MIN_PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(1);

impl Config {
    /// Replaces the advertised TSBPD latency.
    #[must_use]
    pub fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    /// Replaces the MTU.
    #[must_use]
    pub fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Replaces the flow window (packets).
    #[must_use]
    pub fn with_flow_window(mut self, packets: u32) -> Self {
        self.flow_window = packets;
        self
    }

    /// Sets the Stream ID to advertise when calling.
    #[must_use]
    pub fn with_stream_id(mut self, stream_id: impl Into<String>) -> Self {
        self.stream_id = Some(stream_id.into());
        self
    }

    /// Enables AES-128-CTR encryption with `passphrase` (the common case; use
    /// [`with_encryption`](Config::with_encryption) for other key sizes or
    /// AES-GCM).
    #[must_use]
    pub fn with_passphrase(mut self, passphrase: impl Into<Vec<u8>>) -> Self {
        self.encryption = Some(EncryptionSettings {
            passphrase: passphrase.into(),
            key_size: KeySize::Aes128,
            cipher: CipherMode::Ctr,
        });
        self
    }

    /// Sets the full encryption settings.
    #[must_use]
    pub fn with_encryption(mut self, encryption: EncryptionSettings) -> Self {
        self.encryption = Some(encryption);
        self
    }

    /// Sets the pacing bandwidth in bytes per second (`0` = unpaced).
    #[must_use]
    pub fn with_max_bw(mut self, bytes_per_second: u64) -> Self {
        self.max_bw = bytes_per_second;
        self
    }

    /// Sets the key refresh rate in packets (`0` = the default).
    #[must_use]
    pub fn with_km_refresh_rate(mut self, packets: u32) -> Self {
        self.km_refresh_rate = packets;
        self
    }

    /// Enables row FEC with the given group geometry.
    #[must_use]
    pub fn with_fec(mut self, fec: FecConfig) -> Self {
        self.fec = Some(fec);
        self
    }

    /// Sets the handshake timeout.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the peer-idle (dead peer) timeout.
    #[must_use]
    pub fn with_peer_idle_timeout(mut self, timeout: Duration) -> Self {
        self.peer_idle_timeout = timeout;
        self
    }

    /// Sets the close linger window.
    #[must_use]
    pub fn with_linger(mut self, linger: Duration) -> Self {
        self.linger = linger;
        self
    }

    /// Checks every limit a peer (or the protocol) would enforce anyway, so a
    /// bad value fails *here, with a reason* instead of as a silent handshake
    /// timeout. The `srt` I/O crate calls this at `connect`/`bind`; embedders
    /// driving the core directly should too.
    ///
    /// # Errors
    ///
    /// Returns the first [`ConfigError`] found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.latency < MIN_LATENCY {
            return Err(ConfigError::LatencyTooLow {
                min_ms: MIN_LATENCY.as_millis().try_into().unwrap_or(u64::MAX),
            });
        }
        if !(MIN_MTU..=MAX_MTU).contains(&self.mtu) {
            return Err(ConfigError::MtuOutOfRange { mtu: self.mtu });
        }
        if self.flow_window < MIN_FLOW_WINDOW {
            return Err(ConfigError::FlowWindowTooSmall {
                min: MIN_FLOW_WINDOW,
            });
        }
        if let Some(enc) = &self.encryption {
            let len = enc.passphrase.len();
            if !(MIN_PASSPHRASE..=MAX_PASSPHRASE).contains(&len) {
                return Err(ConfigError::PassphraseLength { len });
            }
        }
        if self.connect_timeout < MIN_CONNECT_TIMEOUT {
            return Err(ConfigError::ConnectTimeoutTooLow);
        }
        if self.peer_idle_timeout < MIN_PEER_IDLE_TIMEOUT {
            return Err(ConfigError::PeerIdleTimeoutTooLow);
        }
        Ok(())
    }
}

/// Forward-error-correction parameters (row XOR FEC, libsrt-compatible wire
/// format). One parity packet is emitted per group of `group_size` consecutive
/// data packets; a single lost member of a group is rebuilt at the receiver
/// without a retransmission round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecConfig {
    /// Data packets per row group (floored at 2). Larger groups cost less overhead
    /// (one parity per N packets) but recover only one loss per N packets.
    pub group_size: usize,
}

/// AES key size for the stream cipher (spec §3.2.1, Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySize {
    /// AES-128 (16-byte key).
    Aes128,
    /// AES-192 (24-byte key).
    Aes192,
    /// AES-256 (32-byte key).
    Aes256,
}

impl KeySize {
    /// The key length in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            KeySize::Aes128 => 16,
            KeySize::Aes192 => 24,
            KeySize::Aes256 => 32,
        }
    }

    /// The matching handshake encryption-field value.
    pub(super) const fn to_field(self) -> EncryptionField {
        match self {
            KeySize::Aes128 => EncryptionField::Aes128,
            KeySize::Aes192 => EncryptionField::Aes192,
            KeySize::Aes256 => EncryptionField::Aes256,
        }
    }
}

/// Encryption configuration: the shared passphrase and the key size to use
/// (spec §6). Both peers must configure the same passphrase.
#[derive(Debug, Clone)]
pub struct EncryptionSettings {
    /// The pre-shared passphrase from which the KEK is derived.
    pub passphrase: Vec<u8>,
    /// The AES key size for the stream cipher.
    pub key_size: KeySize,
    /// The payload cipher mode: [`CipherMode::Ctr`] (default) or
    /// [`CipherMode::Gcm`] (authenticated). The caller chooses; the acceptor
    /// adopts whatever the caller's Key Material announces (`CryptoModeAuto`).
    pub cipher: CipherMode,
}

/// The parameters negotiated by a completed handshake, reported with
/// [`Event::Connected`](super::Event::Connected). `#[non_exhaustive]` so it can
/// grow (encryption, the peer's Stream ID, capability flags) without breaking
/// embedders.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Negotiated {
    /// The peer's SRT socket id, used as the destination of every packet we send.
    pub peer_socket_id: SocketId,
    /// The peer's initial sequence number (the first data packet it will send).
    pub peer_initial_seq: SeqNumber,
    /// The agreed TSBPD latency (the larger of the two advertised delays).
    pub latency: Duration,
    /// The agreed encryption.
    pub encryption: EncryptionField,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_deployment_ready() {
        let c = Config::default();
        assert_eq!(c.latency, Duration::from_millis(120));
        assert_eq!(c.mtu, 1500);
        // Bench-informed: throughput caps near flow_window/latency, and 8192
        // at 120 ms throttled a loopback stream to ~650 Mbps (docs/bench.md).
        assert_eq!(c.flow_window, 25600);
        assert_eq!(c.max_bw, 0);
        assert_eq!(c.km_refresh_rate, 0);
        assert!(c.stream_id.is_none());
        assert!(c.encryption.is_none());
        assert!(c.fec.is_none());
        assert_eq!(c.connect_timeout, Duration::from_secs(3));
        assert_eq!(c.peer_idle_timeout, Duration::from_secs(5));
        assert_eq!(c.linger, Duration::from_secs(3));
        assert!(c.validate().is_ok(), "the default config validates");
    }

    #[test]
    fn builders_chain_and_set() {
        let c = Config::default()
            .with_latency(Duration::from_millis(300))
            .with_mtu(1400)
            .with_flow_window(8192)
            .with_stream_id("live/cam1")
            .with_passphrase("0123456789abcdef")
            .with_max_bw(125_000_000)
            .with_connect_timeout(Duration::from_secs(1))
            .with_peer_idle_timeout(Duration::from_secs(10))
            .with_linger(Duration::from_secs(1));
        assert_eq!(c.latency, Duration::from_millis(300));
        assert_eq!(c.mtu, 1400);
        assert_eq!(c.flow_window, 8192);
        assert_eq!(c.stream_id.as_deref(), Some("live/cam1"));
        let enc = c.encryption.as_ref().expect("passphrase set");
        assert_eq!(enc.passphrase, b"0123456789abcdef");
        assert!(matches!(enc.key_size, KeySize::Aes128));
        assert!(matches!(enc.cipher, CipherMode::Ctr));
        assert_eq!(c.max_bw, 125_000_000);
        assert_eq!(c.connect_timeout, Duration::from_secs(1));
        assert_eq!(c.peer_idle_timeout, Duration::from_secs(10));
        assert_eq!(c.linger, Duration::from_secs(1));
        assert!(c.validate().is_ok());
    }

    /// libsrt enforces 10–79 byte passphrases (HAICRYPT limits); accepting an
    /// out-of-range one locally produces a silent handshake timeout against
    /// libsrt — validation turns that into an immediate, explainable error.
    #[test]
    fn validation_enforces_srt_limits() {
        let bad = |c: Config| c.validate().expect_err("must be rejected");

        bad(Config::default().with_passphrase("short"));
        bad(Config::default().with_passphrase("x".repeat(80)));
        assert!(
            Config::default()
                .with_passphrase("0123456789")
                .validate()
                .is_ok(),
            "10 bytes is the minimum valid passphrase"
        );
        assert!(
            Config::default()
                .with_passphrase("x".repeat(79))
                .validate()
                .is_ok(),
            "79 bytes is the maximum valid passphrase"
        );

        bad(Config::default().with_latency(Duration::from_millis(5)));
        bad(Config::default().with_mtu(75));
        bad(Config::default().with_mtu(1501));
        bad(Config::default().with_flow_window(16));
        bad(Config::default().with_connect_timeout(Duration::from_millis(50)));
        bad(Config::default().with_peer_idle_timeout(Duration::from_millis(500)));
    }
}
