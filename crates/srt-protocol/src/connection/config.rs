//! Embedder-supplied configuration and handshake-negotiated parameters.
//!
//! These are the plain data types at the edges of a [`Connection`](super::Connection):
//! [`Config`] (and its [`FecConfig`]/[`EncryptionSettings`]/[`KeySize`] parts) goes
//! *in* when the connection is created; [`Negotiated`] comes *out* when the
//! handshake completes. None of them touch connection state, so they live apart
//! from the state machine.

use std::time::Duration;

use crate::crypto::CipherMode;
use crate::handshake::EncryptionField;
use crate::packet::SocketId;
use crate::seq::SeqNumber;

/// Immutable per-connection configuration supplied by the embedder.
///
/// This is intentionally small for now; encryption material, timeouts, and
/// congestion-control knobs join it as their layers are built.
#[derive(Debug, Clone)]
pub struct Config {
    /// TSBPD latency to advertise. Sent on the wire as whole milliseconds
    /// (spec §3.2.1.1, the receiver/sender TSBPD delay fields).
    pub latency: Duration,
    /// Maximum transmission unit, bytes (spec §3.2.1, the MTU field).
    pub mtu: u32,
    /// Maximum flow-window size, packets (spec §3.2.1).
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
