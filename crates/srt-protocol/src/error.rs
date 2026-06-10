//! Error types for the SRT protocol crate.
//!
//! Errors are layered by abstraction: the loss-list and control-body codecs
//! have their own enums, the [`PacketError`] codec layer wraps them with
//! `#[from]`, and the connection layer's [`ConnectionError`] sits above the
//! packet layer. Every public error enum is `#[non_exhaustive]` so adding
//! variants later is not a breaking change.

/// Failure of an SRT connection (spec §4), the layer above the packet codec.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectionError {
    /// The connect attempt timed out before the handshake completed (spec §4.3).
    #[error("connection timed out during handshake")]
    HandshakeTimeout,

    /// An established connection received nothing from the peer for the idle
    /// timeout (the peer vanished); libsrt's `SRTO_PEERIDLETIMEO`.
    #[error("connection timed out: no packets from the peer")]
    Timeout,

    /// The peer rejected the handshake, carrying the reason it sent
    /// (spec §4.3, Table 7 of handshake rejection reasons).
    #[error("peer rejected handshake: {0}")]
    Rejected(crate::handshake::RejectReason),

    /// The local application called a method the current state forbids (e.g.
    /// sending on a connection that is not yet established or already closed).
    #[error("connection is not in a state that allows this operation")]
    InvalidState,

    /// A received packet could not be decoded.
    #[error(transparent)]
    Decode(#[from] PacketError),

    /// Encryption setup failed (wrong passphrase, missing or malformed key
    /// material).
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// An invalid [`Config`](crate::connection::Config) value, caught by
/// [`Config::validate`](crate::connection::Config::validate) before any
/// packet leaves — each limit here is one a peer (or the protocol itself)
/// would otherwise enforce as a silent handshake failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// TSBPD latency below the protocol's useful floor.
    #[error("latency below the {min_ms} ms minimum")]
    LatencyTooLow {
        /// The enforced floor in milliseconds.
        min_ms: u64,
    },

    /// MTU outside the 76–1500 byte range SRT can carry over UDP/IP.
    #[error("mtu {mtu} outside the supported 76–1500 byte range")]
    MtuOutOfRange {
        /// The rejected value.
        mtu: u32,
    },

    /// Flow window too small to sustain a connection (libsrt's `SRTO_FC` floor).
    #[error("flow window below the {min}-packet minimum")]
    FlowWindowTooSmall {
        /// The enforced floor in packets.
        min: u32,
    },

    /// Passphrase outside libsrt's accepted 10–79 byte range — a peer running
    /// libsrt would refuse the handshake.
    #[error("passphrase length {len} outside the accepted 10–79 byte range")]
    PassphraseLength {
        /// The rejected length in bytes.
        len: usize,
    },

    /// Connect timeout too short for even one handshake round trip.
    #[error("connect timeout below the 100 ms minimum")]
    ConnectTimeoutTooLow,

    /// Peer-idle timeout shorter than the keepalive period; every healthy
    /// connection would be declared dead.
    #[error("peer idle timeout below the 1 s minimum")]
    PeerIdleTimeoutTooLow,
}

/// Failure in the encryption layer (spec §3.2.2, §6): Key Material decoding, key
/// derivation, or key unwrapping.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// A Key Material message was shorter than required.
    #[error("key material too short: need at least {need} bytes, got {got}")]
    TooShort {
        /// Minimum number of bytes required.
        need: usize,
        /// Number of bytes actually present.
        got: usize,
    },

    /// The Key Material version field was not the supported value (1).
    #[error("unsupported key material version {0}")]
    UnsupportedVersion(u8),

    /// The Key Material packet-type field was not `KMmsg` (2).
    #[error("unexpected key material packet type {0}")]
    InvalidPacketType(u8),

    /// The Key Material signature was not the expected `0x2029` ('HAI').
    #[error("invalid key material signature {0:#06x}")]
    InvalidSignature(u16),

    /// The KK (key-flags) field was `00` (no key) or otherwise invalid.
    #[error("invalid key material key flags {0:#04b}")]
    InvalidKeyFlags(u8),

    /// The cipher field named an unsupported cipher (only AES-CTR is supported).
    #[error("unsupported key material cipher {0}")]
    UnsupportedCipher(u8),

    /// The salt length was not the only supported value (128 bits).
    #[error("invalid key material salt length {0} bytes")]
    InvalidSaltLength(usize),

    /// The key length was not 16, 24, or 32 bytes (AES-128/192/256).
    #[error("invalid key material key length {0} bytes")]
    InvalidKeyLength(usize),

    /// Key unwrap failed its integrity check — the KEK (passphrase) is wrong.
    #[error("key unwrap integrity check failed (wrong passphrase)")]
    IntegrityCheckFailed,

    /// AES-GCM authentication failed: the tag did not verify (tampered, corrupt,
    /// or wrong key).
    #[error("aes-gcm authentication failed")]
    AuthFailed,

    /// An encrypted connection was required but the peer supplied no Key Material.
    #[error("no key material provided for an encrypted connection")]
    MissingKeyMaterial,

    /// The peer offered Key Material but this side is configured without
    /// encryption — exactly one side wants the connection secured.
    #[error("peer key material offered on an unencrypted connection")]
    UnexpectedKeyMaterial,
}

/// Failure while decoding a packet from raw bytes (spec §3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PacketError {
    /// The buffer is smaller than the 16-byte common header.
    #[error("packet too short: need at least {need} bytes, got {got}")]
    TooShort {
        /// Minimum number of bytes required.
        need: usize,
        /// Number of bytes actually present.
        got: usize,
    },

    /// A data packet carried key flag `0b11`; "both keys" is only valid inside a
    /// Key Material message, never on a data packet (spec §3.1, §3.2.2).
    #[error("invalid data-packet key flag {0:#04b}")]
    InvalidKeyFlag(u8),

    /// The control packet body could not be decoded.
    #[error(transparent)]
    Control(#[from] ControlError),
}

/// Failure while decoding a control packet body / CIF (spec §3.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    /// The 15-bit control type field matched no known control packet.
    #[error("unknown control packet type {0:#06x}")]
    UnknownType(u16),

    /// A control packet's CIF was not the size its type requires.
    #[error("{kind} control packet has invalid CIF length {len}")]
    InvalidCifLength {
        /// Human-readable name of the control packet type.
        kind: &'static str,
        /// The CIF length that was actually present.
        len: usize,
    },

    /// The NAK loss list inside the CIF was malformed.
    #[error(transparent)]
    LossList(#[from] LossListError),

    /// The handshake body was malformed.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
}

/// Failure while decoding a handshake control body (spec §3.2.1, §4.3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The CIF is shorter than the fixed handshake header.
    #[error("handshake too short: need at least {need} bytes, got {got}")]
    TooShort {
        /// Minimum number of bytes required.
        need: usize,
        /// Number of bytes actually present.
        got: usize,
    },

    /// The encryption field held a value the spec does not define.
    #[error("unknown handshake encryption field {0}")]
    InvalidEncryptionField(u16),

    /// A handshake extension declared a length that runs past the buffer, or was
    /// too short for its type.
    #[error(
        "handshake extension {ext_type:#06x} has invalid length (claimed {claimed} bytes, {available} available)"
    )]
    ExtensionLength {
        /// The extension type whose length was wrong.
        ext_type: u16,
        /// The content length the extension claimed (bytes).
        claimed: usize,
        /// The number of bytes actually available.
        available: usize,
    },

    /// An extension's content was the wrong size for its type (e.g. an HSREQ
    /// that was not exactly 12 bytes).
    #[error("handshake extension {ext_type:#06x} has wrong content size {len}")]
    ExtensionContent {
        /// The extension type.
        ext_type: u16,
        /// The content length that was present.
        len: usize,
    },

    /// The Stream ID extension did not contain valid UTF-8.
    #[error("handshake stream id is not valid UTF-8")]
    InvalidStreamId,
}

/// Failure while decoding a NAK loss list (spec §3.2.5, Appendix A).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LossListError {
    /// The loss list is not a whole number of 32-bit words.
    #[error("loss list length {0} is not a multiple of 4 bytes")]
    Misaligned(usize),

    /// A range-start word (high bit set) was the last word, with no end word.
    #[error("loss list ended mid-range: a range-start word had no end word")]
    TruncatedRange,
}
