//! The connection's two output vocabularies.
//!
//! A [`Connection`](super::Connection) emits nothing directly; it queues
//! [`Event`]s for the application (drained via
//! [`poll_event`](super::Connection::poll_event)) and [`Output`]s for the I/O
//! layer (drained via [`poll_output`](super::Connection::poll_output)). [`TimerId`]
//! names the declarative timers the core asks the I/O layer to run.

use std::time::Duration;

use bytes::Bytes;

use super::Negotiated;
use crate::error::ConnectionError;

/// An application-facing event drained from [`poll_event`](super::Connection::poll_event).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The handshake completed; the connection is usable. Carries the
    /// negotiated parameters.
    Connected(Negotiated),
    /// In-order application data delivered to the receiver (ARQ).
    DataReceived(Bytes),
    /// The connection failed — either it never established, or it was torn down.
    Failed(ConnectionError),
    /// The peer sent a SHUTDOWN; the connection is closed.
    Closed,
    /// The current encryption key is due for rotation (spec §6.1.6): the embedder
    /// must supply `key_size` fresh random bytes via
    /// [`provide_rekey`](super::Connection::provide_rekey). The core never generates
    /// randomness itself.
    KeyRefreshNeeded {
        /// Number of random bytes the new Stream Encrypting Key needs.
        key_size: usize,
    },
}

/// A wire- or timer-facing effect drained from [`poll_output`](super::Connection::poll_output).
///
/// A [`Connection`](super::Connection) is point-to-point, so [`Output::SendDatagram`]
/// needs no address: the I/O layer already knows this connection's single peer.
/// Timers are *declarative* — the core asks for them by [`TimerId`]; the I/O layer
/// owns the actual timer wheel (the shiguredo / quinn-proto pattern).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Output {
    /// Send this fully-encoded datagram to the peer.
    SendDatagram(Bytes),
    /// Arm (or re-arm) the timer `id` to fire `after` from *now*.
    SetTimer {
        /// Which logical timer to arm.
        id: TimerId,
        /// How far in the future it should fire.
        after: Duration,
    },
    /// Cancel the timer `id` if it is armed.
    ClearTimer {
        /// Which logical timer to cancel.
        id: TimerId,
    },
}

/// The set of logical timers the connection multiplexes. Starts minimal and
/// grows per the build order; the I/O layer keeps one real deadline per id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum TimerId {
    /// Caller: resend the induction/conclusion handshake until answered, giving
    /// up after the configured connect timeout (attempt count lives in state, so
    /// one timer covers the whole exchange).
    Handshake,
    /// Receiver: periodic full acknowledgement (spec §4.8.1).
    Ack,
    /// Receiver: periodic loss report / NAK (spec §4.8.2).
    Nak,
    /// Sender: expiration / retransmission timeout, the backstop when no ACK
    /// arrives (spec §4.8). Re-armed on send activity, reset by an incoming ACK.
    Exp,
    /// Receiver: timestamp-based delivery — fires when the next buffered packet
    /// reaches its play time (spec §4.5).
    Tsbpd,
    /// Sender: `LiveCC` pacing — fires when the next queued packet may be sent
    /// (spec §5.1).
    SndPacing,
    /// Sender: graceful-close linger cap — forces SHUTDOWN if the outstanding
    /// data has not drained within the linger window (e.g. the peer vanished).
    Linger,
    /// Periodic keepalive: emits a KEEPALIVE when the connection has been idle for
    /// a keepalive period, so an idle peer does not time us out (spec §3.2.6).
    Keepalive,
    /// Idle / dead-peer timeout: fails the connection if no packet arrives from the
    /// peer for the idle window (libsrt's `SRTO_PEERIDLETIMEO`).
    PeerIdle,
}
