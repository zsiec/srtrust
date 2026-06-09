//! The SRT listener (spec §4.3.1): answers INDUCTION requests with a SYN cookie
//! and, on a valid CONCLUSION, produces an accepted [`Connection`].
//!
//! The listener keeps **no per-peer state** during induction. The SYN cookie it
//! returns is a keyed hash of the peer's address (spec §4.3.1.1), so a flood of
//! induction requests costs it nothing to remember — the anti-DoS property that
//! makes a stateless listen possible, the same idea as TCP SYN cookies. Per-peer
//! state is allocated (a [`Connection`]) only once a returned cookie comes back
//! on a valid conclusion.
//!
//! Like [`Connection`], it is sans-I/O: datagrams and `now` come in; responses
//! and accepted connections drain out. Unlike a connection it is connectionless,
//! so each response is paired with the destination [`SocketAddr`].

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::connection::{Config, Connection, encode_control};
use crate::control::ControlBody;
use crate::handshake::{EncryptionField, Handshake, HandshakeType};
use crate::packet::{Packet, SocketId};
use crate::seq::SeqNumber;
use crate::timestamp::Timestamp;

/// The SRT magic the Listener echoes in an induction response (spec §4.3.1.1).
const SRT_MAGIC: u16 = 0x4A17;
/// The SRT (`HSv5`) protocol version the Listener speaks.
const HS_VERSION_SRT: u32 = 5;
/// Cookie validity granularity: one minute (spec §4.3.1.1). A conclusion is
/// accepted if its cookie matches the current or the previous minute's value.
const COOKIE_QUANTUM: Duration = Duration::from_secs(60);

/// A listening SRT endpoint that accepts caller connections (spec §4.3.1).
#[derive(Debug)]
pub struct Listener {
    config: Config,
    local_socket_id: SocketId,
    local_initial_seq: SeqNumber,
    cookie_secret: u64,
    /// The timestamp / cookie-expiry epoch.
    start: Instant,
    /// Induction responses / rejections awaiting [`Listener::poll_response`].
    responses: VecDeque<(SocketAddr, Bytes)>,
    /// Connections accepted on a valid conclusion, awaiting
    /// [`Listener::poll_accept`].
    accepted: VecDeque<Connection>,
}

impl Listener {
    /// Creates a listener. `local_initial_seq` is the initial sequence number
    /// assigned to the connection it accepts (injected randomness; v1 accepts a
    /// single connection per listener). `cookie_secret` keys the SYN-cookie hash;
    /// `now` becomes the cookie-expiry epoch.
    #[must_use]
    pub fn new(
        config: Config,
        local_socket_id: SocketId,
        local_initial_seq: SeqNumber,
        cookie_secret: u64,
        now: Instant,
    ) -> Self {
        Listener {
            config,
            local_socket_id,
            local_initial_seq,
            cookie_secret,
            start: now,
            responses: VecDeque::new(),
            accepted: VecDeque::new(),
        }
    }

    /// Feeds one received datagram, tagged with the peer address it came `from`
    /// (needed to craft and later validate the SYN cookie). May enqueue a
    /// response and, on a valid conclusion, an accepted connection.
    pub fn feed_recv_buf(&mut self, datagram: &[u8], from: SocketAddr, now: Instant) {
        let Ok(Packet::Control(ctrl)) = Packet::decode(datagram) else {
            return;
        };
        let ControlBody::Handshake(hs) = ctrl.body else {
            return;
        };
        match hs.handshake_type {
            HandshakeType::INDUCTION => self.on_induction(&hs, from, now),
            HandshakeType::CONCLUSION => self.on_conclusion(&hs, from, now),
            _ => {}
        }
    }

    /// Answers an induction request with version 5, the SRT magic, and a fresh
    /// SYN cookie (spec §4.3.1.1). The Listener allocates no state here.
    fn on_induction(&mut self, request: &Handshake, from: SocketAddr, now: Instant) {
        let response = Handshake {
            version: HS_VERSION_SRT,
            encryption: EncryptionField::None,
            extension_field: SRT_MAGIC,
            initial_seq: self.local_initial_seq,
            mtu: self.config.mtu,
            max_flow_window: self.config.flow_window,
            handshake_type: HandshakeType::INDUCTION,
            srt_socket_id: self.local_socket_id,
            syn_cookie: self.cookie(from, self.quantum(now)),
            peer_ip: peer_ip(from),
            extensions: Vec::new(),
        };
        // The response is addressed to the caller's socket id.
        let bytes = encode_control(
            request.srt_socket_id,
            self.wire_ts(now),
            ControlBody::Handshake(response),
        );
        self.responses.push_back((from, bytes));
    }

    /// Validates a conclusion's cookie and, if it checks out, spawns the accepted
    /// connection (spec §4.3.1.2). An invalid cookie — or an encryption mismatch
    /// (wrong passphrase / missing key material) — is silently dropped, leaving
    /// the caller to time out.
    fn on_conclusion(&mut self, conclusion: &Handshake, from: SocketAddr, now: Instant) {
        if !self.cookie_valid(conclusion.syn_cookie, from, now) {
            return;
        }
        if let Ok(conn) = Connection::accept(
            self.config.clone(),
            self.local_socket_id,
            self.local_initial_seq,
            conclusion,
            now,
        ) {
            self.accepted.push_back(conn);
        }
    }

    /// Drains the next response datagram and the address to send it to, if any.
    #[must_use]
    pub fn poll_response(&mut self) -> Option<(SocketAddr, Bytes)> {
        self.responses.pop_front()
    }

    /// Drains the next freshly-accepted [`Connection`], if any.
    #[must_use]
    pub fn poll_accept(&mut self) -> Option<Connection> {
        self.accepted.pop_front()
    }

    // ---- SYN cookie + time ----

    /// The current cookie time quantum: whole minutes since `start`.
    fn quantum(&self, now: Instant) -> u64 {
        (now.saturating_duration_since(self.start).as_secs()) / COOKIE_QUANTUM.as_secs()
    }

    /// The cookie for `from` in time quantum `q`.
    fn cookie(&self, from: SocketAddr, q: u64) -> u32 {
        syn_cookie(self.cookie_secret, from, q)
    }

    /// Whether `cookie` matches the current or previous quantum (the 1-minute
    /// acceptance window, spec §4.3.1.1).
    fn cookie_valid(&self, cookie: u32, from: SocketAddr, now: Instant) -> bool {
        let q = self.quantum(now);
        cookie == self.cookie(from, q) || (q > 0 && cookie == self.cookie(from, q - 1))
    }

    /// A wire timestamp at `now`: microseconds since `start`, wrapping per §3.1.
    #[allow(clippy::cast_possible_truncation)] // 32-bit wrapping timestamp by design
    fn wire_ts(&self, now: Instant) -> Timestamp {
        Timestamp::from_micros(now.saturating_duration_since(self.start).as_micros() as u32)
    }
}

/// A keyed, non-cryptographic SYN cookie (FNV-1a over the peer address, port, and
/// time quantum, mixed with the secret).
///
/// This deviates from libsrt's MD5-based cookie (spec §4.3.1.1 leaves the exact
/// construction unspecified): it is deterministic and dependency-free, which
/// suits the sans-I/O core. Revisit if exact libsrt cookie interop is needed.
fn syn_cookie(secret: u64, from: SocketAddr, quantum: u64) -> u32 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET ^ secret;
    let mut mix = |byte: u8| {
        h ^= u64::from(byte);
        h = h.wrapping_mul(FNV_PRIME);
    };
    match from.ip() {
        IpAddr::V4(a) => a.octets().iter().for_each(|&b| mix(b)),
        IpAddr::V6(a) => a.octets().iter().for_each(|&b| mix(b)),
    }
    from.port().to_be_bytes().iter().for_each(|&b| mix(b));
    quantum.to_be_bytes().iter().for_each(|&b| mix(b));
    // Fold the 64-bit hash down to the 32-bit cookie field.
    #[allow(clippy::cast_possible_truncation)] // deliberate fold to 32 bits
    let cookie = (h ^ (h >> 32)) as u32;
    cookie
}

/// Encodes a peer address into the handshake's 128-bit peer-IP field (spec
/// §3.2.1): IPv4 occupies the first four bytes, the rest zero.
fn peer_ip(from: SocketAddr) -> [u8; 16] {
    let mut ip = [0u8; 16];
    match from.ip() {
        IpAddr::V4(a) => ip[..4].copy_from_slice(&a.octets()),
        IpAddr::V6(a) => ip.copy_from_slice(&a.octets()),
    }
    ip
}
