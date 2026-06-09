//! The SRT connection state machine (spec §4).
//!
//! A [`Connection`] is a pure, deterministic state machine for one SRT
//! connection. It never touches a socket or reads the clock: time enters through
//! the `now: Instant` arguments and every effect leaves through one of two
//! drained queues — [`poll_event`](Connection::poll_event) (application-facing)
//! and [`poll_output`](Connection::poll_output) (wire- and timer-facing). The
//! I/O layer (or the test simulator) owns the UDP socket and the timer wheel and
//! merely obeys the [`Output`] requests it drains.
//!
//! `now` is an opaque monotonic *value*: the embedder reads its clock and passes
//! the result in. The core never calls `Instant::now()`, so the whole machine is
//! a deterministic function of its inputs — which is what makes it exhaustively
//! testable.

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use bytes::{Bytes, BytesMut};

use crate::control::{ControlBody, ControlType};
pub use crate::crypto::CipherMode;
use crate::crypto::{SessionCrypto, SessionKeys};
use crate::drift::DriftTracer;
use crate::error::ConnectionError;
use crate::fec::{FecEncoder, FecReceiver};
use crate::handshake::{Handshake, HandshakeExtension, HandshakeType};
use crate::live_cc::LiveCc;
use crate::packet::{ControlPacket, DataPacket, MsgNumber, Packet, PacketPosition, SocketId};
use crate::rate::RateEstimator;
use crate::recv_buffer::RecvBuffer;
use crate::rtt::RttEstimator;
use crate::send_buffer::SendBuffer;
use crate::seq::SeqNumber;
use crate::stats::Stats;
use crate::timestamp::Timestamp;

mod arq;
mod config;
mod event;
mod rekey;
mod setup;

pub use config::{Config, EncryptionSettings, FecConfig, KeySize, Negotiated};
pub use event::{Event, Output, TimerId};
use setup::{accept_crypto, millis_u16, negotiate, srt_handshake_ext};

// Handshake wire constants (spec §3.2.1, §4.3.1).

/// The version a Caller advertises in the *induction* handshake. It is 4 (UDT),
/// a compatibility artifact of SRT's UDT heritage (spec §4.3.1.1).
const HS_VERSION_UDT: u32 = 4;
/// The SRT (`HSv5`) protocol version, used from the induction *response* onward.
const HS_VERSION_SRT: u32 = 5;
/// The "SRT magic" a Listener echoes in its induction response's extension field
/// to prove it speaks SRT, not bare UDT (spec §4.3.1.1).
const SRT_MAGIC: u16 = 0x4A17;
/// The Caller's induction extension-field value (spec §4.3.1.1).
const INDUCTION_EXT_FIELD: u16 = 2;
/// Conclusion extension-field flag: an HSREQ/HSRSP extension is present
/// (spec §3.2.1, Table 3).
const EXT_FLAG_HSREQ: u16 = 0x0001;
/// Conclusion extension-field flag: a CONFIG extension (e.g. Stream ID) is
/// present (spec §3.2.1, Table 3).
const EXT_FLAG_CONFIG: u16 = 0x0004;
/// The SRT library version advertised in HSREQ/HSRSP (1.5.4 encoded as
/// `major*0x10000 + minor*0x100 + patch`). ≥1.5.4 so a libsrt peer uses the
/// modern AES-GCM nonce (`salt[0..12]`) we implement, not the 1.5.3 legacy one.
const SRT_LIBRARY_VERSION: u32 = 0x0001_0504;
/// Conclusion extension-field flag: a KMREQ extension is present (spec §3.2.1,
/// Table 3).
const EXT_FLAG_KMREQ: u16 = 0x0002;
/// Handshake extension type for a Key Material request (spec §3.2.1, Table 5).
const EXT_KMREQ: u16 = 3;
/// Handshake extension type for a Key Material response (spec §3.2.1, Table 5).
const EXT_KMRSP: u16 = 4;

/// Interval between handshake retransmissions (libsrt's SYN interval).
const SYN_INTERVAL: Duration = Duration::from_millis(250);
/// How long the Caller keeps retrying the handshake before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a graceful close lingers waiting for the send buffer to drain before
/// forcing the SHUTDOWN out anyway (the peer may have vanished). libsrt's default
/// linger is also a few seconds.
const LINGER_TIMEOUT: Duration = Duration::from_secs(3);
/// Default key-refresh rate: rotate the SEK every 2²⁴ packets (libsrt's default,
/// spec §6.1.6), bounding how much data is ever encrypted under one key.
pub const KM_REFRESH_DEFAULT: u32 = 1 << 24;
/// How long an established connection waits for *any* packet from the peer before
/// declaring it dead (libsrt's `SRTO_PEERIDLETIMEO`, default 5 s). Keepalives keep
/// an otherwise-idle peer well inside this window.
const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// One outgoing data packet's worth of an application message: a payload chunk,
/// its position within the message, and the message number it belongs to. A
/// message larger than the payload size is split into several of these (spec
/// §3.2.1: the `PP` and message-number fields tie the fragments together).
#[derive(Debug, Clone)]
struct Fragment {
    payload: Bytes,
    position: PacketPosition,
    message: u32,
}

/// Reassembles in-order data packets back into application **messages** (spec
/// §3.2.1). A single-packet message delivers immediately; a multi-packet message
/// is held until its `Last` fragment, then concatenated. A missing fragment (a
/// loss the receiver dropped, leaving a sequence gap) discards the partial
/// message rather than splicing across the hole.
#[derive(Debug, Default)]
struct Reassembler {
    /// Fragments collected for the message currently being reassembled.
    fragments: Vec<Bytes>,
    /// The sequence number the next fragment of the in-progress message must have.
    next_seq: Option<SeqNumber>,
}

impl Reassembler {
    /// Feeds one delivered (in-order) packet; returns a complete message if this
    /// packet finishes one.
    fn push(&mut self, packet: DataPacket) -> Option<Bytes> {
        match packet.position {
            PacketPosition::Single => {
                self.reset();
                Some(packet.payload)
            }
            PacketPosition::First => {
                self.fragments = vec![packet.payload];
                self.next_seq = Some(packet.seq.next());
                None
            }
            PacketPosition::Middle | PacketPosition::Last => {
                // A fragment must continue the message contiguously; a gap (a
                // dropped fragment) or an orphan fragment voids the partial.
                if self.next_seq != Some(packet.seq) {
                    self.reset();
                    return None;
                }
                self.fragments.push(packet.payload);
                self.next_seq = Some(packet.seq.next());
                if matches!(packet.position, PacketPosition::Last) {
                    let total: usize = self.fragments.iter().map(Bytes::len).sum();
                    let mut message = BytesMut::with_capacity(total);
                    for f in &self.fragments {
                        message.extend_from_slice(f);
                    }
                    self.reset();
                    Some(message.freeze())
                } else {
                    None
                }
            }
        }
    }

    fn reset(&mut self) {
        self.fragments.clear();
        self.next_seq = None;
    }
}

/// Which end of the connection this state machine is. The two ends share almost
/// all logic but differ in who drives the handshake (the Caller retransmits on a
/// timer; the Acceptor only re-answers duplicate conclusions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// The active opener (spec §4.3.1: Caller).
    Caller,
    /// The connection the Listener spawned on a valid conclusion (Responder).
    Acceptor,
}

/// The connection's handshake/established state.
#[derive(Debug)]
enum State {
    /// Caller: induction sent, awaiting the Listener's induction response.
    Induction,
    /// Caller: conclusion sent, awaiting the Listener's conclusion response.
    Conclusion,
    /// The handshake completed; the connection is usable.
    Connected,
    /// The connection failed (e.g. the handshake timed out).
    Failed,
}

/// A single SRT connection's deterministic state machine (spec §4).
#[derive(Debug)]
pub struct Connection {
    config: Config,
    /// Our own SRT socket id (the source id we stamp on outgoing handshakes).
    local_socket_id: SocketId,
    /// Our initial sequence number (first data packet we will send).
    initial_seq: SeqNumber,
    /// The timestamp epoch: wire timestamps are microseconds since this instant.
    start: Instant,
    side: Side,
    state: State,
    /// The peer's socket id, learned during the handshake; the destination of
    /// everything we send. Zero until the induction response (Caller).
    peer_socket_id: SocketId,
    /// The SYN cookie to echo in the conclusion (Caller).
    syn_cookie: u32,
    /// The most recent handshake datagram, cached so the Caller can retransmit it
    /// on a timer and the Acceptor can re-answer a duplicate conclusion.
    last_handshake: Option<Bytes>,
    /// Negotiated session keys (even + odd slots), once an encrypted connection is
    /// established (spec §6). `None` for an unencrypted connection.
    crypto: Option<SessionCrypto>,
    /// The encoded Key Material message to advertise (KMREQ from the caller,
    /// echoed as KMRSP by the acceptor). `None` when unencrypted.
    key_material: Option<Bytes>,
    /// Data packets sent under the current key, for key-refresh accounting.
    packets_on_key: u32,
    /// A [`Event::KeyRefreshNeeded`] has been emitted and we are awaiting the
    /// embedder's fresh key bytes via [`provide_rekey`](Connection::provide_rekey).
    rekey_pending: bool,
    /// The next key slot is installed and announced; the sender switches to it at
    /// the refresh point.
    next_key_ready: bool,

    // ---- ARQ state, live once `state` is `Connected` (see `connection::arq`) ----
    /// Sent-but-unacknowledged data packets, for retransmission.
    send_buffer: SendBuffer,
    /// Out-of-order received data awaiting in-order delivery.
    recv_buffer: RecvBuffer,
    /// TSBPD time base: the (sender-timestamp, local-instant) anchor from the
    /// first received data packet, mapping sender timestamps to local play times
    /// (spec §4.5.1). `None` until the first data packet arrives.
    tsbpd_base: Option<(Timestamp, Instant)>,
    /// Clock-drift correction applied to the TSBPD time base (spec §4.7).
    drift: DriftTracer,
    /// Smoothed RTT / variance from ACK/ACKACK round trips.
    rtt: RttEstimator,
    /// Sequence number for the next data packet we originate.
    next_send_seq: SeqNumber,
    /// Message number for the next message we originate (26-bit, live = 1/packet).
    next_message: u32,
    /// Sequence number stamped on the next full ACK (echoed in its ACKACK).
    next_ack_number: u32,
    /// Full ACKs we have sent and not yet had ACKACK'd, with their send times —
    /// the round-trip samples for [`RttEstimator`].
    pending_acks: VecDeque<(u32, Instant)>,
    /// The last ACK point we sent in a full ACK, to avoid redundant ACKs.
    last_acked_point: Option<SeqNumber>,
    /// The loss list most recently reported in a NAK, to suppress duplicates.
    reported_loss: Vec<(SeqNumber, SeqNumber)>,
    /// Data packets received since the last (light or full) ACK.
    packets_since_ack: u32,
    /// EXP backoff multiplier; grows while no ACK arrives, resets on one.
    exp_count: u32,

    // ---- `LiveCC` pacing (spec §5.1), present when `config.max_bw > 0` ----
    /// The pacer producing the minimum inter-packet send period.
    live_cc: Option<LiveCc>,
    /// Payloads submitted by the application, awaiting their paced send slot.
    send_queue: VecDeque<Fragment>,
    /// Earliest instant the next queued packet may be sent; `None` means now.
    next_send: Option<Instant>,
    /// Set once [`close`](Connection::close) is called while data is still in
    /// flight: the connection lingers — still acknowledging, retransmitting, and
    /// pacing — until the send buffer drains, then sends SHUTDOWN (spec §3.2.7).
    /// New sends are refused while closing.
    closing: bool,
    /// When we last sent any packet (data or control), once established. Drives
    /// keepalive: if the connection has been silent for a keepalive period we send
    /// a KEEPALIVE so an idle-timeout-enforcing peer does not drop us (spec §3.2.6).
    last_sent: Instant,
    /// When we last *received* any packet from the peer. Drives the idle / dead-peer
    /// timeout: if nothing arrives for [`PEER_IDLE_TIMEOUT`], the peer is gone.
    last_recv_any: Instant,
    /// Reassembles received fragments back into application messages.
    reassembler: Reassembler,

    // ---- Forward error correction (spec App.; libsrt packet filter), present
    // when `config.fec` is set ----
    /// Sender-side row parity generator; emits one FEC packet per full group.
    fec_send: Option<FecEncoder>,
    /// Receiver-side row decoder; rebuilds a single lost member of a group.
    fec_recv: Option<FecReceiver>,

    /// Cumulative counters reported by [`Connection::stats`].
    stats: Stats,
    /// Receiver delivery-rate estimator, feeding the full ACK's rate fields.
    rate: RateEstimator,
    /// Arrival time of the previous received data packet (for inter-arrival
    /// intervals); `None` until the first data packet.
    last_recv: Option<Instant>,

    /// Application-facing events awaiting [`Connection::poll_event`].
    events: VecDeque<Event>,
    /// Wire/timer effects awaiting [`Connection::poll_output`].
    outputs: VecDeque<Output>,
}

impl Connection {
    /// Begins a connection from the caller side (spec §4.3.1): the returned
    /// machine has already queued the induction handshake and its retransmit
    /// timer, ready to be drained by [`poll_output`](Connection::poll_output).
    ///
    /// `local_socket_id` and `initial_seq` are the embedder-supplied random
    /// values (randomness is injected, never generated in the core); `now`
    /// becomes this connection's timestamp epoch.
    /// `rng` is the embedder's randomness source; it is invoked (only if
    /// encryption is configured) to generate the salt and Stream Encrypting Key.
    #[must_use]
    pub fn connect(
        config: Config,
        local_socket_id: SocketId,
        initial_seq: SeqNumber,
        now: Instant,
        rng: impl FnMut(&mut [u8]),
    ) -> Self {
        let mut conn = Self::new_base(
            config,
            local_socket_id,
            initial_seq,
            now,
            Side::Caller,
            State::Induction,
        );
        // Generate the session keys up front (used when we send the conclusion's
        // KMREQ) so the deterministic core never holds the RNG.
        if let Some(enc) = &conn.config.encryption {
            let (keys, km) =
                SessionKeys::generate(&enc.passphrase, enc.key_size.bytes(), enc.cipher, rng);
            let mut buf = BytesMut::new();
            km.encode(&mut buf);
            conn.crypto = Some(SessionCrypto::even(keys));
            conn.key_material = Some(buf.freeze());
        }
        conn.send_induction(now);
        conn
    }

    /// The shared field initialization for both connection ends. ARQ fields are
    /// set to empty/initial values here and become live when `enter_connected`
    /// runs; `recv_buffer` is seeded with a placeholder reset to the peer's
    /// initial sequence number at that point.
    fn new_base(
        config: Config,
        local_socket_id: SocketId,
        initial_seq: SeqNumber,
        start: Instant,
        side: Side,
        state: State,
    ) -> Self {
        let config_max_bw = config.max_bw;
        // FEC clips the *wire* payload; size it to the largest unencrypted/CTR
        // payload (MTU less the 16 B SRT and 28 B UDP/IP headers). FEC is
        // unsupported with AES-GCM, so the GCM tag is irrelevant here.
        let fec_clip = (config.mtu as usize).saturating_sub(44).max(1);
        let fec_send = config.fec.map(|f| FecEncoder::new(f.group_size, fec_clip));
        let fec_recv = config.fec.map(|f| FecReceiver::new(f.group_size, fec_clip));
        Connection {
            config,
            local_socket_id,
            initial_seq,
            start,
            side,
            state,
            peer_socket_id: SocketId::new(0),
            syn_cookie: 0,
            last_handshake: None,
            crypto: None,
            key_material: None,
            packets_on_key: 0,
            rekey_pending: false,
            next_key_ready: false,
            send_buffer: SendBuffer::new(),
            recv_buffer: RecvBuffer::new(initial_seq),
            tsbpd_base: None,
            drift: DriftTracer::new(),
            rtt: RttEstimator::new(),
            next_send_seq: initial_seq,
            next_message: 1,
            next_ack_number: 1,
            pending_acks: VecDeque::new(),
            last_acked_point: None,
            reported_loss: Vec::new(),
            packets_since_ack: 0,
            exp_count: 1,
            live_cc: (config_max_bw > 0).then(|| LiveCc::new(config_max_bw)),
            send_queue: VecDeque::new(),
            next_send: None,
            closing: false,
            last_sent: start,
            last_recv_any: start,
            reassembler: Reassembler::default(),
            fec_send,
            fec_recv,
            stats: Stats::default(),
            rate: RateEstimator::new(),
            last_recv: None,
            events: VecDeque::new(),
            outputs: VecDeque::new(),
        }
    }

    /// Builds the listener-side (Acceptor) connection from a validated caller
    /// conclusion (spec §4.3.1.2): it queues the conclusion *response* (HSRSP)
    /// and is immediately `Connected`. Called by [`crate::listener::Listener`].
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionError`] if the connection's encryption requirement is
    /// not met — a missing KMREQ, or a Key Material the listener's passphrase
    /// cannot unwrap (wrong passphrase). The listener then declines the
    /// connection rather than establishing an undecryptable one.
    pub(crate) fn accept(
        config: Config,
        local_socket_id: SocketId,
        local_initial_seq: SeqNumber,
        caller_hs: &Handshake,
        now: Instant,
    ) -> Result<Self, ConnectionError> {
        let negotiated = negotiate(config.latency, caller_hs);
        // Set up encryption from the caller's KMREQ, if the connection uses it.
        let (crypto, key_material) = accept_crypto(config.encryption.as_ref(), caller_hs)?;

        // Advertise the agreed latency back to the caller (spec §4.3.1.2: latency
        // is the greater of the two reported values).
        let latency_ms = millis_u16(negotiated.latency);
        let mut extensions = vec![HandshakeExtension::HsRsp(srt_handshake_ext(latency_ms))];
        let mut extension_field = EXT_FLAG_HSREQ;
        if let Some(km) = &key_material {
            // Echo the Key Material back as KMRSP (spec §4.3.1.2).
            extensions.push(HandshakeExtension::Raw {
                ext_type: EXT_KMRSP,
                content: km.clone(),
            });
            extension_field |= EXT_FLAG_KMREQ;
        }
        let response = Handshake {
            version: HS_VERSION_SRT,
            encryption: caller_hs.encryption,
            extension_field,
            initial_seq: local_initial_seq,
            mtu: config.mtu,
            max_flow_window: config.flow_window,
            handshake_type: HandshakeType::CONCLUSION,
            srt_socket_id: local_socket_id,
            syn_cookie: 0,
            peer_ip: [0u8; 16],
            extensions,
        };
        let peer_socket_id = caller_hs.srt_socket_id;
        let mut conn = Self::new_base(
            config,
            local_socket_id,
            local_initial_seq,
            now,
            Side::Acceptor,
            State::Conclusion,
        );
        conn.crypto = crypto.map(SessionCrypto::even);
        conn.key_material = key_material;
        let bytes = encode_control(
            peer_socket_id,
            conn.wire_ts(now),
            ControlBody::Handshake(response),
        );
        conn.last_handshake = Some(bytes.clone());
        conn.outputs.push_back(Output::SendDatagram(bytes));
        // The handshake is complete from the Acceptor's side the moment it sends
        // the response: enter the ARQ phase and emit `Connected`.
        conn.enter_connected(negotiated, now);
        Ok(conn)
    }

    /// Feeds one received UDP datagram into the machine. The core decodes it and
    /// may enqueue events and outputs. Malformed datagrams are dropped (a
    /// peer-caused failure is never a panic).
    pub fn feed_recv_buf(&mut self, datagram: &[u8], now: Instant) {
        let Ok(packet) = Packet::decode(datagram) else {
            return; // malformed: drop (never panic on peer input)
        };
        // Any well-formed packet from the peer (data, ACK, NAK, keepalive, …)
        // proves it is alive: reset the idle / dead-peer timer.
        if matches!(self.state, State::Connected) {
            self.last_recv_any = now;
        }
        match self.state {
            // Before the connection is up only handshakes matter.
            State::Induction | State::Conclusion => {
                if let Packet::Control(ControlPacket {
                    body: ControlBody::Handshake(hs),
                    ..
                }) = packet
                {
                    if matches!(self.state, State::Induction) {
                        self.on_induction_response(&hs, now);
                    } else {
                        self.on_conclusion_response(&hs, now);
                    }
                }
            }
            State::Connected => self.on_connected_packet(packet, now),
            State::Failed => {}
        }
    }

    /// Dispatches a packet received while `Connected`: data to the receiver, and
    /// each control type to its ARQ handler (see [`mod@arq`]).
    fn on_connected_packet(&mut self, packet: Packet, now: Instant) {
        match packet {
            Packet::Data(data) => self.on_data(data, now),
            Packet::Control(ctrl) => match ctrl.body {
                ControlBody::Ack(ack) => self.on_ack(ack, now),
                ControlBody::AckAck { ack_number } => self.on_ackack(ack_number, now),
                ControlBody::Nak { loss } => self.on_nak(&loss, now),
                ControlBody::Shutdown => {
                    // Graceful close: the peer lingered until we acknowledged its
                    // data, so flush whatever in-order data we still hold (TSBPD
                    // may not have played it out yet) before tearing down. Stop at
                    // the first gap — a real loss hole must not be skipped here.
                    while let Some(packet) = self.recv_buffer.pop_in_order() {
                        if let Some(message) = self.reassembler.push(packet) {
                            self.events.push_back(Event::DataReceived(message));
                        }
                    }
                    self.state = State::Failed;
                    self.clear_arq_timers();
                    self.events.push_back(Event::Closed);
                }
                ControlBody::DropReq { first, last, .. } => self.on_dropreq(first, last, now),
                ControlBody::Raw {
                    control_type: ControlType::UserDefined,
                    subtype,
                    cif,
                    ..
                } => {
                    // Rekey Key Material rides a UMSG_EXT control packet (spec
                    // §6.1.6): a KMREQ announces the next key; a KMRSP confirms ours.
                    if subtype == EXT_KMREQ {
                        self.on_km_req(&cif, now);
                    }
                }
                ControlBody::Handshake(hs) => {
                    // The Acceptor re-answers a conclusion the Caller retransmitted
                    // because our response was lost (spec §4.3.1.2).
                    if self.side == Side::Acceptor
                        && hs.handshake_type == HandshakeType::CONCLUSION
                        && let Some(bytes) = self.last_handshake.clone()
                    {
                        self.outputs.push_back(Output::SendDatagram(bytes));
                    }
                }
                _ => {} // Keepalive, CongestionWarning, etc.: ignored for now.
            },
        }
    }

    /// Fires the timer `id` (the I/O layer's wheel reached its deadline).
    pub fn handle_timer(&mut self, id: TimerId, now: Instant) {
        match id {
            TimerId::Handshake => self.on_handshake_timer(now),
            TimerId::Ack => self.on_ack_timer(now),
            TimerId::Nak => self.on_nak_timer(now),
            TimerId::Exp => self.on_exp_timer(now),
            TimerId::Tsbpd => self.deliver_tsbpd(now),
            TimerId::SndPacing => self.pace(now),
            TimerId::Linger => self.on_linger_timer(now),
            TimerId::Keepalive => self.on_keepalive_timer(now),
            TimerId::PeerIdle => self.on_peer_idle_timer(now),
        }
    }

    /// Caller's handshake retransmit / connect-timeout timer (spec §4.3.1).
    fn on_handshake_timer(&mut self, now: Instant) {
        if !matches!(self.state, State::Induction | State::Conclusion) {
            return;
        }
        if now.saturating_duration_since(self.start) >= CONNECT_TIMEOUT {
            self.state = State::Failed;
            self.outputs.push_back(Output::ClearTimer {
                id: TimerId::Handshake,
            });
            self.events
                .push_back(Event::Failed(ConnectionError::HandshakeTimeout));
            return;
        }
        // Resend the current phase's handshake and re-arm the timer.
        if let Some(bytes) = self.last_handshake.clone() {
            self.outputs.push_back(Output::SendDatagram(bytes));
            self.outputs.push_back(Output::SetTimer {
                id: TimerId::Handshake,
                after: SYN_INTERVAL,
            });
        }
    }

    /// Queues application payload to send reliably (sender side, spec §4.6).
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionError::InvalidState`] if the connection is not yet
    /// established (or has been closed).
    pub fn send(&mut self, payload: Bytes, now: Instant) -> Result<(), ConnectionError> {
        if self.closing || !matches!(self.state, State::Connected) {
            return Err(ConnectionError::InvalidState);
        }
        // One message number per application message; its fragments share it.
        // Message number 0 is reserved as the FEC parity marker on the wire (libsrt
        // convention), so the counter skips it when it wraps the 26-bit field.
        let message = self.next_message;
        self.next_message = match self.next_message.wrapping_add(1) {
            n if MsgNumber::new(n).value() == 0 => 1,
            n => n,
        };
        let fragments = self.fragment_message(payload, message);
        if self.live_cc.is_none() {
            for fragment in fragments {
                self.send_data(fragment, now); // no pacing: send immediately
            }
        } else {
            self.send_queue.extend(fragments);
            self.pace(now);
        }
        Ok(())
    }

    /// The largest payload one data packet carries: the MTU less the SRT (16 B) and
    /// UDP/IP (28 B) headers, and the AES-GCM tag (16 B) when authenticated.
    fn max_payload(&self) -> usize {
        let tag = self
            .crypto
            .as_ref()
            .map_or(0, |c| if c.is_aead() { 16 } else { 0 });
        (self.config.mtu as usize).saturating_sub(44 + tag).max(1)
    }

    /// Splits an application message into packet-sized fragments (spec §3.2.1): one
    /// `Single` if it fits, otherwise `First` … `Middle` … `Last`.
    fn fragment_message(&self, payload: Bytes, message: u32) -> Vec<Fragment> {
        let max = self.max_payload();
        if payload.len() <= max {
            return vec![Fragment {
                payload,
                position: PacketPosition::Single,
                message,
            }];
        }
        let mut fragments = Vec::new();
        let mut offset = 0;
        while offset < payload.len() {
            let end = (offset + max).min(payload.len());
            let position = if offset == 0 {
                PacketPosition::First
            } else if end == payload.len() {
                PacketPosition::Last
            } else {
                PacketPosition::Middle
            };
            fragments.push(Fragment {
                payload: payload.slice(offset..end),
                position,
                message,
            });
            offset = end;
        }
        fragments
    }

    /// Whether the send queue has room for another packet — the backpressure
    /// signal the I/O layer consults before accepting more application data.
    ///
    /// This bounds the **pacing queue**: payloads submitted faster than the pace
    /// (`max_bw`) can release them. That queue is the part that would otherwise
    /// grow without bound (a slow pace versus a fast producer), so it is what
    /// backpressure caps, to the negotiated flow window (spec §3.2.1). We do *not*
    /// gate on the unacknowledged retransmission buffer: that is governed by ARQ,
    /// and blocking the producer the instant it fills would starve the pacer of
    /// the steady call cadence that keeps sending smooth (a stop-start producer
    /// forces the pacer onto coarse OS timers, which burst and overrun the peer).
    #[must_use]
    pub fn send_window_available(&self) -> bool {
        self.send_queue.len() < self.config.flow_window as usize
    }

    /// Begins an orderly close (spec §3.2.7). If data is still in flight the
    /// connection *lingers* — keeping ARQ alive so the send buffer drains — and
    /// only sends SHUTDOWN once everything is acknowledged (or the linger window
    /// expires). With nothing outstanding it shuts down at once. A close before
    /// the connection is established just fails it (no peer to notify).
    pub fn close(&mut self, now: Instant) {
        if self.closing || matches!(self.state, State::Failed) {
            return; // already closing or closed: idempotent
        }
        if !matches!(self.state, State::Connected) {
            // Not yet established: nothing to drain or notify.
            self.state = State::Failed;
            self.events.push_back(Event::Closed);
            return;
        }
        if self.send_buffer.is_empty() && self.send_queue.is_empty() {
            self.finalize_shutdown(now); // drained already: close now
        } else {
            // Linger until the data drains; on_ack / pace finish the close, and
            // the Linger timer is the backstop if the peer stops acknowledging.
            self.closing = true;
            self.outputs.push_back(Output::SetTimer {
                id: TimerId::Linger,
                after: LINGER_TIMEOUT,
            });
        }
    }

    /// Finishes a graceful close once the send buffer has drained: emits the
    /// SHUTDOWN, tears down the timers, and reports `Closed`.
    fn finalize_shutdown(&mut self, now: Instant) {
        let bytes = encode_control(
            self.peer_socket_id,
            self.wire_ts(now),
            ControlBody::Shutdown,
        );
        self.outputs.push_back(Output::SendDatagram(bytes));
        self.clear_arq_timers();
        self.outputs.push_back(Output::ClearTimer {
            id: TimerId::Linger,
        });
        self.closing = false;
        self.state = State::Failed;
        self.events.push_back(Event::Closed);
    }

    /// If a graceful close is in progress and the send side has fully drained,
    /// completes the shutdown. Called after every event that can empty the send
    /// buffer (an ACK) or the send queue (pacing).
    pub(crate) fn finish_close_if_drained(&mut self, now: Instant) {
        if self.closing && self.send_buffer.is_empty() && self.send_queue.is_empty() {
            self.finalize_shutdown(now);
        }
    }

    /// The linger backstop fired: the outstanding data never drained (the peer
    /// likely went away), so force the SHUTDOWN out and close.
    fn on_linger_timer(&mut self, now: Instant) {
        if self.closing {
            self.finalize_shutdown(now);
        }
    }

    /// A snapshot of this connection's cumulative [`Stats`]: the running counters
    /// plus the current RTT, in-flight window, and receive-buffer occupancy.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let mut stats = self.stats;
        stats.rtt_us = u32::try_from(self.rtt.rtt().as_micros()).unwrap_or(u32::MAX);
        stats.rtt_var_us = u32::try_from(self.rtt.var().as_micros()).unwrap_or(u32::MAX);
        stats.flight_size = u32::try_from(self.send_buffer.len()).unwrap_or(u32::MAX);
        stats.recv_buffer_packets = u32::try_from(self.recv_buffer.occupancy()).unwrap_or(u32::MAX);
        let (pps, bps) = self.rate.delivery_rate();
        stats.recv_rate_pps = pps;
        stats.recv_rate_bps = bps;
        stats.link_capacity_pps = self.rate.peak_rate();
        stats
    }

    /// Drains the next application-facing [`Event`], if any.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Drains the next wire/timer [`Output`], if any.
    #[must_use]
    pub fn poll_output(&mut self) -> Option<Output> {
        self.outputs.pop_front()
    }

    /// This connection's wire timestamp at `now`: microseconds since `start`,
    /// wrapping every ~71 minutes (spec §3.1).
    #[allow(clippy::cast_possible_truncation)] // 32-bit wrapping timestamp by design
    fn wire_ts(&self, now: Instant) -> Timestamp {
        let micros = now.saturating_duration_since(self.start).as_micros();
        Timestamp::from_micros(micros as u32)
    }
}

/// Encodes a control body into a complete datagram addressed to `dest`.
pub(crate) fn encode_control(dest: SocketId, timestamp: Timestamp, body: ControlBody) -> Bytes {
    let mut buf = BytesMut::new();
    Packet::Control(ControlPacket {
        timestamp,
        dest_socket_id: dest,
        body,
    })
    .encode(&mut buf);
    buf.freeze()
}
