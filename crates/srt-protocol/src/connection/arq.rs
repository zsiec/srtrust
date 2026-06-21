//! Automatic Repeat reQuest: the reliability engine layered on a connected
//! [`Connection`](super::Connection) (spec §4.5–§4.8).
//!
//! This is a child module of `connection`, so it operates directly on the
//! connection's private ARQ fields via `self` — keeping the data path here and
//! the handshake in the parent file. The behaviors:
//!
//! * **Send** — stamp app data with the next sequence number, buffer it for
//!   retransmission, and emit it (§4.6).
//! * **Receive** — reassemble in order, deliver, and detect gaps (§4.5).
//! * **ACK** — a periodic full ACK carrying RTT/RTTVar (ACKACK'd, §4.8.1), plus a
//!   light ACK every 64 packets.
//! * **NAK** — report losses immediately on detection and on a periodic timer
//!   (§4.8.2); the sender retransmits the named packets.
//! * **RTT** — sample from the ACK→ACKACK round trip (§4.10).
//! * **EXP** — a sender timeout that retransmits everything outstanding when no
//!   ACK arrives, the backstop for lost feedback (§4.8).

use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use super::{Connection, Event, Fragment, Negotiated, Output, State, TimerId, encode_control};
use crate::control::{Ack, AckCif, ControlBody};
use crate::crypto::SessionCrypto;
use crate::fec::{self, FecData, FecParity, RecoveredPacket};
use crate::loss_list::LossRange;
use crate::packet::{DataPacket, Encryption, MsgNumber, Packet, PacketPosition};
use crate::recv_buffer::RecvBuffer;
use crate::seq::SeqNumber;
use crate::timestamp::{Timestamp, TsbpdWrap};

/// Period of the full acknowledgement timer (libsrt's ACK interval).
const ACK_INTERVAL: Duration = Duration::from_millis(10);
/// A light ACK is emitted every this many received data packets (spec §4.8.1).
const LIGHT_ACK_EVERY: u32 = 64;
/// Floor on the periodic NAK interval (spec §4.8.2).
const MIN_NAK_INTERVAL: Duration = Duration::from_millis(20);
/// Floor on the sender's EXP / retransmission timeout (libsrt/srtgo: 300 ms).
const MIN_EXP_INTERVAL: Duration = Duration::from_millis(300);
/// Minimum send-side TLPKTDROP threshold (libsrt `SRT_TLPKTDROP_MINTHRESHOLD_MS`):
/// the sender keeps un-acked packets eligible for retransmission for at least this
/// long regardless of the (typically much smaller) playout latency, so ARQ has a
/// real recovery window before a packet is abandoned.
const SND_DROP_MIN_THRESHOLD: Duration = Duration::from_secs(1);
/// Most outstanding full ACKs tracked for RTT (bounds `pending_acks`).
const MAX_PENDING_ACKS: usize = 16;
/// Cap on the EXP backoff multiplier, so the timeout cannot grow without bound.
const MAX_EXP_COUNT: u32 = 8;
/// Most packets a single [`pace`](Connection::pace) call will release as a
/// catch-up micro-burst, bounding how much a late timer firing can emit at once.
const MAX_PACE_BURST: usize = 256;
/// How long the connection may be silent before it must send a KEEPALIVE (spec
/// §3.2.6; libsrt's keepalive period is 1 s).
const KEEPALIVE_PERIOD: Duration = Duration::from_secs(1);
/// Cap on the adaptive reorder tolerance (libsrt's `SRTO_LOSSMAXTTL` role): a
/// gap is not NAK'd until `Connection::reorder_tolerance` packets have arrived
/// past it, and that tolerance never grows beyond this — so a real loss is
/// never deferred indefinitely, no matter how jittery the link looks.
const MAX_REORDER_TOLERANCE: u32 = 32;
/// Consecutive in-order (non-belated) original arrivals after which the
/// adaptive reorder tolerance decays by one (libsrt's consecutive-ordered-
/// delivery counter), so a link that stops reordering recovers its fast NAKs.
const REORDER_DECAY_AFTER: u32 = 50;

impl Connection {
    /// Transitions into the connected (ARQ) phase: seeds the receive buffer with
    /// the peer's initial sequence number, arms the periodic ACK and NAK timers,
    /// and emits [`Event::Connected`].
    pub(super) fn enter_connected(&mut self, negotiated: Negotiated, now: Instant) {
        self.state = State::Connected;
        self.peer_socket_id = negotiated.peer_socket_id;
        // The agreed latency (the larger of the two advertised values, spec
        // §4.3.1.2) binds both TSBPD play times and the sender's drop budget.
        self.latency = negotiated.latency;
        self.recv_buffer = RecvBuffer::new(negotiated.peer_initial_seq);
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::Ack,
            after: ACK_INTERVAL,
        });
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::Nak,
            after: self.nak_interval(),
        });
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::Keepalive,
            after: KEEPALIVE_PERIOD,
        });
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::PeerIdle,
            after: self.config.peer_idle_timeout,
        });
        self.last_sent = now;
        self.last_recv_any = now; // the conclusion that established us counts
        self.events.push_back(Event::Connected(negotiated));
    }

    /// Sends a fully-encoded datagram to the peer, recording the send time so the
    /// keepalive timer can tell whether the connection has gone idle.
    pub(super) fn emit(&mut self, datagram: Bytes, now: Instant) {
        self.last_sent = now;
        self.outputs.push_back(Output::SendDatagram(datagram));
    }

    /// The keepalive timer fired: if the connection has been silent for a whole
    /// period, send a KEEPALIVE (spec §3.2.6); always re-arm while connected.
    /// Also the re-send cadence for an unconfirmed rekey KMREQ (spec §6.1.6) —
    /// control packets are not ARQ-protected, so that exchange retries here.
    pub(super) fn on_keepalive_timer(&mut self, now: Instant) {
        if !matches!(self.state, State::Connected) {
            return; // not established (or tearing down): stop keepalives
        }
        self.resend_pending_km(now);
        if now.saturating_duration_since(self.last_sent) >= KEEPALIVE_PERIOD {
            let bytes = encode_control(
                self.peer_socket_id,
                self.wire_ts(now),
                ControlBody::Keepalive,
            );
            self.emit(bytes, now);
        }
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::Keepalive,
            after: KEEPALIVE_PERIOD,
        });
    }

    /// The idle / dead-peer timer fired: if nothing has arrived from the peer for
    /// the whole idle window, the peer is gone — fail the connection. Otherwise
    /// re-arm for exactly the time remaining until the window would elapse.
    pub(super) fn on_peer_idle_timer(&mut self, now: Instant) {
        if !matches!(self.state, State::Connected) {
            return;
        }
        let idle = now.saturating_duration_since(self.last_recv_any);
        if idle >= self.config.peer_idle_timeout {
            self.state = State::Failed;
            self.clear_arq_timers();
            self.events
                .push_back(Event::Failed(super::ConnectionError::Timeout));
            return;
        }
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::PeerIdle,
            after: self.config.peer_idle_timeout.saturating_sub(idle),
        });
    }

    // ---- sender ----

    /// Originates one data packet — a whole message or one fragment of one (spec
    /// §4.6) — encrypting the payload if the connection is encrypted (spec §6).
    pub(super) fn send_data(&mut self, fragment: Fragment, now: Instant) {
        // Rotate the encryption key if due, so this packet uses the right slot.
        self.account_key_and_maybe_rotate();
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += fragment.payload.len() as u64;
        let seq = self.next_send_seq;
        // Stamp the even/odd flag first: the header carries it, and AES-GCM
        // authenticates the header (its AAD), so the flag must be fixed before we
        // encrypt. The payload starts as plaintext and is replaced below.
        let encryption = self
            .crypto
            .as_ref()
            .map_or(Encryption::None, SessionCrypto::active_encryption);
        let mut packet = DataPacket {
            seq,
            position: fragment.position,
            in_order: true,
            encryption,
            retransmitted: false,
            message_number: MsgNumber::new(fragment.message),
            timestamp: self.wire_ts(now),
            dest_socket_id: self.peer_socket_id,
            payload: fragment.payload,
        };
        // Encrypt for the wire and store the *ciphertext* packet — for AES-GCM
        // too: the AAD excludes the only header bit a resend changes (the `R`
        // flag), and retransmissions keep the original timestamp, so the stored
        // ciphertext and auth tag stay valid for every resend. This matches
        // libsrt, which encrypts once at first send and resends the buffered
        // ciphertext verbatim.
        let (stored, datagram) = if let Some(crypto) = &self.crypto {
            let aad = packet.header_aad();
            packet.payload = crypto.encrypt(seq.value(), &aad, &packet.payload).0;
            let datagram = encode_data(&packet);
            (packet, datagram)
        } else {
            let datagram = encode_data(&packet);
            (packet, datagram)
        };
        let was_empty = self.send_buffer.is_empty();
        let payload_size = stored.payload.len();
        // FEC: clip this packet's *wire* fields into the current row group (the
        // stored payload is always the wire payload now; FEC stays unsupported
        // with AES-GCM by policy). A completed group yields a parity packet that
        // shares this sequence number (spec App.; libsrt packet filter); it is
        // emitted *after* this data packet below, so the parity always follows
        // the complete group on the wire.
        let parity = self.fec_send.as_mut().map(|fec| {
            fec.feed(FecData {
                length: u16::try_from(payload_size).unwrap_or(u16::MAX),
                flags: encryption.to_bits(),
                timestamp: stored.timestamp.as_micros(),
                payload: &stored.payload,
            })
        });
        self.send_buffer.push(stored);
        self.emit(datagram, now);
        if let Some(Some(parity)) = parity {
            self.emit_fec_parity(seq, &parity, now);
        }
        self.next_send_seq = self.next_send_seq.next();
        // `LiveCC`: fold the sent size into the average payload (spec §5.1.2).
        if let Some(cc) = &mut self.live_cc {
            cc.on_packet_sent(payload_size);
        }
        if was_empty {
            // First unacknowledged packet: start the retransmission backstop.
            self.arm_exp();
        }
    }

    /// Emits a row-FEC parity packet for a completed group (spec App.; libsrt
    /// packet filter). It rides the wire as a data packet *sharing* the group's
    /// last sequence number (`group_last_seq`, consuming no new number), flagged by
    /// message number `0`, never encrypted, carrying the clipped contents as its
    /// payload and the timestamp clip in its timestamp field. It is pure redundancy
    /// — not buffered for retransmission, not ACK-tracked.
    fn emit_fec_parity(&mut self, group_last_seq: SeqNumber, parity: &FecParity, now: Instant) {
        let fec_packet = DataPacket {
            seq: group_last_seq,
            position: PacketPosition::Single,
            in_order: true,
            encryption: Encryption::None,
            retransmitted: false,
            message_number: MsgNumber::new(0),
            timestamp: Timestamp::from_micros(parity.timestamp_clip),
            dest_socket_id: self.peer_socket_id,
            payload: Bytes::from(parity.encode(fec::ROW_INDEX)),
        };
        self.emit(encode_data(&fec_packet), now);
    }

    /// Releases every queued packet whose scheduled send slot has arrived, then
    /// re-arms the `SndPacing` timer for the next one (spec §5.1). A no-op when
    /// pacing is disabled.
    ///
    /// Each slot is scheduled exactly one `snd_period` after the previous slot, so
    /// the long-run rate is precisely `1/period` regardless of *when* `pace` is
    /// called. This **catch-up** matters because the real timer firing `pace` is
    /// far coarser (tokio rounds sub-millisecond sleeps up to ~1 ms) than the
    /// inter-packet period at high rates (~10 µs at 1 Gbps): releasing only one
    /// packet per call would cap throughput at the timer granularity (~1000 pkt/s).
    /// We instead emit the whole backlog the schedule says is due — a bounded
    /// micro-burst (`MAX_PACE_BURST`) that preserves the average rate. When the
    /// queue empties the schedule resets (no debt is carried into an idle period,
    /// so a later refill does not dump a burst).
    pub(super) fn pace(&mut self, now: Instant) {
        let Some(cc) = &self.live_cc else {
            return;
        };
        let period = cc.snd_period();
        let mut released = 0;
        while released < MAX_PACE_BURST {
            // Not yet time for the next slot.
            if self.next_send.is_some_and(|at| now < at) {
                break;
            }
            let Some(fragment) = self.send_queue.pop_front() else {
                self.next_send = None; // drained: carry no pacing debt into idle
                break;
            };
            self.send_data(fragment, now);
            // Advance the schedule from the *last slot* (not `now`), keeping the
            // average rate exact even when this call fired late.
            let last_slot = self.next_send.unwrap_or(now);
            self.next_send = Some(last_slot + period);
            released += 1;
        }
        // If we capped the burst while still behind schedule, resync to now so the
        // debt cannot grow without bound (e.g. after an unusually long gap).
        if released == MAX_PACE_BURST && self.next_send.is_some_and(|at| at < now) {
            self.next_send = Some(now + period);
        }
        if self.send_queue.is_empty() {
            self.outputs.push_back(Output::ClearTimer {
                id: TimerId::SndPacing,
            });
            // A graceful close may now be fully drained (queue empty and, if the
            // last paced packet is already acknowledged, buffer empty too).
            self.finish_close_if_drained(now);
        } else {
            let at = self.next_send.unwrap_or(now);
            self.outputs.push_back(Output::SetTimer {
                id: TimerId::SndPacing,
                after: at.saturating_duration_since(now),
            });
        }
    }

    /// Handles an incoming ACK (spec §4.8.1): release acknowledged packets, reset
    /// the EXP backstop, and (for a full ACK) reply with an ACKACK so the peer can
    /// measure RTT.
    pub(super) fn on_ack(&mut self, ack: Ack, now: Instant) {
        self.stats.acks_received += 1;
        self.send_buffer.ack(ack.last_ack_seq);
        // A full ACK reports how much receive buffer the peer has free (spec
        // §3.2.4); that bounds our send window (spec §4.8) — see
        // `send_window_available`.
        if let AckCif::Full {
            avail_buffer_size, ..
        } = ack.cif
        {
            self.peer_avail_window = avail_buffer_size;
        }
        // Shed any now-too-late unacknowledged packets (send-side TLPKTDROP), so
        // the steady ACK cadence bounds how long a dead packet lingers.
        self.drop_too_late(now);
        // `LiveCC`: recompute the pacing period on ACK (spec §5.1.2, event 2).
        if let Some(cc) = &mut self.live_cc {
            cc.on_ack();
        }
        self.exp_count = 1;
        if self.send_buffer.is_empty() {
            self.outputs
                .push_back(Output::ClearTimer { id: TimerId::Exp });
        } else {
            self.arm_exp();
        }
        // A graceful close finishes once this ACK drains the last outstanding data.
        self.finish_close_if_drained(now);
        if !matches!(ack.cif, AckCif::Light) {
            let bytes = encode_control(
                self.peer_socket_id,
                self.wire_ts(now),
                ControlBody::AckAck {
                    ack_number: ack.ack_number,
                },
            );
            self.emit(bytes, now);
        }
    }

    /// Handles an incoming NAK (spec §4.8.2): retransmit every named packet we
    /// still hold — after first dropping any that are now too late to play
    /// (so we DROPREQ them instead of wastefully retransmitting).
    pub(super) fn on_nak(&mut self, loss: &[LossRange], now: Instant) {
        self.stats.naks_received += 1;
        self.drop_too_late(now);
        for range in loss {
            self.retransmit_range(range.start(), range.end(), now);
        }
    }

    /// Drops unacknowledged packets too old to ever play in time at the receiver
    /// (send-side TLPKTDROP) and announces the dropped range with a DROPREQ (spec
    /// §3.2.9) so the receiver advances cleanly instead of `NAK`-ing for packets that
    /// will never come. A packet whose age exceeds the TSBPD latency cannot arrive
    /// before its play time, so retransmitting it is wasted bandwidth.
    pub(super) fn drop_too_late(&mut self, now: Instant) {
        // libsrt's send-side TLPKTDROP threshold: max(latency, 1000 ms) + 2·SYN
        // (10 ms), not the bare playout latency. A packet is only truly
        // undeliverable once it is older than this window; dropping at bare latency
        // (e.g. 120 ms) abandons packets ARQ could still recover within libsrt's
        // ~1020 ms window and emits DROPREQs the peer would otherwise never see.
        let budget = micros_i64(self.latency).max(micros_i64(SND_DROP_MIN_THRESHOLD))
            + 2 * micros_i64(ACK_INTERVAL);
        let now_ts = self.wire_ts(now);
        let mut first = None;
        let mut last_dropped = None;
        let mut last_msg = 0;
        while let Some(front) = self.send_buffer.front() {
            if i64::from(now_ts.wrapping_diff(front.timestamp)) <= budget {
                break; // young enough to still make its play time
            }
            first.get_or_insert(front.seq);
            last_dropped = Some(front.seq);
            last_msg = front.message_number.value();
            self.send_buffer.drop_front();
            // Count what is shed (libsrt `sndDropTotal`): silent discard would
            // hide undeliverable data from the application entirely.
            self.stats.packets_dropped_sent += 1;
        }
        if let (Some(first), Some(last)) = (first, last_dropped) {
            let bytes = encode_control(
                self.peer_socket_id,
                now_ts,
                ControlBody::DropReq {
                    message_number: last_msg,
                    first,
                    last,
                },
            );
            self.emit(bytes, now);
            if self.send_buffer.is_empty() {
                self.outputs
                    .push_back(Output::ClearTimer { id: TimerId::Exp });
            }
        }
    }

    /// Handles an incoming DROPREQ (spec §3.2.9): the sender will never deliver
    /// `[first, last]`, so drop it from the receive buffer (advancing past a
    /// leading gap), stop reporting it as loss, and deliver anything now in order.
    pub(super) fn on_dropreq(&mut self, first: SeqNumber, last: SeqNumber, now: Instant) {
        let before = self.recv_buffer.ack_point();
        self.recv_buffer.drop_range(first, last);
        let advanced = self.recv_buffer.ack_point().offset_from(before);
        self.stats.packets_dropped += u64::try_from(advanced).unwrap_or(0);
        // The dropped range is no longer outstanding loss; resync so we do not
        // keep NAKing it.
        self.reported_loss = self.recv_buffer.missing();
        self.deliver_tsbpd(now);
    }

    /// The sender's EXP timeout fired: no ACK has arrived, so retransmit
    /// everything outstanding and back off (spec §4.8).
    pub(super) fn on_exp_timer(&mut self, now: Instant) {
        if !matches!(self.state, State::Connected) || self.send_buffer.is_empty() {
            return; // nothing outstanding: leave EXP unarmed
        }
        // Shed packets too late to play before spending bandwidth retransmitting.
        self.drop_too_late(now);
        if self.send_buffer.is_empty() {
            return;
        }
        if let (Some(first), Some(last)) =
            (self.send_buffer.first_seq(), self.send_buffer.last_seq())
        {
            self.retransmit_range(first, last, now);
        }
        self.exp_count = (self.exp_count + 1).min(MAX_EXP_COUNT);
        self.arm_exp();
    }

    /// Retransmits the packets we hold whose sequence falls in `[start, end]`.
    /// Iterates over the buffered packets (bounded by the buffer size) rather than
    /// the range, so a peer's oversized NAK range cannot make us loop unboundedly.
    ///
    /// **Timing-gate:** a packet retransmitted less than one smoothed RTT ago is
    /// skipped — its previous resend is still in flight, so resending again only
    /// produces a duplicate (libsrt's `checkRexmitRightTime`, the live-mode
    /// default; spec §4.8.2: the loss list exists so packets "are not
    /// retransmitted unnecessarily"). The *first* retransmit is never gated.
    fn retransmit_range(&mut self, start: SeqNumber, end: SeqNumber, now: Instant) {
        let (Some(first), Some(last)) = (self.send_buffer.first_seq(), self.send_buffer.last_seq())
        else {
            return;
        };
        let gate = self.rtt.rtt();
        let mut seq = first;
        loop {
            if in_range(seq, start, end)
                && self
                    .send_buffer
                    .last_retransmitted(seq)
                    .is_none_or(|at| now.saturating_duration_since(at) >= gate)
                && let Some(packet) = self.send_buffer.get(seq).cloned()
            {
                self.stats.packets_retransmitted += 1;
                self.stats.bytes_retransmitted += packet.payload.len() as u64;
                // The stored (possibly encrypted) packet is resent verbatim with
                // only the `R` flag set: the original timestamp keeps the
                // receiver's TSBPD schedule (and, under GCM, the auth tag) intact,
                // and the original key flag selects a key the receiver still
                // holds — both slots survive a rotation (spec §6.1.6; matches
                // libsrt's buffered-ciphertext resend).
                self.emit(encode_retransmit(&packet), now);
                self.send_buffer.mark_retransmitted(seq, now);
            }
            if seq == last {
                break;
            }
            seq = seq.next();
        }
    }

    // ---- receiver ----

    /// Routes an incoming data packet, splitting FEC from real data (spec App.;
    /// libsrt packet filter). A **parity** packet (message number `0`) goes to the
    /// FEC decoder, which may rebuild a lost member; every **real** packet is
    /// observed for FEC group accumulation (on its pre-decryption wire payload)
    /// before being buffered and delivered by [`insert_data`](Self::insert_data).
    pub(super) fn on_data(&mut self, data: DataPacket, now: Instant) {
        if let Some(fec) = self.fec_recv.as_mut()
            && data.message_number.value() == 0
        {
            // A parity packet: decode and re-inject anything it recovers. Never
            // buffer the parity itself (it shares a real packet's sequence number).
            let recovered = fec.observe_parity(data.seq, &data.payload, data.timestamp.as_micros());
            for rp in recovered {
                self.inject_recovered(rp, now);
            }
            return;
        }
        // Observe the real packet's *wire* (still-encrypted) payload for FEC group
        // accumulation before we decrypt and consume it below.
        let recovered = if let Some(fec) = self.fec_recv.as_mut() {
            fec.observe_data(
                data.seq,
                u16::try_from(data.payload.len()).unwrap_or(u16::MAX),
                data.encryption.to_bits(),
                data.timestamp.as_micros(),
                data.payload.clone(),
            )
        } else {
            Vec::new()
        };
        self.insert_data(data, now);
        // A late packet can complete a group whose parity already arrived (reorder).
        for rp in recovered {
            self.inject_recovered(rp, now);
        }
    }

    /// Re-injects a FEC-recovered packet into the receive path as if it had arrived
    /// on the wire. The message number and packet position are not recoverable by
    /// XOR, so it is presented as a solo message (matching libsrt; FEC targets live
    /// mode). A recovery whose clipped key flag is invalid (`0b11`, a group
    /// straddling a key rotation) is dropped rather than mis-decrypted.
    fn inject_recovered(&mut self, rp: RecoveredPacket, now: Instant) {
        let Ok(encryption) = Encryption::from_bits(rp.flags) else {
            return;
        };
        self.stats.packets_recovered += 1;
        let packet = DataPacket {
            seq: rp.seq,
            position: PacketPosition::Single,
            in_order: true,
            encryption,
            retransmitted: true,
            message_number: MsgNumber::new(1),
            timestamp: Timestamp::from_micros(rp.timestamp),
            dest_socket_id: self.peer_socket_id,
            payload: rp.payload,
        };
        self.insert_data(packet, now);
    }

    /// Buffers a (real or FEC-recovered) data packet, drives timed (TSBPD)
    /// delivery, light-ACKs periodically, and NAKs newly-discovered gaps (spec
    /// §4.5).
    fn insert_data(&mut self, mut data: DataPacket, now: Instant) {
        // Enforce our advertised receive window locally (spec §3.2.4): a
        // compliant sender stopped when we advertised zero, so anything
        // arriving against a full receive side is a peer ignoring the window
        // — drop it (before paying for decryption) rather than grow without
        // bound while the application is stalled.
        if self.available_recv_buffer() == 0 {
            self.stats.packets_dropped_full += 1;
            return;
        }
        // Decrypt the payload before buffering (spec §6.3); the unencrypted seq
        // in the header reconstructs the AES-CTR counter. Decrypt with the key the
        // packet's even/odd flag selects — using the wrong slot would corrupt the
        // stream, so a packet for a key we do not hold (an un-installed rotation)
        // is dropped as loss instead.
        if !matches!(data.encryption, Encryption::None) {
            let Some(crypto) = &self.crypto else {
                self.stats.packets_undecryptable += 1;
                return; // encrypted packet but no session keys: unusable
            };
            // AES-GCM authenticates the packet header; rebuild it from the received
            // packet as the AAD (CTR ignores it).
            let aad = data.header_aad();
            let Some(plaintext) =
                crypto.decrypt(data.seq.value(), data.encryption, &aad, &data.payload)
            else {
                self.stats.packets_undecryptable += 1;
                return; // no key, or GCM auth failed: drop (never wrong-key plaintext)
            };
            data.payload = plaintext;
        }
        let timestamp = data.timestamp;
        let retransmitted = data.retransmitted;
        let seq = data.seq;
        let payload_len = data.payload.len() as u64;
        if !self.recv_buffer.insert(data) {
            self.stats.packets_duplicate += 1;
            return; // duplicate or already-acknowledged
        }
        self.stats.packets_received += 1;
        self.stats.bytes_received += payload_len;
        self.track_reorder(seq, retransmitted);
        // Feed the windowed delivery-rate estimator with this packet's arrival time
        // (microseconds since the connection began) and its size.
        let arrival_us = u64::try_from(now.saturating_duration_since(self.start).as_micros())
            .unwrap_or(u64::MAX);
        self.rate
            .record(arrival_us, u32::try_from(payload_len).unwrap_or(u32::MAX));
        // Anchor the TSBPD timeline on the first accepted packet (spec §4.5.1.1):
        // it will play `latency` after arrival, and the rest relative to it. The
        // wrap tracker then follows the timestamp stream across its ~71.6-minute
        // numeric wraps so later play times stay correct (spec §4.5.1.1 case 1).
        if self.tsbpd_base.is_none() {
            self.tsbpd_base = Some((timestamp, now));
            self.ts_wrap = Some(TsbpdWrap::new(timestamp));
        } else if let Some(wrap) = &mut self.ts_wrap {
            wrap.observe(timestamp);
        }
        // Sample clock drift from fresh (non-retransmitted) arrivals: a
        // retransmission arrives late by design and would poison the estimate
        // (spec §4.7).
        if !retransmitted && let Some(expected) = self.tsbpd_expected_arrival(timestamp) {
            let observed = signed_micros(expected, now);
            self.drift.sample(observed, micros_i64(self.rtt.rtt()));
        }
        self.deliver_tsbpd(now);
        self.packets_since_ack += 1;
        if self.packets_since_ack >= LIGHT_ACK_EVERY {
            self.send_light_ack(now);
        }
        // Only build the (O(n)) loss list when a gap actually exists; the common
        // in-order case is an O(1) check, which keeps per-packet cost flat even
        // with a large (high-latency) receive buffer.
        if self.recv_buffer.has_gaps() {
            // Hold back gaps that may just be reordered in flight (reorder
            // tolerance); only NAK the aged ones.
            let missing = self.recv_buffer.missing_aged(self.reorder_tolerance);
            if !missing.is_empty() && missing != self.reported_loss {
                self.send_nak(&missing, now);
                self.reported_loss = missing;
            }
        } else if !self.reported_loss.is_empty() {
            self.reported_loss.clear();
        }
    }

    /// Adapts the reorder tolerance to the link (5c in docs/known-issues/05;
    /// libsrt's `SRTO_LOSSMAXTTL` adaptation). A **belated original** — a
    /// non-retransmitted packet arriving circularly behind the highest original
    /// seen — proves the link reordered it rather than dropped it; the
    /// tolerance grows to that observed displacement (capped) so equally-deep
    /// reordering is no longer NAK'd as loss. Sustained in-order arrival decays
    /// the tolerance back, recovering fast loss reports. Retransmissions are
    /// excluded: they arrive behind by design and would inflate the estimate.
    fn track_reorder(&mut self, seq: SeqNumber, retransmitted: bool) {
        if retransmitted {
            return;
        }
        let Some(highest) = self.highest_recv_seq else {
            self.highest_recv_seq = Some(seq);
            return;
        };
        let offset = seq.offset_from(highest);
        if offset >= 0 {
            self.highest_recv_seq = Some(seq);
            self.orderly_streak += 1;
            if self.orderly_streak >= REORDER_DECAY_AFTER {
                self.orderly_streak = 0;
                self.reorder_tolerance = self.reorder_tolerance.saturating_sub(1);
            }
        } else {
            let displacement = offset.unsigned_abs().min(MAX_REORDER_TOLERANCE);
            self.reorder_tolerance = self.reorder_tolerance.max(displacement);
            self.orderly_streak = 0;
        }
    }

    /// Delivers every buffered packet whose play time has arrived, dropping any
    /// too-late gaps (TLPKTDROP, spec §4.6), and re-arms the TSBPD timer for the
    /// next packet's play time.
    pub(super) fn deliver_tsbpd(&mut self, now: Instant) {
        loop {
            let Some((_, timestamp)) = self.recv_buffer.peek() else {
                self.outputs
                    .push_back(Output::ClearTimer { id: TimerId::Tsbpd });
                return;
            };
            let Some(play_time) = self.tsbpd_play_time(timestamp) else {
                return;
            };
            if now < play_time {
                // Not yet time to play: wake when it is.
                self.outputs.push_back(Output::SetTimer {
                    id: TimerId::Tsbpd,
                    after: play_time.saturating_duration_since(now),
                });
                return;
            }
            // `pop` skips (drops) any leading gap before the next present packet
            // (TLPKTDROP). The base advances by the dropped gap plus the one
            // delivered packet; count the gap as dropped.
            let before = self.recv_buffer.ack_point();
            if let Some(packet) = self.recv_buffer.pop() {
                let advanced = self.recv_buffer.ack_point().offset_from(before);
                self.stats.packets_dropped +=
                    u64::try_from(advanced.saturating_sub(1)).unwrap_or(0);
                // Reassemble fragments into messages before delivering.
                if let Some(message) = self.reassembler.push(packet) {
                    self.events.push_back(Event::DataReceived(message));
                }
            }
        }
    }

    /// The local time a packet with sender `timestamp` is *expected to arrive*
    /// (spec §4.5.1, drift-corrected per §4.7): `TsbpdTimeBase + PKT_TIMESTAMP +
    /// Drift`. The play time adds the latency on top.
    ///
    /// The offset comes from the wrap tracker, not a raw `wrapping_diff` against
    /// the frozen anchor — a single circular diff inverts sign past ±2^31 µs
    /// (~35.8 min), which would put every later play time in the past.
    fn tsbpd_expected_arrival(&self, timestamp: Timestamp) -> Option<Instant> {
        let (ref_ts, ref_instant) = self.tsbpd_base?;
        let wrap = self.ts_wrap.as_ref()?;
        let offset =
            wrap.offset_of(timestamp) - i64::from(ref_ts.as_micros()) + self.drift.correction_us();
        Some(apply_signed(ref_instant, offset))
    }

    /// The local play time of a packet with sender `timestamp` (spec §4.5.1):
    /// `TsbpdTimeBase + PKT_TIMESTAMP + TsbpdDelay + Drift`.
    fn tsbpd_play_time(&self, timestamp: Timestamp) -> Option<Instant> {
        Some(self.tsbpd_expected_arrival(timestamp)? + self.latency)
    }

    /// Handles an ACKACK (spec §4.10): the round trip from our ACK to this reply
    /// is an RTT sample.
    pub(super) fn on_ackack(&mut self, ack_number: u32, now: Instant) {
        if let Some(pos) = self.pending_acks.iter().position(|&(n, _)| n == ack_number) {
            let (_, sent_at) = self.pending_acks[pos];
            self.rtt.sample(now.saturating_duration_since(sent_at));
            self.pending_acks.drain(..=pos);
        }
    }

    /// The periodic full-ACK timer fired (spec §4.8.1): acknowledge new data with
    /// an RTT-bearing ACK, recording it for the ACKACK RTT sample.
    pub(super) fn on_ack_timer(&mut self, now: Instant) {
        if !matches!(self.state, State::Connected) {
            return;
        }
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::Ack,
            after: ACK_INTERVAL,
        });
        // ACKs report the contiguously-*received* point, which runs ahead of the
        // delivery base while TSBPD holds data — so the sender can release its
        // retransmission buffer promptly rather than after the latency window.
        // An availability change re-ACKs even with no new data: a sender blocked
        // on our advertised window has no other way to learn it reopened.
        let ack_point = self.recv_buffer.received_ack_point();
        let avail = self.available_recv_buffer();
        if self.last_acked_point == Some(ack_point) && self.last_acked_avail == Some(avail) {
            return; // nothing new to acknowledge or advertise
        }
        let ack_number = self.next_ack_number;
        self.next_ack_number = self.next_ack_number.wrapping_add(1);
        self.pending_acks.push_back((ack_number, now));
        if self.pending_acks.len() > MAX_PENDING_ACKS {
            self.pending_acks.pop_front();
        }
        self.last_acked_point = Some(ack_point);
        self.last_acked_avail = Some(avail);
        self.packets_since_ack = 0;
        let (packets_recv_rate, receiving_rate) = self.rate.delivery_rate();
        let ack = Ack {
            ack_number,
            last_ack_seq: ack_point,
            // A full ACK reports RTT, buffer, and the receiver's measured rates
            // (spec §3.2.4) — what a peer's congestion control reads.
            cif: AckCif::Full {
                rtt: micros_u32(self.rtt.rtt()),
                rtt_variance: micros_u32(self.rtt.var()),
                avail_buffer_size: avail,
                packets_recv_rate,
                estimated_link_capacity: self.rate.peak_rate(),
                receiving_rate,
            },
        };
        self.stats.acks_sent += 1;
        let bytes = encode_control(
            self.peer_socket_id,
            self.wire_ts(now),
            ControlBody::Ack(ack),
        );
        self.emit(bytes, now);
    }

    /// The periodic NAK timer fired (spec §4.8.2): re-report any outstanding loss.
    ///
    /// The periodic NAK is the backstop for a *lost* loss report — not a license
    /// to re-send one every interval. A loss NAK'd less than one RTO ago is
    /// (presumably) already being recovered, its retransmission still in flight;
    /// only after an RTO of NAK silence is it re-reported.
    pub(super) fn on_nak_timer(&mut self, now: Instant) {
        if !matches!(self.state, State::Connected) {
            return;
        }
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::Nak,
            after: self.nak_interval(),
        });
        if self
            .last_nak
            .is_some_and(|at| now.saturating_duration_since(at) < self.rtt.rto())
        {
            return;
        }
        let missing = self.recv_buffer.missing_aged(self.reorder_tolerance);
        if !missing.is_empty() {
            self.send_nak(&missing, now);
        }
    }

    /// How much receive buffer we have free, in packets — what a full ACK
    /// advertises (spec §3.2.4). Packets held for TSBPD play-out and delivered-
    /// but-undrained events both still occupy memory, so both count against the
    /// window; a stalled application therefore closes the peer's send window
    /// instead of letting data pile up unbounded.
    fn available_recv_buffer(&self) -> u32 {
        let held = self.recv_buffer.occupancy() + self.events.len();
        self.config
            .flow_window
            .saturating_sub(u32::try_from(held).unwrap_or(u32::MAX))
    }

    /// Emits a light ACK: the acknowledged sequence only, no RTT, no ACKACK.
    fn send_light_ack(&mut self, now: Instant) {
        self.packets_since_ack = 0;
        let ack = Ack {
            ack_number: 0,
            last_ack_seq: self.recv_buffer.received_ack_point(),
            cif: AckCif::Light,
        };
        self.stats.acks_sent += 1;
        let bytes = encode_control(
            self.peer_socket_id,
            self.wire_ts(now),
            ControlBody::Ack(ack),
        );
        self.emit(bytes, now);
    }

    /// Emits a NAK carrying `missing` as a compressed loss list, stamping the
    /// send time so the periodic NAK timer can back off (see
    /// [`on_nak_timer`](Connection::on_nak_timer)).
    fn send_nak(&mut self, missing: &[(SeqNumber, SeqNumber)], now: Instant) {
        let loss = missing
            .iter()
            .map(|&(start, end)| LossRange::new(start, end))
            .collect();
        let bytes = encode_control(
            self.peer_socket_id,
            self.wire_ts(now),
            ControlBody::Nak { loss },
        );
        self.stats.naks_sent += 1;
        self.emit(bytes, now);
        self.last_nak = Some(now);
    }

    // ---- timers / derived intervals ----

    /// Arms (or re-arms) the EXP timer at the backed-off, floored RTO.
    fn arm_exp(&mut self) {
        let after = (self.rtt.rto() * self.exp_count).max(MIN_EXP_INTERVAL);
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::Exp,
            after,
        });
    }

    /// The periodic NAK interval: `(RTT + 4·RTTVar)/2`, floored (spec §4.8.2).
    fn nak_interval(&self) -> Duration {
        (self.rtt.rto() / 2).max(MIN_NAK_INTERVAL)
    }

    /// Cancels all ARQ / delivery timers (on close / shutdown).
    pub(super) fn clear_arq_timers(&mut self) {
        for id in [
            TimerId::Ack,
            TimerId::Nak,
            TimerId::Exp,
            TimerId::Tsbpd,
            TimerId::SndPacing,
            TimerId::Keepalive,
            TimerId::PeerIdle,
        ] {
            self.outputs.push_back(Output::ClearTimer { id });
        }
    }
}

/// Whether `seq` lies in the inclusive circular range `[start, end]`.
fn in_range(seq: SeqNumber, start: SeqNumber, end: SeqNumber) -> bool {
    seq.offset_from(start) >= 0 && end.offset_from(seq) >= 0
}

/// Encodes a data packet into a datagram.
fn encode_data(packet: &DataPacket) -> Bytes {
    let mut buf = BytesMut::new();
    Packet::Data(packet.clone()).encode(&mut buf);
    buf.freeze()
}

/// Encodes a retransmission: the original packet, bit-for-bit, with only the
/// `R` flag set. The original timestamp is kept — the receiver's TSBPD play
/// time derives from it, and under AES-GCM it is authenticated by the stored
/// tag (matching libsrt, which resends its buffered ciphertext verbatim).
fn encode_retransmit(packet: &DataPacket) -> Bytes {
    let mut resent = packet.clone();
    resent.retransmitted = true;
    let mut buf = BytesMut::new();
    Packet::Data(resent).encode(&mut buf);
    buf.freeze()
}

/// A [`Duration`] as whole microseconds clamped to `u32` (the ACK field width).
fn micros_u32(d: Duration) -> u32 {
    u32::try_from(d.as_micros()).unwrap_or(u32::MAX)
}

/// A [`Duration`] as whole microseconds clamped to `i64` (for drift arithmetic).
fn micros_i64(d: Duration) -> i64 {
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}

/// Offsets `instant` by a signed microsecond amount, saturating at the origin.
fn apply_signed(instant: Instant, micros: i64) -> Instant {
    if micros >= 0 {
        instant + Duration::from_micros(u64::try_from(micros).unwrap_or(0))
    } else {
        instant
            .checked_sub(Duration::from_micros(micros.unsigned_abs()))
            .unwrap_or(instant)
    }
}

/// Signed microseconds from `from` to `to` (`to - from`).
fn signed_micros(from: Instant, to: Instant) -> i64 {
    if to >= from {
        i64::try_from(to.duration_since(from).as_micros()).unwrap_or(i64::MAX)
    } else {
        -i64::try_from(from.duration_since(to).as_micros()).unwrap_or(i64::MAX)
    }
}
