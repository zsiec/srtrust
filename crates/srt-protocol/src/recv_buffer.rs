//! Receiver-side reassembly buffer (ARQ, spec §4.5/§4.6).
//!
//! Incoming data packets may arrive out of order, duplicated, or with gaps where
//! packets were lost. This buffer absorbs that: it stores packets at their
//! sequence offset from a moving `base` (the next sequence the application
//! expects), hands them to the application **in order** as the gaps fill, and
//! reports which sequences are still missing so the connection can NAK them.
//!
//! `base` doubles as the acknowledgement point — the sequence number one past the
//! last contiguously received packet — which is exactly what an ACK reports
//! (spec §3.2.4).
//!
//! Pure and clock-free like the rest of the core: it answers "what is ready" and
//! "what is missing"; the *timing* of ACK/NAK is the connection's job, and the
//! flow window that bounds it is enforced by the caller.

use core::cmp::Ordering;
use std::collections::VecDeque;

use crate::packet::DataPacket;
use crate::seq::SeqNumber;
use crate::timestamp::Timestamp;

/// A reassembly buffer holding out-of-order data until it can be delivered in
/// sequence.
#[derive(Debug)]
pub(crate) struct RecvBuffer {
    /// Next sequence number the application expects; also the ACK point. Slot `i`
    /// in `slots` holds the packet for `base + i`.
    base: SeqNumber,
    /// Sparse storage from `base` onward; `None` marks a not-yet-received slot.
    /// The back slot is always present (storage extends to the highest received),
    /// so `slots.len()` is the span from `base` to the highest received packet.
    slots: VecDeque<Option<DataPacket>>,
    /// Count of present (`Some`) slots, maintained incrementally so [`has_gaps`]
    /// is O(1). Equals `slots.len()` exactly when there is no gap.
    ///
    /// [`has_gaps`]: RecvBuffer::has_gaps
    received: usize,
}

impl RecvBuffer {
    /// Creates a buffer expecting `initial_seq` as the first sequence number
    /// (the peer's initial sequence number from the handshake).
    pub(crate) fn new(initial_seq: SeqNumber) -> Self {
        RecvBuffer {
            base: initial_seq,
            slots: VecDeque::new(),
            received: 0,
        }
    }

    /// The acknowledgement point: the next expected (lowest not-yet-received)
    /// sequence number (spec §3.2.4).
    pub(crate) fn ack_point(&self) -> SeqNumber {
        self.base
    }

    /// How many packets are currently buffered (present slots) — the receive
    /// buffer occupancy reported in connection statistics.
    pub(crate) fn occupancy(&self) -> usize {
        self.received
    }

    /// The acknowledgement point to report in an ACK: one past the last
    /// **contiguously received** packet. This runs ahead of [`ack_point`] (the
    /// delivery base) while TSBPD holds received data for its play time — the
    /// sender clears its retransmission buffer up to this point, so it must
    /// reflect reception, not delivery (otherwise the sender needlessly retains
    /// and retransmits already-received data for the whole latency window).
    ///
    /// [`ack_point`]: RecvBuffer::ack_point
    pub(crate) fn received_ack_point(&self) -> SeqNumber {
        let contiguous = self.slots.iter().take_while(|slot| slot.is_some()).count();
        self.base + u32::try_from(contiguous).unwrap_or(u32::MAX)
    }

    /// Whether any packet below the highest received is still missing — an O(1)
    /// gap check. [`missing`](RecvBuffer::missing) builds the actual loss list and
    /// is O(n), so the connection calls it only when this returns `true`.
    pub(crate) fn has_gaps(&self) -> bool {
        // The back slot is always present, so `slots.len()` is the span; a gap
        // exists exactly when fewer slots are present than the span is wide.
        self.received != self.slots.len()
    }

    /// Inserts a received packet. Returns `true` if it was newly stored, `false`
    /// if it was a duplicate or already-acknowledged (too old) packet.
    pub(crate) fn insert(&mut self, packet: DataPacket) -> bool {
        // A negative offset is a sequence at or below the ACK point: already
        // delivered, so it is a stale duplicate.
        let Ok(offset) = usize::try_from(packet.seq.offset_from(self.base)) else {
            return false;
        };
        if offset >= self.slots.len() {
            self.slots.resize_with(offset + 1, || None);
        }
        if self.slots[offset].is_some() {
            return false; // duplicate
        }
        self.slots[offset] = Some(packet);
        self.received += 1;
        true
    }

    /// The earliest still-buffered packet's sequence number and sender timestamp
    /// (skipping any leading gap), without removing it. This is the spec's
    /// `next_avail()` in the §4.6 receiver read algorithm; the connection uses the
    /// timestamp to decide whether it is time to play.
    pub(crate) fn peek(&self) -> Option<(SeqNumber, Timestamp)> {
        let pos = self.slots.iter().position(Option::is_some)?;
        let packet = self.slots[pos].as_ref()?;
        Some((packet.seq, packet.timestamp))
    }

    /// Removes and returns the earliest still-buffered packet, advancing the ACK
    /// point past it and **dropping any preceding gap** (TLPKTDROP, spec §4.6:
    /// "drop packets which buffer position number is less than i"). The dropped
    /// gap is too late to ever deliver, so the ACK point legitimately moves past
    /// it (the spec's "fake ACK").
    pub(crate) fn pop(&mut self) -> Option<DataPacket> {
        let pos = self.slots.iter().position(Option::is_some)?;
        self.slots.drain(..pos); // drop the leading gap (uncounted Nones)
        let packet = self.slots.pop_front().flatten();
        if let Some(delivered) = &packet {
            self.base = delivered.seq.next();
            self.received -= 1;
        }
        packet
    }

    /// Pops the next packet **only if it sits at the ACK point** (no leading
    /// gap), advancing past it. Unlike [`pop`](RecvBuffer::pop) this never skips a
    /// loss hole — it is the graceful-shutdown flush, delivering the contiguous
    /// data we already hold without papering over a real gap.
    pub(crate) fn pop_in_order(&mut self) -> Option<DataPacket> {
        if matches!(self.slots.front(), Some(Some(_))) {
            self.pop()
        } else {
            None // empty, or a gap at the front
        }
    }

    /// Forcibly drops the sequence range `[first, last]` the sender announced it
    /// will never deliver (DROPREQ, spec §3.2.9), advancing the ACK point past it
    /// so the receiver stops waiting for — and `NAK`-ing — packets that are not
    /// coming.
    ///
    /// Only a range reaching the current ACK point is acted on: a sender drops its
    /// *oldest* unacknowledged packets, which map to the receiver's leading gap,
    /// so `first <= base` in practice. A purely interior range is left to
    /// play-time TLPKTDROP (its packets are skipped when their play time passes).
    pub(crate) fn drop_range(&mut self, first: SeqNumber, last: SeqNumber) {
        // `last` already behind the ACK point: already delivered or dropped.
        if last.circular_cmp(self.base) == Ordering::Less {
            return;
        }
        // Interior range (does not reach the ACK point): leave to play-time drop.
        if first.circular_cmp(self.base) == Ordering::Greater {
            return;
        }
        // Range covers the front: advance the ACK point past `last`.
        let advance = usize::try_from(last.offset_from(self.base)).unwrap_or(0) + 1;
        for _ in 0..advance {
            match self.slots.pop_front() {
                Some(Some(_)) => self.received -= 1,
                Some(None) => {}
                None => break,
            }
        }
        self.base = last.next();
    }

    /// The missing sequence ranges (inclusive) below the highest received packet
    /// — the loss list for a NAK (spec §3.2.5). Empty when there is no gap.
    pub(crate) fn missing(&self) -> Vec<(SeqNumber, SeqNumber)> {
        // Gaps only count below the highest received packet: an absent slot past
        // everything received is simply not here yet, not lost.
        let Some(highest) = self.slots.iter().rposition(Option::is_some) else {
            return Vec::new();
        };
        let mut ranges = Vec::new();
        let mut run_start: Option<SeqNumber> = None;
        // Walk a running sequence number so there are no index-to-seq casts.
        let mut seq = self.base;
        for slot in self.slots.iter().take(highest + 1) {
            if slot.is_none() {
                run_start.get_or_insert(seq);
            } else if let Some(start) = run_start.take() {
                // The run [start, seq) is missing; `highest` is present, so any
                // open run always closes here before the loop ends.
                ranges.push((start, seq.prev()));
            }
            seq = seq.next();
        }
        ranges
    }

    /// Like [`missing`](RecvBuffer::missing), but reports only the part of each gap
    /// that has aged at least `tolerance` packets below the highest received — so a
    /// freshly-opened gap (a packet that may just be reordered in flight) is held
    /// back rather than NAK'd (libsrt's reorder tolerance / `LossMaxTTL`).
    /// `tolerance == 0` is identical to `missing`.
    pub(crate) fn missing_aged(&self, tolerance: u32) -> Vec<(SeqNumber, SeqNumber)> {
        if tolerance == 0 {
            return self.missing();
        }
        let Some(highest_idx) = self.slots.iter().rposition(Option::is_some) else {
            return Vec::new();
        };
        let highest = self.base + u32::try_from(highest_idx).unwrap_or(u32::MAX);
        // The newest sequence still old enough to report; anything above it is
        // "fresh" and given more time to arrive. (31-bit wrap via the masking ctor.)
        let threshold = SeqNumber::new(highest.value().wrapping_sub(tolerance));
        self.missing()
            .into_iter()
            .filter_map(|(start, end)| {
                if start.circular_cmp(threshold) == Ordering::Greater {
                    return None; // the whole gap is fresh
                }
                // Trim the fresh top of the gap, if any.
                let end = if end.circular_cmp(threshold) == Ordering::Greater {
                    threshold
                } else {
                    end
                };
                Some((start, end))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Encryption, MsgNumber, PacketPosition, SocketId};
    use crate::timestamp::Timestamp;
    use bytes::Bytes;

    fn data(seq: SeqNumber) -> DataPacket {
        DataPacket {
            seq,
            position: PacketPosition::Single,
            in_order: true,
            encryption: Encryption::None,
            retransmitted: false,
            message_number: MsgNumber::new(seq.value()),
            // Tag the timestamp with the sequence so `peek` is checkable.
            timestamp: Timestamp::from_micros(seq.value()),
            dest_socket_id: SocketId::new(0),
            payload: Bytes::from_static(b"x"),
        }
    }

    fn ts(seq: SeqNumber) -> Timestamp {
        Timestamp::from_micros(seq.value())
    }

    /// Pops every currently-buffered packet (skipping gaps), returning the seqs.
    fn drain(buf: &mut RecvBuffer) -> Vec<SeqNumber> {
        let mut out = Vec::new();
        while let Some(p) = buf.pop() {
            out.push(p.seq);
        }
        out
    }

    #[test]
    fn delivers_a_contiguous_run_in_order() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        for i in 0..3 {
            assert!(buf.insert(data(base + i)));
        }
        assert_eq!(buf.peek(), Some((base, ts(base))));
        assert_eq!(drain(&mut buf), vec![base, base + 1, base + 2]);
        assert_eq!(buf.ack_point(), base + 3);
        assert!(buf.missing().is_empty());
    }

    #[test]
    fn peek_finds_the_earliest_present_packet_across_a_gap() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        // base+1 arrives before base: peek sees it, but the ACK point holds and
        // base is still a reported gap (peek does not drop anything).
        assert!(buf.insert(data(base + 1)));
        assert_eq!(buf.peek(), Some((base + 1, ts(base + 1))));
        assert_eq!(buf.ack_point(), base, "peek does not advance the ACK point");
        assert_eq!(buf.missing(), vec![(base, base)]);
        // When base arrives, peek prefers it (the lower sequence).
        assert!(buf.insert(data(base)));
        assert_eq!(buf.peek().map(|(seq, _)| seq), Some(base));
        assert_eq!(drain(&mut buf), vec![base, base + 1]);
    }

    #[test]
    fn pop_drops_a_leading_gap_tlpktdrop() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        // base is missing, base+1 present: popping delivers base+1 and drops base.
        assert!(buf.insert(data(base + 1)));
        assert_eq!(buf.pop().map(|p| p.seq), Some(base + 1));
        assert_eq!(buf.ack_point(), base + 2, "ACK point skips the dropped gap");
        assert!(buf.missing().is_empty());
        assert!(buf.pop().is_none());
    }

    #[test]
    fn pop_skips_multiple_gaps() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        buf.insert(data(base)); // present
        buf.insert(data(base + 2)); // gap at base+1
        buf.insert(data(base + 5)); // gap at base+3..=base+4
        assert_eq!(
            buf.missing(),
            vec![(base + 1, base + 1), (base + 3, base + 4)]
        );
        assert_eq!(buf.pop().map(|p| p.seq), Some(base)); // contiguous head
        assert_eq!(buf.pop().map(|p| p.seq), Some(base + 2)); // drops base+1
        assert_eq!(buf.ack_point(), base + 3);
        assert_eq!(buf.pop().map(|p| p.seq), Some(base + 5)); // drops base+3..=base+4
        assert_eq!(buf.ack_point(), base + 6);
    }

    #[test]
    fn has_gaps_tracks_missing_in_o1() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        assert!(!buf.has_gaps(), "empty buffer has no gaps");

        buf.insert(data(base)); // contiguous
        assert!(!buf.has_gaps());

        buf.insert(data(base + 2)); // opens a gap at base+1
        assert!(buf.has_gaps());
        // The cheap flag must agree with the authoritative (O(n)) loss list.
        assert_eq!(buf.has_gaps(), !buf.missing().is_empty());

        buf.insert(data(base + 1)); // fills the gap
        assert!(!buf.has_gaps());
        assert_eq!(buf.has_gaps(), !buf.missing().is_empty());

        // Popping a leading gap (TLPKTDROP) leaves no gap behind it.
        let mut buf = RecvBuffer::new(base);
        buf.insert(data(base + 1)); // base is missing
        assert!(buf.has_gaps());
        assert_eq!(buf.pop().map(|p| p.seq), Some(base + 1)); // drops base
        assert!(!buf.has_gaps(), "the gap was dropped, not left dangling");
        assert_eq!(buf.has_gaps(), !buf.missing().is_empty());
    }

    #[test]
    fn missing_aged_holds_fresh_gaps_until_they_age() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        buf.insert(data(base)); // present
        buf.insert(data(base + 5)); // gap base+1..=base+4, highest = base+5
        assert_eq!(buf.missing(), vec![(base + 1, base + 4)]);
        // tolerance 0 == missing.
        assert_eq!(buf.missing_aged(0), buf.missing());
        // tolerance 3: threshold = base+2; report [base+1, base+2], hold the rest.
        assert_eq!(buf.missing_aged(3), vec![(base + 1, base + 2)]);
        // A large tolerance holds the whole (still-fresh) gap.
        assert!(buf.missing_aged(10).is_empty());
    }

    #[test]
    fn missing_aged_reports_a_gap_whose_top_has_aged() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        buf.insert(data(base));
        buf.insert(data(base + 1));
        buf.insert(data(base + 8)); // gap base+2..=base+7, highest = base+8
        // tolerance 3: threshold = base+5; the gap's fresh top [base+6,base+7] is
        // held, the aged part [base+2, base+5] is reported.
        assert_eq!(buf.missing_aged(3), vec![(base + 2, base + 5)]);
    }

    #[test]
    fn drop_range_at_the_front_advances_the_ack_point() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        buf.insert(data(base + 3)); // base..=base+2 are a leading gap
        // The sender drops base..=base+2; we advance past them.
        buf.drop_range(base, base + 2);
        assert_eq!(buf.ack_point(), base + 3, "advanced past the dropped gap");
        assert!(!buf.has_gaps(), "no gap remains before base+3");
        assert_eq!(
            buf.pop().map(|p| p.seq),
            Some(base + 3),
            "buffered packet survives"
        );
    }

    #[test]
    fn drop_range_past_everything_empties_the_buffer() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        buf.insert(data(base + 1));
        buf.drop_range(base, base + 5); // beyond the highest received
        assert_eq!(buf.ack_point(), base + 6);
        assert!(!buf.has_gaps());
        assert!(buf.pop().is_none(), "everything dropped");
    }

    #[test]
    fn drop_range_interior_is_left_to_playtime_drop() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        buf.insert(data(base)); // present at front
        buf.insert(data(base + 4)); // gap at base+1..=base+3
        // An interior drop (not reaching base) is a deliberate no-op here; the gap
        // stays until play-time TLPKTDROP skips it. base is still expected.
        buf.drop_range(base + 1, base + 3);
        assert_eq!(buf.ack_point(), base, "base unmoved");
        assert_eq!(buf.missing(), vec![(base + 1, base + 3)], "still a gap");
    }

    #[test]
    fn drop_range_already_behind_base_is_a_noop() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        buf.insert(data(base));
        buf.pop(); // ack point now base+1
        buf.drop_range(base.prev(), base); // wholly below the ack point
        assert_eq!(buf.ack_point(), base + 1, "unchanged");
    }

    #[test]
    fn ignores_duplicates_and_old_packets() {
        let base = SeqNumber::new(500);
        let mut buf = RecvBuffer::new(base);
        assert!(buf.insert(data(base)));
        assert!(!buf.insert(data(base)), "duplicate is rejected");
        assert_eq!(buf.pop().map(|p| p.seq), Some(base));
        // base has been delivered; re-receiving it is too old.
        assert!(!buf.insert(data(base)), "already-popped packet is rejected");
        assert_eq!(buf.ack_point(), base + 1);
    }

    #[test]
    fn handles_the_31_bit_wraparound() {
        let base = SeqNumber::MAX.prev(); // MAX-1
        let mut buf = RecvBuffer::new(base);
        // Arrive out of order across the wrap: MAX, then ZERO, then MAX-1.
        buf.insert(data(SeqNumber::MAX));
        buf.insert(data(SeqNumber::ZERO));
        assert_eq!(buf.missing(), vec![(base, base)]);
        buf.insert(data(base));
        assert_eq!(drain(&mut buf), vec![base, SeqNumber::MAX, SeqNumber::ZERO]);
        assert_eq!(buf.ack_point(), SeqNumber::new(1));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::packet::{Encryption, MsgNumber, PacketPosition, SocketId};
    use crate::timestamp::Timestamp;
    use bytes::Bytes;
    use proptest::prelude::*;

    fn data(seq: SeqNumber) -> DataPacket {
        DataPacket {
            seq,
            position: PacketPosition::Single,
            in_order: true,
            encryption: Encryption::None,
            retransmitted: false,
            message_number: MsgNumber::new(seq.value()),
            timestamp: Timestamp::from_micros(0),
            dest_socket_id: SocketId::new(0),
            payload: Bytes::from_static(b"x"),
        }
    }

    proptest! {
        // However a contiguous run base..base+n is permuted on arrival, once all
        // have been inserted the buffer delivers exactly base..base+n in order,
        // leaves no gap, and lands the ACK point at base+n.
        #[test]
        fn any_arrival_order_reassembles_in_sequence(
            base: u32,
            n in 1u32..32,
            swaps in prop::collection::vec(0usize..32, 0..32),
        ) {
            let base = SeqNumber::new(base);
            // A full contiguous run 0..n, shuffled deterministically by `swaps`.
            let mut offsets: Vec<u32> = (0..n).collect();
            let len = offsets.len();
            for (i, &s) in swaps.iter().enumerate() {
                offsets.swap(i % len, s % len);
            }
            let mut buf = RecvBuffer::new(base);
            for &off in &offsets {
                buf.insert(data(base + off));
            }
            let mut delivered = Vec::new();
            while let Some(p) = buf.pop() {
                delivered.push(p.seq);
            }
            let expected: Vec<SeqNumber> = (0..n).map(|i| base + i).collect();
            prop_assert_eq!(delivered, expected);
            prop_assert!(buf.missing().is_empty());
            prop_assert_eq!(buf.ack_point(), base + n);
        }
    }
}
