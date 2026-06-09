//! Sender-side retransmission buffer (ARQ, spec §4.6).
//!
//! Every data packet we send is kept here until the peer acknowledges it, so we
//! can retransmit it on a NAK or a timeout. Packets are stored **contiguous by
//! sequence number** — `push` always appends the next sequence, and `ack` only
//! ever removes a prefix — which lets retransmission lookup be an O(1) index by
//! circular offset rather than a search.
//!
//! Like everything in the core this is pure and clock-free: it stores packets
//! and answers questions about them; *when* to retransmit is the connection's
//! decision. Flow-window limits are enforced by the caller, so the buffer itself
//! is unbounded.

use core::cmp::Ordering;
use std::collections::VecDeque;

use crate::packet::DataPacket;
use crate::seq::SeqNumber;

/// A store of sent-but-unacknowledged data packets, ordered by sequence number.
#[derive(Debug, Default)]
pub(crate) struct SendBuffer {
    /// Unacknowledged packets, oldest at the front, contiguous by sequence.
    packets: VecDeque<DataPacket>,
}

impl SendBuffer {
    /// Creates an empty buffer.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether the buffer holds no unacknowledged packets.
    pub(crate) fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// The number of unacknowledged packets held. Exercised by the unit tests.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.packets.len()
    }

    /// The oldest unacknowledged sequence number, if any.
    pub(crate) fn first_seq(&self) -> Option<SeqNumber> {
        self.packets.front().map(|p| p.seq)
    }

    /// The oldest unacknowledged packet, if any — used to test its age for
    /// send-side too-late dropping (TLPKTDROP / DROPREQ).
    pub(crate) fn front(&self) -> Option<&DataPacket> {
        self.packets.front()
    }

    /// Removes and returns the oldest unacknowledged packet (a send-side drop of a
    /// too-late packet). The buffer stays contiguous since this drops the front.
    pub(crate) fn drop_front(&mut self) -> Option<DataPacket> {
        self.packets.pop_front()
    }

    /// The newest stored sequence number, if any.
    pub(crate) fn last_seq(&self) -> Option<SeqNumber> {
        self.packets.back().map(|p| p.seq)
    }

    /// Stores a freshly-sent packet. Its sequence number must be the one
    /// immediately after the current last (or anything, if the buffer is empty).
    pub(crate) fn push(&mut self, packet: DataPacket) {
        debug_assert!(
            self.packets
                .back()
                .is_none_or(|last| packet.seq == last.seq.next()),
            "send buffer packets must be contiguous by sequence number"
        );
        self.packets.push_back(packet);
    }

    /// Acknowledges everything before `next_expected` (an ACK's "last
    /// acknowledged + 1" point, spec §3.2.4), dropping those packets. Returns how
    /// many were dropped.
    pub(crate) fn ack(&mut self, next_expected: SeqNumber) -> usize {
        let mut dropped = 0;
        while let Some(front) = self.packets.front() {
            if front.seq.circular_cmp(next_expected) == Ordering::Less {
                self.packets.pop_front();
                dropped += 1;
            } else {
                break;
            }
        }
        dropped
    }

    /// Looks up a stored packet by sequence number for retransmission, or `None`
    /// if it has been acknowledged or was never sent.
    ///
    /// Storage is contiguous, so the packet — if present — sits at the circular
    /// offset of `seq` past the front. A negative or out-of-range offset (already
    /// acknowledged, or not yet sent) misses, which `try_from`/`get` report.
    pub(crate) fn get(&self, seq: SeqNumber) -> Option<&DataPacket> {
        let front = self.packets.front()?.seq;
        let offset = usize::try_from(seq.offset_from(front)).ok()?;
        self.packets.get(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Encryption, MsgNumber, PacketPosition, SocketId};
    use crate::timestamp::Timestamp;
    use bytes::Bytes;

    /// Builds a minimal single-packet message at sequence `seq`.
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

    fn filled(base: SeqNumber, n: u32) -> SendBuffer {
        let mut buf = SendBuffer::new();
        for i in 0..n {
            buf.push(data(base + i));
        }
        buf
    }

    #[test]
    fn push_tracks_first_last_and_len() {
        let base = SeqNumber::new(1000);
        let buf = filled(base, 4);
        assert_eq!(buf.len(), 4);
        assert!(!buf.is_empty());
        assert_eq!(buf.first_seq(), Some(base));
        assert_eq!(buf.last_seq(), Some(base + 3));
    }

    #[test]
    fn get_returns_stored_packets_only() {
        let base = SeqNumber::new(1000);
        let buf = filled(base, 3);
        for i in 0..3 {
            assert_eq!(buf.get(base + i), Some(&data(base + i)));
        }
        assert_eq!(buf.get(base.prev()), None, "before the front");
        assert_eq!(buf.get(base + 3), None, "after the back");
    }

    #[test]
    fn get_on_empty_is_none() {
        let buf = SendBuffer::new();
        assert_eq!(buf.get(SeqNumber::new(5)), None);
    }

    #[test]
    fn ack_drops_only_the_acknowledged_prefix() {
        let base = SeqNumber::new(1000);
        let mut buf = filled(base, 5);
        // ACK says "next expected is base+3", i.e. base..base+3 are acknowledged.
        let dropped = buf.ack(base + 3);
        assert_eq!(dropped, 3);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.first_seq(), Some(base + 3));
        assert_eq!(buf.get(base + 2), None, "acknowledged packet is gone");
        assert_eq!(
            buf.get(base + 4),
            Some(&data(base + 4)),
            "later packet remains"
        );
    }

    #[test]
    fn ack_at_or_before_front_drops_nothing() {
        let base = SeqNumber::new(1000);
        let mut buf = filled(base, 3);
        assert_eq!(buf.ack(base), 0);
        assert_eq!(buf.ack(base.prev()), 0);
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn ack_past_the_last_drops_everything() {
        let base = SeqNumber::new(1000);
        let mut buf = filled(base, 4);
        let dropped = buf.ack(base + 4); // one past the last stored seq
        assert_eq!(dropped, 4);
        assert!(buf.is_empty());
        assert_eq!(buf.first_seq(), None);
    }

    #[test]
    fn handles_the_31_bit_wraparound() {
        // Start two below MAX so the buffer straddles the wrap to ZERO.
        let base = SeqNumber::MAX.prev();
        let buf = filled(base, 4); // MAX-1, MAX, 0, 1
        assert_eq!(buf.first_seq(), Some(SeqNumber::MAX.prev()));
        assert_eq!(buf.last_seq(), Some(SeqNumber::new(1)));
        assert_eq!(buf.get(SeqNumber::ZERO), Some(&data(SeqNumber::ZERO)));
        assert_eq!(buf.get(SeqNumber::MAX), Some(&data(SeqNumber::MAX)));

        let mut buf = buf;
        let dropped = buf.ack(SeqNumber::ZERO); // acknowledge MAX-1 and MAX
        assert_eq!(dropped, 2);
        assert_eq!(buf.first_seq(), Some(SeqNumber::ZERO));
        assert_eq!(buf.len(), 2);
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
        // From any base (including near the wrap), acking the k-th sequence drops
        // exactly the first k packets and leaves the rest individually retrievable.
        #[test]
        fn ack_drops_exactly_the_prefix(base: u32, n in 1u32..64, k in 0u32..64) {
            let base = SeqNumber::new(base);
            let mut buf = SendBuffer::new();
            for i in 0..n {
                buf.push(data(base + i));
            }
            let k = k.min(n);
            let dropped = buf.ack(base + k);
            prop_assert_eq!(dropped, k as usize);
            prop_assert_eq!(buf.len(), (n - k) as usize);
            if k < n {
                prop_assert_eq!(buf.first_seq(), Some(base + k));
                for i in k..n {
                    prop_assert!(buf.get(base + i).is_some());
                }
                prop_assert!(buf.get(base + (k.wrapping_sub(1))).is_none());
            } else {
                prop_assert!(buf.is_empty());
            }
        }
    }
}
