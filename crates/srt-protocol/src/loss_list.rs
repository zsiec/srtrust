//! NAK loss-list compression (spec §3.2.5, Appendix A).
//!
//! A NAK reports lost packets as a list of 32-bit words. A word whose high bit
//! is **clear** is a single lost sequence number. A word whose high bit is
//! **set** begins an inclusive range: its low 31 bits are the range start, and
//! the immediately following word (high bit clear) is the range end. This keeps
//! large contiguous gaps compact.
//!
//! We decode into [`LossRange`]s rather than expanding every sequence number,
//! so a crafted "range" spanning the whole sequence space costs two words, not
//! two billion allocations.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::LossListError;
use crate::seq::SeqNumber;

/// High bit of a loss-list word, marking a range-start word.
const RANGE_FLAG: u32 = 0x8000_0000;

/// An inclusive range of lost sequence numbers. A single lost packet is a range
/// whose `start` equals its `end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossRange {
    start: SeqNumber,
    end: SeqNumber,
}

impl LossRange {
    /// A range covering a single lost sequence number.
    #[must_use]
    pub const fn single(seq: SeqNumber) -> Self {
        LossRange {
            start: seq,
            end: seq,
        }
    }

    /// An inclusive range from `start` to `end`.
    #[must_use]
    pub const fn new(start: SeqNumber, end: SeqNumber) -> Self {
        LossRange { start, end }
    }

    /// The first lost sequence number in the range.
    #[must_use]
    pub const fn start(self) -> SeqNumber {
        self.start
    }

    /// The last lost sequence number in the range (inclusive).
    #[must_use]
    pub const fn end(self) -> SeqNumber {
        self.end
    }

    /// Whether this range covers exactly one sequence number.
    #[must_use]
    pub const fn is_single(self) -> bool {
        self.start.value() == self.end.value()
    }
}

/// Encodes a loss list into `out` (appending). Single-element ranges use one
/// word; multi-element ranges use a range-start word plus an end word.
pub fn encode(ranges: &[LossRange], out: &mut BytesMut) {
    for range in ranges {
        if range.is_single() {
            // High bit is clear because a sequence value is only 31 bits.
            out.put_u32(range.start.value());
        } else {
            out.put_u32(range.start.value() | RANGE_FLAG);
            out.put_u32(range.end.value());
        }
    }
}

/// Decodes a loss list from `buf`.
///
/// # Errors
///
/// Returns [`LossListError::Misaligned`] if `buf` is not a multiple of 4 bytes,
/// or [`LossListError::TruncatedRange`] if a range-start word has no following
/// end word.
pub fn decode(buf: &[u8]) -> Result<Vec<LossRange>, LossListError> {
    if buf.len() % 4 != 0 {
        return Err(LossListError::Misaligned(buf.len()));
    }

    let mut cur = buf;
    let mut ranges = Vec::with_capacity(cur.len() / 4);
    while cur.has_remaining() {
        let word = cur.get_u32();
        if word & RANGE_FLAG != 0 {
            // Range start; the end word must follow.
            if cur.remaining() < 4 {
                return Err(LossListError::TruncatedRange);
            }
            let start = SeqNumber::new(word);
            let end = SeqNumber::new(cur.get_u32());
            ranges.push(LossRange::new(start, end));
        } else {
            ranges.push(LossRange::single(SeqNumber::new(word)));
        }
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(v: u32) -> SeqNumber {
        SeqNumber::new(v)
    }

    #[test]
    fn single_round_trips_as_one_word() {
        let list = [LossRange::single(seq(5))];
        let mut buf = BytesMut::new();
        encode(&list, &mut buf);
        assert_eq!(buf.len(), 4);
        // High bit clear => single.
        assert_eq!(buf[0] & 0x80, 0);
        assert_eq!(decode(&buf).unwrap(), list);
    }

    #[test]
    fn range_round_trips_as_two_words() {
        let list = [LossRange::new(seq(10), seq(13))];
        let mut buf = BytesMut::new();
        encode(&list, &mut buf);
        assert_eq!(buf.len(), 8);
        // High bit of the first word set => range start.
        assert_eq!(buf[0] & 0x80, 0x80);
        assert_eq!(decode(&buf).unwrap(), list);
    }

    #[test]
    fn mixed_list_round_trips() {
        let list = [
            LossRange::single(seq(1)),
            LossRange::new(seq(5), seq(9)),
            LossRange::single(seq(20)),
        ];
        let mut buf = BytesMut::new();
        encode(&list, &mut buf);
        assert_eq!(buf.len(), 4 + 8 + 4);
        assert_eq!(decode(&buf).unwrap(), list);
    }

    #[test]
    fn decode_rejects_misaligned_buffer() {
        assert_eq!(decode(&[0u8; 5]), Err(LossListError::Misaligned(5)));
    }

    #[test]
    fn decode_rejects_truncated_range() {
        // One word with the range flag set, but no end word follows.
        let mut buf = BytesMut::new();
        buf.put_u32(RANGE_FLAG | 7);
        assert_eq!(decode(&buf), Err(LossListError::TruncatedRange));
    }

    #[test]
    fn empty_list_round_trips() {
        let mut buf = BytesMut::new();
        encode(&[], &mut buf);
        assert!(buf.is_empty());
        assert_eq!(decode(&buf).unwrap(), Vec::new());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn any_range() -> impl Strategy<Value = LossRange> {
        prop_oneof![
            (0u32..=0x7FFF_FFFF).prop_map(|v| LossRange::single(SeqNumber::new(v))),
            (0u32..=0x7FFF_FFFF, 0u32..=0x7FFF_FFFF)
                .prop_map(|(a, b)| LossRange::new(SeqNumber::new(a), SeqNumber::new(b))),
        ]
    }

    proptest! {
        // Decoding our own encoding recovers the list, and re-encoding is
        // byte-stable.
        #[test]
        fn round_trip(list in prop::collection::vec(any_range(), 0..64)) {
            let mut buf = BytesMut::new();
            encode(&list, &mut buf);
            let decoded = decode(&buf).expect("decoding our own encoding must succeed");
            let mut reencoded = BytesMut::new();
            encode(&decoded, &mut reencoded);
            prop_assert_eq!(&buf[..], &reencoded[..]);
        }
    }

    proptest! {
        // Decoding arbitrary bytes never panics and never allocates unboundedly
        // (it returns at most one range per word).
        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2000)) {
            if let Ok(ranges) = decode(&bytes) {
                prop_assert!(ranges.len() <= bytes.len() / 4);
            }
        }
    }
}
