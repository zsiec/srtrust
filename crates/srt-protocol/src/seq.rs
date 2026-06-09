//! SRT data sequence numbers.
//!
//! SRT numbers data packets with a **31-bit** sequence number that wraps around
//! at `2^31`. Because it wraps, you cannot compare two sequence numbers with a
//! plain `<`: when the counter rolls over, a "newer" packet has a numerically
//! *smaller* value than an "older" one. SRT (following UDT) resolves this with
//! *circular* comparison — the two numbers are assumed to be less than half the
//! number space apart, and whichever is "ahead" within that window is the
//! greater one.
//!
//! We model the sequence number as a [newtype] so the 31-bit invariant and the
//! wrap-aware arithmetic live in one place and can't be bypassed by accident.
//! We deliberately do **not** implement [`Ord`]/[`PartialOrd`]: circular
//! comparison is not a total order (it isn't transitive across the whole space),
//! and implementing those traits with it would silently violate their contracts.
//! Callers use [`SeqNumber::circular_cmp`] explicitly instead.
//!
//! [newtype]: https://doc.rust-lang.org/rust-by-example/generics/new_types.html

use core::cmp::Ordering;
use core::ops::Add;

/// A 31-bit SRT data sequence number.
///
/// The wrapped value is always in `0..=`[`SeqNumber::MAX`]`.value()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeqNumber(u32);

impl SeqNumber {
    /// Mask selecting the low 31 bits.
    const MASK: u32 = 0x7FFF_FFFF;

    /// Number of distinct sequence values (`2^31`).
    const COUNT: u32 = 0x8000_0000;

    /// Half the sequence space — the comparison window. Two sequence numbers
    /// are assumed to be closer than this; whichever is ahead within the window
    /// is the greater. Matches libsrt's `CSeqNo::m_iSeqNoTH`.
    const THRESHOLD: u32 = 0x3FFF_FFFF;

    /// The smallest sequence number.
    pub const ZERO: SeqNumber = SeqNumber(0);

    /// The largest sequence number (`2^31 - 1`). `MAX.next()` wraps to `ZERO`.
    pub const MAX: SeqNumber = SeqNumber(Self::MASK);

    /// Creates a sequence number from a raw value, keeping only the low 31 bits.
    ///
    /// Masking (rather than rejecting) is intentional: this is how a value is
    /// extracted from a wire packet, where the field is exactly 31 bits.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        SeqNumber(value & Self::MASK)
    }

    /// The underlying 31-bit value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// The next sequence number, wrapping `MAX` back to `ZERO`.
    #[must_use]
    pub const fn next(self) -> Self {
        // self.0 <= MASK, so `+ 1` cannot overflow a u32 before masking.
        SeqNumber((self.0 + 1) & Self::MASK)
    }

    /// The previous sequence number, wrapping `ZERO` back to `MAX`.
    #[must_use]
    pub const fn prev(self) -> Self {
        SeqNumber(self.0.wrapping_sub(1) & Self::MASK)
    }

    /// Circular comparison: is `self` before, equal to, or after `other`?
    ///
    /// Returns [`Ordering::Less`] if `self` comes before `other` within the
    /// half-space comparison window, [`Ordering::Greater`] if after.
    #[must_use]
    pub const fn circular_cmp(self, other: SeqNumber) -> Ordering {
        match self.offset_from(other).signum() {
            1 => Ordering::Greater,
            -1 => Ordering::Less,
            _ => Ordering::Equal,
        }
    }

    /// Signed circular distance from `other` to `self`: how many `next()` steps
    /// separate them, positive if `self` is ahead of `other`. Result magnitude
    /// is at most `2^30` (half the sequence space, plus one).
    ///
    /// Mirrors libsrt's `CSeqNo::seqoff` (spec §3.1, Appendix A use circular
    /// sequence comparison).
    // The two `as i32` casts are deliberate two's-complement reinterpretations,
    // each provably within `i32` range (see the branch comments), so the
    // `cast_possible_wrap` warning is expected and suppressed.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub const fn offset_from(self, other: SeqNumber) -> i32 {
        // Forward distance from `other` to `self`, in `0..2^31`.
        let forward = self.0.wrapping_sub(other.0) & Self::MASK;
        if forward <= Self::THRESHOLD {
            // `0..=2^30 - 1`: already a non-negative i32.
            forward as i32
        } else {
            // `2^30..2^31`: `self` is behind `other`; report a negative offset.
            // `forward - 2^31` lands in `-2^30..=-1`, which fits in i32.
            forward.wrapping_sub(Self::COUNT) as i32
        }
    }
}

/// Advance a sequence number by `n`, wrapping within the 31-bit space.
impl Add<u32> for SeqNumber {
    type Output = SeqNumber;

    fn add(self, n: u32) -> SeqNumber {
        // `2^31` divides `2^32`, so reducing mod `2^32` (wrapping_add) before
        // masking to 31 bits yields the correct value mod `2^31`. The mask is
        // the modular reduction, not a logic error in the `Add` impl.
        #[allow(clippy::suspicious_arithmetic_impl)]
        SeqNumber(self.0.wrapping_add(n) & Self::MASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_masks_to_31_bits() {
        // The high bit is the data/control flag on the wire, never part of the
        // sequence number, so new() must drop it.
        assert_eq!(SeqNumber::new(0x8000_0000).value(), 0);
        assert_eq!(SeqNumber::new(0xFFFF_FFFF).value(), 0x7FFF_FFFF);
        assert_eq!(SeqNumber::new(42).value(), 42);
    }

    #[test]
    fn next_increments_and_wraps() {
        assert_eq!(SeqNumber::new(0).next(), SeqNumber::new(1));
        assert_eq!(SeqNumber::MAX.next(), SeqNumber::ZERO);
    }

    #[test]
    fn prev_decrements_and_wraps() {
        assert_eq!(SeqNumber::new(1).prev(), SeqNumber::new(0));
        assert_eq!(SeqNumber::ZERO.prev(), SeqNumber::MAX);
    }

    #[test]
    fn next_and_prev_are_inverses() {
        for v in [0u32, 1, 100, 0x3FFF_FFFF, 0x7FFF_FFFE, 0x7FFF_FFFF] {
            let s = SeqNumber::new(v);
            assert_eq!(s.next().prev(), s);
            assert_eq!(s.prev().next(), s);
        }
    }

    #[test]
    fn add_wraps() {
        assert_eq!(SeqNumber::new(10) + 5, SeqNumber::new(15));
        assert_eq!(SeqNumber::MAX + 1, SeqNumber::ZERO);
        assert_eq!(SeqNumber::MAX + 3, SeqNumber::new(2));
    }

    #[test]
    fn circular_cmp_nearby() {
        let a = SeqNumber::new(100);
        let b = SeqNumber::new(200);
        assert_eq!(a.circular_cmp(b), Ordering::Less);
        assert_eq!(b.circular_cmp(a), Ordering::Greater);
        assert_eq!(a.circular_cmp(a), Ordering::Equal);
    }

    #[test]
    fn circular_cmp_across_wrap() {
        // 0 is MAX.next(), so it is *ahead* of MAX despite being numerically
        // smaller. This is the whole reason circular comparison exists.
        assert_eq!(
            SeqNumber::ZERO.circular_cmp(SeqNumber::MAX),
            Ordering::Greater
        );
        assert_eq!(SeqNumber::MAX.circular_cmp(SeqNumber::ZERO), Ordering::Less);
    }

    #[test]
    fn offset_from_matches_steps() {
        assert_eq!(SeqNumber::new(200).offset_from(SeqNumber::new(100)), 100);
        assert_eq!(SeqNumber::new(100).offset_from(SeqNumber::new(200)), -100);
        assert_eq!(SeqNumber::ZERO.offset_from(SeqNumber::ZERO), 0);
        // Across the wrap: 0 is one step ahead of MAX.
        assert_eq!(SeqNumber::ZERO.offset_from(SeqNumber::MAX), 1);
        assert_eq!(SeqNumber::MAX.offset_from(SeqNumber::ZERO), -1);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Any raw value maps to its low 31 bits and nothing else.
    proptest! {
        #[test]
        fn new_keeps_low_31_bits(v: u32) {
            prop_assert_eq!(SeqNumber::new(v).value(), v & 0x7FFF_FFFF);
        }
    }

    // `next` and `prev` are inverses across the whole space, including the wrap.
    proptest! {
        #[test]
        fn next_prev_round_trip(v: u32) {
            let s = SeqNumber::new(v);
            prop_assert_eq!(s.next().prev(), s);
            prop_assert_eq!(s.prev().next(), s);
        }
    }

    // Adding one is exactly `next`.
    proptest! {
        #[test]
        fn add_one_is_next(v: u32) {
            let s = SeqNumber::new(v);
            prop_assert_eq!(s + 1, s.next());
        }
    }

    // Addition is a homomorphism from `u32` (mod 2^32) into the sequence space:
    // `(s + a) + b == s + (a + b)`.
    proptest! {
        #[test]
        fn add_is_additive(v: u32, a: u32, b: u32) {
            let s = SeqNumber::new(v);
            prop_assert_eq!((s + a) + b, s + a.wrapping_add(b));
        }
    }

    // Within the comparison window a number `delta` steps ahead of `base`
    // compares greater, and the offsets are exactly `±delta` — this is the
    // wraparound-correctness property that plain `<` would get wrong.
    proptest! {
        #[test]
        fn forward_within_window_is_greater(
            base: u32,
            delta in 1u32..=0x3FFF_FFFF,
        ) {
            let b = SeqNumber::new(base);
            let ahead = b + delta;
            let signed = i32::try_from(delta).expect("delta <= i32::MAX");
            prop_assert_eq!(ahead.circular_cmp(b), Ordering::Greater);
            prop_assert_eq!(b.circular_cmp(ahead), Ordering::Less);
            prop_assert_eq!(ahead.offset_from(b), signed);
            prop_assert_eq!(b.offset_from(ahead), -signed);
        }
    }
}
