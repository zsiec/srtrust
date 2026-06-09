//! SRT packet timestamps.
//!
//! Every SRT packet carries a 32-bit **timestamp** measured in microseconds
//! relative to the moment the connection was established (spec §3, common
//! header). Because it is only 32 bits it wraps every `2^32` µs ≈ 71.6 minutes,
//! so — exactly like [`SeqNumber`](crate::seq::SeqNumber) — two timestamps must
//! be compared *circularly*, assuming they are less than half the space
//! (≈ 35.8 minutes) apart.
//!
//! There is a pleasant arithmetic coincidence for the 32-bit case: the wrapping
//! difference of two `u32`s, reinterpreted as `i32`, *is* the signed circular
//! distance in microseconds (range `-2^31..2^31`). That makes the comparison
//! fall out of one subtraction and one cast — see [`Timestamp::wrapping_diff`].
//!
//! This is the on-the-wire timestamp only. The receiver's local notion of "now"
//! (used to decide when a packet is due for delivery) is a separate monotonic
//! clock that the I/O layer passes into the protocol core.

use core::cmp::Ordering;

/// A 32-bit SRT packet timestamp, in microseconds since connection start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Timestamp(u32);

impl Timestamp {
    /// The connection-start timestamp.
    pub const ZERO: Timestamp = Timestamp(0);

    /// The largest representable timestamp; `MAX.wrapping_add_micros(1)` wraps
    /// back to [`Timestamp::ZERO`].
    pub const MAX: Timestamp = Timestamp(u32::MAX);

    /// Creates a timestamp from a raw microsecond count (the wire value).
    #[must_use]
    pub const fn from_micros(micros: u32) -> Self {
        Timestamp(micros)
    }

    /// The raw microsecond value (what goes on the wire).
    #[must_use]
    pub const fn as_micros(self) -> u32 {
        self.0
    }

    /// Advances the timestamp by `micros`, wrapping at `2^32`.
    #[must_use]
    pub const fn wrapping_add_micros(self, micros: u32) -> Self {
        Timestamp(self.0.wrapping_add(micros))
    }

    /// Signed circular difference `self - other`, in microseconds.
    ///
    /// Positive if `self` is later than `other`, within the ±35.8-minute
    /// unambiguous window. For a 32-bit wrapping counter this is exactly the
    /// `u32` wrapping subtraction reinterpreted as `i32`.
    // The `as i32` is the deliberate two's-complement reinterpretation described
    // in the module docs: it turns the forward distance `0..2^32` into a signed
    // distance `-2^31..2^31`, so the `cast_possible_wrap` warning is the point.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub const fn wrapping_diff(self, other: Timestamp) -> i32 {
        self.0.wrapping_sub(other.0) as i32
    }

    /// Circular comparison: is `self` before, equal to, or after `other`?
    #[must_use]
    pub const fn circular_cmp(self, other: Timestamp) -> Ordering {
        match self.wrapping_diff(other).signum() {
            1 => Ordering::Greater,
            -1 => Ordering::Less,
            _ => Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micros_round_trip() {
        assert_eq!(Timestamp::from_micros(1234).as_micros(), 1234);
        assert_eq!(Timestamp::from_micros(0).as_micros(), 0);
        assert_eq!(Timestamp::from_micros(u32::MAX).as_micros(), u32::MAX);
    }

    #[test]
    fn wrapping_add_wraps_at_2_pow_32() {
        assert_eq!(
            Timestamp::from_micros(10).wrapping_add_micros(5),
            Timestamp::from_micros(15)
        );
        assert_eq!(Timestamp::MAX.wrapping_add_micros(1), Timestamp::ZERO);
        assert_eq!(
            Timestamp::MAX.wrapping_add_micros(3),
            Timestamp::from_micros(2)
        );
    }

    #[test]
    fn wrapping_diff_basic() {
        let a = Timestamp::from_micros(200);
        let b = Timestamp::from_micros(100);
        assert_eq!(a.wrapping_diff(b), 100);
        assert_eq!(b.wrapping_diff(a), -100);
        assert_eq!(Timestamp::ZERO.wrapping_diff(Timestamp::ZERO), 0);
    }

    #[test]
    fn wrapping_diff_across_wrap() {
        // ZERO is one microsecond after MAX.
        assert_eq!(Timestamp::ZERO.wrapping_diff(Timestamp::MAX), 1);
        assert_eq!(Timestamp::MAX.wrapping_diff(Timestamp::ZERO), -1);
    }

    #[test]
    fn circular_cmp_orders_across_wrap() {
        let a = Timestamp::from_micros(100);
        let b = Timestamp::from_micros(200);
        assert_eq!(a.circular_cmp(b), Ordering::Less);
        assert_eq!(b.circular_cmp(a), Ordering::Greater);
        assert_eq!(a.circular_cmp(a), Ordering::Equal);
        // Across the wrap, ZERO is *after* MAX despite being numerically smaller.
        assert_eq!(
            Timestamp::ZERO.circular_cmp(Timestamp::MAX),
            Ordering::Greater
        );
        assert_eq!(Timestamp::MAX.circular_cmp(Timestamp::ZERO), Ordering::Less);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Any microsecond value round-trips through the wire representation.
    proptest! {
        #[test]
        fn from_as_round_trip(v: u32) {
            prop_assert_eq!(Timestamp::from_micros(v).as_micros(), v);
        }
    }

    // Advancing by `delta` within the unambiguous window and taking the
    // difference recovers `delta` exactly, regardless of where the wrap falls.
    proptest! {
        #[test]
        fn add_then_diff_recovers_delta(base: u32, delta in 0i32..=i32::MAX) {
            let t = Timestamp::from_micros(base);
            let step = u32::try_from(delta).expect("delta is non-negative");
            let ahead = t.wrapping_add_micros(step);
            prop_assert_eq!(ahead.wrapping_diff(t), delta);
        }
    }
}
