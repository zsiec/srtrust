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

/// Unwraps the 32-bit wrapping packet-timestamp stream into a monotonic 64-bit
/// microsecond offset, so TSBPD survives past the ±2^31 µs (~35.8 min) window
/// that a single circular diff can resolve (spec §4.5.1.1 case 1: the TSBPD
/// time base advances by `MAX_TIMESTAMP + 1` at each wrap).
///
/// [`observe`](TsbpdWrap::observe) feeds it every accepted packet timestamp; a
/// wrap is detected only when a timestamp is circularly *newer* than the newest
/// seen yet numerically smaller — mere reordering (retransmissions, stragglers
/// from before the wrap) is circularly *older* and never advances the state.
/// [`offset_of`](TsbpdWrap::offset_of) is pure: stragglers from the previous
/// period still resolve to their original offsets.
///
/// **Limitation (inherent, shared with libsrt):** each forward step must be
/// less than 2^31 µs. A connection that carries *no data at all* for more than
/// ~35.8 minutes cannot disambiguate the next timestamp — circularly, a jump of
/// `2^31 + d` is indistinguishable from going backward `2^31 - d`. Live streams
/// carry continuous data, so this never arises in SRT's target use.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TsbpdWrap {
    /// Microseconds contributed by completed wrap periods (multiples of 2^32).
    base: u64,
    /// The circularly-newest timestamp seen within the current period.
    last: Timestamp,
}

impl TsbpdWrap {
    /// Starts tracking from the first accepted packet's timestamp.
    pub(crate) const fn new(first: Timestamp) -> Self {
        TsbpdWrap {
            base: 0,
            last: first,
        }
    }

    /// Feeds one accepted packet timestamp, advancing the period state when the
    /// stream crosses the numeric wrap.
    pub(crate) const fn observe(&mut self, ts: Timestamp) {
        if ts.wrapping_diff(self.last) > 0 {
            // Circularly newer. Numerically smaller means the stream crossed the
            // numeric wrap: one more completed 2^32 µs period.
            if ts.as_micros() < self.last.as_micros() {
                self.base += 1 << 32;
            }
            self.last = ts;
        }
        // Circularly older (a retransmission or reordered straggler): ignore —
        // this is the guard the naive "ts < last ⇒ wrap" check lacks.
    }

    /// The monotonic microsecond offset of `ts` from the first period's origin.
    /// Resolves `ts` circularly against the newest seen timestamp, so values up
    /// to ±2^31 µs around it — including stragglers from the previous period —
    /// land in the right period.
    #[allow(clippy::cast_possible_wrap)] // `base` stays far below 2^63
    pub(crate) fn offset_of(&self, ts: Timestamp) -> i64 {
        self.base as i64 + i64::from(self.last.as_micros()) + i64::from(ts.wrapping_diff(self.last))
    }
}

#[cfg(test)]
mod wrap_tests {
    use super::*;

    #[test]
    fn offsets_are_monotonic_across_the_wrap() {
        // Steps must each stay under 2^31 µs (a live stream's always do).
        let mut w = TsbpdWrap::new(Timestamp::from_micros(1000));
        assert_eq!(w.offset_of(Timestamp::from_micros(1000)), 1000);
        w.observe(Timestamp::from_micros(0x7000_0000));
        w.observe(Timestamp::from_micros(0xE000_0000));
        assert_eq!(
            w.offset_of(Timestamp::from_micros(0xE000_0000)),
            0xE000_0000
        );
        // 50 is circularly *newer* than 0xE000_0000: the stream wrapped.
        w.observe(Timestamp::from_micros(50));
        assert_eq!(w.offset_of(Timestamp::from_micros(50)), (1i64 << 32) + 50);
    }

    #[test]
    fn a_straggler_from_the_previous_period_keeps_its_old_offset() {
        let mut w = TsbpdWrap::new(Timestamp::from_micros(0xFFFF_0000));
        w.observe(Timestamp::from_micros(100)); // wrapped
        assert_eq!(w.offset_of(Timestamp::from_micros(100)), (1i64 << 32) + 100);
        // A late retransmission stamped before the wrap resolves into the old
        // period…
        assert_eq!(
            w.offset_of(Timestamp::from_micros(0xFFFF_8000)),
            0xFFFF_8000
        );
        // …and observing it must not advance (or rewind) the wrap state.
        w.observe(Timestamp::from_micros(0xFFFF_8000));
        assert_eq!(w.offset_of(Timestamp::from_micros(200)), (1i64 << 32) + 200);
    }

    #[test]
    fn reordering_near_the_wrap_does_not_double_count() {
        let mut w = TsbpdWrap::new(Timestamp::from_micros(0xFFFF_FF00));
        w.observe(Timestamp::from_micros(10)); // wraps once
        w.observe(Timestamp::from_micros(0xFFFF_FFF0)); // straggler: ignored
        w.observe(Timestamp::from_micros(20)); // same period: no second wrap
        assert_eq!(w.offset_of(Timestamp::from_micros(20)), (1i64 << 32) + 20);
    }

    #[test]
    fn two_full_periods_accumulate() {
        let mut w = TsbpdWrap::new(Timestamp::from_micros(0));
        for _ in 0..2 {
            // Sub-2^31 steps around one full period.
            w.observe(Timestamp::from_micros(0x6000_0000));
            w.observe(Timestamp::from_micros(0xB000_0000));
            w.observe(Timestamp::from_micros(0xFFFF_0000));
            w.observe(Timestamp::from_micros(0x10)); // wraps
        }
        assert_eq!(
            w.offset_of(Timestamp::from_micros(0x10)),
            (2i64 << 32) + 0x10
        );
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
