//! TSBPD clock-drift estimation (spec §4.7).
//!
//! Sender and receiver clocks tick at fractionally different rates, so over time
//! the receiver's mapping of sender timestamps to local time slips by a few
//! microseconds per minute. Left uncorrected this slowly overflows or depletes
//! the receive buffer. The drift tracer measures the slip and feeds a correction
//! into the TSBPD time base (spec §4.5.1, §4.7).
//!
//! Each data packet yields a sample: the difference between when it actually
//! arrived and when the (current) time base said to expect it, minus a
//! correction for any change in one-way delay (derived from the RTT). The actual
//! drift is very slow, so — per §4.7 — samples are averaged over a large fixed
//! *count* (1000) rather than a time window, which attenuates network jitter; the
//! average is then folded into the running correction.
//!
//! ## Deviation from libsrt/srtgo
//!
//! libsrt splits the correction into a time-base shift (absorbing ±5 ms
//! "overdrift" chunks) and a bounded residual offset. We keep a single
//! accumulator and feed it back into the expected-arrival computation, so each
//! epoch measures only the *residual* drift since the last correction and
//! accumulates it. The steady-state correction is the same; drift is an internal
//! delivery-timing concern (never on the wire), so there is no interop
//! constraint. RTT-delta compensation matches the deployed `(rtt - firstRtt)/2`.

/// Number of samples averaged before a correction is applied (spec §4.7: a fixed
/// count, not a duration, so the sample set is large regardless of packet rate).
const DRIFT_SPAN: u32 = 1000;

/// Estimates the cumulative clock drift between sender and receiver, in
/// microseconds, from per-packet arrival-vs-expected samples.
#[derive(Debug, Clone)]
pub(crate) struct DriftTracer {
    /// Running sum of drift samples in the current epoch (microseconds).
    sum_us: i64,
    /// Number of samples accumulated in the current epoch.
    count: u32,
    /// The accumulated drift correction applied to the time base (microseconds).
    correction_us: i64,
    /// The first RTT seen, anchoring one-way-delay-change compensation.
    first_rtt_us: Option<i64>,
}

impl DriftTracer {
    /// A fresh tracer with no correction.
    pub(crate) fn new() -> Self {
        DriftTracer {
            sum_us: 0,
            count: 0,
            correction_us: 0,
            first_rtt_us: None,
        }
    }

    /// The current drift correction in microseconds (signed): add this to a
    /// packet's expected local time.
    pub(crate) fn correction_us(&self) -> i64 {
        self.correction_us
    }

    /// Folds in one sample. `observed_us` is `actual_arrival - expected_arrival`
    /// (where the expectation already includes the current correction), and
    /// `rtt_us` is the current smoothed RTT. Every [`DRIFT_SPAN`] samples the
    /// epoch average is added to the correction.
    pub(crate) fn sample(&mut self, observed_us: i64, rtt_us: i64) {
        // Compensate for a change in one-way delay since the first sample: a
        // longer RTT means packets simply arrive later, which is not clock drift.
        let first_rtt = *self.first_rtt_us.get_or_insert(rtt_us);
        let rtt_delta = (rtt_us - first_rtt) / 2;
        self.sum_us += observed_us - rtt_delta;
        self.count += 1;
        if self.count >= DRIFT_SPAN {
            self.correction_us += self.sum_us / i64::from(self.count);
            self.sum_us = 0;
            self.count = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `n` identical samples (constant RTT, so no RTT-delta term).
    fn feed(tracer: &mut DriftTracer, n: u32, observed_us: i64) {
        for _ in 0..n {
            tracer.sample(observed_us, 10_000);
        }
    }

    #[test]
    fn starts_with_no_correction() {
        assert_eq!(DriftTracer::new().correction_us(), 0);
    }

    #[test]
    fn holds_until_a_full_epoch_completes() {
        let mut tracer = DriftTracer::new();
        feed(&mut tracer, DRIFT_SPAN - 1, 1_000);
        assert_eq!(
            tracer.correction_us(),
            0,
            "no correction before the span fills"
        );
        feed(&mut tracer, 1, 1_000);
        assert_eq!(
            tracer.correction_us(),
            1_000,
            "applied once the span completes"
        );
    }

    #[test]
    fn corrects_by_the_epoch_average() {
        let mut tracer = DriftTracer::new();
        // Half the samples at +2000us, half at 0 → average +1000us.
        feed(&mut tracer, DRIFT_SPAN / 2, 2_000);
        feed(&mut tracer, DRIFT_SPAN / 2, 0);
        assert_eq!(tracer.correction_us(), 1_000);
    }

    #[test]
    fn accumulates_across_epochs() {
        let mut tracer = DriftTracer::new();
        feed(&mut tracer, DRIFT_SPAN, 1_000);
        feed(&mut tracer, DRIFT_SPAN, 1_000);
        assert_eq!(tracer.correction_us(), 2_000, "corrections accumulate");
    }

    #[test]
    fn handles_negative_drift() {
        let mut tracer = DriftTracer::new();
        feed(&mut tracer, DRIFT_SPAN, -1_500);
        assert_eq!(tracer.correction_us(), -1_500);
    }

    #[test]
    fn rtt_growth_is_not_counted_as_drift() {
        let mut tracer = DriftTracer::new();
        // First sample anchors firstRtt = 10_000us with observed 0.
        tracer.sample(0, 10_000);
        // Later samples arrive 2000us "late", but RTT also grew by 4000us, so the
        // one-way delay grew ~2000us: (rtt - firstRtt)/2 = 2000 cancels it out.
        for _ in 1..DRIFT_SPAN {
            tracer.sample(2_000, 14_000);
        }
        assert_eq!(
            tracer.correction_us(),
            0,
            "a one-way delay increase must not be mistaken for clock drift"
        );
    }
}
