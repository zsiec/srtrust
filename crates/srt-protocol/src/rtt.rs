//! Round-trip time estimation (spec §4.10).
//!
//! The receiver measures RTT from the gap between sending an ACK and receiving
//! the matching ACKACK, then smooths it with an exponentially-weighted moving
//! average. The connection feeds each raw sample in; this type holds the smoothed
//! RTT and its variance and derives the retransmission timeout. It is pure: the
//! samples (which the embedder times) come in as [`Duration`]s.
//!
//! ## Deviation from the literal spec text
//!
//! Spec §4.10 writes the update as `RTT = 7/8·RTT + 1/8·rtt` *then*
//! `RTTVar = 3/4·RTTVar + 1/4·|RTT - rtt|`, which reads as using the *new* RTT in
//! the variance term. Deployed SRT (libsrt, and the cross-checked `srtgo`) instead
//! follows Jacobson/RFC-6298: the variance uses the **old** smoothed RTT, and the
//! **first** real sample is assigned directly (`RTT = rtt`, `RTTVar = rtt/2`)
//! rather than blended from the 100 ms initial — otherwise the initial estimate
//! biases the average for a long time. We match the deployed behavior; CLAUDE.md
//! flags §4.10 as a known spec gap to verify against libsrt.

use std::time::Duration;

/// Initial smoothed RTT before any sample (spec §4.10: 100 ms).
const INITIAL_RTT: Duration = Duration::from_millis(100);
/// Initial RTT variance before any sample (spec §4.10: 50 ms).
const INITIAL_RTT_VAR: Duration = Duration::from_millis(50);

/// Smoothed round-trip time and its variance, updated from ACK/ACKACK samples.
#[derive(Debug, Clone)]
pub(crate) struct RttEstimator {
    rtt: Duration,
    var: Duration,
    /// Whether a real sample has been taken yet (the first one is set directly).
    sampled: bool,
}

impl RttEstimator {
    /// A fresh estimator at the spec's initial values (RTT 100 ms, var 50 ms).
    pub(crate) fn new() -> Self {
        RttEstimator {
            rtt: INITIAL_RTT,
            var: INITIAL_RTT_VAR,
            sampled: false,
        }
    }

    /// The current smoothed RTT.
    pub(crate) fn rtt(&self) -> Duration {
        self.rtt
    }

    /// The current RTT variance.
    pub(crate) fn var(&self) -> Duration {
        self.var
    }

    /// Folds a freshly-measured round-trip `sample` into the estimate.
    pub(crate) fn sample(&mut self, sample: Duration) {
        let rtt = micros(sample);
        if !self.sampled {
            // First real sample: assign directly so the 100 ms initial does not
            // bias the average (see the module deviation note).
            self.rtt = sample;
            self.var = Duration::from_micros(rtt / 2);
            self.sampled = true;
            return;
        }
        let old_rtt = micros(self.rtt);
        let old_var = micros(self.var);
        // Variance uses the OLD smoothed RTT (Jacobson/RFC-6298 ordering).
        let new_var = (old_var.saturating_mul(3) + old_rtt.abs_diff(rtt)) / 4;
        let new_rtt = (old_rtt.saturating_mul(7) + rtt) / 8;
        self.rtt = Duration::from_micros(new_rtt);
        self.var = Duration::from_micros(new_var);
    }

    /// The retransmission timeout derived from the estimate: `RTT + 4·RTTVar`
    /// (the base interval SRT uses for NAK/EXP timing; floors are applied by the
    /// connection layer).
    pub(crate) fn rto(&self) -> Duration {
        self.rtt + 4 * self.var
    }
}

/// Whole microseconds in `d`, saturating (RTT samples are never near the u64 cap).
fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn starts_at_the_spec_initial_values() {
        let est = RttEstimator::new();
        assert_eq!(est.rtt(), ms(100));
        assert_eq!(est.var(), ms(50));
    }

    #[test]
    fn first_sample_is_assigned_directly() {
        let mut est = RttEstimator::new();
        est.sample(ms(40));
        // Not blended with the 100 ms initial: set straight to the sample.
        assert_eq!(est.rtt(), ms(40));
        assert_eq!(est.var(), ms(20));
    }

    #[test]
    fn later_samples_blend_with_old_rtt_in_the_variance() {
        let mut est = RttEstimator::new();
        est.sample(ms(40)); // rtt=40ms, var=20ms
        est.sample(ms(80));
        // var uses the OLD rtt (40ms): |80-40| = 40ms.
        //   var = (20*3 + 40)/4 = 25 ms
        //   rtt = (40*7 + 80)/8 = 45 ms
        assert_eq!(est.var(), ms(25));
        assert_eq!(est.rtt(), ms(45));
        // If the variance had (wrongly) used the new rtt (45ms), it would be
        // (60 + 35)/4 = 23.75 ms — this asserts the Jacobson ordering.
    }

    #[test]
    fn rto_is_rtt_plus_four_variances() {
        let mut est = RttEstimator::new();
        est.sample(ms(40));
        est.sample(ms(80)); // rtt=45ms, var=25ms
        assert_eq!(est.rto(), ms(45) + 4 * ms(25)); // 145 ms
    }

    #[test]
    fn converges_to_a_steady_sample() {
        let mut est = RttEstimator::new();
        for _ in 0..100 {
            est.sample(ms(50));
        }
        assert_eq!(est.rtt(), ms(50), "RTT converges to the steady sample");
        assert_eq!(est.var(), Duration::ZERO, "variance decays to zero");
    }

    #[test]
    fn microsecond_precision_is_preserved() {
        let mut est = RttEstimator::new();
        est.sample(Duration::from_micros(12_345));
        assert_eq!(est.rtt(), Duration::from_micros(12_345));
        assert_eq!(est.var(), Duration::from_micros(6_172)); // 12345/2 truncated
    }
}
