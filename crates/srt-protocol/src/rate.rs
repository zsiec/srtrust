//! Receiver-side rate estimation for the full ACK's rate fields (spec §3.2.4).
//!
//! Over a sliding window of recent packet inter-arrival intervals, this estimates
//! the **delivery rate** (packets/s and bytes/s) and a **peak rate** (link-capacity
//! proxy). The delivery-rate filter is cross-checked against `srtgo`'s
//! `deliveryRateFilter`: take the median interval, keep only samples within
//! `(median/8, median*8)` (rejecting bursts and idle gaps), and require a majority
//! of valid samples — otherwise report 0.

/// Wire header bytes added per packet when reporting the byte rate (the SRT/UDP/IP
/// overhead libsrt/srtgo fold in).
const WIRE_HEADER: u64 = 16 + 28;
/// Inter-arrival samples retained.
const WINDOW: usize = 16;

/// A sliding-window estimator of the receiver's packet/byte delivery rate.
#[derive(Debug, Clone)]
pub(crate) struct RateEstimator {
    /// Inter-arrival intervals, microseconds (ring buffer).
    intervals: [u32; WINDOW],
    /// Parallel payload sizes, bytes.
    sizes: [u32; WINDOW],
    pos: usize,
    filled: usize,
}

impl RateEstimator {
    pub(crate) fn new() -> Self {
        RateEstimator {
            intervals: [0; WINDOW],
            sizes: [0; WINDOW],
            pos: 0,
            filled: 0,
        }
    }

    /// Records one received packet: the gap since the previous arrival
    /// (`interval_us`) and its `payload` size.
    pub(crate) fn record(&mut self, interval_us: u32, payload: u32) {
        self.intervals[self.pos] = interval_us;
        self.sizes[self.pos] = payload;
        self.pos = (self.pos + 1) % WINDOW;
        self.filled = (self.filled + 1).min(WINDOW);
    }

    /// The smoothed delivery rate as `(packets_per_sec, bytes_per_sec)`, or
    /// `(0, 0)` until the window holds a stable majority (cross-checked vs srtgo
    /// `deliveryRateFilter`).
    pub(crate) fn delivery_rate(&self) -> (u32, u32) {
        let n = self.filled;
        if n == 0 {
            return (0, 0);
        }
        let mut sorted: Vec<u32> = self.intervals[..n].to_vec();
        sorted.sort_unstable();
        let median = sorted[n / 2];
        if median == 0 {
            return (0, 0);
        }
        let (lower, upper) = (median >> 3, median << 3);
        let mut sum_us: u64 = 0;
        let mut count: u64 = 0;
        let mut total_bytes: u64 = 0;
        for i in 0..n {
            let v = self.intervals[i];
            if v > lower && v < upper {
                sum_us += u64::from(v);
                count += 1;
                total_bytes += u64::from(self.sizes[i]);
            }
        }
        if count <= (n as u64) / 2 || sum_us == 0 {
            return (0, 0);
        }
        total_bytes += WIRE_HEADER * count;
        let pkt_rate = div_ceil(1_000_000 * count, sum_us);
        let byte_rate = div_ceil(1_000_000 * total_bytes, sum_us);
        (clamp_u32(pkt_rate), clamp_u32(byte_rate))
    }

    /// A peak-rate (link-capacity) proxy: the inverse of the smallest in-window
    /// interval — the fastest back-to-back arrival observed, in packets/sec. A
    /// receiver-only estimate; libsrt refines this with sender probe pairs.
    pub(crate) fn peak_rate(&self) -> u32 {
        let n = self.filled;
        let min = self.intervals[..n].iter().copied().filter(|&v| v > 0).min();
        match min {
            Some(interval) => clamp_u32(div_ceil(1_000_000, u64::from(interval))),
            None => 0,
        }
    }
}

/// `ceil(a / b)` for positive `b`.
fn div_ceil(a: u64, b: u64) -> u64 {
    if b == 0 { 0 } else { a.div_ceil(b) }
}

fn clamp_u32(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_estimator_reports_zero() {
        let est = RateEstimator::new();
        assert_eq!(est.delivery_rate(), (0, 0));
        assert_eq!(est.peak_rate(), 0);
    }

    #[test]
    fn steady_arrivals_give_the_inverse_interval_rate() {
        // 16 packets, 1 ms apart, 1000-byte payloads → 1000 pkt/s.
        let mut est = RateEstimator::new();
        for _ in 0..WINDOW {
            est.record(1_000, 1_000);
        }
        let (pps, bps) = est.delivery_rate();
        assert_eq!(pps, 1_000, "1 ms spacing → 1000 packets/s");
        // bytes/s includes the wire header overhead per packet.
        assert_eq!(bps, 1_000 * (1_000 + u32::try_from(WIRE_HEADER).unwrap()));
    }

    #[test]
    fn outliers_are_filtered_out() {
        // Mostly 1 ms spacing, with a couple of huge idle gaps that must be
        // rejected (outside median*8) so the rate reflects the steady stream.
        let mut est = RateEstimator::new();
        for _ in 0..WINDOW - 2 {
            est.record(1_000, 1_000);
        }
        est.record(900_000, 1_000); // a long idle gap
        est.record(800_000, 1_000);
        let (pps, _) = est.delivery_rate();
        assert_eq!(pps, 1_000, "idle gaps filtered, steady rate preserved");
    }

    #[test]
    fn too_few_valid_samples_report_zero() {
        // Half the window is outliers → not a stable majority → 0.
        let mut est = RateEstimator::new();
        for _ in 0..WINDOW / 2 {
            est.record(1_000, 1_000);
        }
        for _ in 0..WINDOW / 2 {
            est.record(500_000, 1_000);
        }
        assert_eq!(est.delivery_rate(), (0, 0));
    }

    #[test]
    fn peak_rate_tracks_the_fastest_arrival() {
        let mut est = RateEstimator::new();
        for _ in 0..WINDOW - 1 {
            est.record(1_000, 1_000); // 1 ms
        }
        est.record(100, 1_000); // one fast 100 µs back-to-back
        assert_eq!(est.peak_rate(), 10_000, "100 µs → 10000 packets/s peak");
    }
}
