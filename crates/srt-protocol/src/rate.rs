//! Receiver-side rate estimation for the full ACK's rate fields (spec §3.2.4) and
//! the [`Stats`](crate::stats::Stats) snapshot.
//!
//! The **delivery rate** is a windowed throughput: packets and bytes actually
//! received over a fixed time window, expressed per second. This matches libsrt's
//! reported receive rate (`mbpsRecvRate` — bytes over the report interval) and,
//! crucially, is robust to *bursty* arrivals. Live video is frame-bursty (an
//! encoder emits a frame's worth of packets back-to-back every frame interval,
//! then idles), so an inter-arrival-median estimate collapses onto the tiny
//! intra-frame gap and reports a rate orders of magnitude too high. Averaging over
//! a window counts whole bursts and idle alike, yielding the true stream rate
//! (cross-checked against libsrt 1.5.5: a 2.4 Mbit/s stream reads ~2.4 Mbit/s).
//!
//! A separate **peak rate** (the inverse of the smallest in-window arrival gap) is
//! kept as a link-capacity proxy — there the burst speed is exactly what's wanted.
//!
//! The estimator works in plain microseconds (the caller passes arrival time as
//! microseconds since the connection began), so it stays clock-free and
//! deterministically testable, like the rest of the core.

/// Wire header bytes added per packet when reporting the byte rate (the SRT/UDP/IP
/// overhead libsrt/srtgo fold in).
const WIRE_HEADER: u64 = 16 + 28;
/// Throughput averaging window, microseconds. One second smooths ~25 video frames
/// into a steady reading while still tracking real rate changes within a second.
const WINDOW_US: u64 = 1_000_000;

/// A windowed estimator of the receiver's packet/byte delivery rate plus a
/// burst-peak link-capacity proxy.
#[derive(Debug, Clone)]
pub(crate) struct RateEstimator {
    /// Start of the current accumulation window (µs since connection start).
    window_start_us: Option<u64>,
    /// Arrival time of the previous packet, for the smallest-gap (peak) tracker.
    last_us: Option<u64>,
    /// Packets accumulated in the current window.
    packets: u32,
    /// Bytes (payload + wire header) accumulated in the current window.
    bytes: u64,
    /// Smallest inter-arrival gap seen in the current window (µs); 0 = none yet.
    min_gap_us: u32,
    /// Last finalized rates, reported until the next window completes.
    pps: u32,
    bps: u32,
    peak_pps: u32,
}

impl RateEstimator {
    pub(crate) fn new() -> Self {
        RateEstimator {
            window_start_us: None,
            last_us: None,
            packets: 0,
            bytes: 0,
            min_gap_us: 0,
            pps: 0,
            bps: 0,
            peak_pps: 0,
        }
    }

    /// Records one received packet: its arrival time (`now_us`, microseconds since
    /// the connection began) and `payload` size in bytes. Finalizes the window's
    /// rates each time a full [`WINDOW_US`] has elapsed.
    pub(crate) fn record(&mut self, now_us: u64, payload: u32) {
        let start = *self.window_start_us.get_or_insert(now_us);
        if let Some(last) = self.last_us {
            let gap = now_us.saturating_sub(last);
            if gap > 0 && (self.min_gap_us == 0 || gap < u64::from(self.min_gap_us)) {
                self.min_gap_us = clamp_u32(gap);
            }
        }
        self.last_us = Some(now_us);
        self.packets += 1;
        self.bytes += u64::from(payload) + WIRE_HEADER;

        let elapsed = now_us.saturating_sub(start);
        if elapsed >= WINDOW_US {
            self.pps = clamp_u32(1_000_000 * u64::from(self.packets) / elapsed);
            self.bps = clamp_u32(1_000_000 * self.bytes / elapsed);
            if self.min_gap_us > 0 {
                self.peak_pps = clamp_u32(1_000_000 / u64::from(self.min_gap_us));
            }
            self.window_start_us = Some(now_us);
            self.packets = 0;
            self.bytes = 0;
            self.min_gap_us = 0;
        }
    }

    /// The windowed delivery rate as `(packets_per_sec, bytes_per_sec)`, or `(0, 0)`
    /// until the first full window has elapsed.
    pub(crate) fn delivery_rate(&self) -> (u32, u32) {
        (self.pps, self.bps)
    }

    /// A peak-rate (link-capacity) proxy: the inverse of the smallest arrival gap
    /// seen in the last completed window, in packets/sec. A receiver-only estimate;
    /// libsrt refines this with sender probe pairs.
    pub(crate) fn peak_rate(&self) -> u32 {
        self.peak_pps
    }
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
    fn reports_zero_until_a_full_window_elapses() {
        let mut est = RateEstimator::new();
        // Half a second of packets — not yet a full window.
        for i in 0..500u64 {
            est.record(i * 1_000, 1_000);
        }
        assert_eq!(
            est.delivery_rate(),
            (0, 0),
            "no reading before the window closes"
        );
    }

    #[test]
    fn steady_arrivals_give_the_throughput_rate() {
        // Packets 1 ms apart, 1000-byte payloads, spanning exactly one window.
        let mut est = RateEstimator::new();
        for i in 0..=1_000u64 {
            est.record(i * 1_000, 1_000);
        }
        // 1001 packets counted over 1_000_000 µs → 1001 pkt/s; bytes include the
        // per-packet wire header.
        let (pps, bps) = est.delivery_rate();
        assert_eq!(pps, 1_001);
        assert_eq!(bps, 1_001 * (1_000 + u32::try_from(WIRE_HEADER).unwrap()));
    }

    #[test]
    fn bursty_arrivals_still_report_the_stream_rate_not_the_burst_rate() {
        // The video case: 10 packets emitted back-to-back (1 µs apart) every 40 ms,
        // i.e. 25 frames/s × 10 = 250 pkt/s, but instantaneously bursty. The old
        // inter-arrival-median estimator reported ~1_000_000 pps here; the windowed
        // one must report ~250.
        let mut est = RateEstimator::new();
        let mut frame_us = 0u64;
        while frame_us <= 1_000_000 {
            for p in 0..10u64 {
                est.record(frame_us + p, 1_000); // 10 packets, 1 µs apart
            }
            frame_us += 40_000; // next frame in 40 ms
        }
        let (pps, _) = est.delivery_rate();
        assert!(
            (240..=260).contains(&pps),
            "bursty 250 pps stream should read ~250 pps, got {pps}"
        );
    }

    #[test]
    fn peak_rate_tracks_the_fastest_in_window_gap() {
        // Mostly 1 ms apart, with one 100 µs back-to-back pair; enough packets to
        // close a full window (the 100 µs gap leaves the run otherwise short).
        let mut est = RateEstimator::new();
        let mut t = 0u64;
        for i in 0..=1_001u64 {
            est.record(t, 1_000);
            t += if i == 500 { 100 } else { 1_000 };
        }
        assert_eq!(
            est.peak_rate(),
            10_000,
            "100 µs smallest gap → 10000 pkt/s peak"
        );
    }
}
