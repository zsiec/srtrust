//! Live Congestion Control (`LiveCC`) sender pacing (spec §5.1).
//!
//! `LiveCC` limits the sender's rate to a configured maximum bandwidth by spacing
//! consecutive packets at least `PKT_SND_PERIOD` apart. The period is derived
//! from the average packet payload size and `MAX_BW` — the spacing between
//! packets is where retransmissions slot in, and the bandwidth overhead is the
//! margin (spec §5.1).
//!
//! This type is just the rate math: it tracks the smoothed payload size and the
//! current send period. *When* to release a queued packet is the connection's
//! decision, driven by the period this provides.

use std::time::Duration;

/// Maximum SRT data-packet payload size, the initial average (spec §5.1.2:
/// "cannot be larger than 1456 bytes").
const MAX_PAYLOAD: usize = 1456;
/// Per-packet wire overhead added to the payload when deriving the pacing period:
/// IPv4 (20) + UDP (8) + SRT (16) = 44 bytes. libsrt uses `iMSS - maxPayloadSize`
/// (the full on-wire frame overhead) so the bandwidth limit counts the bytes that
/// actually traverse the link, not just SRT's own header. (Was 16, which undersized
/// the send period and paced ~2% faster than libsrt for a given `MAX_BW`.)
const WIRE_OVERHEAD: u64 = 44;

/// The sender's pacing state: smoothed payload size and the derived minimum
/// inter-packet send period (spec §5.1.2).
#[derive(Debug, Clone)]
pub(crate) struct LiveCc {
    /// Maximum allowed bandwidth, bytes per second (`MAX_BW`); always non-zero.
    max_bw: u64,
    /// Smoothed average payload size, bytes (`AvgPayloadSize`).
    avg_payload: f64,
    /// Current minimum inter-packet send period (`PKT_SND_PERIOD`).
    snd_period: Duration,
}

impl LiveCc {
    /// Creates a pacer for `max_bw` bytes per second (must be non-zero).
    pub(crate) fn new(max_bw: u64) -> Self {
        #[allow(clippy::cast_precision_loss)] // MAX_PAYLOAD is small (1456)
        let mut cc = LiveCc {
            max_bw,
            avg_payload: MAX_PAYLOAD as f64,
            snd_period: Duration::ZERO,
        };
        cc.snd_period = cc.compute_period();
        cc
    }

    /// The current minimum interval between consecutive sent packets.
    pub(crate) fn snd_period(&self) -> Duration {
        self.snd_period
    }

    /// Folds a just-sent packet's payload size into the smoothed average (spec
    /// §5.1.2, event 1): `AvgPayloadSize = 7/8·AvgPayloadSize + 1/8·size`.
    pub(crate) fn on_packet_sent(&mut self, payload_size: usize) {
        #[allow(clippy::cast_precision_loss)] // payloads are at most ~1456 bytes
        let size = payload_size as f64;
        self.avg_payload = 7.0 / 8.0 * self.avg_payload + 1.0 / 8.0 * size;
    }

    /// Recomputes the send period from the current average (spec §5.1.2, event 2:
    /// on ACK reception).
    pub(crate) fn on_ack(&mut self) {
        self.snd_period = self.compute_period();
    }

    /// `PKT_SND_PERIOD = (AvgPayloadSize + header) · 1_000_000 / MAX_BW` µs.
    fn compute_period(&self) -> Duration {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        // AvgPayloadSize is a small positive average; rounding to whole bytes is
        // exact enough for a send interval.
        let pkt_size = self.avg_payload.round() as u64 + WIRE_OVERHEAD;
        Duration::from_micros(pkt_size.saturating_mul(1_000_000) / self.max_bw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_period_from_the_max_payload() {
        // MAX_BW chosen so (1456 + 44) bytes take exactly 1 ms: 1500 B / 1 ms.
        let cc = LiveCc::new(1_500_000);
        assert_eq!(cc.snd_period(), Duration::from_millis(1));
    }

    #[test]
    fn period_scales_inversely_with_bandwidth() {
        let slow = LiveCc::new(1_500_000);
        let fast = LiveCc::new(3_000_000); // twice the bandwidth
        assert_eq!(fast.snd_period(), slow.snd_period() / 2);
    }

    #[test]
    fn average_payload_decays_toward_sent_sizes() {
        let mut cc = LiveCc::new(1_500_000);
        // Feed many small packets; the average drops toward the small size, so the
        // recomputed period shrinks well below the initial 1 ms.
        for _ in 0..100 {
            cc.on_packet_sent(100);
        }
        cc.on_ack();
        // avg → ~100, pkt_size → ~144 bytes → period ~144/1500 ms < 200 µs.
        assert!(
            cc.snd_period() < Duration::from_micros(200),
            "period followed the smaller payloads, got {:?}",
            cc.snd_period()
        );
    }

    #[test]
    fn send_period_updates_only_on_ack() {
        let mut cc = LiveCc::new(1_500_000);
        let before = cc.snd_period();
        for _ in 0..50 {
            cc.on_packet_sent(100); // changes the average, not yet the period
        }
        assert_eq!(cc.snd_period(), before, "period is steady until an ACK");
        cc.on_ack();
        assert!(cc.snd_period() < before, "the ACK applies the new average");
    }

    #[test]
    fn one_eighth_step_after_a_single_sample() {
        let mut cc = LiveCc::new(1_500_000);
        // avg starts at 1456; one 0-byte sample → 7/8·1456 = 1274; pkt 1318 bytes.
        cc.on_packet_sent(0);
        cc.on_ack();
        // 1318 * 1e6 / 1_500_000 = 878 µs.
        assert_eq!(cc.snd_period(), Duration::from_micros(878));
    }
}
