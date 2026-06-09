//! Connection statistics (cf. libsrt `SRT_TRACEBSTATS`, srtgo `ConnStats`).
//!
//! The core keeps a running [`Stats`] tally as packets flow; the embedder reads a
//! snapshot via [`Connection::stats`](crate::connection::Connection::stats). All
//! counters are cumulative since the connection was established.

/// A snapshot of a connection's cumulative counters. `#[non_exhaustive]` so new
/// counters can be added without breaking embedders.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Original data packets sent (excludes retransmissions).
    pub packets_sent: u64,
    /// Original data payload bytes sent (excludes retransmissions).
    pub bytes_sent: u64,
    /// Data packets retransmitted (on NAK or the EXP backstop).
    pub packets_retransmitted: u64,
    /// Data payload bytes retransmitted.
    pub bytes_retransmitted: u64,
    /// Data packets accepted into the receive buffer (new, in-window).
    pub packets_received: u64,
    /// Data payload bytes accepted (decrypted, post-decryption length).
    pub bytes_received: u64,
    /// Data packets dropped too-late at the receiver (TLPKTDROP / DROPREQ).
    pub packets_dropped: u64,
    /// Received packets discarded as duplicates or already-acknowledged.
    pub packets_duplicate: u64,
    /// Received encrypted packets that could not be decrypted (wrong/absent key,
    /// or — under AES-GCM — a failed authentication tag).
    pub packets_undecryptable: u64,
    /// Lost packets rebuilt by the FEC decoder (no retransmission round-trip).
    pub packets_recovered: u64,
    /// Smoothed round-trip time, microseconds.
    pub rtt_us: u32,
    /// Round-trip time variance, microseconds.
    pub rtt_var_us: u32,
    /// Packets sent but not yet acknowledged (the in-flight window).
    pub flight_size: u32,
    /// Packets currently held in the receive buffer awaiting in-order delivery.
    pub recv_buffer_packets: u32,
    /// Estimated receive delivery rate, packets/second (also sent in full ACKs).
    pub recv_rate_pps: u32,
    /// Estimated receive delivery rate, bytes/second.
    pub recv_rate_bps: u32,
    /// Estimated link capacity (peak observed rate), packets/second.
    pub link_capacity_pps: u32,
}
