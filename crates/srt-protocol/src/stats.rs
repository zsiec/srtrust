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
    /// Data packets the *sender* shed unacknowledged because they aged past the
    /// latency budget (send-side TLPKTDROP; libsrt's `sndDropTotal`). Nonzero
    /// means the application submitted data the path could not deliver in time.
    pub packets_dropped_sent: u64,
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
    /// ACK control packets sent (full and light; libsrt's `pktSentACKTotal`).
    pub acks_sent: u64,
    /// ACK control packets received (libsrt's `pktRecvACKTotal`).
    pub acks_received: u64,
    /// NAK loss reports sent (libsrt's `pktSentNAKTotal`).
    pub naks_sent: u64,
    /// NAK loss reports received (libsrt's `pktRecvNAKTotal`).
    pub naks_received: u64,
    /// Data packets held by the sender: unacknowledged in-flight plus queued
    /// behind the pacer (libsrt's `pktSndBuf`). The send backlog.
    pub send_buffer_packets: u32,
    /// The **negotiated** TSBPD latency, milliseconds — the larger of the two
    /// advertised values (spec §4.3.1.2), not necessarily what was configured.
    pub latency_ms: u32,
}
