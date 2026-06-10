//! Deterministic network-simulator primitives for end-to-end protocol tests.
//!
//! The harness is built from three independently-correct pieces, each
//! reproducible from a seed and driven by an explicit fake clock (micros):
//!
//! * [`Rng`] — a tiny `SplitMix64` PRNG, so the simulator needs no `rand`
//!   dependency and its loss/jitter decisions replay identically from a seed.
//! * [`Link`] — one directional link applying base delay, independent per-packet
//!   loss, and uniform jitter (which can reorder), scheduling deliveries on the
//!   fake clock.
//! * [`TimerWheel`] — the I/O side of the core's declarative timers: it obeys
//!   `SetTimer`/`ClearTimer` and reports the earliest deadline.
//!
//! These compose into the full caller↔listener `Pair` in the handshake unit,
//! where the handshake gives the endpoints something to do.
//!
//! Shared across several test binaries; not every binary exercises every part —
//! hence the module-level `dead_code` allow. `unreachable_pub` is allowed too:
//! these `pub` items are test-internal infrastructure (reachable across the test
//! binary that `mod sim;`-includes this file), not part of any public surface.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::too_many_arguments,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use srt_protocol::connection::{Connection, Event, Output, TimerId};
use srt_protocol::control::ControlBody;
use srt_protocol::listener::Listener;
use srt_protocol::packet::Packet;
use srt_protocol::stats::Stats;

/// A tiny deterministic PRNG (`SplitMix64`). Seeding it fixes the entire stream,
/// so any loss/jitter pattern is exactly reproducible across runs.
pub struct Rng(u64);

impl Rng {
    /// Creates a PRNG from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    /// Returns the next 64-bit output and advances the stream (`SplitMix64`).
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a uniform `f64` in `[0, 1)` using the top 53 bits as the mantissa.
    #[allow(clippy::cast_precision_loss)] // intentional: a 53-bit value and 2^53
    // are both exactly representable in f64, so neither cast actually loses bits.
    pub fn next_unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Returns a uniform integer in `[0, n)`. `n` must be non-zero. The modulo
    /// bias is irrelevant for a test harness's small ranges.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// Network impairment parameters for a single direction.
#[derive(Debug, Clone, Copy)]
pub struct LinkConfig {
    /// Base one-way propagation delay applied to every datagram.
    pub delay: Duration,
    /// Independent drop probability per datagram, in `[0, 1]`.
    pub loss: f64,
    /// Extra delay drawn uniformly from `[0, jitter]` per datagram; nonzero
    /// jitter can reorder datagrams relative to send order.
    pub jitter: Duration,
}

impl LinkConfig {
    /// A 10 ms link with no loss and no jitter: in-order, lossless delivery.
    pub const PERFECT: LinkConfig = LinkConfig {
        delay: Duration::from_millis(10),
        loss: 0.0,
        jitter: Duration::ZERO,
    };
}

/// One directional link: datagrams enter at a send time, are dropped or
/// scheduled for delivery on the fake clock, and drain out in delivery order.
pub struct Link {
    cfg: LinkConfig,
    rng: Rng,
    /// Pending deliveries; `(deliver_at_us, seq, payload)`. `seq` is a
    /// monotonically increasing insertion index used as a stable tiebreaker so
    /// equal delivery times keep send order deterministically.
    pending: Vec<(u64, u64, Bytes)>,
    next_seq: u64,
    dropped: u64,
    /// Optional deterministic drop predicate, consulted before the probabilistic
    /// loss roll; `true` drops the datagram. Lets a test target a *specific*
    /// packet ("the first transmission of seq N") instead of hunting for a seed.
    drop_filter: Option<DropFilter>,
}

/// A deterministic per-datagram drop predicate (`true` = drop).
pub type DropFilter = Box<dyn FnMut(&[u8]) -> bool>;

impl Link {
    /// Creates a link with the given impairments, its PRNG seeded by `seed`.
    #[must_use]
    pub fn new(cfg: LinkConfig, seed: u64) -> Self {
        Link {
            cfg,
            rng: Rng::new(seed),
            pending: Vec::new(),
            next_seq: 0,
            dropped: 0,
            drop_filter: None,
        }
    }

    /// Offers a datagram sent at `now_us`. It is either dropped (per the loss
    /// probability) or scheduled for delivery at `now_us + delay + jitter`.
    ///
    /// The loss roll is taken first, unconditionally, so a datagram's fate
    /// depends only on its position in the stream — not on whether jitter is
    /// enabled — which keeps loss patterns stable as other knobs change.
    pub fn send(&mut self, now_us: u64, payload: Bytes) {
        if let Some(filter) = &mut self.drop_filter
            && filter(&payload)
        {
            self.dropped += 1;
            return;
        }
        let lost = self.cfg.loss > 0.0 && self.rng.next_unit() < self.cfg.loss;
        if lost {
            self.dropped += 1;
            return;
        }
        let jitter_us = duration_us(self.cfg.jitter);
        let extra = if jitter_us == 0 {
            0
        } else {
            self.rng.below(jitter_us + 1)
        };
        let deliver_at = now_us + duration_us(self.cfg.delay) + extra;
        let seq = self.next_seq;
        self.next_seq += 1;
        self.pending.push((deliver_at, seq, payload));
    }

    /// The earliest pending delivery time, or `None` if nothing is in flight.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.pending.iter().map(|&(at, ..)| at).min()
    }

    /// Removes and returns every datagram due at or before `now_us`, in delivery
    /// order (ascending delivery time, send order breaking ties).
    pub fn drain_due(&mut self, now_us: u64) -> Vec<Bytes> {
        let mut due: Vec<(u64, u64, Bytes)> = Vec::new();
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].0 <= now_us {
                due.push(self.pending.swap_remove(i));
            } else {
                i += 1;
            }
        }
        due.sort_by_key(|&(at, seq, _)| (at, seq));
        due.into_iter().map(|(_, _, payload)| payload).collect()
    }

    /// How many datagrams this link has dropped so far.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// The I/O side of the core's declarative timers: one deadline per [`TimerId`],
/// obeying `SetTimer`/`ClearTimer` and reporting the earliest.
#[derive(Debug, Default)]
pub struct TimerWheel {
    deadlines: BTreeMap<TimerId, u64>,
}

impl TimerWheel {
    /// Creates an empty wheel.
    #[must_use]
    pub fn new() -> Self {
        TimerWheel::default()
    }

    /// Arms (or re-arms) `id` to fire at `at_us`.
    pub fn set(&mut self, id: TimerId, at_us: u64) {
        self.deadlines.insert(id, at_us);
    }

    /// Cancels `id` if armed.
    pub fn clear(&mut self, id: TimerId) {
        self.deadlines.remove(&id);
    }

    /// The earliest armed deadline, or `None` if no timer is armed.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.deadlines.values().copied().min()
    }

    /// Removes and returns every timer due at or before `now_us`, in [`TimerId`]
    /// order (deterministic).
    pub fn pop_due(&mut self, now_us: u64) -> Vec<TimerId> {
        let due: Vec<TimerId> = self
            .deadlines
            .iter()
            .filter(|&(_, &at)| at <= now_us)
            .map(|(&id, _)| id)
            .collect();
        for id in &due {
            self.deadlines.remove(id);
        }
        due
    }
}

/// Whole microseconds in `d`, saturating (durations in this harness are small).
fn duration_us(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// The single clock read in the whole project: a fixed, arbitrary origin from
/// which all simulated time is `origin + Duration`. The state machine only ever
/// sees `now - start` deltas, so its behavior is independent of this value and
/// fully reproducible — the absolute instant cancels out. (quinn-proto's
/// `tests/util.rs` takes exactly this approach.) Lives here, in test code, so the
/// `srt-protocol` library itself never calls `Instant::now()`.
#[must_use]
pub fn t0() -> Instant {
    Instant::now()
}

/// A fixed caller address for the simulated endpoints.
const CALLER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);

/// A deterministic two-endpoint network: a caller [`Connection`] and a
/// [`Listener`] (which yields the accepted listener-side connection), joined by
/// two impairment [`Link`]s and driven by a fake clock. Each `step()` advances
/// time to the next event — a datagram delivery or a timer deadline — so the
/// whole handshake plays out with zero sleeps and zero flake.
pub struct Pair {
    origin: Instant,
    now_us: u64,
    caller: Connection,
    listener: Listener,
    /// The listener-side connection, present once a conclusion is accepted.
    accepted: Option<Connection>,
    caller_timers: TimerWheel,
    accepted_timers: TimerWheel,
    /// Caller → listener/accepted direction.
    c2l: Link,
    /// Listener/accepted → caller direction.
    l2c: Link,
    caller_events: Vec<Event>,
    accepted_events: Vec<Event>,
    /// The fake-clock micros at which each accepted `DataReceived` was delivered.
    accepted_data_times: Vec<u64>,
    /// Count of KEEPALIVE control packets each side has emitted.
    caller_keepalives: u32,
    accepted_keepalives: u32,
    /// Count of DROPREQ control packets each side has emitted.
    caller_dropreqs: u32,
    accepted_dropreqs: u32,
    /// Count of NAK control packets each side has emitted.
    caller_naks: u32,
    accepted_naks: u32,
    /// Largest datagram each side has put on the wire (to check MTU compliance).
    caller_max_datagram: usize,
    accepted_max_datagram: usize,
}

impl Pair {
    /// Builds a pair from a pre-constructed caller and listener (both created
    /// with `origin` as their epoch) and the impairments for each direction.
    #[must_use]
    pub fn new(
        origin: Instant,
        caller: Connection,
        listener: Listener,
        c2l: LinkConfig,
        l2c: LinkConfig,
        seed: u64,
    ) -> Self {
        let mut pair = Pair {
            origin,
            now_us: 0,
            caller,
            listener,
            accepted: None,
            caller_timers: TimerWheel::new(),
            accepted_timers: TimerWheel::new(),
            c2l: Link::new(c2l, seed),
            l2c: Link::new(l2c, seed ^ 0xFFFF_FFFF_FFFF_FFFF),
            caller_events: Vec::new(),
            accepted_events: Vec::new(),
            accepted_data_times: Vec::new(),
            caller_keepalives: 0,
            accepted_keepalives: 0,
            caller_dropreqs: 0,
            accepted_dropreqs: 0,
            caller_naks: 0,
            accepted_naks: 0,
            caller_max_datagram: 0,
            accepted_max_datagram: 0,
        };
        // Collect whatever the caller queued at construction (the induction
        // datagram and its retransmit timer).
        pair.pump();
        pair
    }

    /// The current fake clock as an [`Instant`] the core understands.
    fn now(&self) -> Instant {
        self.origin + Duration::from_micros(self.now_us)
    }

    /// Replaces both links' impairments (re-seeding their PRNGs), discarding any
    /// in-flight datagrams. Useful to establish a connection on a clean link and
    /// then degrade it.
    pub fn degrade_links(&mut self, c2l: LinkConfig, l2c: LinkConfig, seed: u64) {
        self.c2l = Link::new(c2l, seed);
        self.l2c = Link::new(l2c, seed ^ 0xFFFF_FFFF_FFFF_FFFF);
    }

    /// Installs a deterministic drop predicate on the caller→listener direction:
    /// every datagram for which `filter` returns `true` is dropped. Targets a
    /// specific packet (by decoding the datagram) without touching the seeded
    /// probabilistic loss.
    pub fn set_c2l_drop_filter(&mut self, filter: impl FnMut(&[u8]) -> bool + 'static) {
        self.c2l.drop_filter = Some(Box::new(filter));
    }

    /// Like [`set_c2l_drop_filter`](Pair::set_c2l_drop_filter), for the
    /// listener→caller direction.
    pub fn set_l2c_drop_filter(&mut self, filter: impl FnMut(&[u8]) -> bool + 'static) {
        self.l2c.drop_filter = Some(Box::new(filter));
    }

    /// Drains all currently-queued outputs/events from every endpoint into the
    /// links, timer wheels, and event logs.
    fn pump(&mut self) {
        let now_us = self.now_us;
        let now = self.now();
        drain_connection(
            now,
            now_us,
            &mut self.caller,
            &mut self.c2l,
            &mut self.caller_timers,
            &mut self.caller_events,
            &mut self.caller_keepalives,
            &mut self.caller_dropreqs,
            &mut self.caller_naks,
            &mut self.caller_max_datagram,
        );
        while let Some((_addr, datagram)) = self.listener.poll_response() {
            self.l2c.send(now_us, datagram);
        }
        while let Some(conn) = self.listener.poll_accept() {
            self.accepted = Some(conn);
        }
        if let Some(accepted) = &mut self.accepted {
            let before = self.accepted_events.len();
            drain_connection(
                now,
                now_us,
                accepted,
                &mut self.l2c,
                &mut self.accepted_timers,
                &mut self.accepted_events,
                &mut self.accepted_keepalives,
                &mut self.accepted_dropreqs,
                &mut self.accepted_naks,
                &mut self.accepted_max_datagram,
            );
            // Timestamp each newly-delivered data packet for pacing assertions.
            for event in &self.accepted_events[before..] {
                if matches!(event, Event::DataReceived(_)) {
                    self.accepted_data_times.push(now_us);
                }
            }
        }
    }

    /// Advances to the next event (delivery or timer) and processes it. Returns
    /// `false` when nothing is pending — the network is quiescent.
    pub fn step(&mut self) -> bool {
        let next = [
            self.c2l.next_deadline(),
            self.l2c.next_deadline(),
            self.caller_timers.next_deadline(),
            self.accepted_timers.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        let Some(at) = next else {
            return false;
        };
        self.now_us = at;
        let now = self.now();

        // Deliver caller→listener datagrams to the accepted connection once it
        // exists (so conclusion retransmits reach it), otherwise to the listener.
        for datagram in self.c2l.drain_due(at) {
            if let Some(accepted) = &mut self.accepted {
                accepted.feed_recv_buf(&datagram, now);
            } else {
                self.listener.feed_recv_buf(&datagram, CALLER_ADDR, now);
            }
        }
        for datagram in self.l2c.drain_due(at) {
            self.caller.feed_recv_buf(&datagram, now);
        }
        for id in self.caller_timers.pop_due(at) {
            self.caller.handle_timer(id, now);
        }
        if let Some(accepted) = &mut self.accepted {
            for id in self.accepted_timers.pop_due(at) {
                accepted.handle_timer(id, now);
            }
        }
        self.pump();
        true
    }

    /// Steps until both sides are connected or `max_steps` is reached. Returns
    /// whether both sides connected.
    pub fn run_until_connected(&mut self, max_steps: usize) -> bool {
        for _ in 0..max_steps {
            if self.both_connected() {
                return true;
            }
            if !self.step() {
                break;
            }
        }
        self.both_connected()
    }

    /// Steps until `max_steps` is reached or the network goes quiescent.
    pub fn run(&mut self, max_steps: usize) {
        for _ in 0..max_steps {
            if !self.step() {
                break;
            }
        }
    }

    /// Whether the caller has emitted a `Connected` event.
    #[must_use]
    pub fn caller_connected(&self) -> bool {
        self.caller_events
            .iter()
            .any(|e| matches!(e, Event::Connected(_)))
    }

    /// Whether the accepted listener-side connection has emitted `Connected`.
    #[must_use]
    pub fn accepted_connected(&self) -> bool {
        self.accepted_events
            .iter()
            .any(|e| matches!(e, Event::Connected(_)))
    }

    /// Whether both sides have connected.
    #[must_use]
    pub fn both_connected(&self) -> bool {
        self.caller_connected() && self.accepted_connected()
    }

    /// The caller's collected events.
    #[must_use]
    pub fn caller_events(&self) -> &[Event] {
        &self.caller_events
    }

    /// The accepted connection's collected events.
    #[must_use]
    pub fn accepted_events(&self) -> &[Event] {
        &self.accepted_events
    }

    /// Sends application data from the caller at the current fake time, then
    /// drains the resulting outputs into the network.
    pub fn caller_send(&mut self, payload: &[u8]) {
        let now = self.now();
        let _ = self.caller.send(Bytes::copy_from_slice(payload), now);
        self.pump();
    }

    /// Begins a graceful close on the caller at the current fake time, then drains
    /// the resulting outputs into the network.
    pub fn caller_close(&mut self) {
        let now = self.now();
        self.caller.close(now);
        self.pump();
    }

    /// Whether the caller has emitted a `Closed` event.
    #[must_use]
    pub fn caller_closed(&self) -> bool {
        self.caller_events
            .iter()
            .any(|e| matches!(e, Event::Closed))
    }

    /// Count of KEEPALIVE control packets the caller has emitted.
    #[must_use]
    pub fn caller_keepalives(&self) -> u32 {
        self.caller_keepalives
    }

    /// Count of KEEPALIVE control packets the accepted side has emitted.
    #[must_use]
    pub fn accepted_keepalives(&self) -> u32 {
        self.accepted_keepalives
    }

    /// Count of DROPREQ control packets the caller has emitted.
    #[must_use]
    pub fn caller_dropreqs(&self) -> u32 {
        self.caller_dropreqs
    }

    /// Count of NAK control packets the accepted side has emitted.
    #[must_use]
    pub fn accepted_naks(&self) -> u32 {
        self.accepted_naks
    }

    /// The largest datagram the caller has put on the wire (bytes).
    #[must_use]
    pub fn caller_max_datagram(&self) -> usize {
        self.caller_max_datagram
    }

    /// The caller's connection statistics.
    #[must_use]
    pub fn caller_stats(&self) -> Stats {
        self.caller.stats()
    }

    /// Whether the caller's send window has room (the I/O layer's backpressure
    /// signal).
    #[must_use]
    pub fn caller_send_window_available(&self) -> bool {
        self.caller.send_window_available()
    }

    /// The accepted side's connection statistics (once it exists).
    #[must_use]
    pub fn accepted_stats(&self) -> Option<Stats> {
        self.accepted.as_ref().map(Connection::stats)
    }

    /// Whether the accepted side has emitted a `Closed` event.
    #[must_use]
    pub fn accepted_closed(&self) -> bool {
        self.accepted_events
            .iter()
            .any(|e| matches!(e, Event::Closed))
    }

    /// The fake-clock micros at which each accepted data packet was delivered,
    /// in delivery order.
    #[must_use]
    pub fn accepted_data_times(&self) -> &[u64] {
        &self.accepted_data_times
    }

    /// The payloads the accepted side has delivered to its application, in order.
    #[must_use]
    pub fn accepted_received(&self) -> Vec<Bytes> {
        self.accepted_events
            .iter()
            .filter_map(|e| match e {
                Event::DataReceived(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .collect()
    }

    /// The current fake clock, microseconds since the origin.
    #[must_use]
    pub fn fake_micros(&self) -> u64 {
        self.now_us
    }

    // ---- deferred accept (the listener's connection-request API) ----

    /// The simulated caller's address, as the listener sees it.
    #[must_use]
    pub fn caller_addr() -> SocketAddr {
        CALLER_ADDR
    }

    /// Drains the listener's next surfaced connection request, if any.
    pub fn listener_poll_request(&mut self) -> Option<srt_protocol::listener::ConnRequest> {
        self.listener.poll_request()
    }

    /// Accepts the pending conclusion from `remote`, installing the resulting
    /// connection as the accepted side.
    pub fn listener_accept_pending(
        &mut self,
        remote: SocketAddr,
    ) -> Result<(), srt_protocol::error::ConnectionError> {
        let now = self.now();
        let conn = self.listener.accept_pending(remote, now)?;
        self.accepted = Some(conn);
        self.pump();
        Ok(())
    }

    /// Rejects the pending conclusion from `remote` with `reason`, returning
    /// whether such a conclusion was pending.
    pub fn listener_reject_pending(
        &mut self,
        remote: SocketAddr,
        reason: srt_protocol::handshake::RejectReason,
    ) -> bool {
        let now = self.now();
        let rejected = self.listener.reject_pending(remote, reason, now);
        self.pump();
        rejected
    }

    /// Advances the fake clock by at least `micros`, processing every event along
    /// the way (jumping straight to the target if the network is quiescent).
    pub fn run_for(&mut self, micros: u64) {
        let target = self.now_us.saturating_add(micros);
        while self.now_us < target {
            if !self.step() {
                self.now_us = target;
                break;
            }
        }
    }

    /// Steps until `predicate` holds or `max_steps` is exhausted (or the network
    /// goes quiescent). Returns whether the predicate ultimately held.
    pub fn run_until(
        &mut self,
        mut predicate: impl FnMut(&Pair) -> bool,
        max_steps: usize,
    ) -> bool {
        for _ in 0..max_steps {
            if predicate(self) {
                return true;
            }
            if !self.step() {
                break;
            }
        }
        predicate(self)
    }
}

/// Drains one connection's outputs into a link and timer wheel, and its events
/// into a log. A free function (not a method) so it can borrow one endpoint and
/// one link disjointly without conflicting with `Pair`'s other fields.
fn drain_connection(
    now: Instant,
    now_us: u64,
    conn: &mut Connection,
    out: &mut Link,
    timers: &mut TimerWheel,
    events: &mut Vec<Event>,
    keepalives: &mut u32,
    dropreqs: &mut u32,
    naks: &mut u32,
    max_datagram: &mut usize,
) {
    while let Some(output) = conn.poll_output() {
        match output {
            Output::SendDatagram(datagram) => {
                *max_datagram = (*max_datagram).max(datagram.len());
                if let Ok(Packet::Control(c)) = Packet::decode(&datagram) {
                    match c.body {
                        ControlBody::Keepalive => *keepalives += 1,
                        ControlBody::DropReq { .. } => *dropreqs += 1,
                        ControlBody::Nak { .. } => *naks += 1,
                        _ => {}
                    }
                }
                out.send(now_us, datagram);
            }
            Output::SetTimer { id, after } => timers.set(id, now_us + duration_us(after)),
            Output::ClearTimer { id } => timers.clear(id),
            // `Output` is `#[non_exhaustive]`; ignore variants added by later layers.
            _ => {}
        }
    }
    while let Some(event) = conn.poll_event() {
        // Act as the embedder for key rotation: supply deterministic "random" SEK
        // bytes when the core asks (the core itself never generates randomness).
        if let Event::KeyRefreshNeeded { key_size } = event {
            let sek: Vec<u8> = (0..key_size)
                .map(|i| (now_us as u8) ^ 0xC0 ^ (i as u8))
                .collect();
            conn.provide_rekey(&sek, now);
        }
        events.push(event);
    }
}
