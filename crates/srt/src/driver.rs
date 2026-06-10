//! The background driver tasks that turn the sans-I/O core into real I/O.
//!
//! A driver owns the UDP socket, the protocol state machine, and a timer wheel.
//! Each loop iteration it captures `now` from the runtime, drains the core's
//! `Output` queue (sending datagrams, arming/clearing timers) and `Event` queue
//! (delivering data and connection status to the application), then waits on the
//! first of: a received datagram, the next timer deadline, or an application
//! command — feeding whichever fires back into the core.

use std::collections::HashMap;
use std::future::{pending, poll_fn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use srt_protocol::connection::{Connection, Event, Output, TimerId};
use srt_protocol::listener::Listener;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};

use crate::batch::{gro_split, gso_batches};
use crate::error::Error;
use crate::runtime::{AsyncUdpSocket, Runtime};

/// The largest datagram we will receive (a comfortably-large UDP buffer).
const RECV_BUF: usize = 65_536;
/// Capacity of the application → driver command channel.
pub(crate) const COMMAND_CAPACITY: usize = 64;
/// Capacity of the driver → application received-data channel.
pub(crate) const DATA_CAPACITY: usize = 256;
/// Capacity of the demux → connection inbound-datagram channel. Sized to absorb a
/// paced sender's catch-up micro-burst (a coarse OS timer makes the pacer release
/// packets in bursts rather than singly) without dropping; a backlog beyond this
/// means the connection's driver is genuinely far behind, and further datagrams
/// are dropped (SRT recovers lost packets through ARQ) so the demux loop never
/// blocks on one slow connection.
pub(crate) const INBOUND_CAPACITY: usize = 4096;

/// Where a connection driver reads its inbound datagrams from.
///
/// A **caller** owns its socket outright and reads datagrams straight off it. An
/// **accepted** connection shares the listener's socket with its siblings, so the
/// endpoint's demux loop forwards its datagrams over a channel instead (one
/// socket cannot be `recv`'d from by several tasks without stealing each other's
/// packets).
pub(crate) enum Inbound {
    /// Caller side: this connection owns the socket; read datagrams directly.
    Owned,
    /// Accepted side: the endpoint's demux loop feeds us our datagrams, each paired
    /// with the [`Instant`] it was read off the socket — so the core sees true
    /// arrival spacing (for delivery-rate estimation), not the later moment this
    /// task happens to dequeue it.
    Demuxed(mpsc::Receiver<(Instant, Bytes)>),
}

impl Inbound {
    /// Awaits the next demuxed datagram and its socket-arrival time. For an
    /// [`Inbound::Owned`] connection this never resolves — that connection's
    /// datagrams arrive on the socket arm of the driver's `select!`, and this arm
    /// is guarded off.
    async fn recv(&mut self) -> Option<(Instant, Bytes)> {
        match self {
            Inbound::Owned => pending().await,
            Inbound::Demuxed(rx) => rx.recv().await,
        }
    }
}

/// A connection's peer address, shared between its driver (which sends to
/// it) and the endpoint demux (which re-pins it when the same connection —
/// identified by destination socket id — starts arriving from a new address,
/// i.e. a NAT rebind). A plain mutex: read once per driver iteration,
/// written almost never.
#[derive(Debug, Clone)]
pub(crate) struct PeerAddr(Arc<std::sync::Mutex<SocketAddr>>);

impl PeerAddr {
    pub(crate) fn new(addr: SocketAddr) -> Self {
        PeerAddr(Arc::new(std::sync::Mutex::new(addr)))
    }

    fn get(&self) -> SocketAddr {
        *self.0.lock().expect("peer-addr lock is never poisoned")
    }

    fn set(&self, addr: SocketAddr) {
        *self.0.lock().expect("peer-addr lock is never poisoned") = addr;
    }
}

/// Application → driver commands.
#[derive(Debug)]
pub(crate) enum Command {
    /// Send application data reliably.
    Send(Bytes),
    /// Begin an orderly close.
    Close,
    /// Request a snapshot of the connection statistics.
    Stats(oneshot::Sender<srt_protocol::stats::Stats>),
}

/// The plumbing connecting an [`crate::SrtStream`] handle to its driver.
pub(crate) struct StreamChannels {
    pub(crate) commands: mpsc::Receiver<Command>,
    pub(crate) data: mpsc::Sender<Bytes>,
    /// Signalled once with the handshake outcome (caller side); `None` for an
    /// already-established acceptor.
    pub(crate) connected: Option<oneshot::Sender<Result<(), Error>>>,
}

/// Drives a single [`Connection`] talking to `peer` until it closes. Datagrams
/// arrive from `inbound` — directly off the socket for a caller, or via the
/// endpoint's demux for an accepted connection (see [`Inbound`]).
pub(crate) async fn drive_connection<R: Runtime>(
    runtime: Arc<R>,
    socket: Arc<dyn AsyncUdpSocket>,
    mut conn: Connection,
    peer_addr: PeerAddr,
    mut channels: StreamChannels,
    mut inbound: Inbound,
) {
    let mut timers: HashMap<TimerId, Instant> = HashMap::new();
    // Only a caller reads the socket here; an accepted connection's buffer stays
    // empty (its datagrams arrive already-owned over the demux channel).
    let mut recv_buf = match inbound {
        Inbound::Owned => vec![0u8; RECV_BUF],
        Inbound::Demuxed(_) => Vec::new(),
    };
    // Set once the app asks to close: we stop pulling commands (the connection is
    // lingering to drain its send buffer) and just let the core run to `Closed`.
    let mut closing = false;
    // A received payload the app's data channel could not take yet (see
    // `drain_events`): re-offered before new events, and flushed the moment the
    // channel has room via the `reserve` arm of the `select!` below.
    let mut pending_data: Option<Bytes> = None;
    // Reused scratch for the per-iteration batch of outgoing datagrams and the GSO
    // concatenation buffer, so the hot path does not allocate per loop.
    let mut sends: Vec<Bytes> = Vec::new();
    let mut gso_buf: Vec<u8> = Vec::new();
    let mut due: Vec<TimerId> = Vec::new();

    loop {
        let now = runtime.now();
        // Re-read each iteration: the endpoint demux re-pins this when the
        // peer's address changes mid-stream (NAT rebind).
        let peer = peer_addr.get();
        // Fire any already-due timers first. tokio's `select!` is free to keep
        // choosing an always-ready socket branch under a heavy inbound flood, so
        // firing timers up front here (rather than only in a select branch) keeps
        // the periodic ACK and TSBPD delivery timers from being starved.
        collect_due_timers(&timers, now, &mut due);
        for id in &due {
            timers.remove(id);
            conn.handle_timer(*id, now);
        }
        if drain_outputs(
            &socket,
            &mut conn,
            peer,
            &mut timers,
            now,
            &mut sends,
            &mut gso_buf,
        )
        .await
        .is_err()
        {
            break;
        }
        if drain_events(&mut conn, &mut channels, &mut pending_data, now) {
            break;
        }

        // All remaining timers are in the future; wake at the earliest.
        let deadline = timers
            .values()
            .copied()
            .min()
            .unwrap_or_else(|| now + Duration::from_secs(3600));
        let timer = runtime.sleep_until(deadline);

        // A caller reads the socket directly; an accepted connection reads the
        // demux channel. Exactly one arm is live per connection (the other is
        // guarded off), so they never race for the same datagram.
        let owned = matches!(inbound, Inbound::Owned);

        tokio::select! {
            received = poll_fn(|cx| socket.poll_recv_gro(cx, &mut recv_buf)), if owned => {
                match received {
                    Ok((len, stride, _from)) => {
                        let now = runtime.now();
                        // One read may carry several GRO-coalesced datagrams.
                        for segment in gro_split(&recv_buf, len, stride) {
                            conn.feed_recv_buf(segment, now);
                        }
                    }
                    Err(_) => break,
                }
            }
            datagram = inbound.recv(), if !owned => {
                match datagram {
                    // Feed with the *arrival* time stamped by the demux loop, not
                    // `runtime.now()` — using a later processing time would collapse
                    // the inter-arrival gaps (and inflate the delivery-rate estimate)
                    // whenever several queued datagrams are drained back-to-back.
                    Some((arrival, bytes)) => conn.feed_recv_buf(&bytes, arrival),
                    None => break, // the endpoint demux dropped us
                }
            }
            // Just a wake-up; the due timer is handled at the top of the loop.
            () = timer => {}
            // The app caught up: hand over the held-back payload the moment the
            // data channel has room, then resume normal event draining.
            permit = channels.data.reserve(), if pending_data.is_some() => {
                match permit {
                    Ok(permit) => {
                        permit.send(pending_data.take().expect("guarded by is_some"));
                    }
                    // The app dropped its receive half mid-backlog: discard
                    // the parked payload and keep the connection running.
                    Err(_) => pending_data = None,
                }
            }
            // Backpressure: only pull application commands while the send window
            // has room. When it is full this arm is disabled, so queued `send`s
            // back up in the bounded command channel and `SrtStream::send` blocks
            // — bounding the in-memory backlog. An incoming ACK (socket/demux arm)
            // frees window and re-enables this arm on the next iteration.
            command = channels.commands.recv(), if !closing && conn.send_window_available() => {
                let now = runtime.now();
                // Drain the whole batch of queued commands in one wake-up, so the
                // per-iteration select/timer overhead is amortized across many
                // packets rather than paid per packet.
                let mut next = command;
                loop {
                    match next {
                        Some(Command::Send(payload)) => { let _ = conn.send(payload, now); }
                        Some(Command::Stats(reply)) => { let _ = reply.send(conn.stats()); }
                        // Begin the (possibly lingering) close and stop reading
                        // commands; the core drives the rest to `Closed`.
                        Some(Command::Close) | None => {
                            conn.close(now);
                            closing = true;
                            break;
                        }
                    }
                    match channels.commands.try_recv() {
                        Ok(more) => next = Some(more),
                        Err(_) => break,
                    }
                }
            }
        }
    }
    tracing::debug!(peer = %peer_addr.get(), "connection driver stopped");
}

/// The application channel ends a freshly-accepted connection is reached through.
pub(crate) type Accepted = (mpsc::Sender<Command>, mpsc::Receiver<Bytes>);

/// What a listener hands its application, in arrival order: an
/// already-established stream (auto-accept/backlog mode, the default) or a
/// connection request awaiting a decision (deferred mode). One listener only
/// ever produces one of the two variants — `SrtListener::accept`/`incoming`
/// match accordingly.
pub(crate) enum Incoming {
    /// Auto-accept: the handshake completed into the backlog.
    Stream(crate::SrtStream),
    /// Deferred: the application must accept or reject.
    Request(crate::ConnRequest),
}

/// A [`crate::ConnRequest`] decision travelling back to the endpoint driver.
pub(crate) enum Decision {
    /// Accept the pending conclusion from `addr`; reply with the new stream's
    /// channel ends (or the error that prevented the accept).
    Accept {
        addr: SocketAddr,
        reply: oneshot::Sender<Result<Accepted, Error>>,
    },
    /// Reject the pending conclusion from `addr` with `reason` (sent to the
    /// caller as a `URQ_FAILURE` handshake).
    Reject {
        addr: SocketAddr,
        reason: srt_protocol::handshake::RejectReason,
    },
}

/// Drives a listening endpoint: owns the one shared socket, answers handshakes,
/// and **demuxes** every inbound datagram to the right connection by its peer
/// address. Each accepted connection runs in its own [`drive_connection`] task
/// and shares the socket for sending; the endpoint forwards its datagrams over a
/// channel. This is what lets one listener serve many concurrent callers.
///
/// The core listener runs in deferred-accept mode: each crypto-valid conclusion
/// surfaces as a [`crate::ConnRequest`] on `requests_tx`, and the application's
/// accept/reject comes back as a [`Decision`] — `SrtListener::accept()` is just
/// `incoming().accept()`, so auto-accept costs one round trip through the same
/// channels.
///
/// Demux key is the peer [`SocketAddr`]: distinct callers bind distinct source
/// ports, so the (ip, port) tuple uniquely identifies a connection. (libsrt also
/// demuxes established connections by destination socket id, which additionally
/// disambiguates a reused 5-tuple; that would require minting a unique socket id
/// per accepted connection in the core — deferred, not needed for v1.)
pub(crate) async fn drive_endpoint<R: Runtime>(
    runtime: Arc<R>,
    socket: Arc<dyn AsyncUdpSocket>,
    mut listener: Listener,
    local_addr: SocketAddr,
    auto_accept: bool,
    incoming_tx: mpsc::Sender<Incoming>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut recv_buf = vec![0u8; RECV_BUF];
    // Established connections, keyed by peer address (the fast path; a UDP
    // flow's source address is stable) — the value forwards inbound datagrams
    // (paired with their arrival time) to that connection's driver task.
    let mut connections: HashMap<SocketAddr, mpsc::Sender<(Instant, Bytes)>> = HashMap::new();
    // The same connections keyed by their local socket id — every packet the
    // peer sends carries it as the destination socket id (spec §3.1), so a
    // datagram from an *unknown* address can still be claimed by its
    // connection (NAT rebind) instead of being mistaken for a handshake.
    let mut by_id: HashMap<u32, IdEntry> = HashMap::new();
    // Decisions flow back from `ConnRequest` handles. The sender side is cloned
    // into every surfaced request; this receiver never closes because we hold a
    // sender too.
    let (decisions_tx, mut decisions_rx) = mpsc::channel::<Decision>(COMMAND_CAPACITY);

    loop {
        // An idle endpoint parks on the socket indefinitely, so the listener
        // handle's drop must be its own wake-up: the `SrtListener` holds the
        // sender half of `shutdown`, and dropping it resolves this arm
        // (BUG-05b, docs/known-issues/05 — task + socket leak on drop).
        let received = tokio::select! {
            received = poll_fn(|cx| socket.poll_recv_gro(cx, &mut recv_buf)) => received,
            decision = decisions_rx.recv() => {
                let Some(decision) = decision else { continue };
                if apply_decision(
                    &runtime,
                    &socket,
                    &mut listener,
                    &mut connections,
                    &mut by_id,
                    decision,
                )
                .await
                .is_err()
                {
                    return;
                }
                continue;
            }
            _ = &mut shutdown => return, // the application dropped the listener
        };
        let Ok((len, stride, from)) = received else {
            return;
        };
        // Stamp arrival once per socket read: every datagram in this batch is fed to
        // its connection with this instant, so the core measures real inter-arrival
        // spacing rather than the time it is later dequeued from the demux channel.
        let now = runtime.now();

        // Established peer: hand each datagram to its driver and move on. A single
        // GRO read from one peer may carry several coalesced datagrams.
        if let Some(tx) = connections.get(&from) {
            if !forward_segments(tx, &recv_buf, len, stride, now) {
                // The driver is gone; forget it (a future caller may reuse the addr).
                connections.remove(&from);
            }
            continue;
        }

        // Unknown address, but the destination socket id may identify an
        // established connection whose peer rebound (NAT mapping reassigned):
        // re-pin that connection to the new address — inbound demux and the
        // driver's outbound sends both follow — and forward as usual.
        if let Some(id) = gro_split(&recv_buf, len, stride)
            .next()
            .and_then(dest_socket_id)
            && let Some(entry) = by_id.get_mut(&id)
        {
            tracing::info!(
                socket_id = id,
                old = %entry.addr,
                new = %from,
                "peer address changed; re-pinning"
            );
            connections.remove(&entry.addr);
            connections.insert(from, entry.tx.clone());
            entry.addr = from;
            entry.peer.set(from);
            if !forward_segments(&entry.tx, &recv_buf, len, stride, now) {
                connections.remove(&from);
                by_id.remove(&id);
            }
            continue;
        }

        // Unknown peer: a handshake for the listener to answer. (Handshake
        // datagrams are never coalesced with established-flow data, but split
        // anyway for uniformity.)
        for segment in gro_split(&recv_buf, len, stride) {
            listener.feed_recv_buf(segment, from, now);
        }
        // Surface each new conclusion to the application *without waiting*: an
        // `.await` here would park this demux loop — the only thing forwarding
        // datagrams to every established connection on the socket — whenever
        // the app fell behind (BUG-05g, docs/known-issues/05). A full backlog
        // rejects the caller outright (`SRT_REJ_BACKLOG`), like a full TCP SYN
        // backlog but with an answer instead of silence.
        if surface_requests(
            &runtime,
            &socket,
            &mut listener,
            &mut connections,
            &mut by_id,
            local_addr,
            auto_accept,
            &incoming_tx,
            &decisions_tx,
            now,
        )
        .is_err()
        {
            return; // the application dropped the listener handle
        }
        if flush_listener_responses(&socket, &mut listener)
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Hands every newly-surfaced conclusion to the application: in auto-accept
/// (backlog) mode the handshake is completed on the spot and the established
/// stream queued; in deferred mode a [`crate::ConnRequest`] is queued for the
/// application's decision. A full backlog rejects the caller
/// (`SRT_REJ_BACKLOG`). `Err` means the application dropped its handle.
#[allow(clippy::too_many_arguments)] // a private seam of one driver loop
fn surface_requests<R: Runtime>(
    runtime: &Arc<R>,
    socket: &Arc<dyn AsyncUdpSocket>,
    listener: &mut Listener,
    connections: &mut HashMap<SocketAddr, mpsc::Sender<(Instant, Bytes)>>,
    by_id: &mut HashMap<u32, IdEntry>,
    local_addr: SocketAddr,
    auto_accept: bool,
    incoming_tx: &mpsc::Sender<Incoming>,
    decisions_tx: &mpsc::Sender<Decision>,
    now: Instant,
) -> Result<(), ()> {
    while let Some(request) = listener.poll_request() {
        let addr = request.remote_addr();
        tracing::debug!(
            remote = %addr,
            stream_id = ?request.stream_id(),
            "connection request"
        );
        // Reserve the application's slot *before* deciding anything, so a
        // full backlog rejects the caller (`SRT_REJ_BACKLOG`) instead of
        // establishing a connection nobody will ever own.
        let permit = match incoming_tx.try_reserve() {
            Ok(permit) => permit,
            Err(TrySendError::Full(())) => {
                tracing::warn!(remote = %addr, "backlog full; rejecting");
                listener.reject_pending(addr, srt_protocol::handshake::RejectReason::Backlog, now);
                continue;
            }
            // The application dropped the listener handle.
            Err(TrySendError::Closed(())) => return Err(()),
        };
        if auto_accept {
            // Backlog semantics (libsrt/srtgo): complete the handshake right
            // now — the caller's connect resolves with no application
            // involvement — and queue the established stream.
            let stream_id = request.stream_id().map(str::to_owned);
            if let Ok((commands, data)) =
                spawn_accepted(runtime, socket, listener, connections, by_id, addr, now)
            {
                let stream = crate::SrtStream::new(
                    commands,
                    data,
                    crate::stream::StreamMeta {
                        local_addr,
                        peer_addr: addr,
                        stream_id,
                    },
                );
                permit.send(Incoming::Stream(stream));
            }
            // On error the core already queued the wire rejection; the
            // unused permit just drops.
        } else {
            permit.send(Incoming::Request(crate::ConnRequest {
                stream_id: request.stream_id().map(str::to_owned),
                remote_addr: addr,
                local_addr,
                decisions: decisions_tx.clone(),
            }));
        }
    }
    Ok(())
}

/// Applies one application accept/reject [`Decision`] to the core listener:
/// an accept spawns the connection's driver and replies with its channel ends;
/// a reject (or a failed accept) sends the queued `URQ_FAILURE` to the caller.
/// `Err` means the socket died and the endpoint should shut down.
async fn apply_decision<R: Runtime>(
    runtime: &Arc<R>,
    socket: &Arc<dyn AsyncUdpSocket>,
    listener: &mut Listener,
    connections: &mut HashMap<SocketAddr, mpsc::Sender<(Instant, Bytes)>>,
    by_id: &mut HashMap<u32, IdEntry>,
    decision: Decision,
) -> Result<(), ()> {
    let now = runtime.now();
    match decision {
        Decision::Accept { addr, reply } => {
            let result = spawn_accepted(runtime, socket, listener, connections, by_id, addr, now)
                .map_err(Error::Protocol);
            let _ = reply.send(result);
        }
        Decision::Reject { addr, reason } => {
            tracing::info!(remote = %addr, %reason, "rejected");
            listener.reject_pending(addr, reason, now);
        }
    }
    flush_listener_responses(socket, listener).await
}

/// Accepts the pending conclusion from `addr`, registers it in both demux
/// maps, and spawns its connection driver — returning the application channel
/// ends. On failure the core has already queued the wire rejection.
fn spawn_accepted<R: Runtime>(
    runtime: &Arc<R>,
    socket: &Arc<dyn AsyncUdpSocket>,
    listener: &mut Listener,
    connections: &mut HashMap<SocketAddr, mpsc::Sender<(Instant, Bytes)>>,
    by_id: &mut HashMap<u32, IdEntry>,
    addr: SocketAddr,
    now: Instant,
) -> Result<Accepted, srt_protocol::error::ConnectionError> {
    let conn = listener.accept_pending(addr, now).inspect_err(|error| {
        tracing::warn!(remote = %addr, %error, "accept failed");
    })?;
    tracing::info!(remote = %addr, "accepted");
    // Evict demux entries whose connection driver has since ended (their
    // channel receiver is gone). Without this sweep a long-running listener
    // accumulates one dead entry per closed peer that never sends another
    // datagram.
    connections.retain(|_, tx| !tx.is_closed());
    by_id.retain(|_, entry| !entry.tx.is_closed());
    let (commands_tx, commands_rx) = mpsc::channel(COMMAND_CAPACITY);
    let (data_tx, data_rx) = mpsc::channel(DATA_CAPACITY);
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_CAPACITY);
    let peer = PeerAddr::new(addr);
    connections.insert(addr, inbound_tx.clone());
    by_id.insert(
        conn.local_socket_id().value(),
        IdEntry {
            tx: inbound_tx,
            addr,
            peer: peer.clone(),
        },
    );
    let channels = StreamChannels {
        commands: commands_rx,
        data: data_tx,
        connected: None, // the acceptor is already connected
    };
    runtime.spawn(Box::pin(drive_connection(
        runtime.clone(),
        socket.clone(),
        conn,
        peer,
        channels,
        Inbound::Demuxed(inbound_rx),
    )));
    Ok((commands_tx, data_rx))
}

/// One established connection as the id-keyed demux sees it: the forwarding
/// channel, the address it currently lives at, and the shared peer address its
/// driver sends to.
struct IdEntry {
    tx: mpsc::Sender<(Instant, Bytes)>,
    addr: SocketAddr,
    peer: PeerAddr,
}

/// Forwards every GRO segment of one socket read to a connection's driver,
/// stamped with its arrival time. A swamped driver drops segments (ARQ
/// recovers them) so the demux loop never blocks. Returns `false` when the
/// driver is gone (its channel closed) and the entry should be evicted.
fn forward_segments(
    tx: &mpsc::Sender<(Instant, Bytes)>,
    recv_buf: &[u8],
    len: usize,
    stride: usize,
    now: Instant,
) -> bool {
    for segment in gro_split(recv_buf, len, stride) {
        match tx.try_send((now, Bytes::copy_from_slice(segment))) {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Closed(_)) => return false,
        }
    }
    true
}

/// The destination socket id of a wire packet — the fourth 32-bit word of
/// both the data and control headers (spec §3.1). `None` for runts.
fn dest_socket_id(datagram: &[u8]) -> Option<u32> {
    let bytes = datagram.get(12..16)?;
    Some(u32::from_be_bytes(
        bytes.try_into().expect("a 4-byte slice"),
    ))
}

/// Sends every response datagram the core listener has queued (induction
/// answers and rejections). `Err` means the socket died.
async fn flush_listener_responses(
    socket: &Arc<dyn AsyncUdpSocket>,
    listener: &mut Listener,
) -> Result<(), ()> {
    while let Some((addr, datagram)) = listener.poll_response() {
        if poll_fn(|cx| socket.poll_send(cx, &datagram, addr))
            .await
            .is_err()
        {
            return Err(());
        }
    }
    Ok(())
}

/// Drains the connection's outputs: collects datagrams to send to `peer` (sent in
/// one pass so equal-sized runs can be GSO-batched), and arms or clears timers in
/// the wheel. Timer ops are independent of the sends, so applying them while
/// collecting (then sending afterwards) is order-safe.
async fn drain_outputs(
    socket: &Arc<dyn AsyncUdpSocket>,
    conn: &mut Connection,
    peer: SocketAddr,
    timers: &mut HashMap<TimerId, Instant>,
    now: Instant,
    sends: &mut Vec<Bytes>,
    gso_buf: &mut Vec<u8>,
) -> Result<(), std::io::Error> {
    sends.clear();
    while let Some(output) = conn.poll_output() {
        match output {
            Output::SendDatagram(datagram) => sends.push(datagram),
            Output::SetTimer { id, after } => {
                timers.insert(id, now + after);
            }
            Output::ClearTimer { id } => {
                timers.remove(&id);
            }
            _ => {}
        }
    }
    flush_sends(socket, peer, sends, gso_buf).await
}

/// Sends a batch of queued datagrams to `peer`, coalescing equal-sized runs into
/// GSO transmits when the socket supports it (one syscall per run instead of one
/// per datagram). On a socket without GSO (`max_gso_segments() == 1`) this is just
/// a send per datagram, with no extra copying.
async fn flush_sends(
    socket: &Arc<dyn AsyncUdpSocket>,
    peer: SocketAddr,
    sends: &[Bytes],
    gso_buf: &mut Vec<u8>,
) -> Result<(), std::io::Error> {
    let max = socket.max_gso_segments();
    if max <= 1 {
        for datagram in sends {
            poll_fn(|cx| socket.poll_send(cx, datagram, peer)).await?;
        }
        return Ok(());
    }
    for batch in gso_batches(sends, max) {
        if let [single] = batch {
            poll_fn(|cx| socket.poll_send(cx, single, peer)).await?;
        } else {
            gso_buf.clear();
            for datagram in batch {
                gso_buf.extend_from_slice(datagram);
            }
            let segment_size = batch[0].len();
            poll_fn(|cx| socket.poll_send_gso(cx, gso_buf, segment_size, peer)).await?;
        }
    }
    Ok(())
}

/// Drains the connection's application-facing events **without ever blocking
/// the driver loop** (BUG-05a, docs/known-issues/05): a `data.send(..).await`
/// here would freeze ACKs, keepalives, and every timer the moment a slow
/// application reader filled the channel — and the *peer* would then tear the
/// connection down as idle.
///
/// A payload the channel cannot take right now is parked in `pending_data`
/// (re-offered first on the next call; the driver also `select!`s on channel
/// capacity), and event polling pauses. Undelivered events then back up inside
/// the core, where they shrink the receive-buffer availability the next ACK
/// advertises — closing the peer's send window instead of growing memory.
///
/// A *closed* data channel (the app dropped its `SrtStream`/`SrtRecvHalf`) is
/// not a stop condition: inbound payloads are discarded and the connection
/// keeps running, exactly like an unread TCP stream — teardown is the command
/// channel's job (dropping the send side closes the connection).
///
/// Returns `true` when the driver should stop (the connection closed or
/// failed).
fn drain_events(
    conn: &mut Connection,
    channels: &mut StreamChannels,
    pending_data: &mut Option<Bytes>,
    now: Instant,
) -> bool {
    // Re-offer the held-back payload before touching new events, preserving
    // delivery order.
    if let Some(payload) = pending_data.take() {
        match channels.data.try_send(payload) {
            // Delivered — or the app dropped its receive half, which only
            // means it stopped reading (payloads are discarded, the
            // connection lives on; cf. dropping a TCP read half).
            Ok(()) | Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(payload)) => {
                *pending_data = Some(payload);
                return false; // app still slow: leave events in the core
            }
        }
    }
    while let Some(event) = conn.poll_event() {
        match event {
            Event::Connected(_) => {
                if let Some(tx) = channels.connected.take() {
                    let _ = tx.send(Ok(()));
                }
            }
            Event::KeyRefreshNeeded { key_size } => {
                // Supply the embedder's randomness for the new key (the core never
                // generates it), then it announces the rotation to the peer.
                let mut sek = vec![0u8; key_size];
                crate::fill_random(&mut sek);
                conn.provide_rekey(&sek, now);
            }
            Event::DataReceived(payload) => match channels.data.try_send(payload) {
                // Delivered, or discarded because the app dropped its receive
                // half (see above) — either way, keep going.
                Ok(()) | Err(TrySendError::Closed(_)) => {}
                Err(TrySendError::Full(payload)) => {
                    *pending_data = Some(payload);
                    return false; // pause event polling until capacity frees
                }
            },
            Event::Failed(reason) => {
                if let Some(tx) = channels.connected.take() {
                    let _ = tx.send(Err(Error::Protocol(reason)));
                }
                return true;
            }
            Event::Closed => return true,
            _ => {}
        }
    }
    false
}

/// The timers whose deadline is at or before `now`.
fn collect_due_timers(timers: &HashMap<TimerId, Instant>, now: Instant, out: &mut Vec<TimerId>) {
    out.clear();
    out.extend(
        timers
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(id, _)| *id),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    /// A socket that records every send (as `(bytes, segment_size)`) instead of
    /// touching the network, so the GSO batching wiring is checkable directly.
    struct RecordingSocket {
        max_gso: usize,
        sent: Mutex<Vec<(Vec<u8>, usize)>>,
    }

    impl AsyncUdpSocket for RecordingSocket {
        fn poll_send(
            &self,
            _: &mut Context<'_>,
            buf: &[u8],
            _: SocketAddr,
        ) -> Poll<io::Result<()>> {
            self.sent.lock().unwrap().push((buf.to_vec(), buf.len()));
            Poll::Ready(Ok(()))
        }
        fn poll_recv(
            &self,
            _: &mut Context<'_>,
            _: &mut [u8],
        ) -> Poll<io::Result<(usize, SocketAddr)>> {
            Poll::Pending
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
        fn max_gso_segments(&self) -> usize {
            self.max_gso
        }
        fn poll_send_gso(
            &self,
            _: &mut Context<'_>,
            buf: &[u8],
            segment_size: usize,
            _: SocketAddr,
        ) -> Poll<io::Result<()>> {
            self.sent.lock().unwrap().push((buf.to_vec(), segment_size));
            Poll::Ready(Ok(()))
        }
    }

    fn dg(len: usize, tag: u8) -> Bytes {
        Bytes::from(vec![tag; len])
    }

    #[tokio::test]
    async fn flush_sends_coalesces_equal_runs_into_gso() {
        let rec = Arc::new(RecordingSocket {
            max_gso: 4,
            sent: Mutex::new(Vec::new()),
        });
        let socket: Arc<dyn AsyncUdpSocket> = rec.clone();
        let peer = "127.0.0.1:9".parse().unwrap();
        // Three equal data packets, then a small control packet, then one more.
        let sends = vec![
            dg(1316, 1),
            dg(1316, 2),
            dg(1316, 3),
            dg(40, 9),
            dg(1316, 4),
        ];
        let mut gso_buf = Vec::new();
        flush_sends(&socket, peer, &sends, &mut gso_buf)
            .await
            .unwrap();

        let sent = rec.sent.lock().unwrap();
        // Run of three 1316s → one GSO send of 3·1316 bytes with stride 1316;
        // the 40 and the trailing lone 1316 each go as their own send.
        assert_eq!(sent.len(), 3, "three transmits: one batch + two singles");
        assert_eq!(sent[0].0.len(), 3 * 1316);
        assert_eq!(sent[0].1, 1316, "GSO segment size is the datagram length");
        assert_eq!(sent[1], (vec![9u8; 40], 40));
        assert_eq!(sent[2].0.len(), 1316);
    }

    #[tokio::test]
    async fn flush_sends_without_gso_sends_each_singly() {
        let rec = Arc::new(RecordingSocket {
            max_gso: 1,
            sent: Mutex::new(Vec::new()),
        });
        let socket: Arc<dyn AsyncUdpSocket> = rec.clone();
        let peer = "127.0.0.1:9".parse().unwrap();
        let sends = vec![dg(1316, 1), dg(1316, 2), dg(1316, 3)];
        let mut gso_buf = Vec::new();
        flush_sends(&socket, peer, &sends, &mut gso_buf)
            .await
            .unwrap();

        let sent = rec.sent.lock().unwrap();
        assert_eq!(sent.len(), 3, "no GSO: one send per datagram");
        assert!(gso_buf.is_empty(), "no concatenation buffer used");
    }
}
