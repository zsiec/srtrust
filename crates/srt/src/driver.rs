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
    /// Accepted side: the endpoint's demux loop feeds us our datagrams.
    Demuxed(mpsc::Receiver<Bytes>),
}

impl Inbound {
    /// Awaits the next demuxed datagram. For an [`Inbound::Owned`] connection this
    /// never resolves — that connection's datagrams arrive on the socket arm of
    /// the driver's `select!`, and this arm is guarded off.
    async fn recv(&mut self) -> Option<Bytes> {
        match self {
            Inbound::Owned => pending().await,
            Inbound::Demuxed(rx) => rx.recv().await,
        }
    }
}

/// Application → driver commands.
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
    peer: SocketAddr,
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
    // Reused scratch for the per-iteration batch of outgoing datagrams and the GSO
    // concatenation buffer, so the hot path does not allocate per loop.
    let mut sends: Vec<Bytes> = Vec::new();
    let mut gso_buf: Vec<u8> = Vec::new();
    let mut due: Vec<TimerId> = Vec::new();

    loop {
        let now = runtime.now();
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
        if drain_events(&mut conn, &mut channels, now).await {
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
                    Some(bytes) => conn.feed_recv_buf(&bytes, runtime.now()),
                    None => break, // the endpoint demux dropped us
                }
            }
            // Just a wake-up; the due timer is handled at the top of the loop.
            () = timer => {}
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
}

/// The application channel ends a freshly-accepted connection is reached through.
pub(crate) type Accepted = (mpsc::Sender<Command>, mpsc::Receiver<Bytes>);

/// Drives a listening endpoint: owns the one shared socket, answers handshakes,
/// and **demuxes** every inbound datagram to the right connection by its peer
/// address. Each accepted connection runs in its own [`drive_connection`] task
/// and shares the socket for sending; the endpoint forwards its datagrams over a
/// channel. This is what lets one listener serve many concurrent callers.
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
    accept_tx: mpsc::Sender<Accepted>,
) {
    let mut recv_buf = vec![0u8; RECV_BUF];
    // Established connections, keyed by peer address; the value forwards inbound
    // datagrams to that connection's driver task.
    let mut connections: HashMap<SocketAddr, mpsc::Sender<Bytes>> = HashMap::new();

    loop {
        let Ok((len, stride, from)) = poll_fn(|cx| socket.poll_recv_gro(cx, &mut recv_buf)).await
        else {
            return;
        };

        // Established peer: hand each datagram to its driver and move on. A single
        // GRO read from one peer may carry several coalesced datagrams.
        if let Some(tx) = connections.get(&from) {
            for segment in gro_split(&recv_buf, len, stride) {
                match tx.try_send(Bytes::copy_from_slice(segment)) {
                    // Delivered, or the driver is swamped (drop and let ARQ recover
                    // the packet) — either way the demux loop never blocks here.
                    Ok(()) | Err(TrySendError::Full(_)) => {}
                    // The driver is gone; forget it (a future caller may reuse the addr).
                    Err(TrySendError::Closed(_)) => {
                        connections.remove(&from);
                        break;
                    }
                }
            }
            continue;
        }

        // Unknown peer: a handshake for the listener to answer. (Handshake
        // datagrams are never coalesced with established-flow data, but split
        // anyway for uniformity.)
        let now = runtime.now();
        for segment in gro_split(&recv_buf, len, stride) {
            listener.feed_recv_buf(segment, from, now);
        }
        while let Some((addr, datagram)) = listener.poll_response() {
            if poll_fn(|cx| socket.poll_send(cx, &datagram, addr))
                .await
                .is_err()
            {
                return;
            }
        }
        while let Some(conn) = listener.poll_accept() {
            let (commands_tx, commands_rx) = mpsc::channel(COMMAND_CAPACITY);
            let (data_tx, data_rx) = mpsc::channel(DATA_CAPACITY);
            let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_CAPACITY);
            if accept_tx.send((commands_tx, data_rx)).await.is_err() {
                return; // the application dropped the listener handle
            }
            connections.insert(from, inbound_tx);
            let channels = StreamChannels {
                commands: commands_rx,
                data: data_tx,
                connected: None, // the acceptor is already connected
            };
            runtime.spawn(Box::pin(drive_connection(
                runtime.clone(),
                socket.clone(),
                conn,
                from,
                channels,
                Inbound::Demuxed(inbound_rx),
            )));
        }
    }
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

/// Drains the connection's application-facing events. Returns `true` when the
/// driver should stop (the connection closed or failed, or the app hung up).
async fn drain_events(conn: &mut Connection, channels: &mut StreamChannels, now: Instant) -> bool {
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
            Event::DataReceived(payload) => {
                if channels.data.send(payload).await.is_err() {
                    return true; // the application dropped its receiver
                }
            }
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
