//! The established-connection handles: [`SrtStream`], its split halves, and
//! their `futures` Stream/Sink adapters.
//!
//! A stream is a pair of channels into the connection's background driver —
//! commands out, received payloads in — plus the connection's metadata. The
//! send side only needs the (cloneable) command sender and the receive side
//! only the data receiver, which is what makes [`SrtStream::into_split`] a
//! plain destructuring rather than an `Arc<Mutex>` affair.

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;

use crate::driver::Command;
use crate::error::{Error, Result};
use srt_protocol::stats::Stats;

/// Who this connection talks to and what was asked of it — fixed at handshake
/// time, shared by the stream and both split halves.
#[derive(Debug, Clone)]
pub(crate) struct StreamMeta {
    pub(crate) local_addr: SocketAddr,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) stream_id: Option<String>,
}

/// An established SRT connection: a reliable, in-order, message-oriented stream.
///
/// Implements [`futures_core::Stream`] (of received payloads) and
/// [`futures_sink::Sink<Bytes>`], so it slots into combinator-based code; the
/// inherent [`send`](SrtStream::send)/[`recv`](SrtStream::recv) methods remain
/// the simple path. [`into_split`](SrtStream::into_split) separates the two
/// directions onto independent tasks.
#[derive(Debug)]
pub struct SrtStream {
    commands: mpsc::Sender<Command>,
    /// The same command channel as `commands`, wrapped for the `Sink` impl
    /// (which needs poll-based reservation state across calls).
    sink: PollSender<Command>,
    data: mpsc::Receiver<Bytes>,
    meta: StreamMeta,
}

impl SrtStream {
    pub(crate) fn new(
        commands: mpsc::Sender<Command>,
        data: mpsc::Receiver<Bytes>,
        meta: StreamMeta,
    ) -> Self {
        SrtStream {
            sink: PollSender::new(commands.clone()),
            commands,
            data,
            meta,
        }
    }

    /// Sends one application message reliably.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the connection has ended.
    pub async fn send(&self, payload: Bytes) -> Result<()> {
        send_command(&self.commands, Command::Send(payload)).await
    }

    /// Receives the next application message, or `None` once the connection ends.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.data.recv().await
    }

    /// Begins an orderly close.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the connection has already ended.
    pub async fn close(&self) -> Result<()> {
        send_command(&self.commands, Command::Close).await
    }

    /// A snapshot of this connection's cumulative [`Stats`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the connection has ended.
    pub async fn stats(&self) -> Result<Stats> {
        fetch_stats(&self.commands).await
    }

    /// The local address this end is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.meta.local_addr
    }

    /// The peer's address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.meta.peer_addr
    }

    /// The connection's Stream ID (spec §3.2.1.3): what the caller advertised
    /// — on either end — or `None` if it advertised none.
    #[must_use]
    pub fn stream_id(&self) -> Option<&str> {
        self.meta.stream_id.as_deref()
    }

    /// Splits the stream into independently-owned send and receive halves, so
    /// each direction can live on its own task. The halves stay tied to the
    /// same connection: dropping (or [`close`](SrtSendHalf::close)-ing) the
    /// **send half** ends it; dropping just the **receive half** only stops
    /// reading — further inbound payloads are discarded and the connection
    /// lives on, like an unread TCP stream.
    #[must_use]
    pub fn into_split(self) -> (SrtSendHalf, SrtRecvHalf) {
        (
            SrtSendHalf {
                commands: self.commands,
                sink: self.sink,
                meta: self.meta.clone(),
            },
            SrtRecvHalf {
                data: self.data,
                meta: self.meta,
            },
        )
    }
}

/// The send direction of a split [`SrtStream`]: `send`/`close`/`stats`, plus
/// the [`futures_sink::Sink<Bytes>`] adapter.
#[derive(Debug)]
pub struct SrtSendHalf {
    commands: mpsc::Sender<Command>,
    sink: PollSender<Command>,
    meta: StreamMeta,
}

impl SrtSendHalf {
    /// Sends one application message reliably.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the connection has ended.
    pub async fn send(&self, payload: Bytes) -> Result<()> {
        send_command(&self.commands, Command::Send(payload)).await
    }

    /// Begins an orderly close of the whole connection (both directions —
    /// the peer sees the stream end after in-flight data drains).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the connection has already ended.
    pub async fn close(&self) -> Result<()> {
        send_command(&self.commands, Command::Close).await
    }

    /// A snapshot of the connection's cumulative [`Stats`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the connection has ended.
    pub async fn stats(&self) -> Result<Stats> {
        fetch_stats(&self.commands).await
    }

    /// The local address this end is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.meta.local_addr
    }

    /// The peer's address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.meta.peer_addr
    }

    /// The connection's Stream ID, if any (spec §3.2.1.3).
    #[must_use]
    pub fn stream_id(&self) -> Option<&str> {
        self.meta.stream_id.as_deref()
    }
}

/// The receive direction of a split [`SrtStream`]: `recv`, plus the
/// [`futures_core::Stream`] adapter.
#[derive(Debug)]
pub struct SrtRecvHalf {
    data: mpsc::Receiver<Bytes>,
    meta: StreamMeta,
}

impl SrtRecvHalf {
    /// Receives the next application message, or `None` once the connection ends.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.data.recv().await
    }

    /// The local address this end is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.meta.local_addr
    }

    /// The peer's address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.meta.peer_addr
    }

    /// The connection's Stream ID, if any (spec §3.2.1.3).
    #[must_use]
    pub fn stream_id(&self) -> Option<&str> {
        self.meta.stream_id.as_deref()
    }
}

/// Queues one command for the driver, mapping a hung-up driver to
/// [`Error::Closed`].
async fn send_command(commands: &mpsc::Sender<Command>, command: Command) -> Result<()> {
    commands.send(command).await.map_err(|_| Error::Closed)
}

/// Round-trips a [`Command::Stats`] request to the driver.
async fn fetch_stats(commands: &mpsc::Sender<Command>) -> Result<Stats> {
    let (reply, response) = oneshot::channel();
    commands
        .send(Command::Stats(reply))
        .await
        .map_err(|_| Error::Closed)?;
    response.await.map_err(|_| Error::Closed)
}

// ---- futures adapters ----
//
// `Stream` yields received payloads; `Sink<Bytes>` queues sends through the
// same bounded command channel the inherent `send` uses, so combinator code
// gets the same backpressure. `poll_flush` is a no-op: a queued payload is
// already owned by the driver, and SRT (live mode) has no flush concept.
// `poll_close` queues an orderly `Command::Close` (the lingering close, same
// as the inherent method).

impl futures_core::Stream for SrtStream {
    type Item = Bytes;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        self.data.poll_recv(cx)
    }
}

impl futures_core::Stream for SrtRecvHalf {
    type Item = Bytes;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        self.data.poll_recv(cx)
    }
}

/// Shared body of the two `Sink` impls.
fn sink_poll_ready(sink: &mut PollSender<Command>, cx: &mut Context<'_>) -> Poll<Result<()>> {
    sink.poll_reserve(cx).map_err(|_| Error::Closed)
}

fn sink_start_send(sink: &mut PollSender<Command>, payload: Bytes) -> Result<()> {
    sink.send_item(Command::Send(payload))
        .map_err(|_| Error::Closed)
}

fn sink_poll_close(sink: &mut PollSender<Command>, cx: &mut Context<'_>) -> Poll<Result<()>> {
    // A driver that already hung up means the connection is down — closed, in
    // other words — so that is success here, not an error.
    if ready!(sink.poll_reserve(cx)).is_ok() {
        let _ = sink.send_item(Command::Close);
    }
    Poll::Ready(Ok(()))
}

impl futures_sink::Sink<Bytes> for SrtStream {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        sink_poll_ready(&mut self.sink, cx)
    }

    fn start_send(mut self: Pin<&mut Self>, payload: Bytes) -> Result<()> {
        sink_start_send(&mut self.sink, payload)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        sink_poll_close(&mut self.sink, cx)
    }
}

impl futures_sink::Sink<Bytes> for SrtSendHalf {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        sink_poll_ready(&mut self.sink, cx)
    }

    fn start_send(mut self: Pin<&mut Self>, payload: Bytes) -> Result<()> {
        sink_start_send(&mut self.sink, payload)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        sink_poll_close(&mut self.sink, cx)
    }
}
