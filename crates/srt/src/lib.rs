#![doc = include_str!("../README.md")]

mod batch;
mod driver;
mod error;
mod runtime;

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use driver::{Command, Inbound, StreamChannels, drive_connection, drive_endpoint};
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

pub use error::{Error, Result};
pub use runtime::{AsyncUdpSocket, Runtime, TokioRuntime};
pub use srt_protocol::connection::{CipherMode, Config, EncryptionSettings, KeySize};
pub use srt_protocol::stats::Stats;

/// Connects to a remote SRT listener, returning a stream once the handshake (and
/// key exchange, if encrypted) completes.
///
/// `local` is the address to bind locally (use a `:0` port for ephemeral).
///
/// # Errors
///
/// Returns [`Error::Io`] if the socket cannot be bound, or [`Error::Protocol`] if
/// the handshake fails (timeout, or a passphrase the listener rejects).
pub async fn connect(local: SocketAddr, remote: SocketAddr, config: Config) -> Result<SrtStream> {
    connect_with(&Arc::new(TokioRuntime), local, remote, config).await
}

/// Like [`connect`], but driven on a caller-supplied [`Runtime`] instead of the
/// default Tokio one — the seam that keeps the I/O layer runtime-agnostic.
///
/// # Errors
///
/// Same as [`connect`].
pub async fn connect_with<R: Runtime>(
    runtime: &Arc<R>,
    local: SocketAddr,
    remote: SocketAddr,
    config: Config,
) -> Result<SrtStream> {
    let socket = runtime.bind(local)?;

    let conn = srt_protocol::connection::Connection::connect(
        config,
        SocketId::new(random_u32()),
        SeqNumber::new(random_u32()),
        runtime.now(),
        fill_random,
    );

    let (commands_tx, commands_rx) = mpsc::channel(driver::COMMAND_CAPACITY);
    let (data_tx, data_rx) = mpsc::channel(driver::DATA_CAPACITY);
    let (connected_tx, connected_rx) = oneshot::channel();
    let channels = StreamChannels {
        commands: commands_rx,
        data: data_tx,
        connected: Some(connected_tx),
    };

    let driver_runtime = runtime.clone();
    runtime.spawn(Box::pin(async move {
        drive_connection(
            driver_runtime,
            socket,
            conn,
            remote,
            channels,
            Inbound::Owned,
        )
        .await;
    }));

    match connected_rx.await {
        Ok(Ok(())) => Ok(SrtStream {
            commands: commands_tx,
            data: data_rx,
        }),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(Error::Closed),
    }
}

/// A listening SRT endpoint that accepts incoming connections.
///
/// Dropping the listener shuts its background driver down and releases the UDP
/// socket. Connections already accepted (and their `SrtStream`s) are
/// independent and keep running.
#[derive(Debug)]
pub struct SrtListener {
    accept_rx: mpsc::Receiver<driver::Accepted>,
    local_addr: SocketAddr,
    /// Held only so its drop resolves the driver's shutdown future.
    _shutdown: oneshot::Sender<()>,
}

impl SrtListener {
    /// Binds a listener to `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket cannot be bound.
    pub fn bind(addr: SocketAddr, config: Config) -> Result<SrtListener> {
        Self::bind_with(&Arc::new(TokioRuntime), addr, config)
    }

    /// Like [`bind`](SrtListener::bind), but driven on a caller-supplied
    /// [`Runtime`] instead of the default Tokio one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket cannot be bound.
    pub fn bind_with<R: Runtime>(
        runtime: &Arc<R>,
        addr: SocketAddr,
        config: Config,
    ) -> Result<SrtListener> {
        let socket = runtime.bind(addr)?;
        let local_addr = socket.local_addr()?;

        let listener = srt_protocol::listener::Listener::new(
            config,
            SocketId::new(random_u32()),
            SeqNumber::new(random_u32()),
            random_u64(),
            runtime.now(),
        );

        let (accept_tx, accept_rx) = mpsc::channel(driver::COMMAND_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let driver_runtime = runtime.clone();
        runtime.spawn(Box::pin(async move {
            drive_endpoint(driver_runtime, socket, listener, accept_tx, shutdown_rx).await;
        }));

        Ok(SrtListener {
            accept_rx,
            local_addr,
            _shutdown: shutdown_tx,
        })
    }

    /// Waits for and returns the next accepted connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the listener's driver has stopped.
    pub async fn accept(&mut self) -> Result<SrtStream> {
        let (commands, data) = self.accept_rx.recv().await.ok_or(Error::Closed)?;
        Ok(SrtStream { commands, data })
    }

    /// The local address the listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// An established SRT connection: a reliable, in-order, message-oriented stream.
#[derive(Debug)]
pub struct SrtStream {
    commands: mpsc::Sender<Command>,
    data: mpsc::Receiver<Bytes>,
}

impl SrtStream {
    /// Sends one application message reliably.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the connection has ended.
    pub async fn send(&self, payload: Bytes) -> Result<()> {
        self.commands
            .send(Command::Send(payload))
            .await
            .map_err(|_| Error::Closed)
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
        self.commands
            .send(Command::Close)
            .await
            .map_err(|_| Error::Closed)
    }

    /// A snapshot of this connection's cumulative [`Stats`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the connection has ended.
    pub async fn stats(&self) -> Result<Stats> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Stats(reply))
            .await
            .map_err(|_| Error::Closed)?;
        response.await.map_err(|_| Error::Closed)
    }
}

/// Fills `buf` with cryptographically-secure random bytes (the embedder-injected
/// randomness the core requires for keys; see `srt_protocol`).
fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("the OS random source is available");
}

/// A random `u32` for socket ids and initial sequence numbers.
fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    fill_random(&mut bytes);
    u32::from_ne_bytes(bytes)
}

/// A random `u64` for the listener's SYN-cookie secret.
fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes);
    u64::from_ne_bytes(bytes)
}
