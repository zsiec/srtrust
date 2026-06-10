#![doc = include_str!("../README.md")]

mod batch;
mod driver;
mod error;
mod runtime;
mod stream;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use driver::{Decision, Inbound, StreamChannels, drive_connection, drive_endpoint};
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;
use stream::StreamMeta;

pub use error::{Error, Result};
pub use runtime::{AsyncUdpSocket, Runtime, TokioRuntime};
pub use srt_protocol::connection::{CipherMode, Config, EncryptionSettings, KeySize};
pub use srt_protocol::error::{ConfigError, ConnectionError};
pub use srt_protocol::handshake::RejectReason;
pub use srt_protocol::stats::Stats;
pub use stream::{SrtRecvHalf, SrtSendHalf, SrtStream};

/// Connects to a remote SRT listener, returning a stream once the handshake (and
/// key exchange, if encrypted) completes.
///
/// `remote` is anything address-like (`"host:port"`, `("host", port)`, a
/// [`SocketAddr`], …), resolved asynchronously; the local end binds an
/// ephemeral port of the matching address family. Use
/// [`connect_from`] to control the local binding (multihomed hosts), or
/// [`connect_with`] to supply your own [`Runtime`].
///
/// # Errors
///
/// Returns [`Error::Config`] if `config` fails validation, [`Error::Io`] if
/// `remote` does not resolve or the socket cannot be bound, or
/// [`Error::Protocol`] if the handshake fails (timeout, or a rejection such as
/// a wrong passphrase).
pub async fn connect(remote: impl tokio::net::ToSocketAddrs, config: Config) -> Result<SrtStream> {
    let remote = tokio::net::lookup_host(remote)
        .await?
        .next()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "remote address resolved to nothing",
            ))
        })?;
    let local = match remote {
        SocketAddr::V4(_) => SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0),
        SocketAddr::V6(_) => SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    connect_from(local, remote, config).await
}

/// Like [`connect`], with an explicit local bind address (use a `:0` port for
/// an ephemeral one) — for multihomed hosts or fixed source ports.
///
/// # Errors
///
/// Same as [`connect`].
pub async fn connect_from(
    local: SocketAddr,
    remote: SocketAddr,
    config: Config,
) -> Result<SrtStream> {
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
    config.validate()?;
    let socket = runtime.bind(local)?;
    let meta = StreamMeta {
        local_addr: socket.local_addr()?,
        peer_addr: remote,
        stream_id: config.stream_id.clone(),
    };

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
        Ok(Ok(())) => {
            tracing::info!(local = %meta.local_addr, %remote, "connected");
            Ok(SrtStream::new(commands_tx, data_rx, meta))
        }
        Ok(Err(error)) => {
            tracing::warn!(%remote, %error, "connect failed");
            Err(error)
        }
        Err(_) => {
            tracing::warn!(%remote, "connect failed: driver stopped");
            Err(Error::Closed)
        }
    }
}

/// A listening SRT endpoint that accepts incoming connections.
///
/// A caller's handshake completes when this application answers its request —
/// via [`accept`](SrtListener::accept) (auto-accept), or
/// [`incoming`](SrtListener::incoming) followed by the [`ConnRequest`]'s
/// `accept`/`reject` (inspect the Stream ID first). Keep one of them running
/// while callers connect: an unanswered caller waits, retransmitting, until
/// its connect timeout.
///
/// Dropping the listener shuts its background driver down and releases the UDP
/// socket. Accepted connections share that socket and receive through the
/// listener's demux loop, so they end (with a clean end-of-stream) when the
/// listener drops — keep the listener alive for as long as its connections
/// matter.
#[derive(Debug)]
pub struct SrtListener {
    requests_rx: mpsc::Receiver<ConnRequest>,
    local_addr: SocketAddr,
    /// Held only so its drop resolves the driver's shutdown future.
    _shutdown: oneshot::Sender<()>,
}

/// A connection attempt awaiting this application's decision: who is calling
/// ([`remote_addr`](ConnRequest::remote_addr)) and what they asked for
/// ([`stream_id`](ConnRequest::stream_id), spec §3.2.1.3 — typically the
/// resource and credentials). Yielded by [`SrtListener::incoming`]; consume it
/// with [`accept`](ConnRequest::accept) or [`reject`](ConnRequest::reject).
///
/// While the request is pending the caller keeps retransmitting its handshake,
/// so the decision can take as long as the caller's `connect_timeout` allows.
/// Dropping the request undecided leaves the caller to time out.
#[derive(Debug)]
pub struct ConnRequest {
    pub(crate) stream_id: Option<String>,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) local_addr: SocketAddr,
    pub(crate) decisions: mpsc::Sender<Decision>,
}

impl ConnRequest {
    /// The Stream ID the caller advertised, if any (spec §3.2.1.3).
    #[must_use]
    pub fn stream_id(&self) -> Option<&str> {
        self.stream_id.as_deref()
    }

    /// The caller's remote address.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Accepts the connection, completing the handshake and returning the
    /// established stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the listener's driver has stopped, or
    /// [`Error::Protocol`] if the connection could no longer be accepted (the
    /// caller gave up and the pending handshake expired).
    pub async fn accept(self) -> Result<SrtStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.decisions
            .send(Decision::Accept {
                addr: self.remote_addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::Closed)?;
        let (commands, data) = reply_rx.await.map_err(|_| Error::Closed)??;
        Ok(SrtStream::new(
            commands,
            data,
            StreamMeta {
                local_addr: self.local_addr,
                peer_addr: self.remote_addr,
                stream_id: self.stream_id,
            },
        ))
    }

    /// Rejects the connection: the caller receives a `URQ_FAILURE` handshake
    /// carrying `reason` and fails its connect with
    /// [`ConnectionError::Rejected`]. Use [`RejectReason::Other`] with a code
    /// of 2000+ for application-defined reasons (libsrt's user range).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the listener's driver has stopped.
    pub async fn reject(self, reason: RejectReason) -> Result<()> {
        self.decisions
            .send(Decision::Reject {
                addr: self.remote_addr,
                reason,
            })
            .await
            .map_err(|_| Error::Closed)
    }
}

impl SrtListener {
    /// Binds a listener to `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `config` fails validation, or [`Error::Io`]
    /// if the socket cannot be bound.
    pub fn bind(addr: SocketAddr, config: Config) -> Result<SrtListener> {
        Self::bind_with(&Arc::new(TokioRuntime), addr, config)
    }

    /// Like [`bind`](SrtListener::bind), but driven on a caller-supplied
    /// [`Runtime`] instead of the default Tokio one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `config` fails validation, or [`Error::Io`]
    /// if the socket cannot be bound.
    pub fn bind_with<R: Runtime>(
        runtime: &Arc<R>,
        addr: SocketAddr,
        config: Config,
    ) -> Result<SrtListener> {
        config.validate()?;
        let socket = runtime.bind(addr)?;
        let local_addr = socket.local_addr()?;

        let mut listener = srt_protocol::listener::Listener::new(
            config,
            SocketId::new(random_u32()),
            SeqNumber::new(random_u32()),
            random_u64(),
            runtime.now(),
        );
        // Every conclusion surfaces as a ConnRequest; `accept()` is just the
        // auto-accepting convenience over `incoming()`.
        listener.defer_accepts();

        let (requests_tx, requests_rx) = mpsc::channel(driver::COMMAND_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let driver_runtime = runtime.clone();
        runtime.spawn(Box::pin(async move {
            drive_endpoint(
                driver_runtime,
                socket,
                listener,
                local_addr,
                requests_tx,
                shutdown_rx,
            )
            .await;
        }));

        tracing::info!(addr = %local_addr, "listening");
        Ok(SrtListener {
            requests_rx,
            local_addr,
            _shutdown: shutdown_tx,
        })
    }

    /// Waits for and returns the next connection request, for the application
    /// to inspect ([`ConnRequest::stream_id`], [`ConnRequest::remote_addr`])
    /// and then [`accept`](ConnRequest::accept) or
    /// [`reject`](ConnRequest::reject).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the listener's driver has stopped.
    pub async fn incoming(&mut self) -> Result<ConnRequest> {
        self.requests_rx.recv().await.ok_or(Error::Closed)
    }

    /// Waits for and returns the next accepted connection — the auto-accept
    /// convenience over [`incoming`](SrtListener::incoming).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the listener's driver has stopped.
    pub async fn accept(&mut self) -> Result<SrtStream> {
        self.incoming().await?.accept().await
    }

    /// The local address the listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
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
