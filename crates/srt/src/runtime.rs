//! Runtime abstraction so the I/O layer is not tied to a single async runtime.
//!
//! The [`Runtime`] trait provides the three effectful things the connection
//! driver needs — the current time, task spawning, sleeping until a deadline,
//! and binding a UDP socket — behind a swappable interface (the quinn design).
//! The default [`TokioRuntime`] implements it with Tokio timers and `quinn-udp`
//! for portable, ECN/GSO/GRO-capable UDP. Everything here is safe code; the
//! platform UDP specifics live inside `quinn-udp`.

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use socket2::{Domain, Protocol, Socket, Type as SocketType};
use tokio::io::Interest;

/// Kernel send/receive buffer size requested per UDP socket. Large enough to hold
/// a paced sender's burst plus jitter headroom; best-effort (the OS may clamp).
const SOCKET_BUFFER: usize = 4 * 1024 * 1024;

/// An async UDP socket the driver sends and receives datagrams on. Poll-based so
/// it is object-safe (`Arc<dyn AsyncUdpSocket>`).
pub trait AsyncUdpSocket: Send + Sync {
    /// Attempts to send `buf` as a single datagram to `dest`.
    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8], dest: SocketAddr)
    -> Poll<io::Result<()>>;

    /// Attempts to receive a single datagram into `buf`, returning its length and
    /// source address.
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>>;

    /// The socket's locally-bound address.
    ///
    /// # Errors
    ///
    /// Propagates the underlying socket error.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// How many equal-sized datagrams may be submitted in one Generic
    /// Segmentation Offload (GSO) send. `1` (the default) means no batching — one
    /// datagram per syscall. A socket that supports GSO overrides this.
    fn max_gso_segments(&self) -> usize {
        1
    }

    /// Sends `buf` as back-to-back `segment_size`-byte datagrams to `dest` in one
    /// GSO operation (the final datagram may be shorter). Only called when
    /// [`max_gso_segments`](AsyncUdpSocket::max_gso_segments) reports more than one
    /// segment; the default — which sends `buf` as a single datagram — therefore
    /// suffices for sockets without GSO.
    fn poll_send_gso(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        segment_size: usize,
        dest: SocketAddr,
    ) -> Poll<io::Result<()>> {
        let _ = segment_size;
        self.poll_send(cx, buf, dest)
    }

    /// Receives a datagram which, with Generic Receive Offload (GRO), may be
    /// several coalesced datagrams. Returns `(total_len, stride, source)`: `buf`
    /// holds `total_len` bytes as `stride`-sized datagrams (last possibly
    /// shorter). The default reports one datagram (`stride == total_len`), which
    /// is correct for sockets without GRO.
    fn poll_recv_gro(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, usize, SocketAddr)>> {
        match ready!(self.poll_recv(cx, buf)) {
            Ok((len, from)) => Poll::Ready(Ok((len, len, from))),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// The async runtime the I/O layer runs on (clock, tasks, timers, UDP).
pub trait Runtime: Send + Sync + 'static {
    /// The current instant from the runtime's clock.
    fn now(&self) -> Instant;

    /// Spawns a background task.
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>);

    /// A future that completes at `deadline`.
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    /// Binds a UDP socket to `addr`.
    ///
    /// # Errors
    ///
    /// Propagates any bind / socket-configuration error.
    fn bind(&self, addr: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>>;
}

/// The default runtime: Tokio timers/tasks and `quinn-udp` sockets.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep_until(deadline.into()))
    }

    fn bind(&self, addr: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let socket = Socket::new(domain, SocketType::DGRAM, Some(Protocol::UDP))?;
        // Generous kernel buffers absorb a paced sender's catch-up bursts and
        // ordinary scheduling jitter without dropping datagrams — SRT depends on
        // this headroom (libsrt likewise defaults its UDP buffers to ~1 MB+). The
        // request is best-effort: the OS may clamp it (e.g. `kern.ipc.maxsockbuf`).
        let _ = socket.set_recv_buffer_size(SOCKET_BUFFER);
        let _ = socket.set_send_buffer_size(SOCKET_BUFFER);
        socket.bind(&addr.into())?;
        socket.set_nonblocking(true)?;
        let std_socket: std::net::UdpSocket = socket.into();
        let state = UdpSocketState::new((&std_socket).into())?;
        let inner = tokio::net::UdpSocket::from_std(std_socket)?;
        Ok(Arc::new(TokioUdpSocket { inner, state }))
    }
}

/// A `quinn-udp`-backed UDP socket driven by Tokio readiness.
struct TokioUdpSocket {
    inner: tokio::net::UdpSocket,
    state: UdpSocketState,
}

impl fmt::Debug for TokioUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokioUdpSocket")
            .field("local_addr", &self.inner.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for TokioUdpSocket {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        dest: SocketAddr,
    ) -> Poll<io::Result<()>> {
        loop {
            ready!(self.inner.poll_send_ready(cx))?;
            let transmit = Transmit {
                destination: dest,
                ecn: None,
                contents: buf,
                segment_size: None,
                src_ip: None,
            };
            match self.inner.try_io(Interest::WRITABLE, || {
                self.state.send((&self.inner).into(), &transmit)
            }) {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        loop {
            ready!(self.inner.poll_recv_ready(cx))?;
            let result = self.inner.try_io(Interest::READABLE, || {
                let mut meta = [RecvMeta::default()];
                let mut iov = [IoSliceMut::new(buf)];
                self.state.recv((&self.inner).into(), &mut iov, &mut meta)?;
                Ok((meta[0].len, meta[0].addr))
            });
            match result {
                Ok(received) => return Poll::Ready(Ok(received)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_gso_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn poll_send_gso(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        segment_size: usize,
        dest: SocketAddr,
    ) -> Poll<io::Result<()>> {
        loop {
            ready!(self.inner.poll_send_ready(cx))?;
            let transmit = Transmit {
                destination: dest,
                ecn: None,
                contents: buf,
                // The kernel splits `contents` into `segment_size`-byte datagrams.
                segment_size: Some(segment_size),
                src_ip: None,
            };
            match self.inner.try_io(Interest::WRITABLE, || {
                self.state.send((&self.inner).into(), &transmit)
            }) {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn poll_recv_gro(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, usize, SocketAddr)>> {
        loop {
            ready!(self.inner.poll_recv_ready(cx))?;
            let result = self.inner.try_io(Interest::READABLE, || {
                let mut meta = [RecvMeta::default()];
                let mut iov = [IoSliceMut::new(buf)];
                self.state.recv((&self.inner).into(), &mut iov, &mut meta)?;
                // `stride` is the per-datagram size when GRO coalesced several;
                // it is the whole length for a single datagram.
                Ok((meta[0].len, meta[0].stride, meta[0].addr))
            });
            match result {
                Ok(received) => return Poll::Ready(Ok(received)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}
