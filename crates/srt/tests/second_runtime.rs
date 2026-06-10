//! Proves the [`Runtime`] / [`AsyncUdpSocket`] traits are a real seam, not
//! Tokio-shaped plumbing: the whole stack (handshake, ARQ, TSBPD) runs unchanged
//! on a `smol` executor with a socket backed by `smol::Async` instead of
//! `quinn-udp`. If the abstraction leaked Tokio assumptions, this would not build
//! or would deadlock.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use bytes::Bytes;
use smol::Executor;
use srt::{AsyncUdpSocket, Config, Runtime, SrtListener, connect_with};

/// A second [`Runtime`] backed by smol's executor, timers, and `async-io` reactor
/// — deliberately nothing in common with [`srt::TokioRuntime`].
struct SmolRuntime {
    ex: Arc<Executor<'static>>,
}

impl Runtime for SmolRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.ex.spawn(future).detach();
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            smol::Timer::at(deadline).await;
        })
    }

    fn bind(&self, addr: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let inner = smol::Async::new(socket)?;
        Ok(Arc::new(SmolUdpSocket { inner }))
    }
}

/// A UDP socket driven by smol's reactor instead of `quinn-udp` — plain
/// `send_to`/`recv_from`, which is all the trait demands.
struct SmolUdpSocket {
    inner: smol::Async<std::net::UdpSocket>,
}

impl AsyncUdpSocket for SmolUdpSocket {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        dest: SocketAddr,
    ) -> Poll<io::Result<()>> {
        loop {
            ready!(self.inner.poll_writable(cx))?;
            match self.inner.get_ref().send_to(buf, dest) {
                Ok(_) => return Poll::Ready(Ok(())),
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
            ready!(self.inner.poll_readable(cx))?;
            match self.inner.get_ref().recv_from(buf) {
                Ok(received) => return Poll::Ready(Ok(received)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.get_ref().local_addr()
    }
}

fn config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(120))
        .with_flow_window(8192)
}

#[test]
fn data_round_trips_on_the_smol_runtime() {
    let ex = Arc::new(Executor::new());
    // `ex.run` drives both the spawned driver tasks and the test future on this
    // one thread, so no background threads are needed.
    smol::block_on(ex.run(async {
        let runtime = Arc::new(SmolRuntime { ex: ex.clone() });

        let mut listener =
            SrtListener::bind_with(&runtime, "127.0.0.1:0".parse().unwrap(), config())
                .expect("bind on smol");
        let addr = listener.local_addr();

        let caller_runtime = runtime.clone();
        let caller = ex.spawn(async move {
            let stream = connect_with(
                &caller_runtime,
                "127.0.0.1:0".parse().unwrap(),
                addr,
                config(),
            )
            .await
            .expect("caller connects on smol");
            for i in 0..5u8 {
                stream
                    .send(Bytes::from(vec![i; 300]))
                    .await
                    .expect("send on smol");
            }
            stream
        });

        let mut server = with_timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("accept within 10s")
            .expect("accept ok");

        for i in 0..5u8 {
            let message = with_timeout(Duration::from_secs(10), server.recv())
                .await
                .expect("recv within 10s")
                .expect("a message");
            assert_eq!(&message[..], &vec![i; 300][..], "message {i} round-trips");
        }

        let _ = caller.await;
    }));
}

/// Awaits `fut`, or `None` if `dur` elapses first — smol has no built-in
/// `timeout`, so race the future against a `Timer` on the surrounding executor.
async fn with_timeout<T>(dur: Duration, fut: impl Future<Output = T>) -> Option<T> {
    let work = async move { Some(fut.await) };
    let timeout = async move {
        smol::Timer::after(dur).await;
        None
    };
    let mut work = pin!(work);
    let mut timeout = pin!(timeout);
    std::future::poll_fn(move |cx| {
        if let Poll::Ready(v) = work.as_mut().poll(cx) {
            return Poll::Ready(v);
        }
        timeout.as_mut().poll(cx)
    })
    .await
}
