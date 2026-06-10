//! Drives the whole stack through the GSO/GRO code paths even on a platform
//! without kernel offload, by injecting an in-memory [`Runtime`] whose sockets
//! *simulate* GSO (a batched send arrives as one coalesced buffer) and GRO (the
//! receiver reports a per-datagram `stride` for the driver to split). If the
//! driver's batching or splitting were wrong, the round trip would corrupt or
//! drop data.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use srt::{AsyncUdpSocket, Config, Runtime, SrtListener, connect_with};
use tokio::sync::mpsc;

/// A datagram in flight on the in-memory network. `stride` is the per-segment size
/// (equal to `data.len()` for an un-batched send), so the receiver can report GRO.
struct InPkt {
    from: SocketAddr,
    data: Vec<u8>,
    stride: usize,
}

/// The shared in-memory "network": an address → inbox map plus a port allocator.
#[derive(Default)]
struct Net {
    inboxes: Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<InPkt>>>,
    next_port: AtomicU64,
    /// How many sends went out as multi-segment GSO batches (test observability).
    gso_batches: AtomicU64,
}

struct MockRuntime {
    net: Arc<Net>,
}

impl Runtime for MockRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep_until(deadline.into()))
    }
    fn bind(&self, _addr: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let port = 50_000 + self.net.next_port.fetch_add(1, Ordering::Relaxed);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        self.net.inboxes.lock().unwrap().insert(addr, tx);
        Ok(Arc::new(MockSocket {
            addr,
            net: self.net.clone(),
            rx: Mutex::new(rx),
        }))
    }
}

/// A socket on the in-memory net that reports GSO/GRO support so the driver
/// exercises its batched send and coalesced receive paths.
struct MockSocket {
    addr: SocketAddr,
    net: Arc<Net>,
    rx: Mutex<mpsc::UnboundedReceiver<InPkt>>,
}

impl MockSocket {
    fn deliver(&self, dest: SocketAddr, data: Vec<u8>, stride: usize) {
        if let Some(tx) = self.net.inboxes.lock().unwrap().get(&dest) {
            let _ = tx.send(InPkt {
                from: self.addr,
                data,
                stride,
            });
        }
    }
}

impl AsyncUdpSocket for MockSocket {
    fn poll_send(&self, _: &mut Context<'_>, buf: &[u8], dest: SocketAddr) -> Poll<io::Result<()>> {
        self.deliver(dest, buf.to_vec(), buf.len());
        Poll::Ready(Ok(()))
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        match self.poll_recv_gro(cx, buf) {
            Poll::Ready(Ok((len, _stride, from))) => Poll::Ready(Ok((len, from))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }

    fn max_gso_segments(&self) -> usize {
        4
    }

    fn poll_send_gso(
        &self,
        _: &mut Context<'_>,
        buf: &[u8],
        segment_size: usize,
        dest: SocketAddr,
    ) -> Poll<io::Result<()>> {
        self.net.gso_batches.fetch_add(1, Ordering::Relaxed);
        // The batch travels as one coalesced buffer; the receiver splits by stride.
        self.deliver(dest, buf.to_vec(), segment_size);
        Poll::Ready(Ok(()))
    }

    fn poll_recv_gro(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, usize, SocketAddr)>> {
        let mut rx = self.rx.lock().unwrap();
        match rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => {
                let len = pkt.data.len().min(buf.len());
                buf[..len].copy_from_slice(&pkt.data[..len]);
                Poll::Ready(Ok((len, pkt.stride, pkt.from)))
            }
            // Pending, or all senders dropped (won't happen mid-test; the net
            // holds them) — either way, nothing to deliver right now.
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }
}

fn config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(120))
        .with_flow_window(8192)
}

#[tokio::test]
async fn data_round_trips_through_gso_and_gro() {
    let net = Arc::new(Net::default());
    let runtime = Arc::new(MockRuntime { net: net.clone() });

    let mut listener =
        SrtListener::bind_with(&runtime, "127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let laddr = listener.local_addr();

    let caller_runtime = runtime.clone();
    let caller = tokio::spawn(async move {
        let stream = connect_with(
            &caller_runtime,
            "127.0.0.1:0".parse().unwrap(),
            laddr,
            config(),
        )
        .await
        .expect("connect via mock");
        // Equal-sized messages so consecutive data packets form GSO-able runs.
        for i in 0..40u8 {
            stream
                .send(Bytes::from(vec![i; 800]))
                .await
                .expect("send via mock");
        }
        stream
    });

    let mut server = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("accept within 10s")
        .expect("accept ok");

    for i in 0..40u8 {
        let message = tokio::time::timeout(Duration::from_secs(10), server.recv())
            .await
            .expect("recv within 10s")
            .expect("a message");
        assert_eq!(
            &message[..],
            &vec![i; 800][..],
            "message {i} round-trips intact through GSO/GRO"
        );
    }

    let _ = caller.await;
    // The bursts of equal-sized packets should have driven the batched-send path
    // at least once (otherwise this test would not be exercising GSO at all).
    assert!(
        net.gso_batches.load(Ordering::Relaxed) > 0,
        "the GSO batch path was exercised"
    );
}
