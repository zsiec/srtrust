//! BUG-05b (docs/known-issues/05): dropping an `SrtListener` must shut its
//! endpoint driver down. The driver used to terminate only on a socket error or
//! when handing a *new* connection to a dropped handle — an idle listener
//! (parked on the socket with no incoming handshakes) leaked its task, its UDP
//! socket, and its demux state for the lifetime of the runtime.

use std::time::Duration;

use srt::{Config, SrtListener};

fn config() -> Config {
    Config::default()
        .with_latency(Duration::from_millis(50))
        .with_flow_window(8192)
}

#[tokio::test]
async fn dropping_an_idle_listener_releases_its_socket() {
    let listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();
    drop(listener);

    // The driver task notices the drop and exits, releasing the UDP socket —
    // after which the port can be bound again (nothing here sets SO_REUSEADDR,
    // so a successful re-bind proves the old socket is gone).
    let mut rebound = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if std::net::UdpSocket::bind(addr).is_ok() {
            rebound = true;
            break;
        }
    }
    assert!(
        rebound,
        "the listener's socket must be released after the handle is dropped"
    );
}
