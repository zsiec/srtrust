# srt

The Tokio + [`quinn-udp`](https://crates.io/crates/quinn-udp) I/O layer for the
sans-I/O [`srt-protocol`](https://crates.io/crates/srt-protocol) core — a
pure-Rust, memory-safe implementation of **SRT** (Secure Reliable Transport).

This is the user-facing crate: it binds UDP sockets, owns the timer wheels, reads
the clock, and drives the protocol state machine in a background task, exposing
`async` handles. It relates to `srt-protocol` the way [`quinn`](https://crates.io/crates/quinn)
relates to `quinn-proto`. The runtime is swappable behind a `Runtime` trait;
Tokio is the default.

> **Status: early (`0.1.0`).** Interop-validated against libsrt 1.5.5. The API is
> not yet stable.

## Example

```rust,no_run
use std::time::Duration;
use bytes::Bytes;
use srt::{connect, Config};

#[tokio::main]
async fn main() -> srt::Result<()> {
    let config = Config {
        latency: Duration::from_millis(120),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: None,
        max_bw: 0,
        km_refresh_rate: 0,
        fec: None,
    };
    let stream = connect(
        "0.0.0.0:0".parse().unwrap(),
        "127.0.0.1:9000".parse().unwrap(),
        config,
    )
    .await?;
    stream.send(Bytes::from_static(b"hello, srt")).await?;
    stream.close().await?;
    Ok(())
}
```

The listener side mirrors this with [`SrtListener::bind`] and
[`SrtListener::accept`]. See [`crates/srt/examples/echo.rs`](./examples/echo.rs)
for a runnable end-to-end demo (`cargo run --example echo`).

## License

[MIT](../../LICENSE).
