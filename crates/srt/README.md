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

## Five-minute tour

One side listens, the other calls. `Config::default()` is deployment-ready
(120 ms latency, 1500-byte MTU, unpaced); refine it with the `with_*` builders.

**Receiver** (listener):

```rust,no_run
use srt::{Config, SrtListener};

#[tokio::main]
async fn main() -> srt::Result<()> {
    let mut listener = SrtListener::bind("0.0.0.0:9000".parse().unwrap(), Config::default())?;
    loop {
        let mut stream = listener.accept().await?;
        tokio::spawn(async move {
            while let Some(payload) = stream.recv().await {
                println!("{} bytes from {}", payload.len(), stream.peer_addr());
            }
        });
    }
}
```

**Sender** (caller):

```rust,no_run
use bytes::Bytes;
use srt::{connect, Config};

#[tokio::main]
async fn main() -> srt::Result<()> {
    // Anything address-like resolves; the local end binds an ephemeral port
    // (`connect_from` if you need to control the local binding).
    let stream = connect("127.0.0.1:9000", Config::default()).await?;
    stream.send(Bytes::from_static(b"hello, srt")).await?;
    stream.close().await?; // orderly close: lingers until delivered
    Ok(())
}
```

A caller's handshake completes into the listener's backlog with no
application involvement (libsrt-compatible); `accept()` hands the established
streams over. To vet callers *before* the handshake completes, bind with
`SrtListener::bind_deferred` and consume `incoming()` instead — there, a
handshake finishes only when the application accepts it.

## Recipes

**Encrypt** — both sides set the same passphrase (10–79 characters, enforced
at `connect`/`bind`); the handshake refuses mismatches with a clear error:

```rust,no_run
# use srt::Config;
let config = Config::default().with_passphrase("correct horse battery");
```

**Vet callers before accepting** — a `bind_deferred` listener surfaces each
caller from `incoming()` with the Stream ID it advertised (the "which
resource, which credentials" field), and lets you reject with a real SRT
rejection code the caller can read:

```rust,no_run
# async fn vet() -> srt::Result<()> {
use srt::{Config, RejectReason, SrtListener};

let mut listener = SrtListener::bind_deferred("0.0.0.0:9000".parse().unwrap(), Config::default())?;

let request = listener.incoming().await?;
# // (loop over incoming() in a real server)
match request.stream_id() {
    Some(id) if id.starts_with("live/") => {
        let stream = request.accept().await?;
        // ... serve it
        # drop(stream);
    }
    _ => request.reject(RejectReason::Other(2403)).await?, // app-defined code
}
# Ok(())
# }
```

The caller sees that as `Error::Protocol(ConnectionError::Rejected(..))` —
immediately, instead of a connect timeout.

**Send and receive on different tasks** — split the stream; dropping the
receive half just stops reading, dropping the send half closes the connection:

```rust,no_run
# async fn split(stream: srt::SrtStream) {
let (tx, mut rx) = stream.into_split();
tokio::spawn(async move {
    while let Some(payload) = rx.recv().await { /* consume */ }
});
tx.send(bytes::Bytes::from_static(b"hi")).await.ok();
# }
```

`SrtStream`/`SrtRecvHalf` also implement `futures::Stream`, and
`SrtStream`/`SrtSendHalf` implement `futures::Sink<Bytes>`, so combinator-based
pipelines work directly.

**Watch a connection** — `stream.stats().await?` snapshots cumulative counters
and gauges (RTT, delivery rates, retransmissions, drops, ACK/NAK counts,
send-buffer depth, the *negotiated* latency). The crate also emits
[`tracing`](https://crates.io/crates/tracing) events for connection lifecycle
(`listening`, `connection request`, `accepted`, `rejected`, `connected`,
failures) — install any `tracing-subscriber` to see them.

**Tune** — the common knobs, all on `Config`:

```rust,no_run
# use std::time::Duration;
# use srt::Config;
let config = Config::default()
    .with_latency(Duration::from_millis(200)) // TSBPD budget: higher = more loss recovery headroom
    .with_stream_id("live/cam1")              // advertised to the listener
    .with_max_bw(12_500_000)                  // pace at 100 Mbps (bytes/sec; 0 = unpaced)
    .with_connect_timeout(Duration::from_secs(1));
```

Invalid values (a 5-character passphrase, a 20-byte MTU) fail at
`connect`/`bind` with a `ConfigError` saying why — not as a silent timeout.

## Runnable examples

| Example | What it shows |
|---|---|
| `cargo run --example echo` | Minimal end-to-end send/receive in one process |
| `cargo run --example restream` | A live ingest-and-fan-out relay (listener → many clients) |
| `cargo run --example srt_bench -- loopback` | Throughput measurement (also sender/receiver modes) |
| `cargo run --example interop_listener -- 9000` | Interop endpoint for testing against libsrt tools |

## License

[MIT](../../LICENSE).
