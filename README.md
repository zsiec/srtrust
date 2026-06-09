# srtrust

A pure-Rust, memory-safe implementation of **SRT** (Secure Reliable Transport) —
the low-latency live-streaming protocol — built as a deterministic, sans-I/O core
with a thin async I/O layer on top.

[![CI](https://github.com/zsiec/srtrust/actions/workflows/ci.yml/badge.svg)](https://github.com/zsiec/srtrust/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](#minimum-supported-rust-version)

> **Status: early (`0.1.0`).** The protocol core is feature-complete for v1
> (live mode, caller/listener) and has been interop-validated against the
> reference C library **libsrt 1.5.5** in both directions, plaintext and
> encrypted. The API is not yet stable and may change before `1.0`.

## What is SRT?

[SRT](https://github.com/Haivision/srt) carries live video over lossy networks
(the public internet) at low, predictable latency. It recovers lost packets with
selective retransmission (ARQ) inside a fixed latency budget, drops packets that
can no longer arrive in time (TLPKTDROP), and optionally encrypts the stream
(AES-CTR / AES-GCM). This crate implements the IETF draft
[`draft-sharabayko-srt-01`](./docs/spec/draft-sharabayko-srt-01.txt).

## Why this implementation?

- **`#![forbid(unsafe_code)]`** in every crate — no `unsafe`, no C FFI. Even the
  cryptography is pure-Rust ([RustCrypto](https://github.com/RustCrypto)).
- **Sans-I/O core.** `srt-protocol` is a pure state machine: it never opens a
  socket, spawns a task, or reads the clock. Time enters as `now` arguments;
  every effect (a packet to send, a timer to set, data to deliver) leaves as a
  returned value. That makes the entire protocol a *deterministic function of its
  inputs* — handshake, retransmission, and timeout behaviour are all tested on a
  fake clock with seeded loss and reordering, no real sockets and no sleeps.
- **Swappable runtime.** The `srt` crate defaults to Tokio + `quinn-udp` (for
  portable GSO/GRO batching) but is generic over a `Runtime` trait.
- **Interop-validated** against libsrt 1.5.5, not just self-consistent.

## The two crates

| Crate | What it is | Use it when |
|-------|-----------|-------------|
| [`srt-protocol`](./crates/srt-protocol) | The sans-I/O state machine. No I/O, no async, no clock. | You own the event loop / sockets, or you're embedding SRT somewhere unusual. |
| [`srt`](./crates/srt) | Tokio + `quinn-udp` I/O layer with `async` handles (`SrtStream`, `SrtListener`). | You just want to send/receive an SRT stream. Start here. |

## Quickstart

Add the I/O crate:

```toml
[dependencies]
srt = "0.1"
tokio = { version = "1", features = ["full"] }
bytes = "1"
```

**Listener** (receiver):

```rust,no_run
use std::time::Duration;
use srt::{Config, SrtListener};

#[tokio::main]
async fn main() -> srt::Result<()> {
    let config = Config {
        latency: Duration::from_millis(120),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: None,   // Some(EncryptionSettings { .. }) to encrypt
        max_bw: 0,          // 0 = unpaced
        km_refresh_rate: 0, // 0 = default
        fec: None,
    };
    let mut listener = SrtListener::bind("0.0.0.0:9000".parse().unwrap(), config)?;
    let mut stream = listener.accept().await?;
    while let Some(payload) = stream.recv().await {
        println!("got {} bytes", payload.len());
    }
    Ok(())
}
```

**Caller** (sender):

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
        "0.0.0.0:0".parse().unwrap(),       // local bind (ephemeral port)
        "127.0.0.1:9000".parse().unwrap(),  // remote listener
        config,
    )
    .await?;
    stream.send(Bytes::from_static(b"hello, srt")).await?;
    stream.close().await?;
    Ok(())
}
```

A runnable end-to-end demo lives in [`crates/srt/examples/echo.rs`](./crates/srt/examples/echo.rs):

```console
cargo run --example echo
```

## Feature scope

**In v1:**

- Caller / Listener handshake (induction + conclusion, SYN cookie)
- Live mode ARQ: periodic + light ACK, immediate + periodic NAK, ACKACK, EXP backstop
- TSBPD timed delivery + TLPKTDROP + DROPREQ
- Clock drift tracing
- Encryption: AES-CTR and AES-GCM, KM exchange, key rotation (even/odd slots)
- LiveCC send pacing (`max_bw`)
- Message-mode framing (fragmentation + reassembly)
- Row FEC (forward error correction) on the wire
- Keepalive + idle/dead-peer timeout, reorder tolerance
- Statistics API

**Deferred (the core is designed to add these without rework):** rendezvous mode,
File/Buffer congestion control, column/staircase FEC layouts + FEC handshake
negotiation, packet groups / bonding.

## Minimum Supported Rust Version

**1.88** (edition 2024). MSRV bumps are not considered breaking changes.

## Development

```console
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The protocol behaviour tests run through a deterministic two-endpoint network
simulator (fake clock, seeded loss/jitter), so they're fast and reproducible.
There is also a gated interop test against the C `srt-live-transmit` binary.

## License

[MIT](./LICENSE).
