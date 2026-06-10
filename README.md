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
use srt::{Config, SrtListener};

#[tokio::main]
async fn main() -> srt::Result<()> {
    // Config::default() is deployment-ready (120 ms latency, 1500 MTU,
    // unpaced); refine it with the with_* builders, e.g.
    // .with_passphrase("...") to encrypt or .with_latency(...) to retune.
    let config = Config::default();
    let mut listener = SrtListener::bind("0.0.0.0:9000".parse().unwrap(), config)?;
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

**Caller** (sender):

```rust,no_run
use bytes::Bytes;
use srt::{connect, Config};

#[tokio::main]
async fn main() -> srt::Result<()> {
    let config = Config::default();
    // Anything address-like works; the local end binds an ephemeral port
    // (use `connect_from` to control the local binding).
    let stream = connect("127.0.0.1:9000", config).await?;
    stream.send(Bytes::from_static(b"hello, srt")).await?;
    stream.close().await?;
    Ok(())
}
```

Good to know, up front:

- **A caller's handshake completes when the listener app accepts it** — keep an
  `accept()`/`incoming()` loop running while callers connect (every server
  looks like the loop above).
- **Vetting callers:** `listener.incoming()` yields a `ConnRequest` exposing
  the caller's Stream ID and address, with `accept().await` /
  `reject(reason)` — the rejection reaches the caller as a real SRT rejection
  code instead of a timeout.
- **Invalid config fails fast:** a 5-character passphrase or 20-byte MTU is
  rejected at `connect`/`bind` with a `ConfigError` saying why.

The [`srt` crate README](./crates/srt/README.md) has copy-paste recipes for
encryption, caller vetting, task-splitting (`into_split`), `futures`
Stream/Sink adapters, stats, and `tracing`.

### Runnable examples

| Example | What it shows |
|---|---|
| `cargo run --example echo` | Minimal end-to-end send/receive in one process |
| `cargo run --example restream` | A live ingest-and-fan-out relay (listener → many clients) |
| `cargo run --example srt_bench -- loopback` | Throughput measurement (also sender/receiver modes) |
| `cargo run --example interop_listener -- 9000` | Interop endpoint for testing against libsrt tools |

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
- Statistics API (RTT, rates, buffer levels, ACK/NAK counters) + `tracing` instrumentation

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
