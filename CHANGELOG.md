# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

First public release. The protocol core is feature-complete for v1 (live mode,
caller/listener) and interop-validated against the reference C library
**libsrt 1.5.5** in both directions, plaintext and encrypted.

### Added

- **`srt-protocol`** — sans-I/O SRT state machine (no sockets, no async, no clock):
  - Caller/Listener handshake: induction + conclusion, SYN cookie.
  - Live-mode ARQ: periodic + light ACK, immediate + periodic NAK, ACKACK, EXP
    retransmission backstop.
  - TSBPD timed delivery, TLPKTDROP, and DROPREQ.
  - Clock-drift tracing.
  - Encryption: AES-CTR and AES-GCM, Key Material exchange, and key rotation
    (even/odd slots) with embedder-injected randomness.
  - LiveCC send pacing (`max_bw`).
  - Message-mode framing: fragmentation and reassembly.
  - Row forward error correction (FEC) on the wire, libsrt-compatible.
  - Keepalive, idle/dead-peer timeout, and reorder tolerance.
  - Statistics API.
- **`srt`** — Tokio + `quinn-udp` I/O layer with async `SrtStream` / `SrtListener`
  handles, GSO/GRO batching, and a swappable `Runtime` trait.

### Notes

- The public API is **not yet stable** and may change before `1.0`.
- Deferred to a later release: rendezvous mode, File/Buffer congestion control,
  column/staircase FEC layouts and FEC handshake negotiation, packet groups /
  bonding.

[Unreleased]: https://github.com/zsiec/srtrust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zsiec/srtrust/releases/tag/v0.1.0
