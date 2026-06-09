# srtrust — project conventions

Pure-Rust, max-safety, strictly-TDD implementation of **SRT** (Secure Reliable
Transport). The author is new to Rust but an experienced Go dev (prior SRT impl
at `~/dev/srtgo`). Explain non-obvious Rust idioms as you introduce them.

## Spec is the source of truth

- The protocol spec is **IETF draft-sharabayko-srt-01** (2021-09-07), saved at
  `docs/spec/draft-sharabayko-srt-01.txt`. Cite section numbers in code comments
  (e.g. `// header layout: spec §3.1`). The Go impl and the two Rust references
  (russelltg/srt-rs, shiguredo/srt-rs) are **cross-checks, not authority** — when
  they disagree with the spec, the spec wins (note the deviation in a comment).
- Known spec gaps to verify against libsrt before hardcoding: RTT EWMA fractions
  (§4.10; libsrt uses smoothed 7/8, var 3/4) and the StreamID key table (App. B).

## Architecture (non-negotiable)

- **Sans-I/O core.** Crate `srt-protocol` is a pure, deterministic state machine.
  It never opens a socket, spawns a task, or reads the clock. Time enters via
  explicit `now` arguments; **never** call `Instant::now()` / `SystemTime::now()`
  inside the core — one stray call breaks test determinism.
- **Effects leave as returned values**, drained by the caller:
  - typed input methods (`feed_recv_buf(bytes, now)`, `handle_timer(id, now)`,
    `send(payload, now)`, `connect(now)`), and
  - two drained output queues — `poll_event() -> Option<Event>` (app-facing) and
    `poll_output() -> Option<Output>` where `Output` is `SendPacket`,
    `SetTimer{id, after}`, or `ClearTimer{id}`. Declarative timers: the core
    requests timers; the I/O layer owns the timer wheel. (shiguredo-style.)
- **I/O layer** is a separate crate `srt` (user-facing, like `quinn`): Tokio
  default runtime + `quinn-udp` for portable GSO/GRO/batching/ECN, behind a
  `Runtime` trait so the runtime is swappable. Built after the core can connect.
- **Scope v1:** live mode, caller/listener only. Defer rendezvous, FileCC, FEC,
  groups/bonding (all exist in srtgo; add later without reworking the core).
- Randomness (encryption keys) is **injected by the embedder**, not generated in
  the core — keeps it deterministic. Core emits `KeyRefreshNeeded`; caller supplies.

## Safety & lints

- `#![forbid(unsafe_code)]` in every crate. No FFI excuse in a Sans-I/O core.
- Crypto = **pure-Rust RustCrypto** (`aes`, `ctr`, `pbkdf2`, `aes-kw` for RFC-3394
  key wrap). **Not** `aws-lc-rs`/`openssl` (they pull in C, break forbid-unsafe).
- Workspace lints (in root `Cargo.toml`): clippy `pedantic` = warn; `unsafe_code`
  = forbid; `missing_debug_implementations`, `unreachable_pub` = warn. Use
  `#![warn(unreachable_pub)]` discipline — write `pub(crate)`/`pub(super)`
  deliberately; only `lib.rs` re-exports the public surface.
- Every change must pass `cargo test` AND `cargo clippy --all-targets -- -D warnings`
  AND `cargo fmt --check` before it's considered done.

## Type & API idioms (Rust API Guidelines)

- **Newtype every wire value** with a private field so the invariant lives in one
  place: `SeqNumber(u32)`, `SocketId(u32)`, `Timestamp(u32)`. A `SeqNumber` and a
  `SocketId` must not be interchangeable even though both are `u32` on the wire.
- **Parse, don't validate.** Fallible smart constructors (`Foo::new -> Result`)
  produce values that are *proof* of validity; downstream code never re-checks.
  Wire-extraction constructors that mask bits (e.g. 31-bit seq) are infallible.
- **Never `derive(Ord/PartialOrd)` on circular values** (sequence numbers,
  timestamps): their order is not total. Provide explicit `circular_cmp`.
- **Errors:** `thiserror` enums, layered by abstraction (codec → packet →
  handshake → connection), `#[from]`/`#[source]` to chain causes,
  `#[non_exhaustive]` on every public error enum. `Display` lowercase, no trailing
  punctuation. Libraries return `Result` for expected/peer-caused failures
  (malformed bytes, short buffers, protocol violations) — **never panic** for
  those. Panics only for our own broken invariants the types can't encode, and
  then via `expect("why this cannot fail")`, never bare `unwrap()`.
- **Derive eagerly** (orphan rule means downstream can't add later): `Debug` on
  all public types; `Clone, Copy, PartialEq, Eq, Hash` on small wire newtypes;
  `Default` only where a true zero exists (and then also provide `new()`).
- **Conversions:** `as_*` free/borrowing, `to_*` allocates, `into_*` consumes.
  No `get_` prefix on getters (`seq.value()`). Implement `From`/`TryFrom`; never
  hand-impl `Into`. `TryFrom<&[u8]>` for fallible wire decode.
- `#[must_use]` on error types, decode results, and `-> Self` builders. Accept
  borrowed/generic in (`&[u8]`, `impl AsRef`), return owned (`Vec<u8>`/`Bytes`).
- **Wire codec** uses the `bytes` crate (`Buf`/`BufMut`) with a small `Codec`
  trait (`decode<B: Buf> -> Result<Self, _>`, `encode<B: BufMut>`); bounds-check
  `buf.remaining()` before every read. (quinn-proto `coding.rs` pattern.)
- **State machine** = one struct with a `state: State` enum field (data-carrying
  variants), sub-concerns as their own modules/fields that own their state but no
  I/O. **Timer multiplexing:** keep N logical timers, expose the earliest
  deadline. (quinn-proto `connection/timer.rs` pattern.)
- Modern idioms: `let ... else` for early bail, if-let chains, `matches!`,
  `const fn` wherever possible, iterator combinators over manual loops,
  `-> impl Iterator` to hide concrete iterator types. Avoid needless `clone()`.
- Keep files focused — don't let `mod.rs` balloon to thousands of lines (a
  quinn-proto pain point); split `Event`/`Error`/`State` into their own files.

## TDD workflow (strict)

1. **Red:** write the failing test first (unit test in `#[cfg(test)] mod tests`,
   or `tests/` for public-API/integration). Stub impls with `todo!()` (bare, not
   `todo!("msg")`, inside `const fn`). Run `cargo test` and watch it fail.
2. **Green:** minimal implementation to pass. Run `cargo test`.
3. **Refactor:** clean up; run `cargo clippy --all-targets -- -D warnings` and
   `cargo fmt`. Tests stay green.
- **proptest is mandatory for every codec:** round-trip (`decode(encode(x)) == x`
  and byte-stable re-encode) and the no-panic invariant (arbitrary `&[u8]` into
  `decode` returns `Err`, never panics — fuzz-lite, pairs with forbid-unsafe).
- Build a **deterministic two-endpoint network simulator** on a fake clock early
  (quinn-proto `tests/util.rs::Pair` pattern: advance time to the next event,
  inject latency/loss/reorder with a seeded RNG). Protocol behavior (handshake,
  NAK/retransmit, timeouts) is tested through it — no real sockets, no sleeps.

## Build order

seq numbers → timestamp → packet header/data/control codec → send/recv buffers →
network simulator → handshake (induction/conclusion + SYN cookie) → ARQ
(ACK/NAK/ACKACK/RTO retransmit) → TSBPD + TLPKTDROP → drift → encryption (KM,
AES-CTR, PBKDF2, key refresh) → LiveCC pacing → `srt` I/O crate (tokio+quinn-udp).

## Commands

- Toolchain: rustup stable, edition 2024. `cargo` via `~/.cargo/bin` (source
  `$HOME/.cargo/env` in fresh shells).
- `cargo test -p srt-protocol` — run core tests.
- `cargo clippy --all-targets -- -D warnings` — lint gate.
- `cargo fmt` / `cargo fmt --check` — format.
