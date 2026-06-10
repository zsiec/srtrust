# srt-protocol

The sans-I/O core of [srtrust](https://github.com/zsiec/srtrust): a pure,
deterministic state machine implementing **SRT** (Secure Reliable Transport) with
**no I/O, no async, and no clock access**.

It never opens a socket, spawns a task, or reads the clock. Time enters through
explicit `now` arguments; every effect — a datagram to send, a timer to arm, data
to deliver — leaves as a returned value drained from two queues. That makes the
whole protocol a *deterministic function of its inputs*, which is what lets the
handshake, retransmission, and timeout logic be tested exhaustively on a fake
clock with seeded loss and reordering.

Most users want the [`srt`](https://crates.io/crates/srt) crate, which wires this
core onto real UDP sockets with Tokio. Reach for `srt-protocol` directly when you
own the event loop, need a different runtime, or are embedding SRT somewhere
unusual.

> **Status: early (`0.1.0`).** Interop-validated against libsrt 1.5.5. The API is
> not yet stable.

## The interaction model

You feed the machine typed inputs (`feed_recv_buf`, `handle_timer`, `send`,
`connect`) and drain its two output queues: `poll_event()` for application-facing
events (data delivered, connection state) and `poll_output()` for wire/timer
effects you must perform.

```rust,no_run
use std::time::Instant;
use srt_protocol::connection::{Config, Connection, Output};
use srt_protocol::packet::SocketId;
use srt_protocol::seq::SeqNumber;

// Config::default() is deployment-ready; refine it with the with_* builders.
let config = Config::default();

// `Instant::now()` lives in *your* code — never inside the core.
let mut conn = Connection::connect(
    config,
    SocketId::new(1),
    SeqNumber::new(100),
    Instant::now(),
    |buf| buf.fill(0), // the embedder injects randomness; the core stays deterministic
);

// Perform the effects the core requested:
while let Some(out) = conn.poll_output() {
    match out {
        Output::SendDatagram(_datagram) => { /* send these bytes on your UDP socket */ }
        Output::SetTimer { id, after } => { /* arm timer `id` to fire after `after` */ }
        Output::ClearTimer { id } => { /* cancel timer `id` */ }
        _ => {}
    }
}
```

When a timer you armed fires, call `conn.handle_timer(id, now)`; when a datagram
arrives, call `conn.feed_recv_buf(bytes, now)`; then drain the queues again.

## License

[MIT](../../LICENSE).
