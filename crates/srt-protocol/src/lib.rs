#![doc = include_str!("../README.md")]

pub mod connection;
pub mod error;
pub mod listener;
pub mod packet;
pub mod seq;
pub mod stats;

// Wire-codec modules exposed only so the integration tests can hand-craft and
// inspect packets (and, for `loss_list`, because it appears in a `control` type).
// They are not part of the supported public API — hidden from the rendered docs
// and carry no stability guarantee.
#[doc(hidden)]
pub mod control;
#[doc(hidden)]
pub mod handshake;
#[doc(hidden)]
pub mod loss_list;
#[doc(hidden)]
pub mod timestamp;

// Internal protocol machinery — no public surface.
mod crypto;
mod drift;
pub(crate) mod fec;
mod live_cc;
mod rate;
mod recv_buffer;
mod rtt;
mod send_buffer;
