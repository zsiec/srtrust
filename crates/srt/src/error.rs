//! Error type for the `srt` I/O layer.

use srt_protocol::error::{ConfigError, ConnectionError};

/// A failure from the `srt` I/O layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An underlying socket / runtime I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The supplied [`Config`](crate::Config) failed validation — caught at
    /// `connect`/`bind`, before any packet leaves.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// The connection failed at the protocol level (e.g. handshake timeout, wrong
    /// passphrase).
    #[error(transparent)]
    Protocol(#[from] ConnectionError),

    /// The connection's driver task ended before the operation completed.
    #[error("connection closed")]
    Closed,
}

/// A convenience result alias for the `srt` I/O layer.
pub type Result<T> = std::result::Result<T, Error>;
