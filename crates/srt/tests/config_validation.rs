//! `connect`/`bind` reject an invalid [`Config`] up front, with a reason —
//! instead of letting a peer-enforced limit (a too-short passphrase, say)
//! surface later as a silent handshake timeout.

use srt::{Config, Error, SrtListener, connect};

#[tokio::test]
async fn connect_rejects_invalid_config() {
    let config = Config::default().with_passphrase("short"); // 5 < 10-byte minimum
    let err = connect("127.0.0.1:9", config)
        .await
        .expect_err("5-byte passphrase must be rejected");
    assert!(
        matches!(err, Error::Config(_)),
        "expected Error::Config, got {err:?}"
    );
}

#[tokio::test]
async fn bind_rejects_invalid_config() {
    let config = Config::default().with_mtu(20); // below the 76-byte header floor
    let err = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config)
        .expect_err("20-byte mtu must be rejected");
    assert!(
        matches!(err, Error::Config(_)),
        "expected Error::Config, got {err:?}"
    );
}
