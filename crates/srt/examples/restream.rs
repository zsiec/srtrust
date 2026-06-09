//! A live SRT **restreamer** built on this crate: receive one SRT stream (e.g.
//! MPEG-TS from ffmpeg) on an *input* listener and fan it out to every client
//! connected to an *output* listener (e.g. VLC). This is the canonical "ingest and
//! redistribute" shape for low-latency live video.
//!
//! ```text
//!   ffmpeg  ──SRT(caller)──►  :5000 input ─┐
//!                                          │  broadcast fan-out
//!                            :6000 output ─┴──SRT──►  VLC, ffprobe, …  (callers)
//! ```
//!
//! Run it:
//!
//! ```console
//! cargo run --example restream                 # ports 5000 (in) and 6000 (out)
//! cargo run --example restream -- 5000 6000     # explicit ports
//! ```
//!
//! Feed it (ffmpeg built with libsrt):
//!
//! ```console
//! ffmpeg -re -f lavfi -i testsrc=size=640x360:rate=25 -f lavfi -i sine \
//!        -c:v libx264 -preset ultrafast -tune zerolatency -c:a aac \
//!        -f mpegts "srt://127.0.0.1:5000"
//! ```
//!
//! Watch it:
//!
//! ```console
//! vlc "srt://127.0.0.1:6000"            # or: ffplay "srt://127.0.0.1:6000"
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use srt::{Config, SrtListener, SrtStream};
use tokio::sync::broadcast;

/// A live-mode configuration with a 120 ms latency budget — typical for SRT
/// contribution. Both listeners use the same shape.
fn live_config() -> Config {
    Config {
        latency: Duration::from_millis(120),
        mtu: 1500,
        flow_window: 8192,
        stream_id: None,
        encryption: None,
        max_bw: 0,
        km_refresh_rate: 0,
        fec: None,
    }
}

#[tokio::main]
async fn main() -> srt::Result<()> {
    let mut args = std::env::args().skip(1);
    let in_port: u16 = args.next().and_then(|s| s.parse().ok()).unwrap_or(5000);
    let out_port: u16 = args.next().and_then(|s| s.parse().ok()).unwrap_or(6000);
    let in_addr: SocketAddr = ([0, 0, 0, 0], in_port).into();
    let out_addr: SocketAddr = ([0, 0, 0, 0], out_port).into();

    // The fan-out bus: the ingest task publishes each received payload; every
    // output client subscribes. A lagging subscriber (a stalled player) drops old
    // packets rather than back-pressuring the live source — the right trade for
    // live video. Sized for a couple of seconds of headroom at typical bitrates.
    let (bus, _) = broadcast::channel::<bytes::Bytes>(4096);

    let input = SrtListener::bind(in_addr, live_config())?;
    let output = SrtListener::bind(out_addr, live_config())?;
    println!("restream: ingest  srt://0.0.0.0:{in_port}  (point ffmpeg here)");
    println!("restream: egress  srt://0.0.0.0:{out_port}  (point VLC here)");

    // Accept output clients (VLC, ffprobe, …) and serve each from its own
    // subscription, concurrently with ingest.
    let egress = tokio::spawn(serve_clients(output, bus.clone()));

    // Ingest: accept the source and republish everything it sends, re-accepting if
    // the source disconnects and reconnects.
    let ingest = tokio::spawn(ingest_loop(input, bus));

    // If either task ends (listener closed), tear down.
    tokio::select! {
        r = egress => r.expect("egress task")?,
        r = ingest => r.expect("ingest task")?,
    }
    Ok(())
}

/// Accepts the upstream source and forwards every payload onto the bus. Loops so a
/// source can disconnect and reconnect without restarting the relay.
async fn ingest_loop(
    mut input: SrtListener,
    bus: broadcast::Sender<bytes::Bytes>,
) -> srt::Result<()> {
    loop {
        let mut source = input.accept().await?;
        println!("restream: source connected");
        let mut packets: u64 = 0;
        let mut bytes_in: u64 = 0;
        while let Some(payload) = source.recv().await {
            packets += 1;
            bytes_in += payload.len() as u64;
            if packets.is_multiple_of(1000) {
                println!(
                    "restream: ingested {packets} packets ({} KiB)",
                    bytes_in / 1024
                );
            }
            // `send` errors only if there are no subscribers; that's fine — we just
            // drop until a player connects.
            let _ = bus.send(payload);
        }
        println!("restream: source disconnected after {packets} packets; awaiting a new source");
    }
}

/// Accepts output clients forever; each runs in its own task fed by a fresh
/// subscription to the bus.
async fn serve_clients(
    mut output: SrtListener,
    bus: broadcast::Sender<bytes::Bytes>,
) -> srt::Result<()> {
    loop {
        let client = output.accept().await?;
        let rx = bus.subscribe();
        println!("restream: player connected");
        tokio::spawn(async move {
            if let Err(e) = pump_to_client(client, rx).await {
                println!("restream: player disconnected ({e})");
            } else {
                println!("restream: player disconnected");
            }
        });
    }
}

/// Streams the bus to one connected client until it disconnects or falls
/// unrecoverably behind.
async fn pump_to_client(
    client: SrtStream,
    mut rx: broadcast::Receiver<bytes::Bytes>,
) -> srt::Result<()> {
    loop {
        match rx.recv().await {
            Ok(payload) => client.send(payload).await?,
            // The player stalled and we lapped the ring buffer: skip ahead to live
            // (MPEG-TS re-syncs on the next PAT/PMT) rather than fall further behind.
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                println!("restream: player lagging, skipped {skipped} packets");
            }
            // The ingest side closed the bus.
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}
