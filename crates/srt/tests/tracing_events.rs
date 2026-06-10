//! The `srt` crate emits `tracing` events for connection lifecycle: listening,
//! connection requests, accept/reject decisions, established connections, and
//! failures. One test function (a global subscriber can be installed only once
//! per process) drives a connect+accept and a reject and asserts the events.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use srt::{Config, RejectReason, SrtListener, connect};
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;

/// Captures every event as one line: `<target> <message> <field>=<value>…`.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

impl Capture {
    fn lines(&self) -> Vec<String> {
        self.0.lock().expect("not poisoned").clone()
    }

    fn assert_event(&self, needles: &[&str]) {
        let lines = self.lines();
        assert!(
            lines
                .iter()
                .any(|line| needles.iter().all(|needle| line.contains(needle))),
            "no event containing all of {needles:?}; events:\n{}",
            lines.join("\n")
        );
    }
}

struct FieldWriter<'a>(&'a mut String);

impl Visit for FieldWriter<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {}={:?}", field.name(), value);
    }
}

impl<S: tracing::Subscriber> Layer<S> for Capture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut line = event.metadata().target().to_string();
        event.record(&mut FieldWriter(&mut line));
        self.0.lock().expect("not poisoned").push(line);
    }
}

fn config() -> Config {
    Config::default().with_latency(Duration::from_millis(50))
}

#[tokio::test]
async fn lifecycle_events_are_traced() {
    let capture = Capture::default();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(capture.clone()))
        .expect("first and only global subscriber");

    let mut listener = SrtListener::bind("127.0.0.1:0".parse().unwrap(), config()).unwrap();
    let addr = listener.local_addr();
    capture.assert_event(&["srt", "listening"]);

    // Accepted connection: request surfaced, accepted, caller connected.
    let caller = tokio::spawn(connect(addr, config().with_stream_id("live/cam1")));
    let request = listener.incoming().await.expect("incoming");
    capture.assert_event(&["srt", "connection request", "live/cam1"]);
    let _server = request.accept().await.expect("accept");
    let stream = caller.await.expect("join").expect("connect");
    capture.assert_event(&["srt", "accepted"]);
    capture.assert_event(&["srt", "connected"]);
    drop(stream);

    // Rejected connection: the decision is traced with its reason.
    let caller = tokio::spawn(connect(addr, config().with_stream_id("intruder")));
    let request = listener.incoming().await.expect("incoming");
    request
        .reject(RejectReason::Other(2403))
        .await
        .expect("reject");
    caller
        .await
        .expect("join")
        .expect_err("the rejected caller must not connect");
    capture.assert_event(&["srt", "rejected", "2403"]);
    capture.assert_event(&["srt", "connect failed"]);
}
