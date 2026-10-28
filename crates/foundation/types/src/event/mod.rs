//! Engine events and the sink they go to.

#[expect(
    clippy::module_inception,
    reason = "files are named after their main item"
)]
mod event;
mod event_sink;
mod null_sink;

pub use event::Event;
pub use event_sink::EventSink;
pub use null_sink::NullSink;
