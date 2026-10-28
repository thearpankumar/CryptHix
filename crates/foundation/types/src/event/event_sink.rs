//! The event sink trait.

use crate::event::Event;

/// Receives engine events.
///
/// `emit` must not block or fail: an implementation queues the event (for example on the bus)
/// and returns. If its queue is full it keeps the newest events, counts the dropped ones and
/// reports the count as soon as there is room, so security events are never lost silently.
/// Engine crates take a `&dyn EventSink` and never know who listens.
pub trait EventSink: Send + Sync {
    /// Reports an event.
    fn emit(&self, event: &Event);
}
