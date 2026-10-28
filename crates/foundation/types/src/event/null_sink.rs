//! An event sink that drops every event.

use crate::event::{Event, EventSink};

/// An [`EventSink`] that drops every event, for tests and tools that do not listen.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _event: &Event) {}
}
