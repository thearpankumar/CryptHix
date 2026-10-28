//! The storage backend trait and its types.

#[expect(
    clippy::module_inception,
    reason = "files are named after their main item"
)]
mod backend;
mod backend_error;
mod byte_range;
mod capabilities;
mod delete_outcome;
mod list_entry;
mod object_meta;
mod put_mode;
mod put_outcome;
mod read_mode;

pub use backend::Backend;
pub use backend_error::BackendError;
pub use byte_range::ByteRange;
pub use capabilities::Capabilities;
pub use delete_outcome::DeleteOutcome;
pub use list_entry::ListEntry;
pub use object_meta::ObjectMeta;
pub use put_mode::PutMode;
pub use put_outcome::PutOutcome;
pub use read_mode::ReadMode;
