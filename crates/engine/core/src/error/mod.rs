//! The errors of the write and read paths.

mod read_error;
mod write_error;

pub use read_error::ReadError;
pub use write_error::WriteError;
