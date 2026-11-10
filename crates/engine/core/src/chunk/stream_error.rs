//! Why a stream could not be cut.

use std::error::Error;
use std::fmt;
use std::io;

use crypthix_crypto::secure_mem::MemError;

/// A [`StreamChunker`](crate::chunk::StreamChunker) failed: no protected memory for its
/// window, the reader failed, or it is used again after a failure.
#[non_exhaustive]
#[must_use]
#[derive(Debug)]
pub enum StreamError {
    /// The reader failed with an error other than [`io::ErrorKind::Interrupted`], which is
    /// retried.
    Io(io::Error),
    /// No protected memory for the window.
    Memory(MemError),
    /// An earlier call failed, and its error was returned then. The chunker is fused on error,
    /// so the rest of an input it could not read is never taken for its end.
    Failed,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StreamError::Io(_) => "the input could not be read",
            StreamError::Memory(_) => "no protected memory for the chunking window",
            StreamError::Failed => "the chunker already failed and cuts nothing more",
        })
    }
}

impl Error for StreamError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            StreamError::Io(error) => Some(error),
            StreamError::Memory(error) => Some(error),
            StreamError::Failed => None,
        }
    }
}

impl From<io::Error> for StreamError {
    fn from(error: io::Error) -> Self {
        StreamError::Io(error)
    }
}

impl From<MemError> for StreamError {
    fn from(error: MemError) -> Self {
        StreamError::Memory(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_the_kind_and_source_is_the_cause() {
        let io = StreamError::from(io::Error::other("disk"));
        assert_eq!(io.to_string(), "the input could not be read");
        assert_eq!(
            io.source().map(ToString::to_string),
            Some("disk".to_owned())
        );
        let memory = StreamError::from(MemError::MapFailed);
        assert_ne!(memory.to_string(), io.to_string());
        assert_eq!(
            memory.source().map(ToString::to_string),
            Some(MemError::MapFailed.to_string())
        );
        let failed = StreamError::Failed;
        assert!(failed.source().is_none());
        assert_ne!(failed.to_string(), io.to_string());
        assert_ne!(failed.to_string(), memory.to_string());
    }
}
