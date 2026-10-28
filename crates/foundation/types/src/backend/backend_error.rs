//! Backend errors.

use std::error::Error;
use std::fmt;
use std::io;

/// A failure of a backend operation.
///
/// It never carries a path or file name, so it is safe to log.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BackendError {
    /// The file does not exist.
    NotFound,
    /// The backend does not support the operation or mode.
    Unsupported,
    /// The credentials do not allow the operation, for example put-only credentials asked to
    /// delete (M-42).
    PermissionDenied,
    /// The backend cannot be reached or did not answer in time.
    Unavailable,
    /// The backend asked the caller to slow down.
    RateLimited,
    /// A concurrent conditional write conflicted; the operation may be retried.
    Conflict,
    /// The store is full or over its quota.
    QuotaExceeded,
    /// The backend answered with something that breaks the protocol, such as more bytes than
    /// were asked for.
    InvalidResponse,
    /// A store name resolved to something other than a regular file, such as a symlink.
    NotRegularFile,
    /// Another local I/O error.
    Io(io::ErrorKind),
}

impl BackendError {
    /// Whether retrying the same operation later may succeed.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            BackendError::Unavailable | BackendError::RateLimited | BackendError::Conflict
        )
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::NotFound => f.write_str("file not found in the store"),
            BackendError::Unsupported => f.write_str("operation not supported by the backend"),
            BackendError::PermissionDenied => f.write_str("backend refused the operation"),
            BackendError::Unavailable => f.write_str("backend unavailable"),
            BackendError::RateLimited => f.write_str("backend rate limit reached"),
            BackendError::Conflict => f.write_str("conflicting concurrent write"),
            BackendError::QuotaExceeded => f.write_str("store full or over quota"),
            BackendError::InvalidResponse => f.write_str("invalid response from the backend"),
            BackendError::NotRegularFile => f.write_str("store entry is not a regular file"),
            BackendError::Io(kind) => write!(f, "store I/O error: {kind}"),
        }
    }
}

impl Error for BackendError {}

impl From<io::Error> for BackendError {
    /// Keeps only the error kind; the message of an [`io::Error`] may contain a path.
    ///
    /// `AlreadyExists` becomes [`BackendError::Io`]: an implementation of
    /// [`PutMode::IfAbsent`](crate::backend::PutMode::IfAbsent) must map the failure of its
    /// no-replace link to [`PutOutcome::AlreadyExists`](crate::backend::PutOutcome) itself,
    /// before any `?`.
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => BackendError::NotFound,
            io::ErrorKind::PermissionDenied => BackendError::PermissionDenied,
            io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => {
                BackendError::QuotaExceeded
            }
            io::ErrorKind::TimedOut => BackendError::Unavailable,
            kind => BackendError::Io(kind),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_keep_only_their_kind() {
        let error = io::Error::new(io::ErrorKind::NotFound, "/var/lib/crypthix/secret-name");
        let backend = BackendError::from(error);
        assert_eq!(backend, BackendError::NotFound);
        assert!(
            !backend.to_string().contains("secret-name"),
            "paths must not reach logs"
        );
        let error = io::Error::from(io::ErrorKind::AlreadyExists);
        assert_eq!(
            BackendError::from(error),
            BackendError::Io(io::ErrorKind::AlreadyExists)
        );
    }

    #[test]
    fn transient_errors() {
        assert!(BackendError::RateLimited.is_transient(), "rate limits pass");
        assert!(
            !BackendError::PermissionDenied.is_transient(),
            "permissions do not"
        );
    }
}
