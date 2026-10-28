//! Response action errors.

use std::error::Error;
use std::fmt;

/// Why a response action failed.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ActionError {
    /// The implementation cannot apply this action to this scope.
    Unsupported,
    /// The process has exited or its PID was reused.
    ProcessGone,
    /// The action failed.
    Failed,
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ActionError::Unsupported => "action not supported for this scope",
            ActionError::ProcessGone => "process no longer exists",
            ActionError::Failed => "action failed",
        })
    }
}

impl Error for ActionError {}
