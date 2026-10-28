//! Where a response action applies.

use crate::id::VaultId;
use crate::response::ProcessRef;

/// The target of a response action.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ActionScope {
    /// A process and all its descendants.
    ProcessTree(ProcessRef),
    /// The whole vault.
    Vault(VaultId),
}
