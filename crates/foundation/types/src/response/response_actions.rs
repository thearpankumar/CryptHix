//! The response actions trait.

use std::num::NonZeroU32;

use crate::response::{ActionError, ActionScope};

/// Actions the guard takes against an attack, implemented by the filesystem layer.
///
/// The guard sits below the filesystem in the layer order, so it calls these through the trait
/// (backlog rule 2). Every action is idempotent: the guard may repeat one, and freezing a frozen
/// scope succeeds. A later throttle on the same scope replaces the earlier one. If an action on
/// a process tree fails, the guard fails closed and applies it to the whole vault (M-30).
pub trait ResponseActions: Send + Sync {
    /// Stops writes in `scope` while reads continue.
    ///
    /// # Errors
    ///
    /// An [`ActionError`] if the action could not be applied.
    fn freeze(&self, scope: ActionScope) -> Result<(), ActionError>;

    /// Limits `scope` to `operations_per_second` file operations, reads and writes alike.
    ///
    /// # Errors
    ///
    /// An [`ActionError`] if the action could not be applied.
    fn throttle(
        &self,
        scope: ActionScope,
        operations_per_second: NonZeroU32,
    ) -> Result<(), ActionError>;

    /// Lifts both a freeze and a throttle on `scope`. Called only after a protected admin
    /// action (A14).
    ///
    /// # Errors
    ///
    /// An [`ActionError`] if the action could not be applied.
    fn unfreeze(&self, scope: ActionScope) -> Result<(), ActionError>;
}
