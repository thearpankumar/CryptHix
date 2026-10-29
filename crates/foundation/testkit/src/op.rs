//! Backend calls as recorded by [`FaultBackend`](crate::FaultBackend).

use crypthix_types::store_key::{StoreKey, StorePrefix};

/// Which backend method was called.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OpKind {
    /// [`Backend::get`](crypthix_types::backend::Backend::get).
    Get,
    /// [`Backend::stat`](crypthix_types::backend::Backend::stat).
    Stat,
    /// [`Backend::put`](crypthix_types::backend::Backend::put).
    Put,
    /// [`Backend::list`](crypthix_types::backend::Backend::list).
    List(StorePrefix),
    /// [`Backend::delete`](crypthix_types::backend::Backend::delete).
    Delete,
}

/// One recorded backend call. `capabilities` is not an operation and is not recorded.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Op {
    /// The method.
    pub kind: OpKind,
    /// The file it touched; `None` for a listing.
    pub key: Option<StoreKey>,
}
