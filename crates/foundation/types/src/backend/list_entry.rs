//! Entries reported while listing a store.

use crate::backend::ObjectMeta;
use crate::store_key::StoreKey;

/// One name found while listing a store.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ListEntry {
    /// A canonical store name and its metadata.
    File {
        /// The name.
        key: StoreKey,
        /// Its metadata.
        meta: ObjectMeta,
    },
    /// A name of a known shape that is not canonical (`NameMismatch`, FS-92), such as
    /// uppercase hex under `shards/`. Never written by CryptHix, so it may be planted; the
    /// caller counts and reports it. The name itself is not passed on, so it cannot reach logs.
    NonCanonical,
}
