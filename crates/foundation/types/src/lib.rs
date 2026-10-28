//! IDs, errors, config, versioned formats and cross-crate traits.
//!
//! This is the lowest crate of the workspace. It depends on no other CryptHix crate and on no
//! cryptography crate, so its types can be shared by everything above it. The byte-level rules
//! it implements are in `docs/format-spec.md`; code cites them as `FS-nn`.
//!
//! Key-bearing traits such as `KeyProvider` live in `crypthix-crypto` (backlog rule 11).

pub mod backend;
pub mod cbor;
pub mod config;
pub mod event;
pub mod format_error;
pub mod id;
pub mod preamble;
pub mod registry;
pub mod response;
pub mod store_key;
