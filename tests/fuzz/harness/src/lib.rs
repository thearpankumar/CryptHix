//! Fuzz target bodies for the `crypthix-types` parsers and the `crypthix-crypto` entry points
//! that read stored bytes (M-29, T-39), and the independent minicbor oracle the CBOR
//! differential target compares against.
//!
//! Each target is a plain function of the input bytes that panics when a property fails. The
//! cargo-fuzz binaries in `tests/fuzz/fuzz_targets` only call these, and `tests/replay.rs` runs
//! them on every vector input and saved regression on stable Rust.

mod cbor_differential;
mod cbor_document;
mod cbor_model;
mod cbor_structured;
mod config_toml;
mod cx_open;
mod id_text;
mod oracle;
mod preamble;
mod store_key;
mod targets;
mod verifying_key;

pub use cbor_differential::{SMALL, cbor_differential};
pub use cbor_document::cbor_document;
pub use cbor_model::CborModel;
pub use cbor_structured::cbor_structured;
pub use config_toml::config_toml;
pub use cx_open::cx_open;
pub use id_text::id_text;
pub use oracle::{OracleLimits, accepts};
pub use preamble::preamble;
pub use store_key::store_key;
pub use targets::{TARGETS, Target};
pub use verifying_key::verifying_key;
