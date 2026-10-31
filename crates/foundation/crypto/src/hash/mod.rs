//! `H(label, x)`, the domain-separated BLAKE3-256 hash of format spec section 7.1.

mod hash32;
mod hasher;

pub use hash32::Hash32;
pub use hasher::{Hasher, hash};
