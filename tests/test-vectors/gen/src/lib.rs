//! The CryptHix test-vector generator (format spec section 20).
//!
//! It writes every `crypthix/v0/tv-*.json` file byte for byte, builds the input bytes by hand
//! rather than through `crypthix-types`, so the vectors stay independent of the decoder they
//! test, and lists every vector input as a fuzz seed. TV-04 and TV-05 draw their inputs from the
//! seeded `test-rng` stream of `crypthix-crypto` (FS-94) and compute their outputs with this
//! crate's own reading of format spec section 7 ([`cx`]), never with `crypthix-crypto`'s
//! primitives, so the two implementations check each other.

mod check;
mod cx;
mod json;
mod labels;
mod pre;
mod seed;
mod test_case;
mod tv02;
mod tv03;
mod tv04;
mod tv05;
mod tv17;
mod vector_set;

pub use check::{Mismatch, Problem, check};
pub use json::Json;
pub use seed::{Seed, SeedTarget, seeds};
pub use vector_set::{VectorSet, sets};
