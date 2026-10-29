//! The CryptHix test-vector generator (format spec section 20).
//!
//! It writes every `crypthix/v0/tv-*.json` file byte for byte, builds the input bytes by hand
//! rather than through `crypthix-types`, so the vectors stay independent of the decoder they
//! test, and lists every vector input as a fuzz seed. The sets so far use no randomness; the
//! seeded stream of FS-94 comes with `crypthix-crypto`.

mod check;
mod json;
mod pre;
mod seed;
mod test_case;
mod tv02;
mod tv03;
mod tv17;
mod vector_set;

pub use check::{Mismatch, Problem, check};
pub use json::Json;
pub use seed::{Seed, SeedTarget, seeds};
pub use vector_set::{VectorSet, sets};
