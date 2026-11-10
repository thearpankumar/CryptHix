//! Content-defined chunking: FastCDC 2020 with a secret per-vault gear table (FS-52).
//!
//! The cut rule is the one of the `fastcdc` crate's `v2020` module, version 5.0.0 (normalised
//! chunking level 2): the loop starts at the minimum size and takes two bytes per step, adding
//! `gear_ls[b] = gear[b] << 1` for the first byte of each pair (after doubling the hash twice)
//! and `gear[b]` for the second, and tests the matching shifted or plain mask after each. It
//! uses the strict mask below the average size and the loose one up to the maximum, and cuts at
//! the maximum when nothing matched. A chunk ends just before the byte whose hash matched. An
//! odd last byte of the scanned range is never tested as a cut point. Input no longer than the
//! minimum is one chunk; empty input has none.
//!
//! [`Chunks`] cuts data already in memory; [`StreamChunker`] cuts a reader through a window of
//! protected memory and gives the same chunks.

mod chunk_params;
mod chunk_ref;
mod chunks;
mod cut;
mod gear_table;
mod masks;
mod object_shape;
mod stream_chunker;
mod stream_error;

pub(crate) use chunk_params::ChunkParams;
pub use chunk_ref::ChunkRef;
pub use chunks::Chunks;
pub use gear_table::GearTable;
pub use masks::{MASK_L, MASK_S};
pub(crate) use object_shape::ChunkCount;
pub use object_shape::ObjectShape;
pub use stream_chunker::StreamChunker;
pub use stream_error::StreamError;
