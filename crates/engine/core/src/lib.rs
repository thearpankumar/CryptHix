//! Write and read pipeline: chunk, compress, pad, encrypt, hash and sign.
//!
//! This crate holds the first stage of the data path, in the fixed order of FS-51: chunk →
//! compress → pad → encrypt. Packs, shards, manifests and the trees come later.
//!
//! - [`chunk`]: FastCDC 2020 with a secret per-vault gear table, 64 KiB / 256 KiB / 1 MiB, for
//!   ordinary objects, and fixed 1 MiB chunks for secret-class objects (FS-52), over memory
//!   ([`Chunks`](chunk::Chunks)) or a reader ([`StreamChunker`](chunk::StreamChunker));
//! - [`compress`]: one zstd frame per chunk, kept only if it saves 1/16, never for the secret
//!   class, and checked strictly before it is decoded (FS-53);
//! - [`pad`] and [`inner`]: the inner plaintext `comp ‖ rsv ‖ payload_len ‖ payload`, padded
//!   with Padmé (FS-54);
//! - [`blob`]: data blobs sealed under `K_chunk` with keyed or random blob IDs (FS-55, FS-56)
//!   and meta blobs sealed under their epoch's key (FS-57).
//!
//! Plaintext, compressed chunks and inner plaintexts live only in fixed-size
//! [`SecretBuf`](crypthix_crypto::secure_mem::SecretBuf)s, wiped on free; a `Vec` holds only
//! ciphertext. On Linux a `SecretBuf` is also locked where `RLIMIT_MEMLOCK` allows and kept out
//! of core dumps; elsewhere, and under Miri, it is plain heap memory
//! ([`secure_mem`](crypthix_crypto::secure_mem)). Two residuals remain: zstd's working memory is on the C heap, not wiped,
//! locked or kept from forked children (see [`compress`], R-26), and the gear table, kept in a
//! `SecretBuf` rather than secret pages, is assumed to leak, since keyed chunkers have been
//! attacked from observed chunk sizes; Padmé only coarsens those sizes and packs hide them
//! (T-84).
//!
//! Errors are [`WriteError`](error::WriteError) and [`ReadError`](error::ReadError). A blob
//! that does not match what refers to it is always a
//! [`FormatError`](crypthix_types::format_error::FormatError), the first failing check of
//! FS-93; running out of memory, a zstd failure of its own and a libzstd other than the pinned
//! version are reported apart, so they never look like tampering.
//!
//! ```
//! use crypthix_core::blob::{ChunkKeys, ObjectClass, ObjectOpener, ObjectSealer};
//! use crypthix_core::blob::BlobContext;
//! use crypthix_core::chunk::{Chunks, GearTable};
//! use crypthix_core::compress::{Compressor, Decompressor};
//! use crypthix_crypto::key::KdfKey;
//! use crypthix_crypto::random;
//! use crypthix_types::id::{DekId, ObjectId, VaultId};
//!
//! let vault_id = VaultId::try_from_bytes(random::bytes()?)?;
//! let gear = GearTable::derive(&KdfKey::random()?, &vault_id)?;
//! let context = BlobContext::new(
//!     vault_id,
//!     ObjectId::try_from_bytes(random::bytes()?)?,
//!     DekId::try_from_bytes(random::bytes()?)?,
//! );
//! let keys = ChunkKeys::derive(&KdfKey::random()?, &random::bytes()?, context)?;
//!
//! let file = b"some file contents ".repeat(20_000);
//! let chunks = Chunks::new(&gear, ObjectClass::Ordinary, &file);
//! // The writer takes the object's shape from the chunker and seals the chunks it cut, in
//! // order; `finish` gives the chunk count for the manifest, from which the reader takes it.
//! let mut sealer = ObjectSealer::new(&keys, chunks.object_shape());
//! let mut compressor = Compressor::new()?;
//! let mut written = Vec::new();
//! for chunk in chunks.chunk_refs() {
//!     written.push((chunk.bytes(), sealer.seal(&mut compressor, chunk)?));
//! }
//! let chunk_count = sealer.finish()?;
//! let opener = ObjectOpener::new(&keys, ObjectClass::Ordinary, chunk_count);
//! let mut decompressor = Decompressor::new();
//! for (chunk, sealed) in written {
//!     let opened = opener.open(&mut decompressor, sealed.entry(), sealed.sealed())?;
//!     assert_eq!(opened.as_slice(), chunk);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod blob;
pub mod chunk;
pub mod compress;
pub mod error;
#[cfg(test)]
mod fault;
pub mod inner;
pub mod limits;
pub mod pad;
#[cfg(test)]
mod test_data;
