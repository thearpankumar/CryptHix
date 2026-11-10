//! zstd per chunk (FS-53): one frame at level 3 with its content size, no checksum, no
//! dictionary ID and a window of at most 1 MiB, kept only if it saves at least 1/16 of the
//! chunk; never for objects of the secret class (T-40).
//!
//! zstd's working memory is on the C heap, outside protected memory (R-26): it is not wiped when
//! a context is freed, not locked, so it can be swapped out, and not `MADV_DONTFORK`, so a forked
//! child gets a copy. It holds pieces of chunk plaintext: the compression context keeps literals
//! and match-finder tables, and the decompression context keeps decoded literals (its
//! `litExtraBuffer`) and any output it buffers. zstd-safe offers no way to give it a caller's
//! buffer without `unsafe`, which this crate does not use; the encrypt pipeline item plans a
//! `ZSTD_customMem` allocator backed by `secure_mem` in `crypthix-crypto`, which may use
//! `unsafe`. Contexts are reused, so until then it is a bounded residual like the cipher state
//! inside `crypthix-crypto`.

mod compress_error;
mod compressor;
mod decompressor;
mod frame_check;
mod keep_compressed;

pub use compress_error::CompressError;
pub use compressor::Compressor;
pub use decompressor::Decompressor;
pub use keep_compressed::keep_compressed;
