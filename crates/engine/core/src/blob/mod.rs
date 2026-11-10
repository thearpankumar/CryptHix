//! Data blobs and meta blobs (format spec 10.4).
//!
//! A data blob is one chunk's inner plaintext sealed under `K_chunk` with an AAD that binds it
//! to its vault, object, DEK and blob ID (FS-55). Its blob ID is keyed per object for ordinary
//! objects of two or more chunks, so an unchanged chunk is reused by the next version of the
//! same object and nothing is shared across objects (T-85); otherwise it is random. A meta blob
//! is a CBOR tree node sealed under its epoch's key for its kind, with a random blob ID (FS-57).
//!
//! Keys are bound to what they were derived for: [`ChunkKeys`] to its object's
//! [`BlobContext`], used through an [`ObjectSealer`] or [`ObjectOpener`] built once per object
//! with its class and chunk count, and a [`MetaKey`] to its [`MetaContext`].

mod blob_context;
mod blob_id_kind;
mod chunk_entry;
mod chunk_keys;
mod data_blob_aad;
mod meta_blob_aad;
mod meta_context;
mod meta_key;
mod meta_kind;
mod object_class;
mod object_opener;
mod object_sealer;
mod open_meta_blob;
mod opened_chunk;
mod seal_meta_blob;
mod sealed_chunk;
mod sealed_meta;

pub use blob_context::BlobContext;
pub use blob_id_kind::BlobIdKind;
pub use chunk_entry::ChunkEntry;
pub use chunk_keys::ChunkKeys;
pub use data_blob_aad::{DATA_BLOB_KIND, data_blob_aad};
pub use meta_blob_aad::meta_blob_aad;
pub use meta_context::MetaContext;
pub use meta_key::MetaKey;
pub use meta_kind::MetaKind;
pub use object_class::ObjectClass;
pub use object_opener::ObjectOpener;
pub use object_sealer::ObjectSealer;
pub use open_meta_blob::open_meta_blob;
pub use opened_chunk::OpenedChunk;
pub use seal_meta_blob::seal_meta_blob;
pub use sealed_chunk::SealedChunk;
pub use sealed_meta::SealedMeta;
