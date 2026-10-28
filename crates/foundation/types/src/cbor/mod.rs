//! Deterministic CBOR (format spec section 5.2).
//!
//! [`Document::parse`] runs one structural pass that enforces every rule of FS-08 to FS-11 that
//! does not depend on a schema. It checks items in byte order, so the first item that breaks a
//! rule decides the error (FS-93); schema readers run only on documents that passed.
//! [`Decoder`] and [`MapReader`] then give typed reads over the checked bytes, and [`Encoder`]
//! writes only the deterministic encoding.
//!
//! No CBOR crate is used: none checks canonical form on decode.

mod decoder;
mod document;
mod encoder;
mod head;
mod limits;
mod map_reader;
mod map_writer;
mod raw_item;
mod unknown_entries;
mod validate;

pub use decoder::{ArrayIter, Decoder, ItemKind};
pub use document::Document;
pub use encoder::Encoder;
pub use limits::Limits;
pub use map_reader::MapReader;
pub use map_writer::MapWriter;
pub use raw_item::{OwnedRawItem, RawItem};
pub use unknown_entries::{SAFE_TO_COPY_MAX, UnknownEntries};
pub(crate) use validate::check_text;
