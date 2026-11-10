//! The list of fuzz targets.

use crate::{cbor_differential, cbor_document, cbor_structured, config_toml, cx_open, id_text};
use crate::{chunker, data_blob_open, decompress, inner_plaintext};
use crate::{preamble, store_key, verifying_key};

/// A fuzz target body: panics when a property fails on the input.
pub type Target = fn(&[u8]);

/// Every target, by the name its fuzz binary and regression directory use.
pub const TARGETS: [(&str, Target); 13] = [
    ("preamble", preamble),
    ("cbor_document", cbor_document),
    ("cbor_differential", cbor_differential),
    ("cbor_structured", cbor_structured),
    ("store_key", store_key),
    ("config_toml", config_toml),
    ("id_text", id_text),
    ("cx_open", cx_open),
    ("verifying_key", verifying_key),
    ("inner_plaintext", inner_plaintext),
    ("decompress", decompress),
    ("data_blob_open", data_blob_open),
    ("chunker", chunker),
];
