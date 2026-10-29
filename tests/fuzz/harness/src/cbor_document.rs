//! A document the validator accepts can be read in full and re-encodes to itself.

use crypthix_types::cbor::{Decoder, Document, Encoder, ItemKind, Limits};
use crypthix_types::format_error::FormatError;

/// How deep to follow CBOR nested inside byte strings; each level costs at least one byte, so
/// an unbounded walk could recurse once per input byte.
const MAX_NESTED_DOCUMENTS: usize = 4;

/// Parses `data`; if it is accepted, reads every item through [`Decoder`] and checks that
/// [`Encoder`] rebuilds exactly `data` from what was read.
///
/// # Panics
///
/// If a typed read fails on an accepted document, or the rebuilt bytes differ.
pub fn cbor_document(data: &[u8]) {
    walk_document(data, 0);
}

fn walk_document(data: &[u8], nesting: usize) {
    let Ok(document) = Document::parse(data, &Limits::FORMAT_0) else {
        return;
    };
    let mut encoder = Encoder::new();
    copy(document.root(), &mut encoder, nesting)
        .unwrap_or_else(|error| panic!("reading an accepted document failed: {error:?}"));
    let rebuilt = encoder
        .finish(&Limits::FORMAT_0)
        .unwrap_or_else(|error| panic!("re-encoding an accepted document failed: {error:?}"));
    assert_eq!(
        rebuilt, data,
        "an accepted document must re-encode to itself"
    );
}

/// Reads one item with the typed reads and writes it to `out`.
fn copy(item: Decoder<'_>, out: &mut Encoder, nesting: usize) -> Result<(), FormatError> {
    match item.kind()? {
        ItemKind::Unsigned => out.uint(item.uint()?),
        ItemKind::Negative => out.int(item.int()?),
        ItemKind::Bytes => {
            let bytes = item.bytes()?;
            if nesting < MAX_NESTED_DOCUMENTS && item.nested_document(&Limits::FORMAT_0).is_ok() {
                walk_document(bytes, nesting + 1);
            }
            out.bytes(bytes);
        }
        ItemKind::Text => out.text(item.text()?)?,
        ItemKind::Bool => out.bool(item.bool()?),
        ItemKind::Null => {
            assert!(
                item.is_null() && item.nullable().is_none(),
                "null reads as null"
            );
            out.null();
        }
        ItemKind::Array => {
            let items = item.array()?;
            out.array(|out| {
                for element in items {
                    copy(element?, out, nesting)?;
                }
                Ok(())
            })?;
        }
        ItemKind::Map => {
            let entries = item.map()?;
            out.map(|map| {
                for (key, value) in entries.iter() {
                    map.entry(key, |out| copy(value, out, nesting))?;
                }
                Ok(())
            })?;
            // Exercises the unknown-key pass; an unread negative key is a schema error, not a
            // crash.
            let _ = item.map()?.finish();
        }
        _ => return Err(FormatError::Schema),
    }
    Ok(())
}
