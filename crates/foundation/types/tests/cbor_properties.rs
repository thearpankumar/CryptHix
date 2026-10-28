//! Property tests for the deterministic CBOR codec (FS-08 to FS-11).

use std::collections::BTreeMap;

use crypthix_types::cbor::{Decoder, Document, Encoder, ItemKind, Limits};
use crypthix_types::format_error::FormatError;
use proptest::prelude::{Just, Strategy, any, prop, prop_assert_eq, prop_oneof, proptest};

/// A CBOR value of the subset format 0 allows.
#[derive(Clone, PartialEq, Debug)]
enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Null,
    Array(Vec<Value>),
    Map(BTreeMap<i32, Value>),
}

fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<i64>().prop_map(Value::Int),
        prop::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        "[a-zA-Z0-9 äöü€]{0,20}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(6, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map(any::<i32>(), inner, 0..8).prop_map(Value::Map),
        ]
    })
}

fn encode(value: &Value, encoder: &mut Encoder) -> Result<(), FormatError> {
    match value {
        Value::Int(int) => encoder.int(*int),
        Value::Bytes(bytes) => encoder.bytes(bytes),
        Value::Text(text) => encoder.text(text)?,
        Value::Bool(flag) => encoder.bool(*flag),
        Value::Null => encoder.null(),
        Value::Array(items) => encoder.array(|items_encoder| {
            items
                .iter()
                .try_for_each(|item| encode(item, items_encoder))
        })?,
        Value::Map(entries) => encoder.map(|map| {
            entries
                .iter()
                .try_for_each(|(key, item)| map.entry(*key, |value| encode(item, value)))
        })?,
    }
    Ok(())
}

fn to_bytes(value: &Value) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encode(value, &mut encoder).expect("generated values are encodable");
    encoder
        .finish(&Limits::FORMAT_0)
        .expect("generated values are within the limits")
}

fn decode(decoder: Decoder<'_>) -> Result<Value, FormatError> {
    Ok(match decoder.kind()? {
        ItemKind::Unsigned | ItemKind::Negative => Value::Int(decoder.int()?),
        ItemKind::Bytes => Value::Bytes(decoder.bytes()?.to_vec()),
        ItemKind::Text => Value::Text(decoder.text()?.to_owned()),
        ItemKind::Bool => Value::Bool(decoder.bool()?),
        ItemKind::Null => Value::Null,
        ItemKind::Array => {
            let items: Result<Vec<Value>, FormatError> =
                decoder.array()?.map(|item| item.and_then(decode)).collect();
            Value::Array(items?)
        }
        ItemKind::Map => {
            let map = decoder.map()?;
            let entries: Result<BTreeMap<i32, Value>, FormatError> = map
                .iter()
                .map(|(key, item)| decode(item).map(|item| (key, item)))
                .collect();
            Value::Map(entries?)
        }
        _ => return Err(FormatError::Schema),
    })
}

proptest! {
    #[test]
    fn decode_of_encode_is_identity(value in value()) {
        let bytes = to_bytes(&value);
        let document = Document::parse(&bytes, &Limits::FORMAT_0)?;
        prop_assert_eq!(decode(document.root())?, value);
    }

    #[test]
    fn accepted_input_re_encodes_to_itself(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        // Random bytes must never panic; whatever is accepted is already canonical.
        if let Ok(document) = Document::parse(&bytes, &Limits::FORMAT_0) {
            let value = decode(document.root())?;
            prop_assert_eq!(to_bytes(&value), bytes);
        }
    }

    #[test]
    fn widening_a_head_is_rejected(value in any::<u8>().prop_filter("needs a 1-byte argument", |v| *v >= 24)) {
        // 0x18 v is canonical; 0x19 0x00 v is the same value in a wider head.
        prop_assert_eq!(Document::parse(&[0x18, value], &Limits::FORMAT_0).map(|_| ()), Ok(()));
        prop_assert_eq!(
            Document::parse(&[0x19, 0x00, value], &Limits::FORMAT_0).map(|_| ()),
            Err(FormatError::NonCanonical)
        );
    }
}
