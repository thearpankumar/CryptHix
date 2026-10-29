//! Values built from a structured model encode, parse and decode back to themselves.

use arbitrary::{Arbitrary, Unstructured};
use crypthix_types::cbor::{Document, Encoder, Limits};
use crypthix_types::format_error::FormatError;

use crate::cbor_model::CborModel;
use crate::oracle::{OracleLimits, accepts};

/// Builds a [`CborModel`] from `data`, encodes it, and checks the encoder's verdict, the
/// parse, the decode and the oracle.
///
/// # Panics
///
/// If the encoder accepts what format 0 forbids or refuses what it allows, or if an encoded
/// value does not parse, decode back to the model and pass the oracle.
pub fn cbor_structured(data: &[u8]) {
    let Ok(model) = CborModel::arbitrary_take_rest(Unstructured::new(data)) else {
        return;
    };
    let mut encoder = Encoder::new();
    let written = model.encode(&mut encoder);
    let too_deep = model.depth() > Limits::FORMAT_0.max_depth();
    if too_deep || model.has_forbidden_text() {
        assert!(
            matches!(written, Err(FormatError::Limit | FormatError::Schema)),
            "the encoder wrote a value format 0 forbids: {model:?}"
        );
        return;
    }
    written.unwrap_or_else(|error| panic!("the encoder refused {model:?}: {error:?}"));
    let bytes = encoder
        .finish(&Limits::FORMAT_0)
        .unwrap_or_else(|error| panic!("the encoder wrote invalid CBOR for {model:?}: {error:?}"));
    let document = Document::parse(&bytes, &Limits::FORMAT_0)
        .unwrap_or_else(|error| panic!("encoded {model:?} does not parse: {error:?}"));
    let decoded = CborModel::decode(document.root())
        .unwrap_or_else(|error| panic!("encoded {model:?} does not decode: {error:?}"));
    assert_eq!(decoded, model, "decode(encode(v)) == v");
    assert!(
        accepts(&bytes, &OracleLimits::FS_11),
        "the oracle rejects the encoding of {model:?}: {bytes:02x?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes (xorshift64), so the test needs no RNG crate.
    fn bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    #[test]
    fn most_models_reach_the_round_trip() {
        let mut encodable = 0;
        for seed in 0..500 {
            let data = bytes(seed, 256);
            cbor_structured(&data);
            let Ok(model) = CborModel::arbitrary_take_rest(Unstructured::new(&data)) else {
                continue;
            };
            if model.depth() <= Limits::FORMAT_0.max_depth() && !model.has_forbidden_text() {
                encodable += 1;
            }
        }
        assert!(
            encodable > 200,
            "only {encodable} of 500 models reach the round trip"
        );
    }
}
