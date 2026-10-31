//! TV-01: the ed25519-speccheck cases through the strict verifier of FS-14.
//!
//! Every case is rejected, and the expected error says which rule rejects it. Cases 0 to 5 and
//! 8 to 11 use a public key of small or mixed order (`WeakKey`), so they never reach signature
//! verification: a mixed-order key (case 3) is the one plain `verify_strict` would accept. Cases
//! 6 and 7 have a valid key and S at or above the group order (`Signature`). The checks on R
//! (small order, non-canonical encoding) are therefore not reached by these cases; they are
//! defence in depth behind the key checks.

#[allow(dead_code, reason = "each runner uses part of the shared helpers")]
mod common;

use crypthix_crypto::sign::{Signature, VerifyingKey};
use crypthix_types::format_error::FormatError;
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    message: String,
    pub_key: String,
    signature: String,
}

/// The error each case must give, in file order.
const EXPECTED: [FormatError; 12] = [
    FormatError::WeakKey,
    FormatError::WeakKey,
    FormatError::WeakKey,
    FormatError::WeakKey,
    FormatError::WeakKey,
    FormatError::WeakKey,
    FormatError::Signature,
    FormatError::Signature,
    FormatError::WeakKey,
    FormatError::WeakKey,
    FormatError::WeakKey,
    FormatError::WeakKey,
];

#[test]
fn every_case_is_rejected_by_its_rule() {
    let cases: Vec<Case> = common::load("external/ed25519-speccheck/cases.json");
    assert_eq!(cases.len(), EXPECTED.len(), "speccheck has 12 cases");
    for (index, (case, expected)) in cases.iter().zip(EXPECTED).enumerate() {
        let result = VerifyingKey::from_bytes(&common::hex_array(&case.pub_key)).and_then(|key| {
            let signature = Signature::from_bytes(common::hex_array(&case.signature));
            key.verify_raw(&common::hex(&case.message), &signature)
        });
        assert_eq!(result, Err(expected), "case {index}");
    }
}
