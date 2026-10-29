//! The preamble parser never panics and round-trips what it accepts.

use crypthix_types::preamble::Preamble;

/// Parses `data` as a whole file.
///
/// # Panics
///
/// If an accepted preamble does not re-encode to the first 20 bytes, or its body length is
/// wrong.
pub fn preamble(data: &[u8]) {
    let Ok((preamble, body)) = Preamble::parse(data) else {
        return;
    };
    assert_eq!(
        preamble.to_bytes()[..],
        data[..Preamble::LEN],
        "to_bytes(parse(x)) == x"
    );
    assert_eq!(
        preamble.context()[..],
        data[..16],
        "the context is the first 16 bytes"
    );
    assert_eq!(
        u64::from(preamble.body_len()),
        body.len() as u64,
        "body_len is the body"
    );
    assert!(
        preamble.body_len() <= preamble.file_type().max_body_len(),
        "accepted bodies are within the cap"
    );
}
