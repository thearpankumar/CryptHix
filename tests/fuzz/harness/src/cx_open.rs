//! CX-AEAD open on hostile input (FS-27, FS-28).
//!
//! Random bytes under a fixed key reach only the length and commitment checks, since a random
//! commitment never matches. So the target also seals the input, flips one byte the input
//! chooses, and checks that the change is caught by the check that owns that region: the
//! commitment for the nonce and commitment, the tag for the ciphertext and tag.

use crypthix_crypto::aad::Aad;
use crypthix_crypto::cx_aead::{self, COMMITMENT_LEN, NONCE_LEN, OVERHEAD, OpenError};
use crypthix_crypto::key::SealKey;
use crypthix_crypto::label::AadLabel;

/// Opens `data` as a sealed field, then seals `data` and opens it intact and with one byte
/// flipped.
///
/// # Panics
///
/// If arbitrary bytes open, a length error is misreported, a seal does not open to its
/// plaintext, or a flipped byte is caught by the wrong check or not at all.
pub fn cx_open(data: &[u8]) {
    let key = SealKey::from_bytes([7; 32]).expect("non-zero key");
    let aad = Aad::new(AadLabel::BlobData).field(&[1; 16]);
    match cx_aead::open_detailed(&key, &aad, data) {
        Ok(_) => panic!("random bytes opened: a forgery or a broken commitment check"),
        Err(OpenError::Truncated) => assert!(data.len() < OVERHEAD, "Truncated at {}", data.len()),
        Err(OpenError::ZeroNonce) => {
            assert_eq!(
                data[..NONCE_LEN],
                [0; NONCE_LEN],
                "ZeroNonce for a non-zero nonce"
            );
        }
        Err(_) => assert!(
            data.len() >= OVERHEAD,
            "a short input passed the length check"
        ),
    }

    // A real seal never has an all-zero nonce (FS-03), so the harness avoids one too.
    let mut nonce: [u8; NONCE_LEN] = std::array::from_fn(|i| data.get(i).copied().unwrap_or(0));
    nonce[0] |= 1;
    let sealed = cx_aead::seal_with_nonce(&key, &aad, data, &nonce);
    let opened = cx_aead::open(&key, &aad, &sealed).expect("a fresh seal opens");
    assert_eq!(
        opened.as_slice(),
        data,
        "a seal opened to another plaintext"
    );

    // The first three input bytes pick the byte to flip (anywhere in the seal) and the bits.
    let (Some(&high), Some(&low), Some(&mask)) = (data.first(), data.get(1), data.get(2)) else {
        return;
    };
    if mask == 0 {
        return;
    }
    let index = usize::from(u16::from_be_bytes([high, low])) % sealed.len();
    let mut tampered = sealed;
    tampered[index] ^= mask;
    let expected = if index < NONCE_LEN + COMMITMENT_LEN {
        OpenError::Commitment
    } else {
        OpenError::AeadTag
    };
    let result = cx_aead::open_detailed(&key, &aad, &tampered).err();
    assert_eq!(
        result,
        Some(expected),
        "byte {index} flipped by {mask:#04x}"
    );
}
