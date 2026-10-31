//! Property tests of CX-AEAD (FS-27, FS-28): seal and open round-trip, and every single-byte
//! change fails with the error of its kind.

use crypthix_crypto::aad::Aad;
use crypthix_crypto::cx_aead::{self, COMMITMENT_LEN, NONCE_LEN, OVERHEAD, OpenError};
use crypthix_crypto::key::SealKey;
use crypthix_crypto::label::AadLabel;
use proptest::prelude::{Strategy, any, prop, prop_assert_eq, prop_assume, proptest};

fn aad(id: &[u8; 16]) -> Aad {
    Aad::new(AadLabel::BlobData).field(id)
}

fn key(bytes: [u8; 32]) -> SealKey {
    SealKey::from_bytes(bytes).expect("non-zero key")
}

fn nonzero_key() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_filter("non-zero", |bytes| bytes != &[0; 32])
}

proptest! {
    #[test]
    fn open_inverts_seal(
        key_bytes in nonzero_key(),
        id in any::<[u8; 16]>(),
        nonce in any::<[u8; 24]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let sealed = cx_aead::seal_with_nonce(&key(key_bytes), &aad(&id), &plaintext, &nonce);
        prop_assert_eq!(sealed.len(), OVERHEAD + plaintext.len());
        let opened = cx_aead::open(&key(key_bytes), &aad(&id), &sealed).map(|opened| opened.to_vec());
        prop_assert_eq!(opened, Ok(plaintext));
    }

    #[test]
    fn a_flipped_byte_fails_by_region(
        key_bytes in nonzero_key(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..64),
        position in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let sealed = cx_aead::seal_with_nonce(&key(key_bytes), &aad(&[1; 16]), &plaintext, &[2; 24]);
        let index = position.index(sealed.len());
        let mut tampered = sealed;
        tampered[index] ^= 1 << bit;
        let expected = if index < NONCE_LEN + COMMITMENT_LEN {
            OpenError::Commitment
        } else {
            OpenError::AeadTag
        };
        prop_assert_eq!(
            cx_aead::open_detailed(&key(key_bytes), &aad(&[1; 16]), &tampered),
            Err(expected)
        );
    }

    #[test]
    fn another_key_or_aad_fails_the_commitment(
        first in nonzero_key(),
        second in nonzero_key(),
        id in any::<[u8; 16]>(),
        other_id in any::<[u8; 16]>(),
    ) {
        prop_assume!(first != second && id != other_id);
        let sealed = cx_aead::seal_with_nonce(&key(first), &aad(&id), b"body", &[3; 24]);
        prop_assert_eq!(
            cx_aead::open_detailed(&key(second), &aad(&id), &sealed),
            Err(OpenError::Commitment)
        );
        prop_assert_eq!(
            cx_aead::open_detailed(&key(first), &aad(&other_id), &sealed),
            Err(OpenError::Commitment)
        );
    }
}

/// The last commitment byte is the easiest region boundary for random flips to miss.
#[test]
fn the_last_commitment_byte_fails_the_commitment() {
    let sealed = cx_aead::seal_with_nonce(&key([4; 32]), &aad(&[1; 16]), b"body", &[2; 24]);
    let mut tampered = sealed;
    tampered[NONCE_LEN + COMMITMENT_LEN - 1] ^= 1;
    let result = cx_aead::open_detailed(&key([4; 32]), &aad(&[1; 16]), &tampered);
    assert_eq!(result.err(), Some(OpenError::Commitment));
}
