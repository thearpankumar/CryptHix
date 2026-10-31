//! A second implementation of `H`, `KDF`, `MAC` and CX-AEAD, written from format spec section 7
//! straight over the audited crates and without `crypthix-crypto`, so TV-04 and TV-05 check that
//! crate against an independent reading of the spec.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// `u8 len(label) ‖ label`.
pub(crate) fn prefix(label: &str) -> Vec<u8> {
    let mut out = vec![u8::try_from(label.len()).expect("short label")];
    out.extend_from_slice(label.as_bytes());
    out
}

/// `H(label, data) = BLAKE3(u8 len ‖ label ‖ data)`.
pub(crate) fn h(label: &str, data: &[u8]) -> [u8; 32] {
    let mut input = prefix(label);
    input.extend_from_slice(data);
    *blake3::hash(&input).as_bytes()
}

/// `KDF(ikm, salt, label, ctx) = HKDF-Expand(HKDF-Extract(salt, ikm), u8 len ‖ label ‖ ctx, 32)`.
pub(crate) fn kdf(ikm: &[u8; 32], salt: Option<&[u8; 32]>, label: &str, ctx: &[u8]) -> [u8; 32] {
    let salt = salt.copied().unwrap_or([0; 32]);
    let mut info = prefix(label);
    info.extend_from_slice(ctx);
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), ikm)
        .expand(&info, &mut okm)
        .expect("32 bytes");
    okm
}

/// `HKDF-Expand(K, u8 len ‖ label ‖ ctx, 32)` keyed directly by `K` (FS-27).
pub(crate) fn expand(key: &[u8; 32], label: &str, ctx: &[u8]) -> [u8; 32] {
    let mut info = prefix(label);
    info.extend_from_slice(ctx);
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::from_prk(key)
        .expect("32-byte PRK")
        .expand(&info, &mut okm)
        .expect("32 bytes");
    okm
}

/// `MAC(k, data)`: keyed BLAKE3-256.
pub(crate) fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// An AAD with `fmt ‖ suite` of format 0 after the label (FS-12).
pub(crate) fn aad(label: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = prefix(label);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    for field in fields {
        out.extend_from_slice(field);
    }
    out
}

fn a(aad: &[u8]) -> [u8; 32] {
    h("crypthix/v0/hash/cx-aad", aad)
}

/// `Seal(K, AAD, pt, nonce) = nonce ‖ C ‖ ct ‖ tag` (FS-27).
pub(crate) fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8], nonce: &[u8; 24]) -> Vec<u8> {
    let mut ctx = nonce.to_vec();
    ctx.extend_from_slice(&a(aad));
    let enc_key = expand(key, "crypthix/v0/kdf/cx-key", &ctx);
    let commitment = expand(key, "crypthix/v0/kdf/cx-commit", &ctx);
    let mut ct = plaintext.to_vec();
    let tag = XChaCha20Poly1305::new(&enc_key.into())
        .encrypt_inout_detached(&XNonce::from(*nonce), aad, ct.as_mut_slice().into())
        .expect("short plaintext");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&commitment);
    out.extend_from_slice(&ct);
    out.extend_from_slice(tag.as_slice());
    out
}

/// The hedged nonce `MAC(K_n, rand ‖ a ‖ pt)[..24]` (FS-29).
pub(crate) fn hedged_nonce(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
    rand: &[u8; 32],
) -> [u8; 24] {
    let nonce_key = expand(key, "crypthix/v0/kdf/cx-nonce", &[]);
    let mut input = rand.to_vec();
    input.extend_from_slice(&a(aad));
    input.extend_from_slice(plaintext);
    first_24(&mac(&nonce_key, &input))
}

/// The synthetic nonce `MAC(K_shn, a ‖ pt)[..24]` (FS-29).
pub(crate) fn synthetic_nonce(nonce_key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> [u8; 24] {
    let mut input = a(aad).to_vec();
    input.extend_from_slice(plaintext);
    first_24(&mac(nonce_key, &input))
}

fn first_24(bytes: &[u8; 32]) -> [u8; 24] {
    bytes[..24].try_into().expect("24 of 32 bytes")
}
