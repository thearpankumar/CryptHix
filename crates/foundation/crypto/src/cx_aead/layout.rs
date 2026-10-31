//! Byte sizes of a CX-AEAD seal (FS-27).

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Commitment length in bytes.
pub const COMMITMENT_LEN: usize = 32;
/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Bytes a seal adds to its plaintext.
pub const OVERHEAD: usize = NONCE_LEN + COMMITMENT_LEN + TAG_LEN;
/// Length of a wrapped 32-byte key.
pub const WRAPPED_KEY_LEN: usize = OVERHEAD + 32;
/// The longest plaintext a seal accepts: no format 0 structure is longer, since a preamble
/// records its body length as a `u32` (section 3).
pub const MAX_PLAINTEXT_LEN: usize = u32::MAX as usize;
