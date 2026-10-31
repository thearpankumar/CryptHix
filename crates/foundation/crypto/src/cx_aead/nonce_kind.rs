//! The two kinds of CX-AEAD nonce (FS-29).

use crate::key::ShardNonceKey;

/// How a seal picks its 24-byte nonce (FS-29).
///
/// There is no plain random nonce: a VM restored from a snapshot without a VM generation ID can
/// replay the kernel's random output, and a replayed nonce under the same key and AAD would
/// reuse the keystream and the Poly1305 key (T-81). A hedged nonce mixes the randomness with the
/// key, AAD and plaintext, so replayed randomness repeats a nonce only for an identical seal.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum NonceKind<'k> {
    /// `MAC(K_n, rand[32] ‖ a ‖ pt)[..24]`, with `K_n` derived from the seal key and `rand` from
    /// `getrandom`: every sealed field except shard headers. If `rand` repeats, two seals share a
    /// nonce only when they are identical, which leaks only that they are equal.
    Hedged,
    /// `MAC(K_shn, a ‖ pt)[..24]`: shard headers, so a rebuilt shard is byte-identical.
    Synthetic(&'k ShardNonceKey),
}
