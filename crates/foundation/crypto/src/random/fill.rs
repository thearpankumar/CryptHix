//! Filling buffers from the kernel.

use crate::random::RandomError;

/// Fills `dest` with bytes from the kernel's `getrandom`.
///
/// # Errors
///
/// [`RandomError`] if the kernel cannot supply randomness, or returns all zeros for a buffer of
/// 16 bytes or more, which only a broken source does (FS-03).
pub fn fill(dest: &mut [u8]) -> Result<(), RandomError> {
    getrandom::fill(dest).map_err(|_| RandomError)?;
    if dest.len() >= 16 && dest.iter().all(|byte| *byte == 0) {
        return Err(RandomError);
    }
    Ok(())
}

/// `N` random bytes, for IDs, salts and nonces.
///
/// ```
/// use crypthix_crypto::random;
/// use crypthix_types::id::ObjectId;
///
/// let id = ObjectId::try_from_bytes(random::bytes()?)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// [`RandomError`] as for [`fill`].
pub fn bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        let first: [u8; 32] = bytes().expect("getrandom works");
        let second: [u8; 32] = bytes().expect("getrandom works");
        assert_ne!(first, second);
    }

    #[test]
    fn empty_buffer_is_fine() {
        fill(&mut []).expect("an empty fill succeeds");
    }
}
