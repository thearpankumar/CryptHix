//! The signature input of FS-13.

use crypthix_types::id::KeyId;

use crate::label::SigLabel;
use crate::label::labels::PrefixSink;
use crate::secure_mem::{MemError, SecretBuf};

/// `u8 len(type_label) ‖ type_label ‖ ctx[16] ‖ signer[32] ‖ u64be(len(body)) ‖ body`, where
/// `ctx` is `preamble[0..16]` of the file, or a synthetic preamble for a nested envelope.
///
/// The body may be plaintext that is sealed afterwards, so the input is built in a
/// [`SecretBuf`] of its exact length: protected, never reallocated, and wiped on drop.
///
/// # Errors
///
/// As [`SecretBuf::try_zeroed`]: [`MemError::MapFailed`] if the kernel maps no buffer, or
/// [`MemError::TooLarge`] if the body is too large for one.
pub(crate) fn sig_input(
    label: SigLabel,
    ctx: &[u8; 16],
    signer: &KeyId,
    body: &[u8],
) -> Result<SecretBuf, MemError> {
    let label_len = 1 + label.as_str().len();
    // A slice holds at most `isize::MAX` bytes, so this sum cannot overflow.
    let mut input = SecretBuf::try_zeroed(label_len + 16 + 32 + 8 + body.len())?;
    let mut rest = input.as_mut_slice();
    label.write_prefix(&mut rest);
    rest.put(ctx);
    rest.put(signer.as_bytes());
    let len = u64::try_from(body.len()).expect("a body length fits in u64");
    rest.put(&len.to_be_bytes());
    rest.put(body);
    debug_assert!(rest.is_empty(), "the input was sized exactly");
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_fs13() {
        let signer = KeyId::try_from_bytes([2; 32]).expect("non-zero");
        let input = sig_input(SigLabel::Root, &[1; 16], &signer, b"abc").expect("a buffer");
        let label = b"crypthix/v0/sig/root";
        assert_eq!(input.len(), 1 + label.len() + 16 + 32 + 8 + 3, "no slack");
        assert_eq!(usize::from(input[0]), label.len());
        assert_eq!(&input[1..=label.len()], label);
        let rest = &input[1 + label.len()..];
        assert_eq!(&rest[..16], &[1; 16]);
        assert_eq!(&rest[16..48], &[2; 32]);
        assert_eq!(&rest[48..56], &3u64.to_be_bytes());
        assert_eq!(&rest[56..], b"abc");
    }

    #[test]
    fn an_empty_body_still_has_its_length_field() {
        let signer = KeyId::try_from_bytes([2; 32]).expect("non-zero");
        let input = sig_input(SigLabel::Root, &[1; 16], &signer, b"").expect("a buffer");
        assert_eq!(&input[input.len() - 8..], &0u64.to_be_bytes());
    }

    /// The body may be plaintext, so the input is in protected memory, not on the heap.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn the_input_is_in_protected_memory() {
        use crate::secure_mem::Level;

        let signer = KeyId::try_from_bytes([2; 32]).expect("non-zero");
        let input =
            sig_input(SigLabel::Root, &[1; 16], &signer, b"plaintext body").expect("a buffer");
        let level = input.level().expect("a non-empty input maps memory");
        assert!(
            (Level::DumpExcluded..=Level::Locked).contains(&level),
            "{level}"
        );
    }

    /// Without protected memory (other systems, and Miri) the input is still a `SecretBuf`,
    /// wiped on drop, on the heap.
    #[cfg(not(all(target_os = "linux", not(miri))))]
    #[test]
    fn the_input_is_on_the_heap_without_protected_memory() {
        use crate::secure_mem::Level;

        let signer = KeyId::try_from_bytes([2; 32]).expect("non-zero");
        let input =
            sig_input(SigLabel::Root, &[1; 16], &signer, b"plaintext body").expect("a buffer");
        assert_eq!(input.level(), Some(Level::Heap));
    }
}
