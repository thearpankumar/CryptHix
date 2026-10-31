//! The signature input of FS-13.

use crypthix_types::id::KeyId;

use crate::label::SigLabel;

/// `u8 len(type_label) ‖ type_label ‖ ctx[16] ‖ signer[32] ‖ u64be(len(body)) ‖ body`, where
/// `ctx` is `preamble[0..16]` of the file, or a synthetic preamble for a nested envelope.
pub(crate) fn sig_input(label: SigLabel, ctx: &[u8; 16], signer: &KeyId, body: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(1 + 32 + 16 + 32 + 8 + body.len());
    label.write_prefix(&mut input);
    input.extend_from_slice(ctx);
    input.extend_from_slice(signer.as_bytes());
    let len = u64::try_from(body.len()).expect("a body length fits in u64");
    input.extend_from_slice(&len.to_be_bytes());
    input.extend_from_slice(body);
    input
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_fs13() {
        let signer = KeyId::try_from_bytes([2; 32]).expect("non-zero");
        let input = sig_input(SigLabel::Root, &[1; 16], &signer, b"abc");
        let label = b"crypthix/v0/sig/root";
        assert_eq!(usize::from(input[0]), label.len());
        let rest = &input[1 + label.len()..];
        assert_eq!(&rest[..16], &[1; 16]);
        assert_eq!(&rest[16..48], &[2; 32]);
        assert_eq!(&rest[48..56], &3u64.to_be_bytes());
        assert_eq!(&rest[56..], b"abc");
    }
}
