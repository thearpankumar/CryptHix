//! The inner plaintext of a data blob (FS-54), built by hand rather than with `crypthix-core`.

use crate::padme::padme;

/// `comp ‖ rsv ‖ u32be(payload_len) ‖ payload ‖ zero pad` to `padme(6 + payload_len)` bytes.
pub(crate) fn inner(comp: u8, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("a payload under 4 GiB");
    let mut out = vec![comp, 0];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out.resize(padded_len(payload.len()), 0);
    out
}

/// `padme(6 + payload_len)` as a length.
pub(crate) fn padded_len(payload_len: usize) -> usize {
    let total = padme(payload_len as u64 + 6);
    usize::try_from(total).expect("fits in memory")
}

/// Just the six header bytes: `comp ‖ rsv ‖ u32be(payload_len)`.
pub(crate) fn header(comp: u8, rsv: u8, payload_len: u32) -> Vec<u8> {
    let mut out = vec![comp, rsv];
    out.extend_from_slice(&payload_len.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        assert_eq!(inner(0, b""), [0; 6]);
        assert_eq!(inner(1, b"abc"), [1, 0, 0, 0, 0, 3, b'a', b'b', b'c', 0]);
    }
}
