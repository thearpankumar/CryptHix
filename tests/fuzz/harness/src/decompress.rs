//! zstd frames of chunks on hostile input (FS-53).
//!
//! The input is a `plain_len` as a 24-bit big-endian number, then the frame. The decoder's
//! answer is compared with zstd's one-shot decoder and with this file's own reading of the
//! frame header: it must accept exactly the frames that are one FS-53 frame declaring
//! `plain_len` and that zstd decodes to `plain_len` bytes.

use std::cell::RefCell;

use crypthix_core::compress::Decompressor;
use crypthix_core::error::ReadError;
use crypthix_core::limits::MAX_PLAIN_LEN;
use crypthix_types::format_error::FormatError;

thread_local! {
    /// One context for every input, as a reader reuses it, so a context left broken by a
    /// failed frame shows up on the next.
    static DECOMPRESSOR: RefCell<Decompressor> = RefCell::new(Decompressor::new());
}

/// Decodes the frame after a 3-byte `plain_len`.
///
/// # Panics
///
/// If the output is not exactly `plain_len` bytes or differs from zstd's, an error other than
/// `Decompress` is given, or a frame is accepted or refused against FS-53.
pub fn decompress(data: &[u8]) {
    let Some(([high, middle, low], frame)) = data.split_first_chunk::<3>() else {
        return;
    };
    let plain_len = u64::from(u32::from_be_bytes([0, *high, *middle, *low]));
    let result = DECOMPRESSOR.with_borrow_mut(|decompressor| decompressor.decode(frame, plain_len));
    let oracle = oracle(frame, plain_len);
    match result {
        Ok(plain) => {
            assert_eq!(plain.len() as u64, plain_len, "output of the wrong length");
            assert_eq!(
                oracle.as_deref(),
                Some(plain.as_slice()),
                "zstd decodes the frame to other bytes, or not at all"
            );
            assert!(
                fs53_header(frame, plain_len),
                "a frame FS-53 forbids was accepted"
            );
        }
        Err(ReadError::Format(FormatError::Decompress)) => assert!(
            oracle.is_none() || !fs53_header(frame, plain_len),
            "a valid FS-53 frame of plain_len bytes was refused"
        ),
        Err(other) => panic!("a frame gave {other:?}; only Decompress exists"),
    }
}

/// What zstd's one-shot decoder makes of `frame` into exactly `plain_len` bytes, if anything
/// and if `plain_len` is within the cap.
fn oracle(frame: &[u8], plain_len: u64) -> Option<Vec<u8>> {
    if plain_len > MAX_PLAIN_LEN {
        return None;
    }
    let len = usize::try_from(plain_len).ok()?;
    let mut out = vec![0u8; len];
    match zstd_safe::decompress(&mut out[..], frame) {
        Ok(written) if written == len => Some(out),
        _ => None,
    }
}

/// Whether `frame` is exactly one zstd frame whose header FS-53 allows: no unused or reserved
/// bit, checksum or dictionary ID, a declared content size of `plain_len` in the shortest field
/// that holds it, a window of at most 1 MiB, and nothing after the frame (RFC 8878 section
/// 3.1.1).
fn fs53_header(frame: &[u8], plain_len: u64) -> bool {
    let Some((magic, rest)) = frame.split_first_chunk::<4>() else {
        return false;
    };
    let Some((&descriptor, rest)) = rest.split_first() else {
        return false;
    };
    if u32::from_le_bytes(*magic) != 0xFD2F_B528 || descriptor & 0x1f != 0 {
        return false;
    }
    let single_segment = descriptor & 0x20 != 0;
    let (window, rest) = if single_segment {
        (None, rest)
    } else {
        let Some((&window, rest)) = rest.split_first() else {
            return false;
        };
        (Some(window), rest)
    };
    let size_bytes = match (descriptor >> 6, single_segment) {
        (0, false) => return false,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    // The shortest field: one byte only without a window descriptor, two with an offset of 256.
    let shortest = match plain_len {
        0..256 if single_segment => 1,
        256..65_792 => 2,
        0..0xFFFF_FFFF => 4,
        _ => 8,
    };
    if size_bytes != shortest {
        return false;
    }
    let Some(field) = rest.get(..size_bytes) else {
        return false;
    };
    let mut bytes = [0u8; 8];
    bytes[..size_bytes].copy_from_slice(field);
    let declared = u64::from_le_bytes(bytes) + if size_bytes == 2 { 256 } else { 0 };
    let window_ok = window.is_none_or(|byte| {
        let base = 1u64 << (10 + (byte >> 3));
        base + base / 8 * u64::from(byte & 7) <= MAX_PLAIN_LEN
    });
    let one_frame = zstd_safe::find_frame_compressed_size(frame) == Ok(frame.len());
    declared == plain_len && window_ok && one_frame
}
