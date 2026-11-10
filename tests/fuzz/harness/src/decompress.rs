//! zstd frames of chunks on hostile input (FS-53).
//!
//! The input is a `plain_len` as a 24-bit big-endian number, then the frame. The decoder's
//! answer is compared with zstd's one-shot decoder and with this file's own reading of the
//! frame and block headers: it must accept exactly the frames that are one FS-53 frame
//! declaring `plain_len` and that zstd decodes to `plain_len` bytes. zstd's one-shot decoder
//! does not check the block maximum, so the block headers are read here too.

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

/// Whether `frame` is exactly one zstd frame that FS-53 allows before decoding: a single
/// segment, so no window descriptor and a window of `plain_len`; no unused or reserved bit,
/// checksum or dictionary ID; a declared content size of `plain_len` in the shortest field that
/// holds it; blocks of a defined type no larger than `min(plain_len, 128 KiB)`, an RLE block
/// counting what it regenerates; and nothing after the last block (RFC 8878 section 3.1.1).
fn fs53_header(frame: &[u8], plain_len: u64) -> bool {
    let Some((magic, rest)) = frame.split_first_chunk::<4>() else {
        return false;
    };
    let Some((&descriptor, rest)) = rest.split_first() else {
        return false;
    };
    // Single segment set, and the unused, reserved, checksum and dictionary bits clear.
    if u32::from_le_bytes(*magic) != 0xFD2F_B528 || descriptor & 0x3f != 0x20 {
        return false;
    }
    let size_bytes = match descriptor >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    // The shortest field: one byte, two with an offset of 256, then four.
    let shortest = match plain_len {
        0..256 => 1,
        256..65_792 => 2,
        65_792..0xFFFF_FFFF => 4,
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
    let blocks_end = blocks_end(&rest[size_bytes..], plain_len.min(128 * 1024));
    let one_frame = zstd_safe::find_frame_compressed_size(frame) == Ok(frame.len());
    declared == plain_len && blocks_end == Some(rest.len() - size_bytes) && one_frame
}

/// Where the blocks at the start of `blocks` end, if each is whole, of a defined type and no
/// larger than `block_max` (RFC 8878 section 3.1.1.2).
fn blocks_end(blocks: &[u8], block_max: u64) -> Option<usize> {
    let mut at = 0;
    loop {
        let header = blocks.get(at..at + 3)?;
        let header = u32::from(header[0]) | u32::from(header[1]) << 8 | u32::from(header[2]) << 16;
        let size = u64::from(header >> 3);
        if size > block_max {
            return None;
        }
        let content = match (header >> 1) & 3 {
            1 => 1,
            3 => return None,
            _ => usize::try_from(size).ok()?,
        };
        at += 3 + content;
        if at > blocks.len() {
            return None;
        }
        if header & 1 == 1 {
            return Some(at);
        }
    }
}
