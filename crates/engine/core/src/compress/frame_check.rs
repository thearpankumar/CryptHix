//! The checks a zstd frame passes before it is decompressed (FS-53).

use crypthix_types::format_error::FormatError;

use crate::limits::MAX_PLAIN_LEN;

/// The magic number of a zstd frame, as its first four bytes.
const ZSTD_MAGIC: [u8; 4] = 0xFD2F_B528_u32.to_le_bytes();

/// Frame header descriptor bits (RFC 8878 section 3.1.1.1.1).
const SINGLE_SEGMENT: u8 = 0x20;
const UNUSED: u8 = 0x10;
const RESERVED: u8 = 0x08;
const CHECKSUM: u8 = 0x04;
const DICT_ID: u8 = 0x03;
const FCS_FLAG_SHIFT: u32 = 6;

/// The largest block, 128 KiB (RFC 8878 section 3.1.1.2.4).
const MAX_BLOCK: u64 = 128 * 1024;

/// Block types (RFC 8878 section 3.1.1.2.2).
const RAW_BLOCK: u32 = 0;
const RLE_BLOCK: u32 = 1;
const COMPRESSED_BLOCK: u32 = 2;

/// Checks that `frame` is exactly one zstd frame as FS-53 writes it, declaring `plain_len`
/// bytes of content: the zstd magic (so no skippable frame); the single-segment bit set, so
/// there is no window descriptor and the window is `plain_len`; the unused and reserved bits
/// clear; no checksum; no dictionary ID; a content size equal to `plain_len` in the shortest
/// field that holds it; blocks of a defined type, each no larger than `min(plain_len, 128 KiB)`,
/// the size it regenerates counting for an RLE block; and no bytes after the last block. Every
/// failure is `Decompress`.
///
/// zstd checks the content against the declared size while decoding; these checks make sure
/// the declaration exists and matches before a byte is decoded. libzstd 1.5.7 ignores the
/// unused bit, reads a content size from a wider field than needed and accepts a window
/// descriptor (RFC 8878 allows all three to a decoder); its encoder never writes them for a
/// chunk of at most 1 MiB, so a frame with them is a second encoding of a chunk and is refused
/// here. libzstd 1.5.7 checks the block maximum only on its block-by-block path, not when it
/// decodes a whole frame in one pass, as `ZSTD_decompressStream` does when given the whole frame
/// and room for its content, so the block headers are walked here.
pub(crate) fn frame_check(frame: &[u8], plain_len: u64) -> Result<(), FormatError> {
    let fail = FormatError::Decompress;
    if plain_len > MAX_PLAIN_LEN {
        return Err(fail);
    }
    let Some((magic, rest)) = frame.split_first_chunk::<4>() else {
        return Err(fail);
    };
    if *magic != ZSTD_MAGIC {
        return Err(fail);
    }
    let Some((&descriptor, rest)) = rest.split_first() else {
        return Err(fail);
    };
    if descriptor & (SINGLE_SEGMENT | UNUSED | RESERVED | CHECKSUM | DICT_ID) != SINGLE_SEGMENT {
        return Err(fail);
    }
    let flag = descriptor >> FCS_FLAG_SHIFT;
    if flag != fcs_flag(plain_len) {
        return Err(fail);
    }
    let (declared, blocks) = content_size(flag, rest).ok_or(fail)?;
    if declared != plain_len {
        return Err(fail);
    }
    // A single segment's window is its content size.
    let block_max = plain_len.min(MAX_BLOCK);
    match after_blocks(blocks, block_max) {
        Some([]) => Ok(()),
        _ => Err(fail),
    }
}

/// The frame content size flag of the shortest field that holds `size` in a single-segment
/// frame (RFC 8878 section 3.1.1.1.1), as libzstd's encoder chooses it: one byte, two bytes
/// with an offset of 256, four, then eight from `0xFFFF_FFFF` on.
fn fcs_flag(size: u64) -> u8 {
    match size {
        0..256 => 0,
        256..65_792 => 1,
        65_792..0xFFFF_FFFF => 2,
        _ => 3,
    }
}

/// The content size in the field that `flag` names at the start of `rest`, in a single-segment
/// frame, and the bytes after it; `None` if the field is cut off.
fn content_size(flag: u8, rest: &[u8]) -> Option<(u64, &[u8])> {
    match flag {
        0 => {
            let (&size, rest) = rest.split_first()?;
            Some((u64::from(size), rest))
        }
        1 => {
            let (size, rest) = rest.split_first_chunk::<2>()?;
            Some((u64::from(u16::from_le_bytes(*size)) + 256, rest))
        }
        2 => {
            let (size, rest) = rest.split_first_chunk::<4>()?;
            Some((u64::from(u32::from_le_bytes(*size)), rest))
        }
        _ => {
            let (size, rest) = rest.split_first_chunk::<8>()?;
            Some((u64::from_le_bytes(*size), rest))
        }
    }
}

/// Walks the blocks at the start of `blocks` (RFC 8878 section 3.1.1.2) and returns the bytes
/// after the last one; `None` if a block is cut off, has the reserved type, or is larger than
/// `block_max`, the regenerated size counting for an RLE block.
fn after_blocks(mut blocks: &[u8], block_max: u64) -> Option<&[u8]> {
    loop {
        let (&[low, middle, high], rest) = blocks.split_first_chunk::<3>()?;
        let header = u32::from_le_bytes([low, middle, high, 0]);
        let last = header & 1 == 1;
        let size = header >> 3;
        if u64::from(size) > block_max {
            return None;
        }
        let content_len = match (header >> 1) & 3 {
            RAW_BLOCK | COMPRESSED_BLOCK => usize::try_from(size).ok()?,
            RLE_BLOCK => 1,
            _ => return None,
        };
        blocks = rest.get(content_len..)?;
        if last {
            return Some(blocks);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A block header: `last`, `kind` and `size` (RFC 8878 section 3.1.1.2).
    fn block_header(last: bool, kind: u32, size: u32) -> [u8; 3] {
        let header = u32::from(last) | kind << 1 | size << 3;
        let [low, middle, high, _] = header.to_le_bytes();
        [low, middle, high]
    }

    /// A single-segment frame of one raw block holding `content`, declaring `declared` bytes in
    /// the shortest field, with the given descriptor bits added.
    pub(crate) fn raw_frame(content: &[u8], declared: u32, extra: u8) -> Vec<u8> {
        sized_frame(content, declared, fcs_flag(u64::from(declared)), extra)
    }

    /// [`raw_frame`] with the content size in the field that `flag` names.
    fn sized_frame(content: &[u8], declared: u32, flag: u8, extra: u8) -> Vec<u8> {
        let mut frame = header_of(declared, flag, extra);
        let size = u32::try_from(content.len()).expect("small");
        frame.extend_from_slice(&block_header(true, RAW_BLOCK, size));
        frame.extend_from_slice(content);
        frame
    }

    /// The magic, the descriptor and the content size field of a single-segment frame.
    fn header_of(declared: u32, flag: u8, extra: u8) -> Vec<u8> {
        let mut frame = ZSTD_MAGIC.to_vec();
        frame.push((flag << FCS_FLAG_SHIFT) | SINGLE_SEGMENT | extra);
        let field = match flag {
            0 => vec![u8::try_from(declared).expect("below 256")],
            1 => u16::try_from(declared - 256)
                .expect("below 65,792")
                .to_le_bytes()
                .to_vec(),
            2 => declared.to_le_bytes().to_vec(),
            _ => u64::from(declared).to_le_bytes().to_vec(),
        };
        frame.extend_from_slice(&field);
        frame
    }

    /// A single-segment frame of one RLE block of `len` copies of `byte`.
    pub(crate) fn rle_frame(byte: u8, len: u32) -> Vec<u8> {
        blocks_frame(len, &[(RLE_BLOCK, len, &[byte])])
    }

    /// A single-segment frame declaring `declared` bytes with the given blocks, each a type, a
    /// `Block_Size` and its content; the last is marked as such.
    fn blocks_frame(declared: u32, blocks: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut frame = header_of(declared, fcs_flag(u64::from(declared)), 0);
        for (index, (kind, size, content)) in blocks.iter().enumerate() {
            let last = index + 1 == blocks.len();
            frame.extend_from_slice(&block_header(last, *kind, *size));
            frame.extend_from_slice(content);
        }
        frame
    }

    fn check(frame: &[u8], plain_len: u64) -> Result<(), FormatError> {
        frame_check(frame, plain_len)
    }

    const FAIL: Result<(), FormatError> = Err(FormatError::Decompress);

    /// What libzstd's one-shot decoder makes of `frame` into `capacity` bytes.
    fn zstd_decodes(frame: &[u8], capacity: usize) -> Result<usize, usize> {
        let mut out = vec![0u8; capacity];
        zstd_safe::decompress(&mut out[..], frame)
    }

    #[test]
    fn short_and_foreign_input_fails() {
        for frame in [
            &b""[..],
            b"\x28\xB5\x2F",
            b"\x28\xB5\x2F\xFD",
            b"PK\x03\x04\x00\x00",
        ] {
            assert_eq!(check(frame, 0), FAIL, "{frame:?}");
        }
        let mut skippable = raw_frame(b"x", 1, 0);
        skippable[..4].copy_from_slice(&0x184D_2A50_u32.to_le_bytes());
        assert_eq!(check(&skippable, 1), FAIL);
        for bit in [UNUSED, RESERVED, CHECKSUM, 1, 2, 3] {
            assert_eq!(check(&raw_frame(b"x", 1, bit), 1), FAIL, "{bit}");
        }
    }

    #[test]
    fn a_frame_cut_inside_its_header_fails() {
        let frame = raw_frame(&[b'a'; 300], 300, 0);
        assert_eq!(check(&frame, 300), Ok(()));
        // Magic and descriptor only; one of the two content size bytes; a cut block header.
        for len in [5, 6, 7, 8, 9] {
            assert_eq!(check(&frame[..len], 300), FAIL, "{len} bytes");
        }
    }

    #[test]
    fn raw_and_rle_frames_pass() {
        assert_eq!(check(&raw_frame(b"hello", 5, 0), 5), Ok(()));
        assert_eq!(check(&raw_frame(b"", 0, 0), 0), Ok(()));
        let mixed = blocks_frame(8, &[(RLE_BLOCK, 3, b"a"), (RAW_BLOCK, 5, b"hello")]);
        assert_eq!(check(&mixed, 8), Ok(()));
        let empty_rle = blocks_frame(0, &[(RLE_BLOCK, 0, b"a")]);
        assert_eq!(check(&empty_rle, 0), Ok(()));
    }

    #[test]
    fn the_content_size_must_be_declared_and_equal() {
        let frame = raw_frame(b"hello", 5, 0);
        assert_eq!(check(&frame, 4), FAIL);
        assert_eq!(check(&frame, 6), FAIL);
        // No content size: descriptor 0 and a window descriptor.
        let mut no_size = ZSTD_MAGIC.to_vec();
        no_size.extend_from_slice(&[0x00, 0x00, 0x29, 0, 0]);
        no_size.extend_from_slice(b"hello");
        assert_eq!(check(&no_size, 5), FAIL);
        assert_eq!(check(&frame, MAX_PLAIN_LEN + 1), FAIL);
    }

    #[test]
    fn exactly_one_frame_and_nothing_after_it() {
        let frame = raw_frame(b"hello", 5, 0);
        let mut two = frame.clone();
        two.extend_from_slice(&frame);
        assert_eq!(check(&two, 5), FAIL);
        let mut trailing = frame.clone();
        trailing.push(0);
        assert_eq!(check(&trailing, 5), FAIL);
        let mut skippable_after = frame.clone();
        skippable_after.extend_from_slice(&0x184D_2A50_u32.to_le_bytes());
        skippable_after.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(check(&skippable_after, 5), FAIL);
        assert_eq!(check(&frame[..frame.len() - 1], 5), FAIL, "truncated");
        let not_last = blocks_frame(5, &[(RAW_BLOCK, 5, b"hello"), (RAW_BLOCK, 0, b"")]);
        assert_eq!(
            check(&not_last[..not_last.len() - 3], 5),
            FAIL,
            "no last block"
        );
    }

    #[test]
    fn content_size_flags_are_the_shortest_field() {
        assert_eq!(fcs_flag(0), 0);
        assert_eq!(fcs_flag(255), 0);
        assert_eq!(fcs_flag(256), 1);
        assert_eq!(fcs_flag(65_791), 1);
        assert_eq!(fcs_flag(65_792), 2);
        assert_eq!(fcs_flag(0xFFFF_FFFE), 2);
        assert_eq!(fcs_flag(0xFFFF_FFFF), 3);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn a_content_size_field_wider_than_needed_fails() {
        // Each of these decodes with libzstd 1.5.7.
        for flag in [2, 3] {
            let frame = sized_frame(b"hello", 5, flag, 0);
            assert_eq!(zstd_decodes(&frame, 5), Ok(5), "{flag}");
            assert_eq!(check(&frame, 5), FAIL, "{flag}");
        }
        let long = vec![b'a'; 300];
        assert_eq!(check(&sized_frame(&long, 300, 1, 0), 300), Ok(()));
        assert_eq!(check(&sized_frame(&long, 300, 2, 0), 300), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn the_unused_bit_fails_although_libzstd_ignores_it() {
        let frame = raw_frame(b"hello", 5, UNUSED);
        assert_eq!(zstd_decodes(&frame, 5), Ok(5));
        assert_eq!(check(&frame, 5), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn a_window_descriptor_fails_although_libzstd_decodes_it() {
        // Descriptor 0xC0: an eight-byte content size and no single segment, then a window of
        // 2^20 bytes, the most FS-53 allows a writer.
        let mut frame = ZSTD_MAGIC.to_vec();
        frame.extend_from_slice(&[0xC0, 10 << 3]);
        frame.extend_from_slice(&5u64.to_le_bytes());
        frame.extend_from_slice(&block_header(true, RAW_BLOCK, 5));
        frame.extend_from_slice(b"hello");
        assert_eq!(zstd_decodes(&frame, 5), Ok(5));
        assert_eq!(check(&frame, 5), FAIL);
        // The shortest field for 5 bytes without a single segment is four bytes wide.
        let mut four = ZSTD_MAGIC.to_vec();
        four.extend_from_slice(&[0x80, 10 << 3]);
        four.extend_from_slice(&5u32.to_le_bytes());
        four.extend_from_slice(&block_header(true, RAW_BLOCK, 5));
        four.extend_from_slice(b"hello");
        assert_eq!(zstd_decodes(&four, 5), Ok(5));
        assert_eq!(check(&four, 5), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn a_block_over_the_block_maximum_fails_although_libzstd_decodes_it() {
        let mib = 1u32 << 20;
        let one_rle = blocks_frame(mib, &[(RLE_BLOCK, mib, &[0])]);
        assert_eq!(zstd_decodes(&one_rle, 1 << 20), Ok(1 << 20));
        assert_eq!(check(&one_rle, 1 << 20), FAIL);
        let max = u32::try_from(MAX_BLOCK).expect("small");
        let rle_over = blocks_frame(max + 1, &[(RLE_BLOCK, max + 1, &[0])]);
        assert_eq!(check(&rle_over, MAX_BLOCK + 1), FAIL);
        let content = vec![7u8; 128 * 1024 + 1];
        let raw_over = raw_frame(&content, max + 1, 0);
        assert_eq!(zstd_decodes(&raw_over, content.len()), Ok(content.len()));
        assert_eq!(check(&raw_over, MAX_BLOCK + 1), FAIL);
        let raw_at = raw_frame(&content[1..], max, 0);
        assert_eq!(check(&raw_at, MAX_BLOCK), Ok(()));
        let two = blocks_frame(
            max + 1,
            &[(RAW_BLOCK, max, &content[1..]), (RLE_BLOCK, 1, &[7])],
        );
        assert_eq!(check(&two, MAX_BLOCK + 1), Ok(()));
    }

    #[test]
    fn a_block_over_the_window_fails() {
        // The window of a single segment is its content size.
        let rle = blocks_frame(5, &[(RLE_BLOCK, 6, b"a")]);
        assert_eq!(check(&rle, 5), FAIL);
        let compressed = blocks_frame(5, &[(COMPRESSED_BLOCK, 6, b"abcdef")]);
        assert_eq!(check(&compressed, 5), FAIL);
        let at_window = blocks_frame(5, &[(RLE_BLOCK, 5, b"a")]);
        assert_eq!(check(&at_window, 5), Ok(()));
    }

    #[test]
    fn a_block_of_the_reserved_type_fails() {
        let reserved = blocks_frame(5, &[(3, 5, b"hello")]);
        assert_eq!(check(&reserved, 5), FAIL);
    }
}
