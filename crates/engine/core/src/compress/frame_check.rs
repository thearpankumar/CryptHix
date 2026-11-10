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

/// Checks that `frame` is exactly one zstd frame as FS-53 writes it, declaring `plain_len`
/// bytes of content: the zstd magic (so no skippable frame), the unused and reserved bits
/// clear, no checksum, no dictionary ID, a content size equal to `plain_len` in the shortest
/// field that holds it, a window of at most 1 MiB, and no bytes after the frame. Every failure
/// is `Decompress`.
///
/// zstd checks the content against the declared size while decoding; these checks make sure
/// the declaration exists and matches before a byte is decoded. libzstd 1.5.7 ignores the
/// unused bit and reads a content size from a wider field than needed (RFC 8878 allows both
/// to a decoder); its encoder never writes either, so a frame with them is not one FS-53
/// writes and is refused here.
pub(crate) fn frame_check(frame: &[u8], plain_len: u64) -> Result<(), FormatError> {
    let fail = FormatError::Decompress;
    let Some((magic, rest)) = frame.split_first_chunk::<4>() else {
        return Err(fail);
    };
    if *magic != ZSTD_MAGIC {
        return Err(fail);
    }
    let Some((&descriptor, rest)) = rest.split_first() else {
        return Err(fail);
    };
    if descriptor & (UNUSED | RESERVED | CHECKSUM | DICT_ID) != 0 {
        return Err(fail);
    }
    let single_segment = descriptor & SINGLE_SEGMENT != 0;
    if descriptor >> FCS_FLAG_SHIFT == 0 && !single_segment {
        // No content size at all.
        return Err(fail);
    }
    if descriptor >> FCS_FLAG_SHIFT != fcs_flag(plain_len, single_segment) {
        return Err(fail);
    }
    if !single_segment {
        let window = rest.first().map(|&byte| window_size(byte)).ok_or(fail)?;
        if window > MAX_PLAIN_LEN {
            return Err(fail);
        }
    }
    match zstd_safe::get_frame_content_size(frame) {
        Ok(Some(size)) if size == plain_len => {}
        _ => return Err(fail),
    }
    match zstd_safe::find_frame_compressed_size(frame) {
        Ok(size) if size == frame.len() => Ok(()),
        _ => Err(fail),
    }
}

/// The frame content size flag of the shortest field that holds `size` (RFC 8878 section
/// 3.1.1.1.1), as libzstd's encoder chooses it: one byte only in a single-segment frame, two
/// bytes with an offset of 256, four, then eight from `0xFFFF_FFFF` on.
fn fcs_flag(size: u64, single_segment: bool) -> u8 {
    match size {
        0..256 if single_segment => 0,
        256..65_792 => 1,
        0..0xFFFF_FFFF => 2,
        _ => 3,
    }
}

/// The window size a window descriptor byte declares (RFC 8878 section 3.1.1.1.2).
fn window_size(descriptor: u8) -> u64 {
    let window_log = 10 + u32::from(descriptor >> 3);
    let base = 1u64 << window_log;
    base + (base / 8) * u64::from(descriptor & 0x07)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A frame of one raw block holding `content`, declaring `declared` bytes in the shortest
    /// field, with the given descriptor bits and, if `window` is `Some`, that window descriptor
    /// instead of a single segment.
    pub(crate) fn raw_frame(
        content: &[u8],
        declared: u32,
        extra: u8,
        window: Option<u8>,
    ) -> Vec<u8> {
        let flag = fcs_flag(u64::from(declared), window.is_none());
        sized_frame(content, declared, flag, extra, window)
    }

    /// [`raw_frame`] with the content size in the field that `flag` names.
    fn sized_frame(
        content: &[u8],
        declared: u32,
        flag: u8,
        extra: u8,
        window: Option<u8>,
    ) -> Vec<u8> {
        let mut frame = ZSTD_MAGIC.to_vec();
        let mut descriptor = (flag << FCS_FLAG_SHIFT) | extra;
        if window.is_none() {
            descriptor |= SINGLE_SEGMENT;
        }
        frame.push(descriptor);
        frame.extend(window);
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
        let block = u32::try_from(content.len()).expect("small") << 3 | 1;
        frame.extend_from_slice(&block.to_le_bytes()[..3]);
        frame.extend_from_slice(content);
        frame
    }

    fn check(frame: &[u8], plain_len: u64) -> Result<(), FormatError> {
        frame_check(frame, plain_len)
    }

    const FAIL: Result<(), FormatError> = Err(FormatError::Decompress);

    #[test]
    fn window_descriptors_decode_as_rfc_8878_says() {
        assert_eq!(window_size(0), 1 << 10);
        assert_eq!(window_size(10 << 3), 1 << 20);
        assert_eq!(window_size(10 << 3 | 1), (1 << 20) + (1 << 17));
        assert_eq!(window_size(9 << 3 | 7), (1 << 19) + 7 * (1 << 16));
        assert_eq!(window_size(11 << 3), 1 << 21);
        assert_eq!(window_size(u8::MAX), (1 << 41) + 7 * (1 << 38));
    }

    #[test]
    fn short_and_foreign_input_fails_before_calling_zstd() {
        for frame in [
            &b""[..],
            b"\x28\xB5\x2F",
            b"\x28\xB5\x2F\xFD",
            b"PK\x03\x04\x00\x00",
        ] {
            assert_eq!(check(frame, 0), FAIL, "{frame:?}");
        }
        let mut skippable = raw_frame(b"x", 1, 0, None);
        skippable[..4].copy_from_slice(&0x184D_2A50_u32.to_le_bytes());
        assert_eq!(check(&skippable, 1), FAIL);
        for bit in [UNUSED, RESERVED, CHECKSUM, 1, 2, 3] {
            assert_eq!(check(&raw_frame(b"x", 1, bit, None), 1), FAIL, "{bit}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn a_raw_frame_passes() {
        assert_eq!(check(&raw_frame(b"hello", 5, 0, None), 5), Ok(()));
        assert_eq!(check(&raw_frame(b"", 0, 0, None), 0), Ok(()));
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn the_content_size_must_be_declared_and_equal() {
        let frame = raw_frame(b"hello", 5, 0, None);
        assert_eq!(check(&frame, 4), FAIL);
        assert_eq!(check(&frame, 6), FAIL);
        // No content size: descriptor 0 and a window descriptor.
        let mut no_size = ZSTD_MAGIC.to_vec();
        no_size.extend_from_slice(&[0x00, 0x00, 0x29, 0, 0]);
        no_size.extend_from_slice(b"hello");
        assert_eq!(check(&no_size, 5), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn exactly_one_frame_and_nothing_after_it() {
        let frame = raw_frame(b"hello", 5, 0, None);
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
    }

    #[test]
    fn content_size_flags_are_the_shortest_field() {
        assert_eq!(fcs_flag(0, true), 0);
        assert_eq!(fcs_flag(255, true), 0);
        assert_eq!(fcs_flag(255, false), 2, "one byte only in a single segment");
        assert_eq!(fcs_flag(256, true), 1);
        assert_eq!(fcs_flag(65_791, false), 1);
        assert_eq!(fcs_flag(65_792, true), 2);
        assert_eq!(fcs_flag(0xFFFF_FFFE, true), 2);
        assert_eq!(fcs_flag(0xFFFF_FFFF, true), 3);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn a_content_size_field_wider_than_needed_fails() {
        // Each of these decodes with libzstd 1.5.7.
        for flag in [2, 3] {
            let frame = sized_frame(b"hello", 5, flag, 0, None);
            let mut out = [0u8; 5];
            assert_eq!(zstd_safe::decompress(&mut out[..], &frame), Ok(5), "{flag}");
            assert_eq!(check(&frame, 5), FAIL, "{flag}");
        }
        let long = vec![b'a'; 300];
        assert_eq!(check(&sized_frame(&long, 300, 1, 0, None), 300), Ok(()));
        assert_eq!(check(&sized_frame(&long, 300, 2, 0, None), 300), FAIL);
        let windowed = sized_frame(b"hello", 5, 3, 0, Some(10 << 3));
        assert_eq!(check(&windowed, 5), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn the_unused_bit_fails_although_libzstd_ignores_it() {
        let frame = raw_frame(b"hello", 5, UNUSED, None);
        let mut out = [0u8; 5];
        assert_eq!(zstd_safe::decompress(&mut out[..], &frame), Ok(5));
        assert_eq!(check(&frame, 5), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn the_window_is_at_most_one_mib() {
        let at_cap = raw_frame(b"hello", 5, 0, Some(10 << 3));
        assert_eq!(check(&at_cap, 5), Ok(()));
        let over = raw_frame(b"hello", 5, 0, Some(10 << 3 | 1));
        assert_eq!(check(&over, 5), FAIL);
        let double = raw_frame(b"hello", 5, 0, Some(11 << 3));
        assert_eq!(check(&double, 5), FAIL);
    }
}
