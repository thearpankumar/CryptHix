//! The read side of FS-53.

use std::fmt;

use crypthix_crypto::secure_mem::SecretBuf;
use crypthix_types::format_error::FormatError;
use zstd_safe::{DCtx, DParameter, InBuffer, OutBuffer, ResetDirective};

use crate::compress::CompressError;
use crate::compress::frame_check::frame_check;
use crate::error::ReadError;
use crate::limits::{MAX_PLAIN_LEN, WINDOW_LOG};

/// Decompresses chunk frames into buffers of protected memory of exactly their `plain_len`,
/// reusing one zstd context whose window is capped at 1 MiB (FS-53).
///
/// The context is made at the first frame that gets past the `plain_len` cap, after the
/// version check, so a reader that only meets raw chunks never calls into libzstd.
pub struct Decompressor {
    dctx: Option<DCtx<'static>>,
}

impl Decompressor {
    /// A decompressor whose window will be capped at 1 MiB. It holds no zstd context yet.
    #[must_use]
    pub fn new() -> Self {
        Self { dctx: None }
    }

    /// The `plain_len` bytes `frame` decompresses to.
    ///
    /// In this order, each failure being `Decompress` (FS-53) unless said otherwise:
    /// 1. `plain_len` is at most 1 MiB, checked before anything else;
    /// 2. on first use, the linked libzstd is the version FS-53 pins and a context is made
    ///    ([`ReadError::Zstd`] if not), before any other call into libzstd;
    /// 3. the frame is exactly one frame with no checksum, no dictionary ID, a declared content
    ///    size equal to `plain_len` and a window of at most 1 MiB;
    /// 4. a streaming decoder writes into a buffer of exactly `plain_len` bytes, and must fill
    ///    it, finish the frame and use every input byte; output that does not fit, or a frame
    ///    that ends early, fails.
    ///
    /// # Errors
    ///
    /// - [`ReadError::Format`] with `Decompress` as above.
    /// - [`ReadError::Memory`] if protected memory cannot be allocated for the output.
    /// - [`ReadError::Zstd`] with [`CompressError::Version`] if the linked libzstd is not the
    ///   version FS-53 pins; otherwise if zstd cannot make, set up or reset the context, or
    ///   runs out of memory while decoding (it allocates its stream buffers on first use).
    pub fn decode(&mut self, frame: &[u8], plain_len: u64) -> Result<SecretBuf, ReadError> {
        if plain_len > MAX_PLAIN_LEN {
            return Err(FormatError::Decompress.into());
        }
        let dctx = match &mut self.dctx {
            Some(dctx) => dctx,
            slot @ None => slot.insert(context(zstd_safe::version_number)?),
        };
        frame_check(frame, plain_len)?;
        let len = usize::try_from(plain_len).map_err(|_| FormatError::Decompress)?;
        // A failed call leaves the context unusable until it is reset (zstd.h).
        dctx.reset(ResetDirective::SessionOnly)
            .map_err(|code| ReadError::Zstd(CompressError::from_code(code)))?;
        let mut plain = SecretBuf::try_zeroed(len)?;
        let written = stream(dctx, frame, plain.as_mut_slice())?;
        // Defence in depth: zstd already fails a frame whose content differs from its declared
        // size, and frame_check made that size `plain_len`, so this cannot fail today.
        if written != len {
            return Err(FormatError::Decompress.into());
        }
        Ok(plain)
    }
}

impl Default for Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

/// A decompression context with the window capped at 1 MiB, made only once `linked` reports
/// the libzstd version FS-53 pins: no other call into libzstd comes before that check.
fn context(linked: impl FnOnce() -> u32) -> Result<DCtx<'static>, ReadError> {
    CompressError::check_version(linked()).map_err(ReadError::Zstd)?;
    let mut dctx = DCtx::try_create().ok_or(ReadError::Zstd(CompressError::Context))?;
    dctx.set_parameter(DParameter::WindowLogMax(WINDOW_LOG))
        .map_err(|code| ReadError::Zstd(CompressError::from_code(code)))?;
    Ok(dctx)
}

/// Runs the streaming decoder until the frame ends, and returns how much it wrote.
fn stream(dctx: &mut DCtx<'static>, frame: &[u8], out: &mut [u8]) -> Result<usize, ReadError> {
    let fail = ReadError::Format(FormatError::Decompress);
    let mut output = OutBuffer::around(out);
    let mut input = InBuffer::around(frame);
    loop {
        let before = (input.pos(), output.pos());
        let hint = dctx
            .decompress_stream(&mut output, &mut input)
            .map_err(stream_error)?;
        if hint == 0 {
            break;
        }
        // No progress: the input ended inside the frame, or the output is full and the
        // frame has more to give.
        if (input.pos(), output.pos()) == before {
            return Err(fail);
        }
    }
    // Defence in depth: frame_check found the frame to end exactly at `frame.len()`, and zstd
    // stops at the end of a frame, so this cannot fail today.
    if input.pos() != frame.len() {
        return Err(fail);
    }
    Ok(output.pos())
}

/// What a failed `ZSTD_decompressStream` means: running out of memory is the reader's own
/// trouble, so it must not look like tampering; anything else is the frame's fault.
fn stream_error(code: usize) -> ReadError {
    if CompressError::is_allocation_failure(code) {
        ReadError::Zstd(CompressError::from_code(code))
    } else {
        FormatError::Decompress.into()
    }
}

/// Prints nothing of the context.
impl fmt::Debug for Decompressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Decompressor(..)")
    }
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::{any, prop_assert_eq, proptest};
    use zstd_safe::{CCtx, CParameter};

    use super::*;
    use crate::compress::frame_check::tests::raw_frame;

    const FAIL: Result<Vec<u8>, ReadError> = Err(ReadError::Format(FormatError::Decompress));

    fn decode(frame: &[u8], plain_len: u64) -> Result<Vec<u8>, ReadError> {
        Decompressor::new()
            .decode(frame, plain_len)
            .map(|plain| plain.to_vec())
    }

    /// A frame of `data` with the given extra parameters.
    fn frame_of(data: &[u8], parameters: &[CParameter]) -> Vec<u8> {
        let mut cctx = CCtx::create();
        for parameter in parameters {
            cctx.set_parameter(*parameter).expect("sets");
        }
        let mut frame = vec![0u8; zstd_safe::compress_bound(data.len())];
        let written = cctx
            .compress2(frame.as_mut_slice(), data)
            .expect("compresses");
        frame.truncate(written);
        frame
    }

    fn text(len: usize) -> Vec<u8> {
        b"0123456789abcdef"
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    #[test]
    fn another_libzstd_is_refused_before_any_call_into_it() {
        assert_eq!(
            context(|| 10_508).map(|_| ()),
            Err(ReadError::Zstd(CompressError::Version(10_508)))
        );
    }

    #[test]
    fn nothing_touches_libzstd_before_the_first_frame_past_the_cap() {
        let mut decompressor = Decompressor::default();
        assert_eq!(format!("{decompressor:?}"), "Decompressor(..)");
        assert_eq!(
            decompressor
                .decode(b"not even a frame", (1 << 20) + 1)
                .map(|_| ()),
            Err(ReadError::Format(FormatError::Decompress))
        );
        assert!(
            decompressor.dctx.is_none(),
            "no context for a refused length"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn the_context_is_made_once_and_kept() {
        let mut decompressor = Decompressor::new();
        assert!(decompressor.dctx.is_none());
        assert_eq!(
            decompressor.decode(b"not even a frame", 5).map(|_| ()),
            Err(ReadError::Format(FormatError::Decompress))
        );
        assert!(decompressor.dctx.is_some(), "made at the first frame");
        let plain = decompressor
            .decode(&raw_frame(b"hello", 5, 0, None), 5)
            .expect("decodes");
        assert_eq!(plain.as_slice(), b"hello");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn frames_decode_to_exactly_their_length() {
        let data = text(300_000);
        let frame = frame_of(&data, &[]);
        assert_eq!(decode(&frame, 300_000), Ok(data));
        assert_eq!(
            decode(&raw_frame(b"hello", 5, 0, None), 5),
            Ok(b"hello".to_vec())
        );
        assert_eq!(decode(&raw_frame(b"", 0, 0, None), 0), Ok(Vec::new()));
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn plain_len_is_capped_at_one_mib_first() {
        let data = text(1 << 20);
        let frame = frame_of(&data, &[]);
        assert_eq!(decode(&frame, 1 << 20), Ok(data));
        let over = text((1 << 20) + 1);
        let frame = frame_of(&over, &[CParameter::WindowLog(20)]);
        assert_eq!(decode(&frame, (1 << 20) + 1), FAIL);
        assert_eq!(decode(b"not even a frame", u64::MAX), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn content_longer_or_shorter_than_declared_fails() {
        assert_eq!(decode(&raw_frame(b"hello!", 5, 0, None), 5), FAIL);
        assert_eq!(decode(&raw_frame(b"hell", 5, 0, None), 5), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn frames_with_a_checksum_fail() {
        let data = text(10_000);
        let checksum = frame_of(&data, &[CParameter::ChecksumFlag(true)]);
        assert_eq!(decode(&checksum, 10_000), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn frames_with_a_dictionary_id_fail() {
        // Well-formed frames of one raw block that name dictionary 7, then 0x01020304.
        let mut frame = raw_frame(b"hello", 5, 1, None);
        frame.insert(5, 7);
        assert_eq!(
            zstd_safe::get_dict_id_from_frame(&frame).map(u32::from),
            Some(7)
        );
        assert_eq!(decode(&frame, 5), FAIL);
        let mut frame = raw_frame(b"hello", 5, 3, None);
        frame.splice(5..5, 0x0102_0304_u32.to_le_bytes());
        assert_eq!(
            zstd_safe::get_dict_id_from_frame(&frame).map(u32::from),
            Some(0x0102_0304)
        );
        assert_eq!(decode(&frame, 5), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn frames_without_a_content_size_fail() {
        let data = text(10_000);
        let unknown_size = frame_of(&data, &[CParameter::ContentSizeFlag(false)]);
        assert_eq!(decode(&unknown_size, 10_000), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn running_out_of_memory_while_decoding_is_not_tampering() {
        let allocation = 0usize.wrapping_sub(64);
        assert!(matches!(
            stream_error(allocation),
            ReadError::Zstd(CompressError::Zstd(_))
        ));
        // ZSTD_error_corruption_detected and ZSTD_error_dstSize_tooSmall.
        for code in [0usize.wrapping_sub(20), 0usize.wrapping_sub(70)] {
            assert_eq!(stream_error(code), FormatError::Decompress.into());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn a_window_over_one_mib_fails() {
        // A window descriptor of 2 MiB on content that is small enough.
        assert_eq!(decode(&raw_frame(b"hello", 5, 0, Some(11 << 3)), 5), FAIL);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn corrupt_blocks_fail_and_the_context_recovers() {
        let data = text(50_000);
        let frame = frame_of(&data, &[]);
        let mut decompressor = Decompressor::new();
        let mut corrupt = frame.clone();
        let last = corrupt.len() - 1;
        corrupt[last / 2] ^= 0xFF;
        corrupt[last] ^= 0xFF;
        assert!(decompressor.decode(&corrupt, 50_000).is_err());
        let plain = decompressor
            .decode(&frame, 50_000)
            .expect("a reset context works again");
        assert_eq!(plain.as_slice(), data.as_slice());
    }

    proptest! {
        #[test]
        #[cfg_attr(miri, ignore = "calls into libzstd")]
        fn round_trips_and_wrong_lengths_fail(data in vec(0u8..8, 0..20_000), delta in 1u64..3) {
            let frame = frame_of(&data, &[CParameter::CompressionLevel(3)]);
            let len = data.len() as u64;
            prop_assert_eq!(decode(&frame, len), Ok(data));
            prop_assert_eq!(decode(&frame, len + delta), FAIL);
            if len >= delta {
                prop_assert_eq!(decode(&frame, len - delta), FAIL);
            }
        }

        #[test]
        #[cfg_attr(miri, ignore = "calls into libzstd")]
        fn arbitrary_bytes_never_panic(bytes in vec(any::<u8>(), 0..200), len in 0u64..300) {
            let _ = decode(&bytes, len);
        }
    }
}
