//! The write side of FS-53.

use std::fmt;

use crypthix_crypto::secure_mem::SecretBuf;
use crypthix_types::format_error::FormatError;
use zstd_safe::{CCtx, CParameter};

use crate::blob::ObjectClass;
use crate::compress::{CompressError, keep_compressed};
use crate::error::WriteError;
use crate::inner::{Comp, encode_inner};
use crate::limits::{MAX_CHUNK, WINDOW_LOG, ZSTD_LEVEL};

/// Turns chunks into inner plaintexts (FS-53, FS-54), reusing one zstd context and one scratch
/// buffer of protected memory for the frame.
///
/// The frame is one zstd frame at level 3 with its content size, no checksum, no dictionary
/// ID and a window of at most 1 MiB. It is kept only if `16 × frame ≤ 15 × chunk`
/// ([`keep_compressed`]); otherwise, and always for the secret class, the chunk is stored raw.
pub struct Compressor {
    cctx: CCtx<'static>,
    /// Large enough for the frame of a maximum chunk; wiped after each use.
    scratch: SecretBuf,
}

impl Compressor {
    /// A compressor with the parameters of FS-53.
    ///
    /// # Errors
    ///
    /// - [`WriteError::Zstd`] with [`CompressError::Version`] if the linked libzstd is not
    ///   the version FS-53 pins, as its output could then differ from the test vectors.
    /// - [`WriteError::Zstd`] if zstd cannot make the context or refuses a parameter.
    /// - [`WriteError::Memory`] if protected memory cannot be allocated for the scratch buffer.
    pub fn new() -> Result<Self, WriteError> {
        CompressError::check_version(zstd_safe::version_number())?;
        let mut cctx = CCtx::try_create().ok_or(CompressError::Context)?;
        let parameters = [
            CParameter::CompressionLevel(ZSTD_LEVEL),
            CParameter::ContentSizeFlag(true),
            CParameter::ChecksumFlag(false),
            CParameter::DictIdFlag(false),
            CParameter::WindowLog(WINDOW_LOG),
        ];
        for parameter in parameters {
            cctx.set_parameter(parameter)
                .map_err(CompressError::from_code)?;
        }
        let scratch = SecretBuf::try_zeroed(zstd_safe::compress_bound(MAX_CHUNK))?;
        Ok(Self { cctx, scratch })
    }

    /// The inner plaintext of `chunk`: its zstd frame where that is kept, else the chunk itself
    /// (FS-53, FS-54). Objects of the secret class are never compressed.
    ///
    /// # Errors
    ///
    /// - [`WriteError::Format`] with `Limit` if `chunk` is longer than 1 MiB.
    /// - [`WriteError::Zstd`] if zstd fails. The chunk is then not stored raw instead.
    /// - [`WriteError::Memory`] if protected memory cannot be allocated for the inner plaintext.
    pub fn encode_chunk(
        &mut self,
        chunk: &[u8],
        class: ObjectClass,
    ) -> Result<SecretBuf, WriteError> {
        if chunk.len() > MAX_CHUNK {
            return Err(FormatError::Limit.into());
        }
        match class {
            ObjectClass::Secret => return encode_inner(Comp::Raw, chunk),
            ObjectClass::Ordinary => {}
        }
        let scratch = self.scratch.as_mut_slice();
        let written = match self.cctx.compress2(scratch, chunk) {
            Ok(written) => written,
            Err(code) => {
                // zstd may have written part of a frame, and does not say how much.
                scratch.fill(0);
                return Err(CompressError::from_code(code).into());
            }
        };
        // zstd never reports more than the buffer it was given; failing instead keeps this
        // panic-free.
        let Some(frame) = scratch.get_mut(..written) else {
            scratch.fill(0);
            return Err(CompressError::Zstd("frame longer than its buffer").into());
        };
        let inner = if keep_compressed(frame.len() as u64, chunk.len() as u64) {
            encode_inner(Comp::Zstd, frame)
        } else {
            encode_inner(Comp::Raw, chunk)
        };
        frame.fill(0);
        inner
    }
}

/// Prints nothing of the scratch buffer.
impl fmt::Debug for Compressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Compressor(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::frame_check::frame_check;
    use crate::inner::decode_inner;
    use crate::test_data::pseudo_random;

    fn text(len: usize) -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog. "
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn compressible_chunks_are_kept_as_one_checked_frame() {
        let mut compressor = Compressor::new().expect("context");
        let chunk = text(100_000);
        let inner = compressor
            .encode_chunk(&chunk, ObjectClass::Ordinary)
            .expect("encodes");
        let view = decode_inner(&inner).expect("well formed");
        assert_eq!(view.comp(), Comp::Zstd);
        assert!(view.payload().len() < 1_000);
        assert_eq!(frame_check(view.payload(), 100_000), Ok(()));
        // No checksum, no dictionary ID, content size declared.
        assert_eq!(view.payload()[4] & 0x0F, 0);
        let again = compressor
            .encode_chunk(&chunk, ObjectClass::Ordinary)
            .expect("encodes");
        assert_eq!(
            inner.as_slice(),
            again.as_slice(),
            "the encoder is deterministic"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn frames_pass_the_reader_checks_at_every_content_size_field() {
        // One, two and four-byte content sizes, at the edges where the field widens.
        let mut compressor = Compressor::new().expect("context");
        for len in [0, 1, 255, 256, 257, 65_791, 65_792, MAX_CHUNK] {
            let chunk = text(len);
            let mut frame = vec![0u8; zstd_safe::compress_bound(len)];
            let written = compressor
                .cctx
                .compress2(&mut frame[..], &chunk)
                .expect("compresses");
            frame.truncate(written);
            assert_eq!(frame_check(&frame, len as u64), Ok(()), "{len}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn incompressible_chunks_are_raw() {
        let mut compressor = Compressor::new().expect("context");
        let chunk = pseudo_random(1, 70_000);
        let inner = compressor
            .encode_chunk(&chunk, ObjectClass::Ordinary)
            .expect("encodes");
        let view = decode_inner(&inner).expect("well formed");
        assert_eq!(view.comp(), Comp::Raw);
        assert_eq!(view.payload(), chunk.as_slice());
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn secret_chunks_are_never_compressed() {
        let mut compressor = Compressor::new().expect("context");
        let chunk = text(100_000);
        let inner = compressor
            .encode_chunk(&chunk, ObjectClass::Secret)
            .expect("encodes");
        let view = decode_inner(&inner).expect("well formed");
        assert_eq!(view.comp(), Comp::Raw);
        assert_eq!(view.payload(), chunk.as_slice());
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn chunks_up_to_one_mib_and_no_longer() {
        let mut compressor = Compressor::new().expect("context");
        let largest = text(MAX_CHUNK);
        let inner = compressor
            .encode_chunk(&largest, ObjectClass::Ordinary)
            .expect("1 MiB");
        assert_eq!(decode_inner(&inner).map(|view| view.comp()), Ok(Comp::Zstd));
        let random = pseudo_random(2, MAX_CHUNK);
        let raw = compressor
            .encode_chunk(&random, ObjectClass::Ordinary)
            .expect("1 MiB");
        assert_eq!(raw.len(), MAX_CHUNK + (1 << 15));
        for class in [ObjectClass::Ordinary, ObjectClass::Secret] {
            let over = text(MAX_CHUNK + 1);
            assert_eq!(
                compressor.encode_chunk(&over, class).map(|_| ()),
                Err(WriteError::Format(FormatError::Limit))
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn a_chunk_that_compresses_too_little_is_raw() {
        // Random bytes with a compressible run: zstd saves something, but less than 1/16.
        let mut compressor = Compressor::new().expect("context");
        let mut chunk = pseudo_random(3, 16_000);
        chunk[..600].fill(0);
        let inner = compressor
            .encode_chunk(&chunk, ObjectClass::Ordinary)
            .expect("encodes");
        assert_eq!(decode_inner(&inner).map(|view| view.comp()), Ok(Comp::Raw));
        let mut frame = vec![0u8; zstd_safe::compress_bound(chunk.len())];
        let mut cctx = CCtx::create();
        cctx.set_parameter(CParameter::CompressionLevel(ZSTD_LEVEL))
            .expect("sets");
        let written = cctx
            .compress2(frame.as_mut_slice(), &chunk)
            .expect("compresses");
        assert!(written < chunk.len(), "zstd did save a little");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn debug_prints_nothing() {
        let compressor = Compressor::new().expect("context");
        assert_eq!(format!("{compressor:?}"), "Compressor(..)");
    }
}
