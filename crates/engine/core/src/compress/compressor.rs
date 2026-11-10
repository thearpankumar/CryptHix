//! The write side of FS-53.

use std::fmt;

use crypthix_crypto::secure_mem::SecretBuf;
use crypthix_types::format_error::FormatError;
use zstd_safe::{CCtx, CParameter};

use crate::blob::ObjectClass;
use crate::compress::{self, CompressError};
use crate::error::WriteError;
use crate::inner::{self, Comp};
use crate::limits::{MAX_CHUNK, WINDOW_LOG, ZSTD_LEVEL};

/// Turns chunks into inner plaintexts (FS-53, FS-54), reusing one zstd context and one scratch
/// buffer of protected memory for the frame.
///
/// The frame is one zstd frame at level 3 with its content size, no checksum, no dictionary
/// ID and a window of at most 1 MiB. It is kept only if `16 × frame ≤ 15 × chunk`
/// ([`keep_compressed`](compress::keep_compressed)); otherwise, and always for the secret
/// class, the chunk is stored raw.
pub struct Compressor {
    cctx: CCtx<'static>,
    /// Large enough for the frame of a maximum chunk. The part zstd is given, the bound of the
    /// chunk, is wiped after each use.
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
        #[cfg(test)]
        crate::fault::allocation()?;
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
            ObjectClass::Secret => return inner::encode_inner(Comp::Raw, chunk),
            ObjectClass::Ordinary => {}
        }
        // zstd is given only the bound of this chunk, so the slice to wipe afterwards grows with
        // the chunk, not with the buffer. The scratch buffer holds the bound of a maximum chunk,
        // so this cannot fail; failing instead keeps this panic-free.
        let bound = zstd_safe::compress_bound(chunk.len());
        let Some(scratch) = self.scratch.as_mut_slice().get_mut(..bound) else {
            return Err(CompressError::Zstd("chunk bound longer than the scratch buffer").into());
        };
        let compressed = self.cctx.compress2(&mut *scratch, chunk);
        #[cfg(test)]
        let compressed = crate::fault::compress(compressed);
        let inner = match compressed {
            // zstd never reports more than the buffer it was given; failing instead keeps this
            // panic-free.
            Ok(written) => match scratch.get(..written) {
                Some(frame)
                    if compress::keep_compressed(frame.len() as u64, chunk.len() as u64) =>
                {
                    inner::encode_inner(Comp::Zstd, frame)
                }
                Some(_) => inner::encode_inner(Comp::Raw, chunk),
                None => Err(CompressError::Zstd("frame longer than its buffer").into()),
            },
            Err(code) => Err(CompressError::from_code(code).into()),
        };
        // libzstd writes past the length it returns: its bit streams flush whole words, 3 to 7
        // bytes past the frame, and the tests below see up to 53 for some chunks. It never
        // writes past the slice it was given, so that whole slice is wiped on every path, not
        // only the frame.
        scratch.fill(0);
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
    use crypthix_crypto::secure_mem::MemError;

    use super::*;
    use crate::compress::frame_check;
    use crate::fault::{self, Fault};
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
        let view = inner::decode_inner(&inner).expect("well formed");
        assert_eq!(view.comp(), Comp::Zstd);
        assert!(view.payload().len() < 1_000);
        assert_eq!(frame_check::frame_check(view.payload(), 100_000), Ok(()));
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
            assert_eq!(
                frame_check::frame_check(&frame, len as u64),
                Ok(()),
                "{len}"
            );
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
        let view = inner::decode_inner(&inner).expect("well formed");
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
        let view = inner::decode_inner(&inner).expect("well formed");
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
        assert_eq!(
            inner::decode_inner(&inner).map(|view| view.comp()),
            Ok(Comp::Zstd)
        );
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
        assert_eq!(
            inner::decode_inner(&inner).map(|view| view.comp()),
            Ok(Comp::Raw)
        );
        let mut frame = vec![0u8; zstd_safe::compress_bound(chunk.len())];
        let mut cctx = CCtx::create();
        cctx.set_parameter(CParameter::CompressionLevel(ZSTD_LEVEL))
            .expect("sets");
        let written = cctx
            .compress2(frame.as_mut_slice(), &chunk)
            .expect("compresses");
        assert!(written < chunk.len(), "zstd did save a little");
    }

    /// Chunks of text, random bytes and both, at which zstd writes past the length it returns.
    fn residue_chunks() -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        for len in [100, 1_000, 5_000, 70_000, 300_000] {
            chunks.push(text(len));
            chunks.push(pseudo_random(4, len));
            let mut mixed = pseudo_random(5, len / 2);
            mixed.extend(b"abc".iter().copied().cycle().take(len - len / 2));
            chunks.push(mixed);
        }
        chunks
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn zstd_writes_past_the_frame_it_reports() {
        const MARK: u8 = 0xA5;
        let mut compressor = Compressor::new().expect("context");
        let mut most = 0;
        for chunk in residue_chunks() {
            let mut out = vec![MARK; zstd_safe::compress_bound(chunk.len())];
            let written = compressor
                .cctx
                .compress2(&mut out[..], &chunk)
                .expect("compresses");
            let touched = out
                .iter()
                .rposition(|byte| *byte != MARK)
                .map_or(0, |at| at + 1);
            most = most.max(touched.saturating_sub(written));
        }
        // More than a word: wiping the frame and a word after it would leave bytes behind.
        assert!(most > 8, "zstd wrote at most {most} bytes past the frame");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn nothing_zstd_wrote_survives_in_the_scratch_buffer() {
        const MARK: u8 = 0xA5;
        let mut compressor = Compressor::new().expect("context");
        for chunk in residue_chunks() {
            compressor.scratch.as_mut_slice().fill(MARK);
            compressor
                .encode_chunk(&chunk, ObjectClass::Ordinary)
                .expect("encodes");
            let bound = zstd_safe::compress_bound(chunk.len());
            let (given, beyond) = compressor.scratch.as_slice().split_at(bound);
            assert!(
                given.iter().all(|byte| *byte == 0),
                "residue in the slice zstd was given, for {} bytes",
                chunk.len()
            );
            assert!(
                beyond.iter().all(|byte| *byte == MARK),
                "zstd wrote past its slice for {} bytes",
                chunk.len()
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn frames_are_single_segment_at_every_size() {
        // libzstd shrinks the window to the content size, so it writes no window descriptor
        // (FS-53): at every size near a power of two and at a stride up to 1 MiB.
        let mut compressor = Compressor::new().expect("context");
        let mut lengths: Vec<usize> = (0..300).collect();
        lengths.extend((10..=20).flat_map(|log| [(1 << log) - 1, 1 << log, (1 << log) + 1]));
        lengths.extend((1..64).map(|step| step * 16_411));
        lengths.retain(|len| *len <= MAX_CHUNK);
        let random = pseudo_random(6, MAX_CHUNK);
        for len in lengths {
            for chunk in [text(len), random[..len].to_vec(), vec![0; len]] {
                let mut frame = vec![0u8; zstd_safe::compress_bound(len)];
                let written = compressor
                    .cctx
                    .compress2(&mut frame[..], &chunk)
                    .expect("compresses");
                frame.truncate(written);
                assert_eq!(frame[4] & 0x20, 0x20, "{len} bytes");
                assert_eq!(
                    frame_check::frame_check(&frame, len as u64),
                    Ok(()),
                    "{len} bytes"
                );
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn a_zstd_error_wipes_the_scratch_and_never_stores_raw() {
        const MARK: u8 = 0xA5;
        // ZSTD_error_GENERIC, as a negated size_t; injected after zstd has written its frame.
        let code = 0usize.wrapping_sub(1);
        let mut compressor = Compressor::new().expect("context");
        for (chunk, class) in [
            (text(100_000), ObjectClass::Ordinary),
            (pseudo_random(7, 70_000), ObjectClass::Ordinary),
        ] {
            compressor.scratch.as_mut_slice().fill(MARK);
            let guard = fault::inject(Fault::Compress(code));
            assert_eq!(
                compressor.encode_chunk(&chunk, class).map(|_| ()),
                Err(WriteError::Zstd(CompressError::from_code(code))),
                "a failed frame is an error, not a raw chunk"
            );
            assert!(fault::fired(), "the compressor called zstd");
            drop(guard);
            let bound = zstd_safe::compress_bound(chunk.len());
            let (given, beyond) = compressor.scratch.as_slice().split_at(bound);
            assert!(
                given.iter().all(|byte| *byte == 0),
                "zstd's output survives a failed call"
            );
            assert!(beyond.iter().all(|byte| *byte == MARK));
            let again = compressor
                .encode_chunk(&chunk, class)
                .expect("the next call works");
            assert!(inner::decode_inner(&again).is_ok());
        }
        // A secret chunk never reaches zstd, so the fault stays armed.
        let _guard = fault::inject(Fault::Compress(code));
        compressor
            .encode_chunk(&text(1_000), ObjectClass::Secret)
            .expect("no zstd for the secret class");
        assert!(!fault::fired());
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn no_protected_memory_fails_with_memory() {
        {
            let _guard = fault::inject(Fault::Allocation(0));
            assert_eq!(
                Compressor::new().map(|_| ()),
                Err(WriteError::Memory(MemError::MapFailed)),
                "the scratch buffer"
            );
        }
        let mut compressor = Compressor::new().expect("context");
        for class in [ObjectClass::Ordinary, ObjectClass::Secret] {
            let _guard = fault::inject(Fault::Allocation(0));
            assert_eq!(
                compressor.encode_chunk(&text(10_000), class).map(|_| ()),
                Err(WriteError::Memory(MemError::MapFailed)),
                "the inner plaintext"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn debug_prints_nothing() {
        let compressor = Compressor::new().expect("context");
        assert_eq!(format!("{compressor:?}"), "Compressor(..)");
    }
}
