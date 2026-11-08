//! A fixed-length array of plain values in its own protected mapping.
#![expect(unsafe_code, reason = "building slices over a mapping the vector owns")]

use std::marker::PhantomData;
use std::mem;
use std::num::NonZeroUsize;

use crate::secure_mem::lock_budget::Budget;
use crate::secure_mem::region::{Refusal, Region};
use crate::secure_mem::{Fallback, Level, MemError};
use crate::secure_mem::{buffer_level, global};

/// `len` values of `T` in a locked mapping if `RLIMIT_MEMLOCK` allows, else in one left out of core
/// dumps. On Linux there is no third choice: if the kernel refuses both mappings (for example once
/// `vm.max_map_count`, 65530 by default, is reached, as each vector is three memory areas: two
/// guard pages and its data), the vector is not made, rather than put plaintext on a heap that core
/// dumps include. Each vector also costs up to seven system calls over its life (`mmap`, two
/// `mprotect`s, two `madvise`s, `mlock` when it is locked, and `munmap`) and at least one whole
/// page; see [`SecretBuf`](crate::secure_mem::SecretBuf). Only under Miri and on other systems,
/// which have no such mappings here, is it the heap: wiped before it is freed, but not locked,
/// guarded, or kept out of core dumps and forked children.
///
/// It is never in `memfd_secret`; the
/// [`secure_mem`](crate::secure_mem#why-plaintext-stays-out-of-secret-memory) docs say why.
///
/// The length is fixed, so the values are never copied by a reallocation, and the mapping is
/// wiped before it is freed. `T: Copy` means no element needs dropping.
pub(crate) struct SecretVec<T> {
    region: Option<Region>,
    len: usize,
    elements: PhantomData<T>,
}

impl<T: Copy + Default> SecretVec<T> {
    /// Rejects at compile time a `T` aligned beyond the smallest page.
    const ALIGNED: () = assert!(mem::align_of::<T>() <= 4096, "pages are 4 KiB aligned");

    /// The levels a vector may get, strongest first. Off Linux and under Miri the mapped levels
    /// are tried too, though they are always refused, so the fallback to the heap is reported
    /// as [`Fallback::Platform`], as it is for keys.
    const TIERS: &[Level] = if cfg!(all(target_os = "linux", not(miri))) {
        &[Level::Locked, Level::DumpExcluded]
    } else {
        &[Level::Locked, Level::DumpExcluded, Level::Heap]
    };

    /// `len` default values, at the strongest [`TIERS`](SecretVec::TIERS) level that has the
    /// memory. A vector below [`Level::Locked`], or refused at every level, records why for
    /// [`Status::buffer_reason`](crate::secure_mem::Status::buffer_reason). Sets up the key
    /// pool with [`Config::default`](crate::secure_mem::Config::default) first if there is
    /// none, whatever `len` is.
    ///
    /// # Errors
    ///
    /// - [`MemError::TooLarge`] if the values, rounded up to whole pages and with two guard pages,
    ///   would pass `isize::MAX` bytes. No level is tried and no reason recorded.
    /// - [`MemError::MapFailed`] if every level was refused.
    pub(crate) fn try_new(len: usize) -> Result<Self, MemError> {
        let () = Self::ALIGNED;
        // Before anything is locked, so the share of `RLIMIT_MEMLOCK` kept for keys is that of
        // the pool every later key uses, and an `init` after this buffer is refused instead of
        // getting a share this buffer may hold part of (see `secure_mem::init`).
        global::set_up_pool();
        let bytes = len
            .checked_mul(mem::size_of::<T>())
            .ok_or(MemError::TooLarge)?;
        let Some(pages) = NonZeroUsize::new(bytes.div_ceil(Region::page_size())) else {
            return Ok(Self {
                region: None,
                len,
                elements: PhantomData,
            });
        };
        if !Region::fits(pages) {
            return Err(MemError::TooLarge);
        }
        let mut last_refusal: Option<Refusal> = None;
        for level in Self::TIERS {
            match Region::new(*level, pages, Budget::Buffers) {
                Ok(region) => {
                    let reason = Fallback::cause(*level, region.level(), last_refusal);
                    buffer_level::record(region.level(), reason);
                    return Ok(Self::filled(region, len));
                }
                Err(refusal) => last_refusal = Some(refusal),
            }
        }
        if let Some(refusal) = last_refusal {
            buffer_level::record_refusal(refusal.fallback());
        }
        Err(MemError::MapFailed)
    }

    /// `len` default values at the start of `region`, which holds at least
    /// `len * size_of::<T>()` bytes.
    fn filled(region: Region, len: usize) -> Self {
        let start = region.as_ptr().cast::<T>();
        for index in 0..len {
            // SAFETY: the region holds at least `len * size_of::<T>()` bytes, is page-aligned
            // and so aligned for `T`, and only this vector refers to it.
            unsafe { start.add(index).write(T::default()) };
        }
        Self {
            region: Some(region),
            len,
            elements: PhantomData,
        }
    }

    /// The values.
    pub(crate) fn as_slice(&self) -> &[T] {
        match &self.region {
            // SAFETY: `try_new` initialised `len` values at the start of the region, which lives as
            // long as `self`; `&self` rules out a mutable reference.
            Some(region) => unsafe {
                std::slice::from_raw_parts(region.as_ptr().cast::<T>(), self.len)
            },
            None => &[],
        }
    }

    /// The values, mutably.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        match &self.region {
            // SAFETY: as in `as_slice`; `&mut self` makes this the only reference.
            Some(region) => unsafe {
                std::slice::from_raw_parts_mut(region.as_ptr().cast::<T>(), self.len)
            },
            None => &mut [],
        }
    }

    /// The protection the values got; `None` for an empty vector, which maps nothing.
    pub(crate) fn level(&self) -> Option<Level> {
        self.region.as_ref().map(Region::level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_start_at_default_and_keep_writes() {
        let mut vec = SecretVec::<u64>::try_new(1000).expect("memory for a test vector");
        assert!(vec.as_slice().iter().all(|value| *value == 0));
        vec.as_mut_slice()[999] = 7;
        assert_eq!(vec.as_slice()[999], 7);
        assert_eq!(vec.as_slice().len(), 1000);
    }

    /// The level every non-empty vector gets in this build.
    fn expected_levels() -> std::ops::RangeInclusive<Level> {
        if cfg!(all(target_os = "linux", not(miri))) {
            Level::DumpExcluded..=Level::Locked
        } else {
            Level::Heap..=Level::Heap
        }
    }

    /// Checks `vec` holds `len` default values, aligned for `T`, whose last can be set to
    /// `last` and read back, at a level this build gives. `word` reads a value's last `u64`.
    fn check_sizes<T: Copy + Default>(
        vec: &mut SecretVec<T>,
        len: usize,
        last: T,
        word: fn(&T) -> u64,
    ) {
        let zero = word(&T::default());
        assert_eq!(vec.as_slice().len(), len);
        assert!(vec.as_slice().iter().all(|value| word(value) == zero));
        assert!(vec.as_slice().as_ptr().is_aligned(), "{len}");
        vec.as_mut_slice()[len - 1] = last;
        assert_eq!(word(&vec.as_slice()[len - 1]), word(&last), "{len}");
        assert_eq!(word(&vec.as_slice()[0]) == word(&last), len == 1, "{len}");
        let level = vec.level().expect("a non-empty vector maps memory");
        assert!(expected_levels().contains(&level), "{len}: {level}");
    }

    #[test]
    fn every_length_around_a_page_is_whole_and_usable() {
        let page = Region::page_size();
        for len in [1, page - 1, page, page + 1, 3 * page + 7] {
            check_sizes(
                &mut SecretVec::<u8>::try_new(len).expect("memory for a test vector"),
                len,
                0xa5,
                |byte| u64::from(*byte),
            );
            let mut buf =
                crate::secure_mem::SecretBuf::try_zeroed(len).expect("memory for a test buffer");
            assert_eq!(buf.len(), len);
            buf.as_mut_slice()[len - 1] = 0x5a;
            assert_eq!(buf[len - 1], 0x5a);
            assert!(
                buf.level()
                    .is_some_and(|level| expected_levels().contains(&level))
            );
        }
    }

    /// Argon2's 1 KiB blocks are 64-byte aligned, which the page-aligned mapping gives, and a
    /// vector of them spans whole blocks, crossing pages where it must.
    #[test]
    fn argon2_blocks_are_aligned_and_whole() {
        use argon2::Block;

        assert_eq!(
            (mem::size_of::<Block>(), mem::align_of::<Block>()),
            (1024, 64)
        );
        let mut last = Block::default();
        last.as_mut()[127] = 7;
        for len in [1, 4, 5, 9] {
            let mut blocks = SecretVec::<Block>::try_new(len).expect("memory for a test vector");
            assert_eq!(blocks.as_slice().as_ptr().addr() % 64, 0);
            check_sizes(&mut blocks, len, last, |block| block.as_ref()[127]);
        }
    }

    #[test]
    fn a_length_past_the_address_space_is_too_large_not_a_map_failure() {
        let page = Region::page_size();
        // Far past `isize::MAX`; at it; and a page below it, which the guard pages push past.
        for bytes in [
            usize::MAX,
            isize::MAX.unsigned_abs(),
            isize::MAX.unsigned_abs() - page,
        ] {
            assert_eq!(
                SecretVec::<u8>::try_new(bytes).err(),
                Some(MemError::TooLarge),
                "{bytes}"
            );
        }
        assert_eq!(
            SecretVec::<u64>::try_new(usize::MAX).err(),
            Some(MemError::TooLarge),
            "the byte count overflows"
        );
    }

    /// Off Linux and under Miri a vector is on the heap, and `status` says why, as for keys.
    #[cfg(not(all(target_os = "linux", not(miri))))]
    #[test]
    fn without_protected_memory_a_vector_says_why_it_is_on_the_heap() {
        let vec = SecretVec::<u8>::try_new(1).expect("memory for a test vector");
        assert_eq!(vec.level(), Some(Level::Heap));
        let status = crate::secure_mem::status();
        assert_eq!(status.buffer_level, Some(Level::Heap));
        assert_eq!(status.buffer_reason, Some(Fallback::Platform));
    }

    #[test]
    fn empty_maps_nothing() {
        let mut vec = SecretVec::<u8>::try_new(0).expect("memory for a test vector");
        assert_eq!(&*vec.as_mut_slice(), &[] as &[u8]);
        assert_eq!(vec.level(), None);
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn plaintext_never_goes_in_secret_memory() {
        let vec = SecretVec::<u8>::try_new(10).expect("memory for a test vector");
        let level = vec.level().expect("a non-empty vector maps memory");
        assert!((Level::DumpExcluded..=Level::Locked).contains(&level));
    }
}
