//! How an app sets up protected memory.

use std::num::NonZeroUsize;

use crate::secure_mem::Level;
use crate::secure_mem::region::Region;

/// The settings of the process-wide key pool, passed once to
/// [`secure_mem::init`](crate::secure_mem::init).
///
/// ```
/// use crypthix_crypto::secure_mem::{Config, Level};
///
/// let config = Config::default()
///     .with_minimum(Level::platform_floor())
///     .with_pages_per_arena(4)
///     .with_max_pages(64);
/// assert_eq!(config.minimum(), Level::platform_floor());
/// assert_eq!(config.max_pages(), 64);
/// ```
///
/// Each setting has a getter of its name and a `with_` method that returns a copy with it
/// changed, as [`Path::with_extension`](std::path::Path::with_extension) does.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Config {
    minimum: Level,
    strongest: Level,
    pages_per_arena: NonZeroUsize,
    /// As set; [`max_pages`](Config::max_pages) raises it to at least `pages_per_arena`, so
    /// the two setters may be called in either order.
    max_pages: usize,
}

impl Config {
    /// The weakest level a key may get. Creating a key fails with
    /// [`MemError::BelowMinimum`](crate::secure_mem::MemError::BelowMinimum) rather than use a
    /// weaker one.
    pub const fn with_minimum(mut self, level: Level) -> Self {
        self.minimum = level;
        self
    }

    /// The strongest level to try first. Lowering it skips the levels above: an app on a
    /// laptop that hibernates may cap keys at [`Level::Locked`], since while a
    /// [`Level::Secret`] page exists the kernel refuses to hibernate.
    pub const fn with_strongest(mut self, level: Level) -> Self {
        self.strongest = level;
        self
    }

    /// Pages in each arena of key slots, raised to at least 1.
    pub const fn with_pages_per_arena(mut self, pages: usize) -> Self {
        self.pages_per_arena = match NonZeroUsize::new(pages) {
            Some(pages) => pages,
            None => NonZeroUsize::MIN,
        };
        self
    }

    /// The most pages all arenas may use together, raised to at least
    /// [`pages_per_arena`](Config::pages_per_arena).
    ///
    /// On Linux, enough of `RLIMIT_MEMLOCK` for these pages and the guard pages of their arenas
    /// is kept for keys: plaintext buffers lock only what is left, so they can never push a key
    /// arena down a level. The pool is set up, with this reserve, before any buffer locks: by
    /// [`init`](crate::secure_mem::init), or with [`Config::default`] by the first key or
    /// buffer, after which `init` fails with
    /// [`MemError::AlreadyInitialised`](crate::secure_mem::MemError::AlreadyInitialised)
    /// rather than keep less than it asks for.
    pub const fn with_max_pages(mut self, pages: usize) -> Self {
        self.max_pages = pages;
        self
    }

    /// The weakest level a key may get.
    #[must_use]
    pub const fn minimum(&self) -> Level {
        self.minimum
    }

    /// The strongest level tried first.
    #[must_use]
    pub const fn strongest(&self) -> Level {
        self.strongest
    }

    /// Pages in each arena.
    #[must_use]
    pub const fn pages_per_arena(&self) -> NonZeroUsize {
        self.pages_per_arena
    }

    /// The most pages all arenas may use together, at least
    /// [`pages_per_arena`](Config::pages_per_arena).
    #[must_use]
    pub const fn max_pages(&self) -> usize {
        if self.max_pages < self.pages_per_arena.get() {
            self.pages_per_arena.get()
        } else {
            self.max_pages
        }
    }

    /// The most bytes of `RLIMIT_MEMLOCK` a pool with this config can charge: every page up to
    /// [`max_pages`](Config::max_pages), plus the two guard pages of each arena, which the lock
    /// budget charges a `memfd_secret` mapping for (see `lock_budget::try_charge`). Saturates at
    /// `usize::MAX`.
    #[cfg_attr(
        not(any(test, all(target_os = "linux", not(miri)))),
        expect(dead_code, reason = "only Linux locks memory")
    )]
    pub(crate) fn lock_reserve(&self) -> usize {
        let arenas = self.max_pages() / self.pages_per_arena;
        arenas
            .saturating_mul(2)
            .saturating_add(self.max_pages())
            .saturating_mul(Region::page_size())
    }
}

/// The arena size of [`Config::default`], checked to be non-zero when this crate is built.
const DEFAULT_PAGES_PER_ARENA: NonZeroUsize = NonZeroUsize::new(4).expect("4 is not zero");

impl Default for Config {
    /// The best level the system gives, down to [`Level::platform_floor`]; arenas of 4 pages,
    /// up to 256 pages. With 4 KiB pages that is 512 keys an arena, 32 768 in all.
    ///
    /// On Linux, with the guard pages of its arenas, 384 pages of `RLIMIT_MEMLOCK` are kept for
    /// keys: with 4 KiB pages 1.5 MiB of the usual 8 MiB limit. Larger pages scale every byte
    /// count: with 64 KiB pages the reserve passes 8 MiB, so keys may lock the whole limit and
    /// buffers are not locked. Elsewhere pages are the 4 KiB heap blocks and nothing is locked.
    fn default() -> Self {
        Self {
            minimum: Level::platform_floor(),
            strongest: Level::Secret,
            pages_per_arena: DEFAULT_PAGES_PER_ARENA,
            max_pages: 256,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_counts_are_at_least_one_and_ordered() {
        let pages = |config: Config| (config.pages_per_arena().get(), config.max_pages());
        let config = Config::default().with_pages_per_arena(0).with_max_pages(0);
        assert_eq!(pages(config), (1, 1));
        let config = Config::default().with_pages_per_arena(8).with_max_pages(2);
        assert_eq!(pages(config), (8, 8));
        let config = Config::default().with_max_pages(2).with_pages_per_arena(8);
        assert_eq!(pages(config), (8, 8), "in either order");
        let config = Config::default().with_max_pages(2).with_pages_per_arena(1);
        assert_eq!(
            pages(config),
            (1, 2),
            "the maximum as set, once arenas are small enough"
        );
    }

    #[test]
    fn the_lock_reserve_covers_every_page_and_guard_the_pool_can_map() {
        let page = Region::page_size();
        assert_eq!(
            Config::default()
                .with_pages_per_arena(1)
                .with_max_pages(4)
                .lock_reserve(),
            (4 + 2 * 4) * page
        );
        // Arenas of 3 pages fit twice into 7, so only 6 pages are ever mapped; the reserve
        // still covers all 7.
        assert_eq!(
            Config::default()
                .with_pages_per_arena(3)
                .with_max_pages(7)
                .lock_reserve(),
            (7 + 2 * 2) * page
        );
        assert_eq!(Config::default().lock_reserve(), (256 + 2 * 64) * page);
        assert_eq!(
            Config::default()
                .with_pages_per_arena(1)
                .with_max_pages(usize::MAX)
                .lock_reserve(),
            usize::MAX
        );
    }

    #[test]
    fn default_tries_secret_first_down_to_the_floor() {
        let config = Config::default();
        assert_eq!(config.strongest(), Level::Secret);
        assert_eq!(config.minimum(), Level::platform_floor());
    }
}
