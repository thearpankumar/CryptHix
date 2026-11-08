//! One mapping of secret memory: the only code that maps, locks, wipes and frees it.

#[cfg(all(target_os = "linux", not(miri)))]
mod mapping;
mod refusal;
#[expect(
    clippy::module_inception,
    reason = "files are named after their main item"
)]
mod region;

pub(crate) use refusal::Refusal;
pub(crate) use region::Region;
