//! The two classes of object (FS-52, FS-53, FS-55).

/// How an object's chunks are cut and written.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ObjectClass {
    /// Cut with keyed FastCDC (FS-52), compressed where it pays (FS-53), and with keyed blob IDs
    /// when the object has two or more chunks, so an unchanged chunk is reused by the next
    /// version (FS-55).
    Ordinary,
    /// Cut at fixed 1 MiB steps without reading the bytes (FS-52), never compressed, so nothing
    /// in the object shares a compression context with its secrets (T-40), and always with
    /// random blob IDs, so nothing is reused (FS-55, T-85).
    Secret,
}
