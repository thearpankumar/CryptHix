//! Nested types: envelopes inside other structures (format spec section 5.3).

/// A nested type. Never a file of its own; used only in synthetic preambles (FS-13).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum NestedType {
    /// Manifest, `0x20`.
    Manifest,
    /// Log entry, `0x21`.
    LogEntry,
    /// Device proof of possession, `0x22`.
    DeviceProofOfPossession,
    /// Epoch device wrap, `0x23`.
    EpochDeviceWrap,
}

impl NestedType {
    /// The registry code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            NestedType::Manifest => 0x20,
            NestedType::LogEntry => 0x21,
            NestedType::DeviceProofOfPossession => 0x22,
            NestedType::EpochDeviceWrap => 0x23,
        }
    }
}
