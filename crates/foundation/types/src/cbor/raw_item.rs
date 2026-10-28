//! Raw CBOR items, kept byte for byte.

use crate::cbor::Decoder;

/// One validated CBOR item, kept as its exact bytes.
///
/// Unknown map entries are carried as raw items so that a structure re-encodes to exactly the
/// bytes it was read from (FS-08, FS-20). A raw item can only come from a validated document, so
/// writing one back never produces non-canonical output.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RawItem<'a> {
    bytes: &'a [u8],
}

impl<'a> RawItem<'a> {
    /// Wraps the bytes of one item that the crate has already validated or encoded.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The encoded bytes of the item.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// A decoder positioned on the item.
    #[must_use]
    pub const fn decoder(&self) -> Decoder<'a> {
        Decoder::new(self.bytes)
    }

    /// An owned copy of the item.
    #[must_use]
    pub fn to_owned_item(&self) -> OwnedRawItem {
        OwnedRawItem {
            bytes: self.bytes.to_vec(),
        }
    }
}

/// An owned copy of a [`RawItem`].
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct OwnedRawItem {
    bytes: Vec<u8>,
}

impl OwnedRawItem {
    /// Borrows the item.
    #[must_use]
    pub fn as_raw(&self) -> RawItem<'_> {
        RawItem::new(&self.bytes)
    }
}
