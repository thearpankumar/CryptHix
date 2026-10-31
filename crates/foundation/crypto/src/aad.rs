//! The associated data of a CX-AEAD seal (FS-12).

use crypthix_types::registry::{FormatVersion, SuiteId};

use crate::hash;
use crate::label::{AadLabel, HashLabel};

/// A fixed-width AAD: `u8 len(label) ‖ label ‖ fmt ‖ suite ‖ field_1 ‖ … ‖ field_n` (FS-12).
///
/// Every field has a fixed width: IDs at full size, counters as `u32be` or `u64be`.
/// Variable-length data enters only as its hash `H(hash/aad-part, data)`. The encoding is
/// unambiguous because each label has one fixed list of fields (FS-12); the builder does not
/// check that list, the code that builds each structure does.
///
/// ```
/// use crypthix_crypto::aad::Aad;
/// use crypthix_crypto::label::AadLabel;
///
/// let vault_id = [1u8; 16];
/// let aad = Aad::new(AadLabel::Keyring).field(&vault_id).u32be(1);
/// assert_eq!(aad.as_bytes().len(), 1 + "crypthix/v0/aad/keyring".len() + 2 + 2 + 16 + 4);
/// ```
#[must_use]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Aad {
    /// The label, or `None` for raw bytes from a test vector.
    label: Option<AadLabel>,
    bytes: Vec<u8>,
}

impl Aad {
    /// Starts an AAD with its label, followed by `fmt ‖ suite` of format 0.
    pub fn new(label: AadLabel) -> Self {
        let mut bytes = Vec::with_capacity(128);
        label.write_prefix(&mut bytes);
        bytes.extend_from_slice(&FormatVersion::V0.code().to_be_bytes());
        bytes.extend_from_slice(&SuiteId::SUITE_0001.code().to_be_bytes());
        Self {
            label: Some(label),
            bytes,
        }
    }

    /// Starts an AAD with its label, followed by `preamble[0..16]`, which already includes
    /// `fmt` and `suite`; used where a structure gives the preamble, such as a shard header.
    pub fn with_preamble(label: AadLabel, preamble_context: &[u8; 16]) -> Self {
        let mut bytes = Vec::with_capacity(128);
        label.write_prefix(&mut bytes);
        bytes.extend_from_slice(preamble_context);
        Self {
            label: Some(label),
            bytes,
        }
    }

    /// Appends a fixed-width field, such as an ID.
    pub fn field<const N: usize>(mut self, bytes: &[u8; N]) -> Self {
        self.bytes.extend_from_slice(bytes);
        self
    }

    /// Appends a `u8`.
    pub fn u8(mut self, value: u8) -> Self {
        self.bytes.push(value);
        self
    }

    /// Appends a `u32be`.
    pub fn u32be(self, value: u32) -> Self {
        self.field(&value.to_be_bytes())
    }

    /// Appends a `u64be`.
    pub fn u64be(self, value: u64) -> Self {
        self.field(&value.to_be_bytes())
    }

    /// Appends variable-length data as `H(hash/aad-part, data)`.
    pub fn hashed_part(self, data: &[u8]) -> Self {
        self.field(hash::hash(HashLabel::AadPart, data).as_bytes())
    }

    /// Wraps AAD bytes built elsewhere, for the test-vector runners only.
    #[cfg(feature = "vectors")]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { label: None, bytes }
    }

    /// The AAD bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The label the AAD was built with; `None` only for raw vector bytes.
    pub(crate) fn label(&self) -> Option<AadLabel> {
        self.label
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_label_then_format_then_fields() {
        let aad = Aad::new(AadLabel::DekWrap)
            .field(&[0xAA; 16])
            .u8(7)
            .u64be(258);
        let bytes = aad.as_bytes();
        let label = b"crypthix/v0/aad/dek-wrap";
        assert_eq!(usize::from(bytes[0]), label.len());
        assert_eq!(&bytes[1..=label.len()], label);
        let rest = &bytes[1 + label.len()..];
        assert_eq!(&rest[..4], &[0, 0, 0, 1], "fmt 0x0000 then suite 0x0001");
        assert_eq!(&rest[4..20], &[0xAA; 16]);
        assert_eq!(rest[20], 7);
        assert_eq!(&rest[21..], &[0, 0, 0, 0, 0, 0, 1, 2]);
    }

    #[test]
    fn preamble_form_replaces_format_and_suite() {
        let aad = Aad::with_preamble(AadLabel::ShardHeader, &[3; 16]);
        assert_eq!(&aad.as_bytes()[aad.as_bytes().len() - 16..], &[3; 16]);
    }

    #[test]
    fn hashed_part_appends_the_aad_part_hash() {
        let base = Aad::new(AadLabel::ShareSlot);
        let start = base.as_bytes().len();
        let aad = base.hashed_part(&[0; 1000]);
        let expected = hash::hash(HashLabel::AadPart, &[0; 1000]);
        assert_eq!(&aad.as_bytes()[start..], expected.as_bytes().as_slice());
    }
}
