//! A decoded inner plaintext, borrowed from the opened blob.

use std::fmt;

use crate::inner::Comp;

/// The checked fields of an inner plaintext (FS-54), borrowing its payload.
#[derive(Clone, Copy)]
pub struct InnerView<'a> {
    comp: Comp,
    payload: &'a [u8],
}

impl<'a> InnerView<'a> {
    /// A view of checked fields.
    pub(crate) const fn new(comp: Comp, payload: &'a [u8]) -> Self {
        Self { comp, payload }
    }

    /// How the payload is stored.
    #[must_use]
    pub const fn comp(&self) -> Comp {
        self.comp
    }

    /// The payload: the chunk itself, or one zstd frame of it.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Prints the compression and length only: the payload is plaintext.
impl fmt::Debug for InnerView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InnerView")
            .field("comp", &self.comp)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_shows_no_payload() {
        let view = InnerView::new(Comp::Raw, b"secret");
        let text = format!("{view:?}");
        assert_eq!(text, "InnerView { comp: Raw, payload_len: 6 }");
    }
}
