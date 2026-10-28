//! Decoding limits (FS-11).

const MIB: usize = 1024 * 1024;

/// Limits applied while decoding a CBOR document, before any allocation (FS-11, T-39).
///
/// [`Limits::FORMAT_0`] holds the values of the format spec. A structure may tighten them with
/// the `with_*` methods, which never raise a limit above the format 0 value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Limits {
    document_len: usize,
    depth: usize,
    container_len: u64,
    total_items: u64,
    string_len: u64,
}

impl Limits {
    /// The limits of format 0.
    pub const FORMAT_0: Self = Self {
        document_len: 16 * MIB,
        depth: 8,
        container_len: 1 << 20,
        total_items: 1 << 22,
        string_len: 16 * 1024 * 1024,
    };

    /// Largest document in bytes.
    #[must_use]
    pub const fn max_document_len(&self) -> usize {
        self.document_len
    }

    /// Deepest nesting of arrays and maps; a top-level array or map has depth 1.
    #[must_use]
    pub const fn max_depth(&self) -> usize {
        self.depth
    }

    /// Most items in one array, or entries in one map.
    #[must_use]
    pub const fn max_container_len(&self) -> u64 {
        self.container_len
    }

    /// Most items in one document, counted recursively: every head counts once, containers
    /// included, so a map entry counts as two.
    #[must_use]
    pub const fn max_total_items(&self) -> u64 {
        self.total_items
    }

    /// Longest byte or text string in bytes.
    #[must_use]
    pub const fn max_string_len(&self) -> u64 {
        self.string_len
    }

    /// Lowers the document length limit; a value above the current limit changes nothing.
    #[must_use]
    pub const fn with_max_document_len(mut self, value: usize) -> Self {
        if value < self.document_len {
            self.document_len = value;
        }
        self
    }

    /// Lowers the depth limit; a value above the current limit changes nothing.
    #[must_use]
    pub const fn with_max_depth(mut self, value: usize) -> Self {
        if value < self.depth {
            self.depth = value;
        }
        self
    }

    /// Lowers the container length limit; a value above the current limit changes nothing.
    #[must_use]
    pub const fn with_max_container_len(mut self, value: u64) -> Self {
        if value < self.container_len {
            self.container_len = value;
        }
        self
    }

    /// Lowers the total item limit; a value above the current limit changes nothing.
    #[must_use]
    pub const fn with_max_total_items(mut self, value: u64) -> Self {
        if value < self.total_items {
            self.total_items = value;
        }
        self
    }

    /// Lowers the string length limit; a value above the current limit changes nothing.
    #[must_use]
    pub const fn with_max_string_len(mut self, value: u64) -> Self {
        if value < self.string_len {
            self.string_len = value;
        }
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::FORMAT_0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_only_tighten() {
        let raised = Limits::FORMAT_0
            .with_max_depth(100)
            .with_max_container_len(u64::MAX);
        assert_eq!(
            raised,
            Limits::FORMAT_0,
            "limits must never rise above format 0"
        );
        assert_eq!(Limits::FORMAT_0.with_max_depth(3).max_depth(), 3);
    }
}
