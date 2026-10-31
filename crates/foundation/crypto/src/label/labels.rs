//! The macro that defines one label class.

/// Defines a label enum whose variants map to the full ASCII label strings of one class.
macro_rules! labels {
    (
        $(#[$doc:meta])* $name:ident, $class:literal,
        $($(#[$variant_doc:meta])* $variant:ident => $purpose:literal,)+
    ) => {
        $(#[$doc])*
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub enum $name {
            $($(#[$variant_doc])* $variant,)+
        }

        impl $name {
            /// Every label of the class, in the order of the spec's registry.
            pub const ALL: &'static [$name] = &[$($name::$variant,)+];

            /// The full label, for example `crypthix/v0/kdf/root`.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => concat!("crypthix/v0/", $class, "/", $purpose),)+
                }
            }

            /// The purpose part of the label, as listed in the spec's registry.
            #[must_use]
            pub const fn purpose(self) -> &'static str {
                match self {
                    $($name::$variant => $purpose,)+
                }
            }

            /// `u8 len(label) ‖ label`, the prefix every use of the label starts with (FS-12).
            pub(crate) fn write_prefix(self, out: &mut impl crate::label::labels::PrefixSink) {
                let label = self.as_str().as_bytes();
                // Every label is a short ASCII constant; the registry test checks the lengths.
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "labels are at most 40 bytes, checked by labels_fit_one_length_byte"
                )]
                out.put(&[label.len() as u8]);
                out.put(label);
            }
        }
    };
}

pub(crate) use labels;

/// Something a label prefix can be written into: a byte vector or a hasher.
pub(crate) trait PrefixSink {
    /// Appends bytes.
    fn put(&mut self, bytes: &[u8]);
}

impl PrefixSink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

impl PrefixSink for blake3::Hasher {
    fn put(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

#[cfg(test)]
mod tests {
    use crate::label::{AadLabel, HashLabel, KdfLabel, SigLabel};

    const FORMAT_SPEC: &str = include_str!("../../../../../docs/format-spec.md");

    /// The purposes listed for `class` in the registry table of spec section 7.1.
    fn spec_purposes(class: &str) -> Vec<&'static str> {
        let row_start = format!("| `{class}/` | ");
        let row = FORMAT_SPEC
            .lines()
            .find(|line| line.starts_with(&row_start))
            .expect("the registry has a row for every class");
        row[row_start.len()..]
            .trim_end_matches(" |")
            .split(", ")
            .map(|purpose| purpose.trim_matches('`'))
            .collect()
    }

    fn check(class: &str, labels: impl Iterator<Item = (&'static str, &'static str)>) {
        let (purposes, full): (Vec<&str>, Vec<&str>) = labels.unzip();
        assert_eq!(
            purposes,
            spec_purposes(class),
            "{class} labels drifted from spec section 7.1"
        );
        for (purpose, label) in purposes.iter().zip(&full) {
            assert_eq!(*label, format!("crypthix/v0/{class}/{purpose}"));
            assert!(label.is_ascii(), "{label} is not ASCII");
        }
    }

    #[test]
    fn labels_match_the_spec_registry() {
        check(
            "kdf",
            KdfLabel::ALL
                .iter()
                .map(|label| (label.purpose(), label.as_str())),
        );
        check(
            "aad",
            AadLabel::ALL
                .iter()
                .map(|label| (label.purpose(), label.as_str())),
        );
        check(
            "sig",
            SigLabel::ALL
                .iter()
                .map(|label| (label.purpose(), label.as_str())),
        );
        check(
            "hash",
            HashLabel::ALL
                .iter()
                .map(|label| (label.purpose(), label.as_str())),
        );
    }

    #[test]
    fn labels_fit_one_length_byte() {
        let lengths = KdfLabel::ALL
            .iter()
            .map(|label| label.as_str().len())
            .chain(AadLabel::ALL.iter().map(|label| label.as_str().len()))
            .chain(SigLabel::ALL.iter().map(|label| label.as_str().len()))
            .chain(HashLabel::ALL.iter().map(|label| label.as_str().len()));
        for len in lengths {
            assert!(u8::try_from(len).is_ok(), "a label of {len} bytes");
        }
    }

    #[test]
    fn prefix_is_length_then_label() {
        let mut out = Vec::new();
        KdfLabel::CxKey.write_prefix(&mut out);
        assert_eq!(
            out[0], 22,
            "the spec's example: crypthix/v0/kdf/cx-key is 22 bytes"
        );
        assert_eq!(&out[1..], b"crypthix/v0/kdf/cx-key");
    }
}
