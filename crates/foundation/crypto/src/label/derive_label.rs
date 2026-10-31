//! Typed KDF labels: each enum lists the labels one output type may be derived under, so a key
//! derived for one purpose cannot be asked for as another type (FS-25).

use crate::key::sealed::Sealed;
use crate::label::KdfLabel;

/// A KDF label whose output type is fixed: [`kdf`](crate::kdf::kdf) returns `Self::Output`.
///
/// The trait is sealed. The CX-AEAD labels `cx-key`, `cx-commit` and `cx-nonce` belong to no
/// typed enum, so only CX-AEAD itself derives under them.
pub trait DeriveLabel: Copy + Into<KdfLabel> + private::Sealed {
    /// The type of the derived value.
    type Output: Sealed;
}

pub(crate) mod private {
    /// Keeps [`DeriveLabel`](super::DeriveLabel) implemented by this crate only.
    pub trait Sealed {}
}

/// Defines one typed label enum and its conversion into [`KdfLabel`].
macro_rules! derive_labels {
    ($(#[$doc:meta])* $name:ident => $output:ty { $($variant:ident,)+ }) => {
        $(#[$doc])*
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub enum $name {
            $(
                #[doc = concat!(
                    "Derives under [`KdfLabel::", stringify!($variant),
                    "`](crate::label::KdfLabel::", stringify!($variant), ")."
                )]
                $variant,
            )+
        }

        impl $name {
            /// Every label of this type, in the order of the spec's registry.
            pub const ALL: &'static [$name] = &[$($name::$variant,)+];
        }

        impl From<$name> for crate::label::KdfLabel {
            fn from(label: $name) -> Self {
                match label {
                    $($name::$variant => crate::label::KdfLabel::$variant,)+
                }
            }
        }

        impl crate::label::derive_label::private::Sealed for $name {}

        impl crate::label::DeriveLabel for $name {
            type Output = $output;
        }
    };
}

pub(crate) use derive_labels;
