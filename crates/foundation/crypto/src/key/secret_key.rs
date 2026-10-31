//! The macro that defines one 32-byte zeroizing key type.

/// Defines a key newtype over `[u8; 32]` that is wiped on drop and prints no bytes.
macro_rules! secret_key {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(zeroize::ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        impl $name {
            /// A new key of 32 bytes straight from the kernel's `getrandom` (FS-01, M-36).
            ///
            /// # Errors
            ///
            /// [`RandomError`](crate::random::RandomError) if the kernel cannot supply
            /// randomness.
            pub fn random() -> Result<Self, crate::random::RandomError> {
                let mut key = Self([0u8; 32]);
                crate::random::fill(&mut key.0)?;
                Ok(key)
            }

            /// Wraps known key bytes, for the test-vector runners only.
            ///
            /// # Errors
            ///
            /// [`FormatError::ZeroValue`](crypthix_types::format_error::FormatError::ZeroValue)
            /// for an all-zero key (FS-03).
            #[cfg(feature = "vectors")]
            pub fn from_bytes(
                bytes: [u8; 32],
            ) -> Result<Self, crypthix_types::format_error::FormatError> {
                crate::key::check_nonzero::check_nonzero(&bytes)?;
                Ok(Self(bytes))
            }

            /// A copy of the key bytes, for the test-vector runners only.
            #[cfg(feature = "vectors")]
            #[must_use]
            pub fn to_bytes(&self) -> [u8; 32] {
                self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }

        impl crate::key::sealed::Sealed for $name {
            fn from_material(bytes: [u8; 32], _: crate::key::sealed::Token) -> Self {
                Self(bytes)
            }

            fn material(&self, _: crate::key::sealed::Token) -> &[u8; 32] {
                &self.0
            }
        }

        impl crate::key::KeyMaterial for $name {}
    };
}

pub(crate) use secret_key;
