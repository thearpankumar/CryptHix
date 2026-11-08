//! The macro that defines one 32-byte zeroizing key type.

/// Defines a key newtype over a 32-byte slot of protected memory (O1), wiped on drop, that
/// prints no bytes.
macro_rules! secret_key {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(crate::secure_mem::KeySlot);

        impl $name {
            /// A new key of 32 bytes straight from the kernel's `getrandom` (FS-01, M-36).
            ///
            /// # Errors
            ///
            /// - [`KeyError::Random`](crate::key::KeyError::Random) if the kernel cannot supply
            ///   randomness.
            /// - [`KeyError::Memory`](crate::key::KeyError::Memory) if no protected memory is
            ///   free.
            pub fn random() -> Result<Self, crate::key::KeyError> {
                crate::key::sealed::new_random()
            }

            /// Wraps known key bytes, for the test-vector runners only.
            ///
            /// # Errors
            ///
            /// - [`KeyError::Format`](crate::key::KeyError::Format) with `ZeroValue` for an
            ///   all-zero key (FS-03).
            /// - [`KeyError::Memory`](crate::key::KeyError::Memory) if no protected memory is
            ///   free.
            #[cfg(feature = "vectors")]
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, crate::key::KeyError> {
                crate::key::check_nonzero::check_nonzero(&bytes)?;
                crate::key::sealed::new_with(|material| {
                    *material = bytes;
                    Ok::<(), crate::key::KeyError>(())
                })
            }

            /// A copy of the key bytes, for the test-vector runners only.
            ///
            /// # Panics
            ///
            /// On Linux, in a child forked without `exec` after the key was made
            /// ([`secure_mem`](crate::secure_mem#fork)).
            #[cfg(feature = "vectors")]
            #[must_use]
            pub fn to_bytes(&self) -> [u8; 32] {
                *self.0.bytes()
            }

            /// The protection the key's memory got.
            #[must_use]
            pub fn level(&self) -> crate::secure_mem::Level {
                self.0.level()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }

        impl crate::key::sealed::Sealed for $name {
            fn zeroed(
                _: crate::key::sealed::Token,
            ) -> Result<Self, crate::secure_mem::MemError> {
                crate::secure_mem::take_key_slot().map(Self)
            }

            fn material(&self, _: crate::key::sealed::Token) -> &[u8; 32] {
                self.0.bytes()
            }

            fn material_mut(&mut self, _: crate::key::sealed::Token) -> &mut [u8; 32] {
                self.0.bytes_mut()
            }
        }

        impl crate::key::KeyMaterial for $name {}
    };
}

pub(crate) use secret_key;
