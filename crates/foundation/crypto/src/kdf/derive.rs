//! HKDF-SHA-256 under a labelled info string (section 7.1).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::kdf::KdfContext;
use crate::key::KdfKey;
use crate::key::sealed;
use crate::label::{DeriveLabel, KdfLabel};

/// Derives a 32-byte value: `HKDF-Expand(HKDF-Extract(salt, ikm), u8 len ‖ label ‖ ctx, 32)`
/// (section 7.1, FS-38). The label decides the output type.
///
/// `salt` is `None` for every derivation of FS-38 except those from a DEK, which use its
/// `dek_salt`; `None` is HKDF's default of 32 zero bytes.
#[must_use]
pub fn kdf<L: DeriveLabel>(
    ikm: &KdfKey,
    salt: Option<&[u8; 32]>,
    label: L,
    context: &KdfContext,
) -> L::Output {
    let hkdf = Hkdf::<Sha256>::new(salt.map(<[u8; 32]>::as_slice), sealed::material(ikm));
    sealed::from_material(*expand_with(&hkdf, label.into(), &[context.as_bytes()]))
}

/// `HKDF-Expand(key, u8 len ‖ label ‖ parts, 32)` keyed directly by a uniform 32-byte key, as
/// CX-AEAD does (FS-27, RFC 5869 section 3.3).
pub(crate) fn expand(key: &[u8; 32], label: KdfLabel, parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::from_prk(key).expect("a 32-byte PRK is long enough");
    expand_with(&hkdf, label, parts)
}

fn expand_with(hkdf: &Hkdf<Sha256>, label: KdfLabel, parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(128);
    label.write_prefix(&mut info);
    for part in parts {
        info.extend_from_slice(part);
    }
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, okm.as_mut_slice())
        .expect("32 bytes is below the HKDF output limit");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash32;
    use crate::key::SealKey;
    use crate::label::{CommitLabel, KdfKeyLabel, SealKeyLabel};

    fn ikm(byte: u8) -> KdfKey {
        sealed::from_material([byte; 32])
    }

    fn hkdf(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(salt, ikm)
            .expand(info, &mut out)
            .expect("valid length");
        out
    }

    #[test]
    fn matches_hkdf_with_the_label_prefix() {
        let mut info = vec![20u8];
        info.extend_from_slice(b"crypthix/v0/kdf/root");
        info.extend_from_slice(&[9; 16]);
        let root: KdfKey = kdf(
            &ikm(1),
            None,
            KdfKeyLabel::Root,
            &KdfContext::new().field(&[9; 16]),
        );
        assert_eq!(sealed::material(&root), &hkdf(None, &[1; 32], &info));
    }

    #[test]
    fn salt_label_and_context_all_change_the_key() {
        let context = KdfContext::new().field(b"ctx");
        let base: SealKey = kdf(&ikm(1), None, SealKeyLabel::DekWrap, &context);
        let salted: SealKey = kdf(&ikm(1), Some(&[3; 32]), SealKeyLabel::DekWrap, &context);
        let relabelled: SealKey = kdf(&ikm(1), None, SealKeyLabel::PackKeyWrap, &context);
        let other: SealKey = kdf(
            &ikm(1),
            None,
            SealKeyLabel::DekWrap,
            &KdfContext::new().field(b"ctY"),
        );
        for derived in [&salted, &relabelled, &other] {
            assert_ne!(
                sealed::material(&base),
                sealed::material(derived),
                "an input was ignored"
            );
        }
    }

    #[test]
    fn root_commit_is_hkdf_under_its_label() {
        let mut info = vec![27u8];
        info.extend_from_slice(b"crypthix/v0/kdf/root-commit");
        info.extend_from_slice(&[9; 16]);
        let context = KdfContext::new().field(&[9; 16]);
        let commit: Hash32 = kdf(&ikm(1), None, CommitLabel::RootCommit, &context);
        assert_eq!(commit.as_bytes(), &hkdf(None, &[1; 32], &info));
    }

    #[test]
    fn expand_is_keyed_directly_by_the_key() {
        let mut info = vec![22u8];
        info.extend_from_slice(b"crypthix/v0/kdf/cx-key");
        info.extend_from_slice(b"n");
        let mut expected = [0u8; 32];
        Hkdf::<Sha256>::from_prk(&[4; 32])
            .expect("32 bytes")
            .expand(&info, &mut expected)
            .expect("valid length");
        assert_eq!(*expand(&[4; 32], KdfLabel::CxKey, &[b"n"]), expected);
    }
}
