//! Vector inputs as fuzz seeds.

use crate::test_case::Input;
use crate::vector_set::sets;

/// Which fuzz targets a seed feeds.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SeedTarget {
    /// A whole file starting with a preamble.
    Preamble,
    /// A CBOR document.
    Cbor,
    /// A store name.
    StoreKey,
    /// A TOML config file.
    Config,
    /// The text form of an ID or counter.
    IdText,
    /// A CX-AEAD sealed field.
    Sealed,
    /// An Ed25519 public key, signature and message.
    Signed,
}

impl SeedTarget {
    /// The fuzz targets this kind of seed feeds, by name.
    #[must_use]
    pub const fn fuzz_targets(self) -> &'static [&'static str] {
        match self {
            SeedTarget::Preamble => &["preamble"],
            SeedTarget::Cbor => &["cbor_document", "cbor_differential"],
            SeedTarget::StoreKey => &["store_key"],
            SeedTarget::IdText => &["id_text"],
            SeedTarget::Config => &["config_toml"],
            SeedTarget::Sealed => &["cx_open"],
            SeedTarget::Signed => &["verifying_key"],
        }
    }
}

/// One seed input.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Seed {
    /// The kind of input.
    pub target: SeedTarget,
    /// A file name: the set and test ID, such as `tv-03-0042`.
    pub name: String,
    /// The input.
    pub bytes: Vec<u8>,
}

/// Configs that reach past the TOML parser into the schema and `validate` checks.
const CONFIGS: [(&str, &str); 5] = [
    ("empty", ""),
    (
        "local",
        "[local]\nstore_root = \"/var/lib/crypthix/00112233445566778899aabbccddeeff/store\"\n",
    ),
    ("relative-root", "[local]\nstore_root = \"store\"\n"),
    ("unknown-key", "[local]\nstore_root = \"/x\"\ncolour = 1\n"),
    ("wrong-type", "local = 3\n"),
];

/// ID and counter texts at the edges of FS-92: zero, leading zeros, the largest counters,
/// full-length hex, wrong case and wrong length.
const ID_TEXTS: [(&str, &str); 9] = [
    ("zero", "0"),
    ("one", "1"),
    ("leading-zero", "01"),
    ("u32-max", "4294967295"),
    ("u64-max", "18446744073709551615"),
    ("hex-16", "00112233445566778899aabbccddeeff"),
    (
        "hex-32",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    ),
    ("hex-upper", "00112233445566778899AABBCCDDEEFF"),
    ("hex-zero", "00000000000000000000000000000000"),
];

/// `public key ‖ signature ‖ message` of RFC 8032 section 7.1 TEST 2, and the same with the
/// identity point and an order-2 point as the key.
const SIGNED: [(&str, &str); 3] = [
    (
        "rfc8032-test2",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c\
         92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00\
         72",
    ),
    (
        "identity-key",
        "0100000000000000000000000000000000000000000000000000000000000000\
         92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00\
         72",
    ),
    (
        "order-two-key",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ),
];

/// Every vector input that a fuzz target can start from, plus a few configs, ID texts and
/// signed messages.
#[must_use]
pub fn seeds() -> Vec<Seed> {
    let mut out = Vec::new();
    for set in sets() {
        // "tv-03-cbor.json" becomes "tv-03".
        let prefix = set.file.get(..5).unwrap_or(set.file);
        for (index, (_, test)) in set.tests().enumerate() {
            for (key, input) in &test.inputs {
                let (target, bytes) = match (*key, input) {
                    ("file", Input::Bytes(bytes)) => (SeedTarget::Preamble, bytes.clone()),
                    ("cbor", Input::Bytes(bytes)) => (SeedTarget::Cbor, bytes.clone()),
                    ("path", Input::Text(path)) => (SeedTarget::StoreKey, path.as_bytes().to_vec()),
                    ("sealed", Input::Bytes(bytes)) => (SeedTarget::Sealed, bytes.clone()),
                    _ => continue,
                };
                // The input name keeps two inputs of one test apart.
                let name = format!("{prefix}-{:04}-{key}", index + 1);
                out.push(Seed {
                    target,
                    name,
                    bytes,
                });
            }
        }
    }
    for (name, text) in CONFIGS {
        out.push(Seed {
            target: SeedTarget::Config,
            name: format!("config-{name}"),
            bytes: text.as_bytes().to_vec(),
        });
    }
    for (name, hex) in SIGNED {
        out.push(Seed {
            target: SeedTarget::Signed,
            name: format!("signed-{name}"),
            bytes: crate::pre::h(hex),
        });
    }
    for (name, text) in ID_TEXTS {
        out.push(Seed {
            target: SeedTarget::IdText,
            name: format!("id-{name}"),
            bytes: text.as_bytes().to_vec(),
        });
    }
    out
}
