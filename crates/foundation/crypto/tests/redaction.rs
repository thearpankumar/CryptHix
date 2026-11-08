//! What every public type holding a secret shares: it is `Send + Sync`, and its `Debug` shows no
//! secret byte, plaintext or address. The crate-private `KeySlot` is checked in its own module.

use crypthix_crypto::argon2id::DeriveError;
use crypthix_crypto::hash::Hasher;
use crypthix_crypto::key::{KdfKey, KeyError, MacKey, Passphrase, SealKey, ShardNonceKey, XofKey};
use crypthix_crypto::label::HashLabel;
use crypthix_crypto::secure_mem::{self, Level, MemError, SecretBuf};
use crypthix_crypto::sign::SigningKey;

const fn send_sync<T: Send + Sync>() {}

// Keys and buffers are made on one thread and used or dropped on others; a field that is not
// `Send + Sync` fails the build here.
const _: () = {
    send_sync::<SealKey>();
    send_sync::<MacKey>();
    send_sync::<KdfKey>();
    send_sync::<XofKey>();
    send_sync::<ShardNonceKey>();
    send_sync::<SigningKey>();
    send_sync::<Passphrase>();
    send_sync::<SecretBuf>();
    send_sync::<Hasher>();
};

/// Every secret byte in these tests: 171 in decimal, `ab` in hex.
const BYTE: u8 = 0xab;

/// `debug` names `name` and shows no secret byte, in decimal or hex, and no run of hex digits
/// that could be one.
fn assert_redacted(name: &str, debug: &str) {
    assert!(debug.contains(name), "{debug}");
    for leak in ["171", "ab, ab", "abab", "hunter"] {
        assert!(!debug.contains(leak), "{debug} shows {leak:?}");
    }
    let longest_hex_run = debug
        .split(|c: char| !c.is_ascii_hexdigit())
        .map(str::len)
        .max();
    assert!(longest_hex_run < Some(8), "{debug}");
}

/// Both `{:?}`, which must show no address (`0x`), and `{:#x?}`, in which a derived `Debug`
/// would print bytes in hex (and counts as `0x..`, which is why only the first is checked for
/// addresses).
fn check(name: &str, value: &impl std::fmt::Debug) {
    let debug = format!("{value:?}");
    assert_redacted(name, &debug);
    assert!(!debug.contains("0x"), "{debug} shows an address");
    assert_redacted(name, &format!("{value:#x?}"));
}

#[test]
fn debug_shows_no_key_bytes_plaintext_or_address() {
    let bytes = [BYTE; 32];
    check("SealKey", &SealKey::from_bytes(bytes).expect("a key"));
    check("MacKey", &MacKey::from_bytes(bytes).expect("a key"));
    check("KdfKey", &KdfKey::from_bytes(bytes).expect("a key"));
    check("XofKey", &XofKey::from_bytes(bytes).expect("a key"));
    check(
        "ShardNonceKey",
        &ShardNonceKey::from_bytes(bytes).expect("a key"),
    );
    check("SigningKey", &SigningKey::from_seed(&bytes).expect("a key"));
    check(
        "Passphrase",
        &Passphrase::new("hunter2".to_owned()).expect("a buffer"),
    );
    check(
        "SecretBuf",
        &SecretBuf::try_copy_from(&bytes).expect("memory for a buffer"),
    );
    let mut hasher = Hasher::new(HashLabel::File);
    hasher.update(b"hunter2").update(&bytes);
    check("Hasher", &hasher);
    check("Status", &secure_mem::status());
    let below = MemError::BelowMinimum {
        got: Level::Heap,
        want: Level::Secret,
    };
    check("BelowMinimum", &below);
    check("Memory", &KeyError::Memory(below));
    check("KeyMemory", &DeriveError::KeyMemory(below));
    check("ArgonMemory", &DeriveError::ArgonMemory);
}
