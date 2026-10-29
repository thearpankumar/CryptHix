//! Store names: canonical names round-trip, and nothing panics.

use crypthix_types::store_key::StoreKey;

/// Parses `data` as a store name when it is UTF-8.
///
/// # Panics
///
/// If an accepted name does not print back exactly (FS-92), or its type check fails.
pub fn store_key(data: &[u8]) {
    let Ok(name) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(Some(key)) = StoreKey::parse(name) {
        assert_eq!(key.to_string(), name, "a store name has one canonical form");
        assert_eq!(
            key.check_type(key.file_type()),
            Ok(()),
            "its own type matches"
        );
        assert!(key.max_file_len() > 0, "every file kind has a size cap");
        assert_eq!(
            StoreKey::parse(&key.to_string()),
            Ok(Some(key)),
            "parse(print(k)) == k"
        );
    }
}
