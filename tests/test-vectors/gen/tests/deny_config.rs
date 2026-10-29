//! `tests/deny.toml` is the root `deny.toml` plus the licence exceptions test tooling needs.

use std::fs;
use std::path::Path;

/// The only text `tests/deny.toml` adds to the root file, after its header comment.
const EXCEPTIONS: &str = "\
# Test tooling in tests/ only, never shipped: libFuzzer's runtime is under the LLVM licence
# (NCSA), and minicbor, the CBOR fuzz oracle, under the permissive Blue Oak licence.
exceptions = [
    { crate = \"libfuzzer-sys\", allow = [\"NCSA\"] },
    { crate = \"minicbor\", allow = [\"BlueOak-1.0.0\"] },
]
";

#[test]
fn side_deny_config_is_the_root_plus_its_exceptions() {
    let root_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let root = fs::read_to_string(root_dir.join("deny.toml")).expect("root deny.toml");
    let side = fs::read_to_string(root_dir.join("tests/deny.toml")).expect("tests/deny.toml");
    let (header, body) = side
        .split_once("\n\n")
        .expect("a header comment, then the config");
    assert!(
        header.lines().all(|line| line.starts_with('#')),
        "the header of tests/deny.toml is only comments"
    );
    assert!(
        body.contains(EXCEPTIONS),
        "tests/deny.toml lists the tooling exceptions"
    );
    assert_eq!(
        body.replacen(EXCEPTIONS, "", 1),
        root,
        "tests/deny.toml must equal deny.toml apart from its header and exceptions"
    );
}
