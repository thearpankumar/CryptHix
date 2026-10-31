//! TV-04: labels, `H`, `KDF`, `MAC`, every derived key of FS-38, and zero values (FS-03, FS-04,
//! FS-12, FS-25, FS-26, FS-38).

use crypthix_crypto::test_rng::Stream;

use crate::cx;
use crate::labels;
use crate::test_case::{Input, TestCase};
use crate::vector_set::VectorSet;

/// The seed of the set's streams: `BLAKE3("crypthix-vector-gen TV-04")`.
fn seed() -> [u8; 32] {
    *blake3::hash(b"crypthix-vector-gen TV-04").as_bytes()
}

fn label_tests() -> Vec<TestCase> {
    labels::all()
        .into_iter()
        .map(|label| {
            TestCase::new(
                label,
                &["LabelRegistry"],
                "Ok",
                vec![("label", Input::text(label))],
            )
            .with_outputs(vec![("prefix", Input::bytes(&cx::prefix(label)))])
        })
        .collect()
}

fn hash_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut long = vec![0u8; 1000];
    Stream::new(seed, "hash/long").fill_bytes(&mut long);
    let cases: [(&'static str, &'static str, Vec<u8>); 5] = [
        ("H over the empty input", "file", Vec::new()),
        ("H over three bytes", "key-id", b"abc".to_vec()),
        ("H over 1,000 bytes", "aad-part", long.clone()),
        ("the CX-AEAD AAD digest", "cx-aad", long),
        ("the empty Merkle tree", "merkle-manifest", Vec::new()),
    ];
    cases
        .into_iter()
        .map(|(comment, purpose, data)| {
            let label = labels::full("hash", purpose);
            TestCase::new(
                comment,
                &["DomainHash"],
                "Ok",
                vec![("label", Input::text(label)), ("data", Input::bytes(&data))],
            )
            .with_outputs(vec![("hash", Input::bytes(&cx::h(label, &data)))])
        })
        .collect()
}

/// The inputs of FS-38, drawn from labelled streams.
struct Inputs {
    vault_id: [u8; 16],
    device_id: [u8; 16],
    object_id: [u8; 16],
    dek_id: [u8; 16],
    pack_id: [u8; 16],
    root_secret: [u8; 32],
    chunker_seed: [u8; 32],
    kek: [u8; 32],
    kek_active: [u8; 32],
    dek: [u8; 32],
    dek_salt: [u8; 32],
    pack_key: [u8; 32],
}

impl Inputs {
    fn draw(seed: &[u8; 32]) -> Self {
        let mut stream = Stream::new(seed, "derived-keys/inputs");
        Self {
            vault_id: stream.bytes(),
            device_id: stream.bytes(),
            object_id: stream.bytes(),
            dek_id: stream.bytes(),
            pack_id: stream.bytes(),
            root_secret: stream.bytes(),
            chunker_seed: stream.bytes(),
            kek: stream.bytes(),
            kek_active: stream.bytes(),
            dek: stream.bytes(),
            dek_salt: stream.bytes(),
            pack_key: stream.bytes(),
        }
    }
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// One row of FS-38.
fn derived(
    comment: &'static str,
    key_type: &str,
    ikm: &[u8; 32],
    salt: Option<&[u8; 32]>,
    purpose: &str,
    context: &[u8],
) -> TestCase {
    let label = labels::full("kdf", purpose);
    let mut inputs = vec![
        ("ikm", Input::bytes(ikm)),
        ("label", Input::text(label)),
        ("context", Input::bytes(context)),
        ("keyType", Input::text(key_type)),
    ];
    if let Some(salt) = salt {
        inputs.insert(1, ("salt", Input::bytes(salt)));
    }
    TestCase::new(comment, &["DerivedKey"], "Ok", inputs).with_outputs(vec![(
        "key",
        Input::bytes(&cx::kdf(ikm, salt, label, context)),
    )])
}

fn derived_key_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let i = Inputs::draw(seed);
    let v = &i.vault_id[..];
    let epoch = 3u32.to_be_bytes();
    let generation = 2u32.to_be_bytes();
    let root_seq = 7u64.to_be_bytes();
    let rk = cx::kdf(&i.root_secret, None, labels::full("kdf", "root"), v);
    let ve = cat(&[v, &epoch]);
    let vod = cat(&[v, &i.object_id, &i.dek_id]);
    let vp = cat(&[v, &i.pack_id]);
    let vd = cat(&[v, &i.device_id]);
    #[rustfmt::skip]
    let tests = vec![
        derived("RK from the root secret", "KdfKey", &i.root_secret, None, "root", v),
        derived("root_commit", "RootCommit", &rk, None, "root-commit", v),
        derived("K_keyring_g", "SealKey", &rk, None, "keyring-wrap", &cat(&[v, &generation])),
        derived("K_vsign", "SealKey", &rk, None, "vault-sign-wrap", v),
        derived("K_devwrap", "SealKey", &rk, None, "device-key-wrap", &vd),
        derived("K_state", "MacKey", &rk, None, "device-state", &vd),
        derived("K_queue", "MacKey", &rk, None, "queue-mac", &vd),
        derived("K_cfg", "SealKey", &rk, None, "config-seal", v),
        derived("K_canary", "KdfKey", &rk, None, "canary-seed", v),
        derived("K_logkey", "SealKey", &rk, None, "log-key-wrap", v),
        derived("K_gear from the chunker seed", "XofKey", &i.chunker_seed, None, "gear", v),
        derived("K_dekwrap_e", "SealKey", &i.kek, None, "dek-wrap", &ve),
        derived("K_pkwrap_e", "SealKey", &i.kek, None, "pack-key-wrap", &ve),
        derived("K_idx_e", "SealKey", &i.kek, None, "index-key", &ve),
        derived("K_kt_e", "SealKey", &i.kek, None, "key-table-key", &ve),
        derived("K_loc_e", "SealKey", &i.kek, None, "location-key", &ve),
        derived("K_pt_e", "SealKey", &i.kek, None, "pack-table-key", &ve),
        derived("K_root_s", "SealKey", &i.kek_active, None, "root-seal", &cat(&[v, &root_seq])),
        derived("K_man, salted with dek_salt", "SealKey", &i.dek, Some(&i.dek_salt), "manifest-key", &vod),
        derived("K_chunk, salted with dek_salt", "SealKey", &i.dek, Some(&i.dek_salt), "chunk-key", &vod),
        derived("K_blobid, salted with dek_salt", "MacKey", &i.dek, Some(&i.dek_salt), "blob-id-key", &vod),
        derived("K_ptmac, salted with dek_salt", "MacKey", &i.dek, Some(&i.dek_salt), "plaintext-mac-key", &vod),
        derived("K_ph", "SealKey", &i.pack_key, None, "pack-header-key", &vp),
        derived("K_sh", "SealKey", &i.pack_key, None, "shard-header-key", &vp),
        derived("K_shn", "ShardNonceKey", &i.pack_key, None, "shard-nonce", &vp),
    ];
    tests
}

fn mac_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut stream = Stream::new(seed, "mac");
    let key: [u8; 32] = stream.bytes();
    let gear_key: [u8; 32] = stream.bytes();
    let mut gear = vec![0u8; 2048];
    let hasher = blake3::Hasher::new_keyed(&gear_key);
    hasher.finalize_xof().fill(&mut gear);
    vec![
        TestCase::new(
            "MAC over the empty input",
            &["Mac"],
            "Ok",
            vec![("key", Input::bytes(&key)), ("data", Input::bytes(b""))],
        )
        .with_outputs(vec![("mac", Input::bytes(&cx::mac(&key, b"")))]),
        TestCase::new(
            "MAC over a chunk",
            &["Mac"],
            "Ok",
            vec![
                ("key", Input::bytes(&key)),
                ("data", Input::bytes(b"chunk plaintext")),
            ],
        )
        .with_outputs(vec![(
            "mac",
            Input::bytes(&cx::mac(&key, b"chunk plaintext")),
        )]),
        TestCase::new(
            "the 2,048-byte gear table",
            &["GearTable"],
            "Ok",
            vec![("key", Input::bytes(&gear_key))],
        )
        .with_outputs(vec![("xof", Input::bytes(&gear))]),
    ]
}

fn zero_tests() -> Vec<TestCase> {
    let zero = |comment, kind: &str, value: Input, expect| {
        TestCase::new(
            comment,
            &["ZeroValue"],
            expect,
            vec![("kind", Input::text(kind)), ("value", value)],
        )
    };
    vec![
        zero(
            "an all-zero key",
            "key",
            Input::bytes(&[0; 32]),
            "ZeroValue",
        ),
        zero(
            "a key with one non-zero byte",
            "key",
            Input::bytes(&[[0u8; 31].as_slice(), &[1]].concat()),
            "Ok",
        ),
        zero(
            "an all-zero object ID",
            "objectId",
            Input::bytes(&[0; 16]),
            "ZeroValue",
        ),
        zero(
            "an all-zero hash",
            "hash",
            Input::bytes(&[0; 32]),
            "ZeroValue",
        ),
        zero("epoch 0", "epoch", Input::Int(0), "ZeroValue"),
        zero("root_seq 0", "rootSeq", Input::Int(0), "ZeroValue"),
        zero("epoch 1, the first", "epoch", Input::Int(1), "Ok"),
    ]
}

/// TV-04.
pub(crate) fn set() -> VectorSet {
    let seed = seed();
    VectorSet {
        file: "tv-04-domain-separation.json",
        set: "TV-04",
        structure: "domain-separation",
        seed: Some(seed),
        extra: vec![],
        notes: vec![
            (
                "LabelRegistry",
                &["FS-12", "FS-25", "M-37"],
                "Every label of the section 7.1 registry and its `u8 len ‖ label` prefix.",
            ),
            (
                "DomainHash",
                &["FS-12", "FS-26", "M-37", "T-83"],
                "`H(label, x) = BLAKE3(u8 len ‖ label ‖ x)`.",
            ),
            (
                "DerivedKey",
                &["FS-26", "FS-38", "M-37"],
                "Every derived key of FS-38: `KDF(ikm, salt, label, ctx)` with its key type.",
            ),
            ("Mac", &["FS-26", "M-37"], "`MAC(k, x)`: keyed BLAKE3-256."),
            (
                "GearTable",
                &["FS-52", "M-39"],
                "The first 2,048 bytes of the keyed BLAKE3 XOF over the empty input.",
            ),
            (
                "ZeroValue",
                &["FS-03", "FS-04", "T-37"],
                "All-zero keys, IDs and hashes, and zero counters, are invalid.",
            ),
        ],
        groups: vec![
            ("LabelPrefix", label_tests()),
            ("Hash", hash_tests(&seed)),
            ("DerivedKey", derived_key_tests(&seed)),
            ("Mac", mac_tests(&seed)),
            ("ZeroValue", zero_tests()),
        ],
    }
}
