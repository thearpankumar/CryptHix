# CryptHix test vectors

Layout and file schema are defined in [format spec section 20](../../docs/format-spec.md#20-test-vectors).

| Path | Contents |
| --- | --- |
| `crypthix/v0/tv-<NN>-<name>.json` | CryptHix format vectors, one file per set (TV-01 to TV-21) |
| `schema/vector-file.schema.json` | JSON Schema (draft 2020-12) every vector file must match |
| `gen/` | `crypthix-vector-gen`, which writes every file under `crypthix/` byte for byte |
| `external/<source>/` | Vendored vectors from other projects, unchanged, each with `SOURCE` and `LICENSE` |

Each file follows the Wycheproof shape: `testGroups` of `tests`, each with a `tcId`, a `comment`, `flags` and `inputs`. Instead of Wycheproof's `result`, each test has an `expect`: `Ok` or an error name from [format spec section 19](../../docs/format-spec.md#19-errors). Every flag in `notes` cites the FS rule it tests and at least one M- or T- ID from the threat model. Byte inputs are lowercase hex.

| Set | Runner | Status |
| --- | --- | --- |
| TV-02 preamble | `crates/foundation/types/tests/vectors.rs` | Generated, deterministic |
| TV-03 deterministic CBOR | `crates/foundation/types/tests/vectors.rs` | Generated, deterministic; the `GeneratedDocumentParse` group is built by the runner from its inputs |
| TV-17 versions, criticality, feature bits and GREASE | `crates/foundation/types/tests/vectors.rs` | Generated, deterministic |

## Changing a vector

Never edit a file under `crypthix/` by hand. Change the set in `gen/src/tv<NN>.rs`, then:

```bash
cargo xtask vectors          # rewrite the files
cargo xtask vectors --check  # the check CI will run: fails if a committed file differs
cargo xtask test-extra       # schema, external vectors and fuzz replay
```

Vectors are frozen per format, so a changed committed vector needs a row in the [format spec changelog](../../docs/format-spec.md#23-changelog). The generator builds every input by hand rather than through `crypthix-types`, so a bug in the decoder cannot write itself into the vectors. The sets so far draw no randomness; the seeded `test-rng` stream of FS-94 comes with `crypthix-crypto`.

## External vectors

| Source | Files | Licence |
| --- | --- | --- |
| `wycheproof/` | XChaCha20-Poly1305, Ed25519 and HKDF-SHA-256 from `testvectors_v1/` | Apache-2.0 |
| `blake3/` | `test_vectors.json` | CC0-1.0 |
| `ed25519-speccheck/` | `cases.json`, the strict-verification edge cases | Apache-2.0 |
| `rfc8439/`, `xchacha-draft/`, `rfc5869/`, `rfc9106/`, `rfc8032/` | Not transcribed yet: `SOURCE` names the sections | IETF Trust (Revised BSD) |

`SOURCE` pins the upstream commit. To update a source, download the files at a new commit, replace them unchanged, and update `SOURCE`. The runners, and the transcription of the RFC vectors, come with the `crypthix-crypto` item. `.gitattributes` keeps these files byte-exact (no line-ending conversion; the pre-commit hook skips its final-newline check for them), and `.gitleaks.toml` allowlists the two files whose public test keys gitleaks flags. They stay diffable, so an update shows in review.
