# CryptHix test vectors

Layout and file schema are defined in [format spec section 20](../../docs/format-spec.md#20-test-vectors).

| Path | Contents |
| --- | --- |
| `crypthix/v0/tv-<NN>-<name>.json` | CryptHix format vectors, one file per set (TV-01 to TV-21) |
| `schema/vector-file.schema.json` | JSON Schema (draft 2020-12) every vector file must match |
| `gen/` | `crypthix-vector-gen`, which writes every file under `crypthix/` byte for byte |
| `external/<source>/` | Vendored vectors from other projects, unchanged, each with `SOURCE` and `LICENSE` |

Each file follows the Wycheproof shape: `testGroups` of `tests`, each with a `tcId`, a `comment`, `flags` and `inputs`. Instead of Wycheproof's `result`, each test has an `expect`: `Ok` or an error name from [format spec section 19](../../docs/format-spec.md#19-errors) (`Commitment` and `AeadTag` only in TV-05). Expected outputs, such as a derived key or a sealed field, sit beside `expect`. Every flag in `notes` cites the FS rule it tests and at least one M- or T- ID from the threat model. Byte inputs are lowercase hex.

| Set | Runner | Status |
| --- | --- | --- |
| TV-02 preamble | `crates/foundation/types/tests/vectors.rs` | Generated, deterministic |
| TV-03 deterministic CBOR | `crates/foundation/types/tests/vectors.rs` | Generated, deterministic; the `GeneratedDocumentParse` group is built by the runner from its inputs |
| TV-04 labels, `H`, `KDF`, `MAC`, the gear-table XOF, derived keys and zero values | `crates/foundation/crypto/tests/tv04.rs` | Generated from the seeded stream; outputs computed by the generator's own section 7 code (`gen/src/cx.rs`) |
| TV-05 CX-AEAD seal, open, commitment, hedged and synthetic nonces (including replayed randomness), an all-zero nonce | `crates/foundation/crypto/tests/tv05.rs` | Generated from the seeded stream; outputs computed by `gen/src/cx.rs` |
| TV-07 chunk boundaries, Padmé, inner plaintexts, compression, data and meta blobs | `crates/engine/core/tests/tv07.rs` | Generated from the seeded stream; boundaries from an independent one-byte-at-a-time FastCDC (`gen/src/cdc.rs`) for the `ordinary` class and from the length alone for the `secret` class, frames built by hand (`gen/src/zstd_frame.rs`) or by the zstd encoder named in the header (`zstd`), seals by `gen/src/cx.rs`. Inputs too large for hex are a `dataKey` and `length` (the keyed BLAKE3 XOF over the empty input), a `pattern` repeated to `length`, or `zeros`; a frame with a run of more than 1,024 zero bytes is `frameHead`, `frameZeros` zero bytes, then `frameTail`, and an all-zero expected plaintext of more than 1,024 bytes is `plaintextZeros`, its length. The `CutEdges` chunking cases are found by a deterministic search over data keys and chunker seeds, and the generator checks with its own chunker that each cuts where its comment says. The `Compress` and `DataBlobSeal` groups hold only under that zstd version, and the runner fails if it links another. The decoding groups give the results FS-53 defines through libzstd 1.5.7; a reader on another decoder must give the same results, and `crypthix-core`'s own `Decompressor` requires 1.5.7 |
| TV-17 versions, criticality, feature bits and GREASE | `crates/foundation/types/tests/vectors.rs` | Generated, deterministic |

## Changing a vector

Never edit a file under `crypthix/` by hand. Change the set in `gen/src/tv<NN>.rs`, then:

```bash
cargo xtask vectors          # rewrite the files
cargo xtask vectors --check  # what CI runs: fails if a committed file differs
cargo xtask test-extra       # schema, external vectors and fuzz replay
```

Vectors are frozen per format, so a changed committed vector needs a row in the [format spec changelog](../../docs/format-spec.md#23-changelog). The generator builds every input by hand rather than through `crypthix-types`, so a bug in the decoder cannot write itself into the vectors. TV-04 and TV-05 draw their inputs from the seeded `test-rng` stream of `crypthix-crypto` (one labelled stream per test, `fill_bytes` only, the seed in the file header) and compute every output with `gen/src/cx.rs`, a second implementation of format spec section 7 over the audited crates, so the vectors check `crypthix-crypto` rather than copy it.

## External vectors

| Source | Files | Licence |
| --- | --- | --- |
| `wycheproof/` | XChaCha20-Poly1305, Ed25519 and HKDF-SHA-256 from `testvectors_v1/` | Apache-2.0 |
| `blake3/` | `test_vectors.json` | CC0-1.0 |
| `ed25519-speccheck/` | `cases.json`, the strict-verification edge cases | Apache-2.0 |
| `rfc8439/`, `xchacha-draft/`, `rfc5869/`, `rfc9106/`, `rfc8032/` | The test vectors of the sections `SOURCE` names, transcribed byte for byte to JSON | IETF Trust (Revised BSD) |

`SOURCE` pins the upstream commit, or for a transcribed set the document, its sections and the transcription date. To update a source, download the files at a new commit, replace them unchanged, and update `SOURCE`. The runners are `crates/foundation/crypto/tests/kat_*.rs` (TV-01): each asserts how many cases it ran, and the Ed25519 cases run through the strict verifier of FS-14. `.gitattributes` keeps these files byte-exact (no line-ending conversion; the pre-commit hook skips its final-newline check for them), and `.gitleaks.toml` allowlists, file by file, the vector files whose public test keys gitleaks flags. They stay diffable, so an update shows in review.
