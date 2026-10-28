# CryptHix test vectors

Layout and file schema are defined in [format spec section 20](../../docs/format-spec.md#20-test-vectors).

| Path | Contents |
| --- | --- |
| `crypthix/v0/tv-<NN>-<name>.json` | CryptHix format vectors, one file per set (TV-01 to TV-21) |

Each file follows the Wycheproof shape: `testGroups` of `tests`, each with a `tcId`, a `comment`, `flags` and `inputs`. Instead of Wycheproof's `result`, each test has an `expect`: `Ok` or an error name from [format spec section 19](../../docs/format-spec.md#19-errors). Every flag in `notes` cites the FS rule it tests and at least one M- or T- ID from the threat model.

| Set | Runner | Status |
| --- | --- | --- |
| TV-02 preamble | `crates/foundation/types/tests/vectors.rs` | Hand-written, deterministic |
| TV-03 deterministic CBOR | `crates/foundation/types/tests/vectors.rs` | Hand-written, deterministic; the `GeneratedDocumentParse` group is built by the runner from its inputs |
| TV-17 versions, criticality, feature bits and GREASE | `crates/foundation/types/tests/vectors.rs` | Hand-written, deterministic |

These sets use no randomness, so the seeded generator planned in `gen/` must reproduce them byte for byte. Hex inputs are lowercase. The runner also checks that every cited FS rule exists in the format spec and every M- and T- ID in the threat model. The JSON Schema of section 20.1 and the generator come with the fuzzing and test-harness item.
