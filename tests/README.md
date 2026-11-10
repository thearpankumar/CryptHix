# Tests

Cross-crate tests and test tooling live here. Unit tests stay inside each crate, and a crate's own integration tests in its `tests/`.

| Path | Contents |
| --- | --- |
| `test-vectors/` | Format vectors, their JSON Schema, the generator and vendored external vectors ([README](test-vectors/README.md)) |
| `fuzz/` | cargo-fuzz targets for every parser and for the `crypthix-crypto` entry points that read stored bytes; `fuzz/harness` holds their bodies and the minicbor oracle |
| `integration/` | Cross-crate tests (from Phase 1) |
| `bench/`, `demo/` | MVP benchmarks against gocryptfs and the scripted demo (Phase 2) |

`tests/Cargo.toml` makes this folder its own Cargo workspace, outside the main one. That keeps cargo-fuzz's nightly toolchain and C++ libFuzzer out of normal builds, and keeps the `test-rng` and `vectors` features of `crypthix-crypto` and the `vectors` feature of `crypthix-core`, which the generator and the fuzz harness use, from being unified into a release build (format spec FS-01; `cargo xtask check-features` guards the main workspace). Its lints copy the root `[workspace.lints]`; keep the two in sync. `tests/deny.toml` is the root `deny.toml` plus the two licence exceptions only test tooling needs (libFuzzer's NCSA, minicbor's Blue Oak); a test keeps the two files in sync. The generator is the one crate besides `crypthix-crypto` that may use `blake3`, `hkdf`, `sha2` and `chacha20poly1305` directly: it reimplements format spec section 7 to compute TV-04 and TV-05 independently. With `crypthix-core` and the fuzz harness it is also one of the three crates that may use `zstd-safe`: TV-07 builds its frames by hand and takes only encoder output from zstd.

```bash
cargo xtask test-extra                        # on stable: vector check, schema, external vectors, fuzz replay, cargo-deny
cargo xtask vectors                           # rewrite the vector files from the generator
cargo xtask vectors --check                   # fail if a committed vector differs from the generator
cargo xtask fuzz cbor_differential --time 60  # fuzz one target on nightly, or `all`
```

## Fuzzing

Targets: `preamble`, `cbor_document`, `cbor_differential`, `cbor_structured`, `store_key`, `config_toml`, `id_text`, `cx_open` (CX-AEAD open never accepts arbitrary bytes, a seal round-trips, and a flipped byte fails the commitment or the tag check that owns its region), `verifying_key` (key parsing and strict verification compared with a second reading of FS-14 on curve25519-dalek and `verify_strict`), `inner_plaintext` (an accepted inner plaintext re-encodes to itself; only `Padding`, or `Limit` exactly for a well-formed header over 1 MiB), `decompress` (a 3-byte `plain_len`, then a frame: accepted exactly when it is one FS-53 frame that zstd's one-shot decoder turns into the same `plain_len` bytes; only `Decompress`), `data_blob_open` (arbitrary bytes only fail to decrypt; the input sealed as an inner plaintext under the blob's own key and AAD gets the result its stages give alone, in the order of FS-93, so a frame error or a payload of the wrong length comes before a wrong blob ID; a written chunk opens to itself and fails with a flipped byte) and `chunker` (a file of up to 2.25 MiB, past two maximum chunks, a keyed stream with the input's tail XOR-ed over all of it, repeated, so every input byte reaches the hash at every cut point, cut in memory, through a reader with input-chosen read sizes and interruptions, and by `fastcdc::v2020::cut_gear` 5.0.0 with the same gear table, which must all agree, and cut again as a secret-class object, which must give fixed 1 MiB chunks; then the tail alone the same ways at the scaled-down sizes 64, 256 and 1,024 bytes through `crypthix-core`'s `scaled_for_fuzzing` constructors, which only its test-only `vectors` feature exposes, where a few KiB of input reach every edge of the cut rule). `cargo xtask fuzz` needs cargo-fuzz (`cargo install cargo-fuzz --locked`) and a nightly toolchain (`rustup toolchain install nightly`; set `CRYPTHIX_FUZZ_TOOLCHAIN` to pin another). It writes every vector input into `fuzz/corpus/<target>/` as a seed, reads `fuzz/regressions/<target>/` as a second corpus, and runs with the dictionaries in `fuzz/dicts/`. Builds are optimised but keep debug assertions and overflow checks (`-O -a`), with a 10 s timeout and a 64 MB allocation limit per input, so a parser that allocates for a declared length before checking it fails (FS-11). Inputs are at most 4096 bytes, except for `preamble` and `data_blob_open` (8 KiB) and `decompress` (144 KiB, for frames that reach zstd's 128 KiB block edges); libFuzzer cuts longer corpus files short, so `cargo xtask fuzz` fails if a seed is longer than its target's limit (`max_len` in `xtask/src/side.rs`). The stable replay test pins the fewest seeds the vectors give each target, so a generator change that stops feeding one fails it. Fuzzing is supported on Linux and macOS; on Windows it is best effort.

Of the fuzz data folders, only `fuzz/dicts/` and `fuzz/regressions/` are tracked; `corpus/`, `artifacts/` and `coverage/` are local. When a target fails:

1. Minimise the input: `cd tests && cargo +nightly-2026-10-15 fuzz tmin --fuzz-dir fuzz --target x86_64-unknown-linux-gnu <target> fuzz/artifacts/<target>/<file>` (the failure message prints this with your host triple).
2. Fix the bug.
3. Commit the minimised input as `fuzz/regressions/<target>/<short-name>`. The replay test runs it on every `cargo xtask test-extra` from then on.

The FUSE-request and API-message targets of M-29 come with the FUSE and daemon items in Phase 2.
