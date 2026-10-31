# Tests

Cross-crate tests and test tooling live here. Unit tests stay inside each crate, and a crate's own integration tests in its `tests/`.

| Path | Contents |
| --- | --- |
| `test-vectors/` | Format vectors, their JSON Schema, the generator and vendored external vectors ([README](test-vectors/README.md)) |
| `fuzz/` | cargo-fuzz targets for every parser and for the `crypthix-crypto` entry points that read stored bytes; `fuzz/harness` holds their bodies and the minicbor oracle |
| `integration/` | Cross-crate tests (from Phase 1) |
| `bench/`, `demo/` | MVP benchmarks against gocryptfs and the scripted demo (Phase 2) |

`tests/Cargo.toml` makes this folder its own Cargo workspace, outside the main one. That keeps cargo-fuzz's nightly toolchain and C++ libFuzzer out of normal builds, and keeps the `test-rng` and `vectors` features of `crypthix-crypto`, which the generator and the fuzz harness use, from being unified into a release build (format spec FS-01; `cargo xtask check-features` guards the main workspace). Its lints copy the root `[workspace.lints]`; keep the two in sync. `tests/deny.toml` is the root `deny.toml` plus the two licence exceptions only test tooling needs (libFuzzer's NCSA, minicbor's Blue Oak); a test keeps the two files in sync. The generator is the one crate besides `crypthix-crypto` that may use `blake3`, `hkdf`, `sha2` and `chacha20poly1305` directly: it reimplements format spec section 7 to compute TV-04 and TV-05 independently.

```bash
cargo xtask test-extra                        # on stable: vector check, schema, external vectors, fuzz replay, cargo-deny
cargo xtask vectors                           # rewrite the vector files from the generator
cargo xtask vectors --check                   # fail if a committed vector differs from the generator
cargo xtask fuzz cbor_differential --time 60  # fuzz one target on nightly, or `all`
```

## Fuzzing

Targets: `preamble`, `cbor_document`, `cbor_differential`, `cbor_structured`, `store_key`, `config_toml`, `id_text`, `cx_open` (CX-AEAD open never accepts arbitrary bytes, a seal round-trips, and a flipped byte fails the commitment or the tag check that owns its region) and `verifying_key` (key parsing and strict verification compared with a second reading of FS-14 on curve25519-dalek and `verify_strict`). `cargo xtask fuzz` needs cargo-fuzz (`cargo install cargo-fuzz --locked`) and a nightly toolchain (`rustup toolchain install nightly`; set `CRYPTHIX_FUZZ_TOOLCHAIN` to pin another). It writes every vector input into `fuzz/corpus/<target>/` as a seed, reads `fuzz/regressions/<target>/` as a second corpus, and runs with the dictionaries in `fuzz/dicts/`. Builds are optimised but keep debug assertions and overflow checks (`-O -a`), with a 10 s timeout and a 64 MB allocation limit per input, so a parser that allocates for a declared length before checking it fails (FS-11). Fuzzing is supported on Linux and macOS; on Windows it is best effort.

Of the fuzz data folders, only `fuzz/dicts/` and `fuzz/regressions/` are tracked; `corpus/`, `artifacts/` and `coverage/` are local. When a target fails:

1. Minimise the input: `cd tests && cargo +nightly-2026-10-15 fuzz tmin --fuzz-dir fuzz --target x86_64-unknown-linux-gnu <target> fuzz/artifacts/<target>/<file>` (the failure message prints this with your host triple).
2. Fix the bug.
3. Commit the minimised input as `fuzz/regressions/<target>/<short-name>`. The replay test runs it on every `cargo xtask test-extra` from then on.

The FUSE-request and API-message targets of M-29 come with the FUSE and daemon items in Phase 2.
