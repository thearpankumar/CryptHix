# CryptHix Rust Style Guide

CryptHix follows the [Google Rust Style Guide](https://google.github.io/styleguide/rustguide.html), published by Google in October 2026. This page summarises its rules in our own words, notes how each one is enforced in this repository, and lists the CryptHix-specific rules that sit on top. When this page and the Google guide disagree, the Google guide wins, except for the [CryptHix additions](#crypthix-additions) at the end.

The Google guide in turn defers to the official [Rust Style Guide](https://doc.rust-lang.org/style-guide/) and the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) wherever it does not say otherwise.

## Goals

- **Readability over writeability.** Code is read far more often than it is written.
- **Automate what can be automated.** If `rustfmt` or Clippy can enforce a rule, they do.
- **Stay close to the wider Rust ecosystem.**
- **Only rules that pull their weight.** No rules that just settle taste.

### Library code and application code

The API design rules are **binding for library crates** (everything under `crates/`) and **strong recommendations for binaries** (`apps/`, `xtask/`). In application code, prefer simplicity and avoid premature generalisation.

## How the rules are enforced

| Mechanism | File | What it covers |
| --- | --- | --- |
| rustfmt | `rustfmt.toml` | All formatting; `max_width = 100`, 2024 style edition |
| Workspace lints | `Cargo.toml` `[workspace.lints]` | `missing_docs`, `unsafe_code`, `unreachable_pub`, Clippy `all` and `pedantic`, and the Google-aligned lints listed below |
| Clippy config | `clippy.toml` | Project words accepted in docs; `unwrap`/`expect` allowed in tests |
| Layer check | `cargo xtask check-layers` | Crate dependency rules from [backlog.md](backlog.md#architecture-rules) |
| Release features | `cargo xtask check-features` | No release build enables the test-only `test-rng` or `vectors` features of `crypthix-crypto` ([format spec FS-01](format-spec.md#4-identifiers-primitives-and-randomness)) |
| cargo-deny | `deny.toml` | Licences, advisories, sources, and "only `crypthix-crypto` imports crypto crates", including `getrandom`, `subtle` and `curve25519-dalek` |
| Pre-commit hook | `.githooks/pre-commit`, `xtask/src/pre_commit.rs` | File hygiene, secrets (gitleaks), formatting and Clippy on staged changes; Clippy and tests of the `tests/` workspace when it, `crypthix-types` or `crypthix-crypto` changes |
| Line endings | `.gitattributes` | LF in the repository on every platform; vendored test vectors kept byte for byte |
| Secret scanner config | `.gitleaks.toml` | Default gitleaks rules; only vendored, transcribed and generated vector JSON is allowlisted, file by file |
| Test vectors | `cargo xtask vectors --check` | The committed vectors match the generator byte for byte ([format spec FS-94](format-spec.md#20-test-vectors)) |
| `tests/` workspace | `cargo xtask test-extra` | Vector schema, external vectors, generator check and fuzz replay on stable, then cargo-deny with `tests/deny.toml` |
| Fuzzing | `cargo xtask fuzz <target \| all>` | cargo-fuzz on nightly, seeded from the vectors ([Testing](#testing)) |
| Docs check | `cargo xtask check-docs` | Relative links and anchors in every tracked Markdown file; `FS-`, `TV-`, `M-` and `T-` IDs cited in the docs and vectors are defined |
| Vendored vectors | `cargo xtask check-vendored` | Each file under `tests/test-vectors/external/` has the git blob ID its SOURCE records |
| Commit messages | `cargo xtask check-commits <base>` | One-line `<type>: <summary>` messages ([CONTRIBUTING](CONTRIBUTING.md#commit-messages)) |
| Spelling | `_typos.toml` | [typos](https://github.com/crate-ci/typos) over code and docs; vector data excluded |
| Workflow lint | `.github/zizmor.yml` | actionlint and zizmor over `.github/` |
| Toolchain | `rust-toolchain.toml` | Latest stable; fuzzing and Miri use the nightly pinned in `xtask/src/side.rs` |
| CI | `cargo xtask ci`, `.github/workflows/` | Runs all of the above with warnings as errors ([CONTRIBUTING](CONTRIBUTING.md#continuous-integration)) |

Enable the pre-commit hook once per clone with `cargo xtask install-hooks`. On every commit it checks the staged changes for file hygiene (trailing whitespace, conflict markers, a final newline, files over 1 MiB), secrets ([gitleaks](https://github.com/gitleaks/gitleaks), installed with `go install github.com/zricethezav/gitleaks/v8@v8.30.1`), formatting and Clippy. The checks are written in Rust (`xtask/src/pre_commit.rs`) and the hook is one line of POSIX `sh`, so they run the same on Linux, macOS and Windows (Git for Windows' bundled shell).

Run everything CI runs, locally, before pushing:

```bash
cargo fmt --all
cargo xtask ci
```

Every crate inherits the shared lints with `[lints] workspace = true`. Create new crates with `cargo new` inside a group folder (for example `cargo new --lib --name crypthix-foo crates/engine/foo`); Cargo then inherits the workspace package fields and lints automatically.

## Code organisation

- **Name files after their main item.** `Manifest` lives in `manifest.rs`.
- **Non-leaf modules hold no implementations.** They contain only `mod` declarations and re-exports, plus a little glue. `mod tests` belongs in leaf modules.
- **No glob imports** (`use foo::*`). Allowed: `use super::*` in an inline test module, `use Enum::*` inside that enum's own methods, and `pub use submodule::*` in a non-leaf module. Do not define preludes. Clippy `wildcard_imports` warns.
- **One module per `use` line.** Write `use foo::bar::{Bar, Baz};` and `use foo::Foo;`, never `use foo::{Foo, bar::Bar};`.
- **Import traits locally** inside the function that needs them, unless the trait is used throughout the file.
- **Call free functions through their module:** `mem::take(x)`, not a bare `take(x)` after importing it.
- **Use type names unqualified:** `Regex`, not `regex::Regex`. Qualify or rename ambiguous ones such as `io::Error`.

## Formatting

- `rustfmt` formats everything. Do not hand-format.
- `#[rustfmt::skip]` only for deliberate alignment (tables, matrices, test vectors) or generated code, never for personal taste.

## Ownership and borrowing

- **Avoid `Rc` and `Arc`.** Prefer unique ownership and borrowing; use shared ownership only when the alternative is unreasonably complex.
- **Borrow instead of deep-copying.** Call `.clone()` only when a copy is genuinely needed. Cloning an `Rc` or `Arc` is fine.

## Function inputs and outputs

- **Accept the most flexible borrowed form:**

  | Use | Instead of |
  | --- | --- |
  | `&T` | `&Box<T>` |
  | `&[T]` | `&Vec<T>` |
  | `&str` | `&String` |
  | `Option<&T>` | `&Option<T>` |

- **Library code returns iterators** (`impl Iterator`) rather than `Vec<T>`, and accepts `impl IntoIterator` when it only iterates. Application code may use `Vec<T>` and `&[T]` when simpler.
- **`impl Into<T>` parameters** only in library APIs where call-site ergonomics really matter. Almost never in application code.
- **Prefer an `enum` to a `bool` parameter** when the meaning is not obvious at the call site. If you keep a `bool`, add an inline comment at the call.
- **Report errors by contract:**
  - `Option` for simple, obvious failures (checked arithmetic, lookups).
  - `Result` for recoverable failures where the caller needs context.
  - `panic!` only for bugs and broken invariants. See the CryptHix additions for where panics are not allowed.

## Types

- **Use a newtype** (`struct EpochId(u32);`) when the value has its own meaning, needs its own API, may change representation, or could be mixed up with another value of the same type. Prefer it to a type alias.
- **Prefer named fields to tuples**, except for single-field newtypes and very local code.

## Traits

- **Implement standard traits** instead of look-alike methods: `FromStr`, not a bare `from_str`.
- **Use `#[derive]`** whenever it can express the impl.
- **Generics over `dyn Trait`** in libraries, unless code size matters.
- **Define a trait only** for generic bounds, `impl Trait` / `dyn Trait` APIs, or extension traits. Do not use traits just to group methods.
- **Extension traits** end in `Ext` (`PathExt`).
- **Which standard traits to implement:**
  - `Clone` for most types, but not for types that represent an external resource.
  - `Copy` only when the type will clearly stay `Copy`; error types should be `Copy` when possible.
  - `Default` when there is a `new()` or a natural default; options structs always implement `Default`.
  - `PartialEq` and `PartialOrd` unless `Eq` and `Ord` truly hold.
  - Map keys implement `Hash` and `Eq`, plus `Ord` if there is a clear total order.
- **Pair important `From` impls** with an explicit constructor such as `from_bytes()`.

## Concurrency

- **Never reach inside a poisoned mutex.** Treat poison as a bug.
- The Google guide's "no `async`" and "no `std::thread`" rules apply only to Chromium. CryptHix does not adopt them.

## Macros

Prefer, in order: plain functions, types and traits; then `macro_rules!`; then other code generation; then procedural macros last. Macros hurt IDE support and readability.

## Naming

- **Conversions:** `as_` (cheap borrow), `to_` (expensive or owned), `into_` (consumes `self`). Clippy `wrong_self_convention` checks this.
- **Constructors:** `new()`, `new_with_foo()`, `try_new()` when it returns `Result`; `from_foo()` alongside a `From` impl.
- **Getters and setters:** `foo()`, `foo_mut()`, `set_foo(value)`, `take_foo()`, `replace_foo(value)`, and closure-based `with_foo()` / `with_mut_foo()`.
- **Lifetimes:** descriptive names (`'manifest`), except `'_`, highly generic code, and up to two single letters for simple input/output relationships.
- **Generic parameters:** short, and hint at the main bound (`K: Key`); `T` and `U` are fine when unbounded.
- **No abbreviations** outsiders would not know, and no dropped letters (`manifest`, not `mnfst`). Common ones like `Ip` or `Dek` that are defined in our docs are fine.

## Documentation

- **Document every public item.** The `missing_docs` lint warns.
- `///` for items, `//!` at the top of modules and crates, `//` for implementation notes.
- Include examples somewhere in each crate, document panics on bad input, and spell out invariants for anything `unsafe`.
- Write full sentences with capitals and full stops. Do not restate what the code already says.

## Other language features

- **`unsafe`:** avoid it unless no safe option exists. Wrap it in a small safe abstraction, add a `// SAFETY:` comment explaining why it is sound, and justify why safe code will not do (with benchmarks if the reason is speed). Clippy `undocumented_unsafe_blocks` is denied.
- **No unstable features.** We build on stable Rust.
- **`len()` comes with `is_empty()`.**
- **Do not use `#[doc(hidden)]` items** from crates you do not own.
- **Mark public functions `const`** only if they will stay `const`; removing it is a breaking change.
- **Overload operators** only for real mathematical or logical meaning.
- **`#[non_exhaustive]`** on public enums and on public structs with public fields that other crates use, unless the set is truly fixed.
- **`#[must_use]`** on functions whose result must not be ignored, and on error types and lazy computations.
- **No code before `main()`** (no `ctor`-style tricks).

## Implementation details

- **Don't lean too hard on type inference.** Give variables explicit types instead of turbofish, especially for `.into()`, `.parse()` and long iterator chains.
- **Match instead of check-then-unwrap:** `if let Some(x) = value`, never `if value.is_some() { value.unwrap() }`.
- **`expect("reason")` over `unwrap()`** when a panic is intended. Clippy `unwrap_used` warns.
- **On `#[non_exhaustive]` enums, list every known variant** and keep the wildcard arm for the rest.
- **Give `assert!` a message** that adds information, not a restatement of the condition.
- **Keep iterator chains short.** Don't build chains inside a `for` header, avoid side effects in combinators, and avoid `for_each`.
- **No `catch_unwind`** in first-party code.
- **Use `format!` / `write!`** to join more than two strings or to substitute values.

## Testing

Where each kind of test lives, and the conventions for each.

- **Unit tests** sit in a `mod tests` at the bottom of the leaf module they test. **Integration tests** of one crate sit in its `tests/`; cross-crate tests go in `tests/integration/`.
- **Test vectors** live in `tests/test-vectors/` ([format spec section 20](format-spec.md#20-test-vectors)). Never edit a vector file by hand: change the generator in `tests/test-vectors/gen`, run `cargo xtask vectors`, and add a format-spec changelog row. `cargo xtask vectors --check` fails when a committed file differs from the generator, and the schema test checks every file against `schema/vector-file.schema.json`. Vendored vectors under `external/` stay unchanged; each folder has a `SOURCE` (repository and commit, or the document a vector set was transcribed from, and the files) and a `LICENSE`. Every runner pins how many cases a file holds (and, for generated sets, which groups), so an emptied or trimmed file fails the runner as well as `vectors --check`.
- **Fuzz targets** for every parser (backlog rule 10, M-29), including the text forms of IDs and counters. A target's body is a plain function in `tests/fuzz/harness` that panics when a property fails; the cargo-fuzz binary in `tests/fuzz/fuzz_targets` only calls it. `cargo xtask test-extra` runs every body on stable against each vector input, one-bit mutations of the short ones and every saved regression. `cargo xtask fuzz <target>` fuzzes on nightly (`cargo install cargo-fuzz --locked`, `rustup toolchain install nightly-2026-10-15`, the nightly pinned in `xtask/src/side.rs`), starting from the vector inputs, with debug assertions on and a per-input allocation limit. Test every limit at exactly its value and one above: random fuzzing rarely lands on an exact length. When fuzzing finds a crash, minimise it with the `cargo fuzz tmin` command the failure message prints, fix the bug, and commit the input under `tests/fuzz/regressions/<target>/`. CBOR targets compare our validator with an independent minicbor oracle; compare acceptance only, since error precedence is pinned by the vectors.
- **Property tests** use proptest with its default 256 cases. Set `PROPTEST_CASES=4096` for a deep run. Commit any `proptest-regressions/` file proptest writes, so a found case is rerun forever.
- **Slow tests**, such as Argon2id at its 256 MiB floor, are marked `#[ignore = "slow: <why>"]`. Run them with `cargo test -- --ignored`; the scheduled deep-test job does.
- **Test-only features** of `crypthix-crypto` (`test-rng`, `vectors`) are enabled only by the crate's own tests, through `required-features`, and by the `tests/` workspace. `cargo xtask check-features` fails if anything in the main workspace would enable them in a release build.
- **Crash tests** for anything that writes to a store use `crypthix-testkit` (a dev-dependency only; `check-layers` rejects it anywhere else): `MemoryBackend`, `FaultBackend` for lost replies, injected errors and corrupt uncached reads (assert `applied()` so a misplaced fault cannot pass), and `for_each_crash_point`, which crashes a deterministic workload after every operation and checks what a restart finds (M-44). Faults are whole operations, matching the `Backend` contract; torn writes and reordering below it come with the local backend.
- **Benchmarks** use criterion in each crate's `benches/` with `harness = false`. Run them with `cargo bench -p <crate> --bench <name>`; `cargo clippy --all-targets` keeps them compiling.

## CryptHix additions

These rules are specific to this project and come from the [architecture rules](backlog.md#architecture-rules).

1. **Only `crypthix-crypto` touches cryptography crates.** cargo-deny enforces this.
2. **Keys never cross crate APIs as plain byte vectors.** Use the zeroizing key types from `crypthix-crypto`.
3. **`unsafe` lives only in `crypthix-crypto`, `crypthix-hardening` and `crypthix-fs`.** `unsafe_code` is denied workspace-wide; those crates opt in per module with `#[allow(unsafe_code)]` and a `SAFETY:` comment on every block.
4. **No panics on data paths.** Code that handles user data, keys, shards or the genome log returns `Result`; a panic there could lose data or leave a half-rotated key. Panics stay for programmer errors in setup code and tests.
5. **Never log secrets or plaintext paths.** Log IDs and hashes instead.
6. **Dependencies point down the layers only.** `cargo xtask check-layers` enforces this.
7. **Library crates hold no global state.** Only `apps/` wire concrete types together.
8. **Platform code sits behind `cfg(target_os)`** in `crypthix-fs` and `crypthix-hardening`, with stubs elsewhere.

## Source

Summarised and adapted from the [Google Rust Style Guide](https://google.github.io/styleguide/rustguide.html), which is licensed under [CC-BY 3.0](https://creativecommons.org/licenses/by/3.0/). Rules marked in the Google guide as specific to Chromium, Android or Fuchsia (small crates with a flat file layout, `chromium::import!`, no `async`, no `std` threads, `fuchsia_sync::Mutex`, per-codebase test frameworks) are not adopted.
