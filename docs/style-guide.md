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
| cargo-deny | `deny.toml` | Licences, advisories, sources, and "only `crypthix-crypto` imports crypto crates" |
| CI | `.github/workflows/ci.yml` | Runs all of the above with warnings as errors |

Run everything locally before pushing:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo xtask check-layers
cargo deny check
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
