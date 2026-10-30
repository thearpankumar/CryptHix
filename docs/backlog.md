# CryptHix Backlog

Top-level features in **implementation order**. Each item is a feature, not a micro task; break items down when you plan each sprint. Feature IDs (E, A, U, M, O) match [project-vision.md](project-vision.md). The crate each feature lives in is shown in `code` as `group/crate`; the workspace layout and crate rules are at the end of this file.

Tick a box when the feature is merged, tested and documented. CLI commands and VS Code panels for a feature ship with that feature.

Each phase ends with a [threat-model review](threat-model.md#15-did-we-do-a-good-job). Each item names what it must deliver from the two design documents:
- **Threat model.** "(M-8)" is a design requirement from [section 11.1](threat-model.md#111-new-mitigations-design-requirements), whose "Lands with" column names the item here. W1… are [windows of exposure](threat-model.md#122-windows-of-exposure) an item opens or closes, and OQ-… are [open questions](threat-model.md#14-open-questions) the item must decide.
- **Format spec.** Section links, FS- rules and TV- vector sets point into [format-spec.md](format-spec.md). Fields marked *Reserved Px* there are already part of format 0, so the item that first writes one fills that field and does not invent a new one.

---

## Phase 0: Foundations

- [x] **Cargo workspace skeleton** — Repo as one Cargo workspace using the grouped layout at the end of this file (`crates/<group>/<crate>`, `apps/`, `extensions/`), shared lints and dependency versions, `rust-toolchain.toml`, licence, CI (build, test, clippy, fmt, `cargo-deny`, layer-rule check). `workspace root`
- [x] **Threat model document** — Attackers, assets, trust boundaries and what each phase defends, based on [project-vision.md section 8](project-vision.md#8-threat-model). See [threat-model.md](threat-model.md). `docs/`
- [x] **On-disk format spec v0** — Manifest, shard, key-file and log-entry formats with version fields and a test-vector plan. Must include full AAD binding (M-8), key commitment (M-9), authenticated KDF parameters (M-10), per-device signing keys (M-14), retirable random epoch KEKs (M-34), no-downgrade suite pinning (M-33), domain separation (M-37), encrypted manifests and shard headers (M-39), a signed vault root (M-40), versioned shares and a field for the anti-rollback counter. See [format-spec.md](format-spec.md). `docs/`
- [x] **Shared types and errors** — IDs (object, shard, epoch, device), error types matching the format spec's error table, config loading, the preamble and our own strict deterministic CBOR codec ([format spec 5](format-spec.md#5-encoding)), store names, cross-crate traits (`Backend`, `EventSink`, `ResponseActions`; `KeyProvider` lives in `crypthix-crypto`, rule 11), TV-02, TV-03 and TV-17 vectors. `foundation/crypthix-types`
- [x] **Fuzzing and test harness** — `cargo-fuzz` targets for the `crypthix-types` parsers (preamble, CBOR document, a CBOR differential against an independent `minicbor` oracle, structure-aware CBOR, store names, ID and counter text, and TOML config, M-29), replayed on stable by `cargo xtask test-extra`; the vector JSON Schema and the generator with `cargo xtask vectors --check` ([format spec 20](format-spec.md#20-test-vectors)); property-test conventions; Wycheproof, BLAKE3 and ed25519-speccheck vectors vendored as in [format spec 20](format-spec.md#20-test-vectors); the `crypthix-testkit` crash-point harness (M-44); criterion benchmarks. Moved to later items: FUSE-request and API-message targets (P2), TV-20 crash tests (local backend), the seeded `test-rng` stream and the known-answer runners (crypto wrappers). `tests/`, `foundation/crypthix-testkit`

## Phase 1: Engine core

- [ ] **Crypto wrappers (E4)** — Thin wrappers over audited crates for suite `0x0001`: XChaCha20-Poly1305 inside the committing CX-AEAD, HKDF-SHA-256, BLAKE3, Argon2id, Ed25519 with strict verification; zeroizing key types; known-answer runners over the vendored Wycheproof, BLAKE3 and ed25519-speccheck vectors and the RFC vectors transcribed with them (TV-01); the seeded `ChaCha20Rng` `test-rng` stream for the vector generator, with a build check that no release binary enables it (FS-01, FS-94); no other crate calls crypto libraries directly, and `cargo-deny` also bans `curve25519-dalek`, `subtle` and `getrandom` outside this crate. cargo-deny `wrappers` allow only direct parents, so these entries list the audited crates that pull them in (for example `ed25519-dalek`), and `getrandom` stays allowed for dev-dependencies such as `proptest`. Covers key commitment (M-9), keys and nonces straight from the kernel's `getrandom` (M-36), the HKDF label registry, signature context prefixes and Ed25519 `verify_strict` (M-37), and vector sets TV-01, TV-04 and TV-05 ([format spec 4.2](format-spec.md#42-suite-0x0001), [7](format-spec.md#7-domain-separation-and-committing-aead)). Decides OQ-13 (FIPS mode). `foundation/crypthix-crypto`
- [ ] **Protected key memory (O1)** — Key buffers in `memfd_secret`, `mlock`, excluded from core dumps, with a fallback on older kernels; covers derived keys and plaintext buffers too, not only the root key (T-31). `foundation/crypthix-crypto`
- [ ] **Chunking, compression and padding (E1, E2, E3)** — FastCDC chunking with secret per-vault parameters (M-39), zstd with auto-skip for already-compressed data and per-chunk compression only (T-40), Padmé padding to size buckets; deduplication only inside one ordinary object and never for secret files (T-85, FS-55); TV-07 ([format spec 10.1–10.4](format-spec.md#10-data-path-chunks-blobs-packs-and-shards)). `engine/crypthix-core`
- [ ] **Encrypt pipeline and signed manifests (E4, E5)** — Data and meta blobs, size-class packs, shards, device-signed manifests with Merkle trees, the path index and the signed vault root (M-8, M-9, M-39, M-40); shard IDs and pack hashes checked before decoding (T-47); read-after-write check (M-45); full write and read path; vector sets TV-10 to TV-13 (shards with k = 1) and TV-21 ([format spec 10](format-spec.md#10-data-path-chunks-blobs-packs-and-shards), [11](format-spec.md#11-object-manifest), [12](format-spec.md#12-path-index), [14](format-spec.md#14-signed-vault-root-and-monotonicity)). Opens W5: per-device monotonicity only until E18 ([format spec 2.2](format-spec.md#22-limits-of-format-0-in-phase-1)). `engine/crypthix-core`
- [ ] **Key hierarchy (E6)** — Root key → random keyring → random epoch KEKs (M-34) → per-object DEKs; vault signing key and the first device certificate (M-14); passphrase share slot and printed recovery share (M-10, M-18, M-35); wrapped key storage; root rotation (FS-39); vector sets TV-06, TV-08, TV-09, TV-14 and TV-16 with t = 1 ([format spec 8](format-spec.md#8-key-hierarchy), [9](format-spec.md#9-key-files), [13](format-spec.md#13-vault-config-and-devices)). Opens W4 (rotation is a KEK re-wrap only) and W6 (the passphrase or recovery sheet alone is the root). `engine/crypthix-keys`
- [ ] **Local storage backend** — Shard, key-file and vault-root I/O on `/var/lib/crypthix/<vault-id>/store` behind the `Backend` trait; commit order with compare-and-swap on the root (M-44), crash-tested at every commit step with `crypthix-testkit`, plus torn-write and lost-unsynced-data faults below the `Backend` trait for the file I/O itself. The local backend may use std and `rustix` file APIs behind `cfg(target_os = "linux")`, without `unsafe`, as an exception to rule 4. Directory layout, store names, the single-writer lock and two-phase garbage collection (FS-89, FS-91, FS-92); root sequences checked per device (TV-15); the golden tiny vault, crash and GC vectors (TV-20) ([format spec 14](format-spec.md#14-signed-vault-root-and-monotonicity), [17](format-spec.md#17-commit-rotation-and-garbage-collection), [18](format-spec.md#18-directory-layout)). `engine/crypthix-store`
- [ ] **Automatic KEK rotation (E7)** — Scheduled re-wrap of DEKs and pack keys and re-seal of the encrypted trees under a new epoch KEK, in the background (daily by default, [format spec FS-90](format-spec.md#17-commit-rotation-and-garbage-collection)). `engine/crypthix-keys`
- [ ] **Embedded event queue (M1)** — Persistent in-process queue for rotation, scrub and repair jobs and alerts, behind the `Bus` trait; jobs are authenticated and carry sequence numbers and expiry (M-12, FS-86, TV-18, [format spec 16](format-spec.md#16-queue-job-envelope)). `foundation/crypthix-bus`
- [ ] **CLI v0** — `crypthix init / put / get / verify / rotate / status`; `init` prints a recovery share (M-35) in the SLIP-39 recovery text ([format spec 9.2](format-spec.md#92-share-plaintext-and-recovery-text)). Decides OQ-16 (QR code). `apps/crypthix-cli`

## Phase 2: Workspace MVP → 0.1 alpha

- [ ] **Daemon and local API** — `crypthixd` process that owns keys and wires all crates; JSON-over-Unix-socket API for CLI and extension. Runs as its own system user that owns the store and config, checks socket peers with `SO_PEERCRED` and pidfd, fails closed, and reports Full or Degraded hardening mode (M-13, M-15). Decides OQ-7 (daemon capabilities and users). Opens W11 (Degraded mode wherever BPF-LSM is off). A root helper mounts the vault and brokers caller identity (M-20, M-21); keys live in a separate key-holder process (M-29). A `cargo-fuzz` target for API messages (M-29). `apps/crypthixd`, `access/crypthix-api`
- [ ] **Transparent encrypted folder (A1)** — FUSE mount backed by the engine; open, read, write, rename, delete, mmap-safe; `crypthix mount`. Secret paths use direct I/O with no shared page cache; the caller's UID is checked on every request; lookups and listings follow the same policy (M-1, M-15, M-23); writes the manifest's `fs_attrs` field (*Reserved P2*, [format spec 11](format-spec.md#11-object-manifest)). A `cargo-fuzz` target for FUSE requests (M-29). Decides OQ-14 (`getxattr` leaks). Opens W2: not ransomware-safe until snapshots. `access/crypthix-fs`
- [ ] **Program identity resolution** — Caller PID → exe path, binary hash (cached), parent chain, uid, cgroup. pidfd and start-time checks against PID reuse; identity by exe device, inode and hash, never by process name; launch-environment check; reads the exec-time record of the root helper in Full mode (M-2, M-3, M-17, M-20). Decides OQ-3 (container profiles). `access/crypthix-policy`
- [ ] **Per-program policy engine (A2)** — `policy.toml` rules by program and path, most-specific-first matching, default ask for unknown programs and deny for secret paths. Policy changes only through the API (M-7); files that steer allowed programs are protected (M-6); identity by exe, never name (M-3); lookups and listings gated too (M-23); interpreter grants bound to a project and an interactive launch (M-25); no secrets for editors and browsers by default (M-26). Opens W1 until O4 and O5. `access/crypthix-policy`
- [ ] **First-use prompts and deny log (A3, A4)** — Allow once / always / deny prompts via the API, never accepted from the VS Code extension alone (M-26); every denial logged with its process tree, rate-limited and aggregated; approvals recorded with the approving identity and presence method, signed once E12 lands (M-31). `access/crypthix-policy`, `access/crypthix-api`
- [ ] **Protected admin actions (A14)** — Loosening policy, unfreezing, deleting snapshots, adding devices and disabling the guard require user presence (passphrase or OS authentication), so malware running as the user cannot switch protection off. Passphrase or polkit first; FIDO2 touch or second-device confirmation later (M-5). Policy and guard config change only here (M-7). Opens W3: passphrase or polkit presence can be faked by same-user code. `access/crypthix-api`, `access/crypthix-policy`
- [ ] **AI coding agent guard (U1)** — Agent profiles matching process trees (Claude Code, Cursor, Codex); deny secrets, allow code; per-agent access feed. `crypthix agent run` cgroup launcher and own-exe matching (M-4), agent configs protected as steering files (M-6), agent-write taint (M-24), no secrets for editors and browsers by default (M-26), agent options that keep secrets out of transcripts (M-27); stated as best effort. Decides OQ-8 (agent sandboxes). `access/crypthix-policy`
- [ ] **Secrets never on disk (U2)** — Secret-path presets (`.env*`, `.ssh/**`, `*.pem`, cloud credentials) readable only by named programs; import of existing secrets into the vault; no grants under package-manager lifecycle scripts and build backends (M-25); MCP profiles get named secrets only, never `.env*` globs (T-72). `access/crypthix-policy`, `apps/crypthix-cli`
- [ ] **VS Code extension v1 (A5)** — Lock status and hardening mode (M-13), blocked-access feed, approve and revoke, agent profile editor, rotate now. Approvals here always go through the daemon's own prompt, never the extension alone (M-26). `extensions/vscode`
- [ ] **MVP benchmarks and demo** — Build benchmark against plain disk and gocryptfs; scripted demo where a malicious `postinstall` and an AI agent fail to read `.env` while `python` and `git` work. Decides OQ-15 (pack size classes and packing for small commits, [format spec 22](format-spec.md#22-open-items)). `tests/bench`, `tests/demo`

## Phase 3: Immune system and recovery → 0.5 beta

- [ ] **Genome log (E12)** — Append-only, hash-chained, signed log of puts, rotations, repairs, guard actions, incidents and restores; `crypthix log --verify`; optional public log heads. Signed approvals and policy changes with its own storage quota (M-31); the vault root commits to the log head (M-40). Fills the reserved log fields: entries and segments, `log_head` in the root, `last_log` in device state, feature bit 0 and the `sign-log` capability; TV-19 ([format spec 15](format-spec.md#15-genome-log-entry)). Comes first in this phase because incidents and rollback read its timeline. Closes the unsigned-deny-log part of W5. `engine/crypthix-log`
- [ ] **Snapshots (E11)** — Copy-on-write snapshots of the manifest tree (hourly, plus one pinned on every freeze), immutable shards, retention policy, point-in-time restore of a file, folder or the whole vault. Fills the reserved snapshot fields: `snapshot_set` in the root, the snapshot-root file type and node blob kind, feature bit 1 ([format spec 14.1](format-spec.md#141-root-fields)). Closes W2 together with E17. `engine/crypthix-snapshot`
- [ ] **Snapshot lock (E17)** — Snapshot deletion and retention changes are protected actions with a 7-day delay; snapshots tied to an open incident cannot be deleted; delays counted on a monotonic counter in signed state, not the wall clock (M-32); changes to backend retention are a guard signal (M-42). `engine/crypthix-snapshot`
- [ ] **Guard: canaries and honey keys (A6)** — Generate, place and watch decoy files and keys; canaries match real files in timing and attributes (M-23, T-23). `security/crypthix-guard`
- [ ] **Guard: behaviour detection (A7)** — Per-program baselines for read and write rate, renames and write entropy; writes to steering files, lockfiles and dependency manifests as signals (M-6); scoring; retention limits on baselines (M-49). `security/crypthix-guard`
- [ ] **Guard learning mode and tuning (A16)** — Alert-only period while baselines settle, never auto-allowing unknown programs; per-program exceptions for noisy but legitimate tools. Opens W7 (alert-only for the first 7 days). `security/crypthix-guard`
- [ ] **Response playbook (A8)** — Alert → throttle → freeze + snapshot → emergency rotation + revocation, configured in `guard.toml`; canary hits and unauthenticated admin attempts go straight to freeze, within a DoS budget (M-30). Until E8 and E14 land, emergency rotation means KEK rotation and revocation means withdrawing program approvals. `security/crypthix-guard`
- [ ] **Incident workflow (A15)** — Incident view with log timeline, process tree, files touched, suggested clean snapshot and one-click actions (roll back, rotate, revoke, unfreeze); incident report written to the log. `security/crypthix-guard`, `extensions/vscode`
- [ ] **Ransomware rollback (U3)** — Pick the last clean snapshot (before the first anomaly); restore only affected files or the whole vault while keeping clean edits; restored executables and steering files flagged for review (M-47); one click from CLI and extension. `engine/crypthix-snapshot`, `extensions/vscode`
- [ ] **Leak-path control (A9)** — Redirect or block editor swap and backup files, `__pycache__`, build caches and `/tmp` copies; warn on unencrypted swap and on agent transcripts and editor history (M-27). `access/crypthix-fs`
- [ ] **Self-sandbox (O2)** — Landlock, seccomp-bpf and no-new-privs for the daemon. `security/crypthix-hardening`
- [ ] **BPF-LSM guard (O4)** — Only the daemon may open shards; block `ptrace`, `process_vm_readv` and `/proc/<pid>/mem` into allowed programs; block foreign unmounts and forced crash dumps (M-22); pinned links with a heartbeat (M-28); exec-time identity records for the daemon (M-20); Full mode shown in status (M-13). Closes W1 together with O5, in Full mode only. `security/crypthix-hardening`
- [ ] **Binary integrity and eBPF telemetry (O5, O6)** — fs-verity and IMA checks on allowed programs and the daemon; process context fed to the guard. `security/crypthix-hardening`
- [ ] **TPM sealing (O3)** — Root share sealed to the boot state; salted TPM sessions, TPM PIN, signed PCR policy (M-19); recovery share printed at enrolment (M-16); keys wiped on suspend and lock (M-11). Fills the reserved TPM slot kind and `tpm` field and device-key protectors 2 and 3 ([format spec 9.1](format-spec.md#91-share-slot), [9.6](format-spec.md#96-device-key)). `engine/crypthix-keys` (`tpm` feature)
- [ ] **Webhooks and SIEM bridge (M4)** — Push alerts and rotation reports to Slack, email or a SIEM. `foundation/crypthix-bus` (`webhooks` feature)

## Phase 4: Durability and sync

- [ ] **DEK rotation and epoch retirement (E8)** — Background re-encryption with rate budget and checkpoints; two-phase retirement with grace period; proof that retired keys decrypt nothing. Upgrades the playbook's emergency rotation to full re-encryption. Retirement waits for retention windows and rotates the keyring generation (M-41, FS-47, FS-48); crash-injection tests mid re-encryption (M-44); full re-encryption needs A14 presence, shows a cost estimate and runs one at a time (M-30). Closes W4. `engine/crypthix-keys`
- [ ] **Anti-rollback and tamper detection (E18)** — Monotonic counter and log heads on every device (optionally TPM) detect a backend serving old or altered data; raises a guard alert. Fills the reserved `expires_at`, `counter_anchors`, `tpm_nv_index` and `max_head_age` fields; freeze detection (FS-83, T-42) with the skew rules of M-32 ([format spec 14.3](format-spec.md#143-anti-rollback-counter-and-expiry)). Decides OQ-1 (where the counter lives). Closes W5. `engine/crypthix-log`, `engine/crypthix-store`
- [ ] **Erasure coding and placement (E9)** — Reed-Solomon k+m shards; placement policy across backends, with region constraints (M-49) and wrapped keys and the log replicated with the shards (T-50). Fills the reserved `erasure_default` and feature bit 2; TV-12 with m > 0 ([format spec 10.7](format-spec.md#107-shard-file)). `engine/crypthix-store`
- [ ] **Cloud backends** — S3, Google Drive and Dropbox implementations of the `Backend` trait. Settles what the local backend did not need: S3 `If-None-Match` for atomic create and a real capability probe (FS-87); delete semantics on versioned and Object Lock buckets (a delete marker counts as `Deleted`, a locked version as `Locked` or `PermissionDenied`, FS-91); per-call timeouts and cancellation; mapping provider errors to `BackendError` with retries for transient ones; a backend ID on backend events (M-46). Google Drive has no atomic create, so it never holds roots. Credentials encrypted under the vault and held by the daemon (T-46). Decides OQ-10 (Google Drive). `engine/crypthix-store` (`s3`, `gdrive`, `dropbox` features)
- [ ] **Immutable cloud copies (E19)** — S3 Object Lock, bucket versioning and provider equivalents so stolen cloud credentials cannot delete backups. S3 compliance mode in a separate account with hardened put-only credentials (M-42); cloud backends stay off by default until E18 and E19 land (W8). Key files never locked longer than the E8 grace period (M-41, FS-48); retirement claims name the retention window (W13). `engine/crypthix-store`
- [ ] **Metabolism (E10)** — Scrub scheduler, shard verification, automatic rebuild and rebalancing within a repair budget (M-43). `engine/crypthix-metabolism`
- [ ] **Self-repairing multi-cloud backup (U8)** — Shards spread over 2–3 providers with automatic repair and a health view; a liveness probe per backend, and no provider holds more than m shards of an object (M-46). `engine/crypthix-store`, `engine/crypthix-metabolism`
- [ ] **Restore verification and drills (E20)** — `crypthix restore --verify` dry-run restore; scheduled monthly recovery drill with a pass/fail report; drills verify ciphertext and MACs or restore only inside the mount (M-47). `engine/crypthix-snapshot`, `apps/crypthix-cli`
- [ ] **Post-quantum key wrapping (E13)** — Hybrid X25519 + ML-KEM-768 device and member keypairs through X-Wing, every wrap signed (M-38, FS-46). Fills the reserved KEM suite entry, `kem_pk`, `device_wraps` and the device-share slot kind ([format spec 4.2](format-spec.md#42-suite-0x0001), [9.4](format-spec.md#94-epoch-key-file)). `foundation/crypthix-crypto`, `engine/crypthix-keys`
- [ ] **Capability tokens (E14)** — Biscuit tokens with attenuation, expiry and revocation lists; the playbook now revokes device and sync tokens too. Tokens stored inside the vault in the reserved token-wrapper file type; expiry checks with the skew rules of M-32. Decides OQ-12 (revocation-list staleness). `engine/crypthix-tokens`
- [ ] **Emergency access t-of-n (U7)** — Shamir split and recover of the root key; optional dead-man's switch; verifiable, versioned shares (M-18, FS-42–FS-45, TV-16 with t > 1, [format spec 9.2](format-spec.md#92-share-plaintext-and-recovery-text)). Closes W6. `engine/crypthix-keys`
- [ ] **Unphishable user presence (M-5)** — A14 confirmation by FIDO2 touch or on a second device that shows the action; closes W3. Decides OQ-6 (which FIDO2 or second-device flow). `access/crypthix-api`
- [ ] **Multi-device vault (U9)** — Enrol and revoke devices, per-device key shares and tokens, shared shard backends; revoking a lost device triggers emergency rotation. Release gate W9: per-device keys (M-14) land first, with device keys TPM-sealed with a PIN once a device receives KEKs (FS-49) and the `receive-kek` capability ([format spec 13](format-spec.md#13-vault-config-and-devices)). Concurrent writers fill feature bit 3 and `merge_parents` (FS-89); decides OQ-11 (conflict policy). `sync/crypthix-sync`
- [ ] **Disaster recovery on a new machine (U10)** — `crypthix recover`: rebuild the root from t-of-n shares, pull shards from cloud backends, verify signatures and log freshness, remount. `sync/crypthix-sync`, `apps/crypthix-cli`
- [ ] **Encrypted git sync (U4)** — `git-remote-crypthix` remote helper; encrypted packs on GitHub, GitLab or S3; token-based clone. `sync/crypthix-git`, `apps/git-remote-crypthix`
- [ ] **VS Code extension v2** — Genome log viewer, durability and repair status, snapshot browser, device management. `extensions/vscode`
- [ ] **VS Code FileSystemProvider mode (A10)** — `crypthix://` URIs talking to the daemon, no mount needed. `extensions/vscode`

## 1.0 release gate

- [ ] **External security audit** — Cryptography and code audit; fix all high and critical findings. Format 1 freezes here (format spec FS-24), so the open format questions (OQ-17) are decided first. `SECURITY.md`, `cargo-vet`, SHA-pinned Actions and signed releases in place (M-48).
- [ ] **1.0 release** — Signed, reproducible builds; signed updates that refuse older versions (M-33, M-48); packaging; docs; all success metrics in [project-vision.md section 16](project-vision.md#16-success-metrics) met. Closes W12. `deploy/`

## Phase 5: Teams and platforms (after 1.0)

- [ ] **RabbitMQ adapter (M2)** — AMQP backend for the `Bus` trait, topic exchange `crypthix.team`. `foundation/crypthix-bus` (`rabbitmq` feature)
- [ ] **Signed events (M3)** — Sign and verify every bus message with sequence number, expiry and audience (M-12), filling the reserved `sig` field of the job envelope ([format spec 16](format-spec.md#16-queue-job-envelope)); mirror into the genome log; compare log heads. `foundation/crypthix-bus`, `engine/crypthix-log`
- [ ] **Team folders with revocation (U6)** — Members, roles, per-member wrapped keys, removal-triggered rotation over the bus. Release gate W10: signed events (M3) and a DPIA (M-49) come first. `sync/crypthix-sync`
- [ ] **Windows support (A11)** — WinFsp drive; minifilter later. `access/crypthix-fs`
- [ ] **macOS support (A12)** — FSKit or macFUSE. `access/crypthix-fs`
- [ ] **Office status add-in (A13)** — Word side pane showing lock and access state. `extensions/office`
- [ ] **KMS plugins (E15)** — AWS, GCP, Azure Key Vault and HashiCorp Vault as a root share, in the reserved KMS slot kind ([format spec 9.1](format-spec.md#91-share-slot)). `engine/crypthix-keys` (`kms` feature)
- [ ] **S3-compatible gateway (E16)** — Expose a vault as an S3 endpoint. `access/crypthix-gateway`
- [ ] **Confidential VM dev box (O7)** — Template for running the workspace in SEV-SNP or TDX VMs. `deploy/`

---

## Restore and attack coverage

Where each part of restore and attack handling lives in this backlog.

| Area | Backlog items, in order |
| --- | --- |
| Detect attacks | Deny log (A4), canaries (A6), behaviour detection (A7), learning mode (A16), BPF-LSM signals (O4, O6), tamper detection (E18) |
| Stop attacks | Per-program policy (A2), agent guard (U1), protected admin actions (A14), freeze and playbook (A8), injection blocking (O4), self-sandbox (O2) |
| Contain damage | Emergency rotation (A8, then full re-encryption with E8), revocation (A8, then tokens with E14), device revocation (U9), alerts and webhooks (M4) |
| Investigate | Genome log timeline (E12), incident workflow (A15) |
| Restore data | Snapshots (E11), snapshot lock (E17), ransomware rollback (U3), self-repair (E10), multi-cloud rebuild (U8), immutable cloud copies (E19) |
| Recover access | Emergency access (U7), disaster recovery (U10), restore drills (E20) |

---

## Architecture rules

### Workspace layout

One Cargo workspace. The root holds only a few top-level folders; crates are grouped by domain under `crates/`, binaries under `apps/`.

```text
crypthix/
├── Cargo.toml                 # [workspace] members = ["crates/*/*", "apps/*"], shared deps and lints
├── rust-toolchain.toml
├── deny.toml                  # cargo-deny: licences, advisories, banned deps
├── README.md  LICENSE
│
├── crates/
│   ├── foundation/            # shared by everything, no CryptHix deps of its own
│   │   ├── types/             # crypthix-types: IDs, errors, config, formats, cross-crate traits
│   │   ├── crypto/            # crypthix-crypto: the ONLY crate that touches crypto libraries
│   │   ├── bus/               # crypthix-bus: Bus trait, embedded queue, RabbitMQ + webhooks (features)
│   │   └── testkit/           # crypthix-testkit: test doubles and crash points, dev-dependency only
│   │
│   ├── engine/                # the "Genome": storing, keys, integrity, durability
│   │   ├── core/              # crypthix-core: chunk, compress, pad, encrypt, manifest
│   │   ├── keys/              # crypthix-keys: hierarchy, rotation, retirement, Shamir, TPM, KMS
│   │   ├── tokens/            # crypthix-tokens: Biscuit capability tokens
│   │   ├── store/             # crypthix-store: backends, erasure coding, placement, Object Lock
│   │   ├── log/               # crypthix-log: genome log, anti-rollback
│   │   ├── snapshot/          # crypthix-snapshot: snapshots, lock, rollback, restore drills
│   │   └── metabolism/        # crypthix-metabolism: scrub, verify, repair
│   │
│   ├── security/              # the "immune system" and OS hardening
│   │   ├── guard/             # crypthix-guard: signals, scoring, playbook, incidents
│   │   └── hardening/         # crypthix-hardening: Landlock, seccomp, BPF-LSM (aya), fs-verity
│   │
│   ├── sync/                  # moving data between devices, people and git
│   │   ├── sync/              # crypthix-sync: multi-device, teams, disaster recovery
│   │   └── git/               # crypthix-git: git remote helper logic
│   │
│   └── access/                # how apps and people reach the data
│       ├── policy/            # crypthix-policy: program identity, rules, agent profiles, prompts
│       ├── fs/                # crypthix-fs: FUSE / WinFsp / FSKit, leak-path control
│       ├── api/               # crypthix-api: local socket API, protected admin actions
│       └── gateway/           # crypthix-gateway: S3-compatible endpoint (later)
│
├── apps/                      # thin binaries that wire crates together
│   ├── crypthixd/             # the daemon
│   ├── crypthix-cli/          # the `crypthix` command
│   └── git-remote-crypthix/   # git remote helper binary
│
├── extensions/
│   ├── vscode/                # TypeScript extension, talks to crypthix-api
│   └── office/                # Word add-in (later)
│
├── docs/                      # project-vision.md, backlog.md, threat-model.md, format-spec.md, examples/
├── tests/                     # own workspace: integration/, fuzz/, bench/, demo/, test-vectors/
└── deploy/                    # packaging, systemd unit, release signing, confidential-VM template
```

Folder names are short (`engine/keys`); package names keep the `crypthix-` prefix (`crypthix-keys`) so they are unique on crates.io.

### Group boundaries

Groups form layers. A crate may depend only on crates in its own group or in a lower layer.

| Layer | Group | Crates | May depend on |
| --- | --- | --- | --- |
| 0 | `crates/foundation` | types → crypto → bus → testkit | external crates only (in that order inside the group); testkit only as a dev-dependency |
| 1 | `crates/engine` | core, keys, tokens, store, log → snapshot, metabolism | foundation |
| 2 | `crates/security` | hardening → guard | foundation, engine |
| 2 | `crates/sync` | sync, git | foundation, engine |
| 3 | `crates/access` | policy, fs, api, gateway | foundation, engine, security, sync |
| 4 | `apps/` | crypthixd, crypthix-cli, git-remote-crypthix | anything |
| — | `extensions/` | vscode, office | `crypthix-api` over the socket only, never Rust crates |

`security` and `sync` sit on the same layer and must not depend on each other.

### Dependency rules

1. **Dependencies only point down the layers**, never up and never in cycles. CI enforces this with a small check over `cargo metadata` plus `cargo-deny` bans.
2. **Upward calls go through traits or events.** When the guard needs to freeze the filesystem, it calls the `ResponseActions` trait from `crypthix-types` (implemented in `access/crypthix-fs`) or publishes on the bus; it never imports `crypthix-fs`.
3. **Only `crypthix-crypto` imports cryptography crates**, so an audit covers one crate.
4. **Engine crates know nothing about FUSE, policies, prompts or the OS.** `crypthix-core` stays a pure library that works without the daemon.
5. **Inside a group, crates talk through traits from `crypthix-types`** (`Backend`, `EventSink`) and reach keys through `KeyProvider` from `crypthix-crypto`; `snapshot` and `metabolism` may use the other engine crates directly.
6. **Only `apps/` wire things together.** Binaries create concrete types and inject them; library crates hold no global state.
7. **Platform code is isolated** in `access/crypthix-fs` and `security/crypthix-hardening` behind `cfg(target_os)`, with stubs elsewhere.
8. **Optional backends are Cargo features**: `s3`, `gdrive`, `dropbox`, `rabbitmq`, `webhooks`, `tpm`, `kms`, `bpf-lsm`. The default build is a single-user, single-binary laptop product.
9. **Keys never cross crate APIs as plain byte vectors**; use the zeroizing key types from `crypthix-crypto`.
10. **Every crate ships its own unit tests**; parsers and format code also ship fuzz targets in `tests/fuzz`. Cross-crate behaviour is tested in `tests/integration`.
11. **Formats are versioned in `crypthix-types`**, so any crate can read every supported format version (format 0 makes no compatibility promise, [format spec FS-24](format-spec.md#6-versioning-and-no-downgrade)). The opaque `Decrypt` error and the format error enum live in `crypthix-types`; key-bearing traits such as `KeyProvider` live in `crypthix-crypto`, so key types never cross a crate API as bytes.
12. **Adding a crate means adding it to a group**, never directly under `crates/`. A new group needs a line in the table above.
