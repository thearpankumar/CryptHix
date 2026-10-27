# CryptHix Backlog

Top-level features in **implementation order**. Each item is a feature, not a micro task; break items down when you plan each sprint. Feature IDs (E, A, U, M, O) match [vision.md](vision.md). The crate each feature lives in is shown in `code` as `group/crate`; the workspace layout and crate rules are at the end of this file.

Tick a box when the feature is merged, tested and documented. CLI commands and VS Code panels for a feature ship with that feature.

---

## Phase 0: Foundations

- [x] **Cargo workspace skeleton** — Repo as one Cargo workspace using the grouped layout at the end of this file (`crates/<group>/<crate>`, `apps/`, `extensions/`), shared lints and dependency versions, `rust-toolchain.toml`, licence, CI (build, test, clippy, fmt, `cargo-deny`, layer-rule check). `workspace root`
- [ ] **Threat model document** — Attackers, assets, trust boundaries and what each phase defends, based on vision.md section 8. `docs/`
- [ ] **On-disk format spec v0** — Manifest, shard, key-file and log-entry formats with version fields and a test-vector plan. `docs/`
- [ ] **Shared types and errors** — IDs (object, shard, epoch, device), error types, config loading, versioned serialization, cross-crate traits (`Backend`, `KeyProvider`, `EventSink`, `ResponseActions`). `foundation/crypthix-types`
- [ ] **Fuzzing and test harness** — `cargo-fuzz` targets, property-test setup, known-answer test vectors, benchmark harness. `tests/`

## Phase 1: Engine core

- [ ] **Crypto wrappers (E4)** — Thin wrappers over audited crates for XChaCha20-Poly1305 / AES-256-GCM, HKDF, Argon2id, Ed25519; zeroizing key types; no other crate calls crypto libraries directly. `foundation/crypthix-crypto`
- [ ] **Protected key memory (O1)** — Key buffers in `memfd_secret`, `mlock`, excluded from core dumps, with a fallback on older kernels. `foundation/crypthix-crypto`
- [ ] **Chunking, compression and padding (E1, E2, E3)** — FastCDC chunking, zstd with auto-skip for already-compressed data, padding to size buckets. `engine/crypthix-core`
- [ ] **Encrypt pipeline and signed manifests (E4, E5)** — Per-chunk AEAD with AAD (object, index, epoch), Merkle tree, Ed25519-signed manifest; full write and read path. `engine/crypthix-core`
- [ ] **Key hierarchy (E6)** — Root key → epoch KEKs → per-object DEKs; passphrase root share (Argon2id); wrapped key storage. `engine/crypthix-keys`
- [ ] **Local storage backend** — Shard and manifest I/O on a local directory behind the `Backend` trait. `engine/crypthix-store`
- [ ] **Automatic KEK rotation (E7)** — Scheduled re-wrap of DEKs under a new epoch KEK (daily by default). `engine/crypthix-keys`
- [ ] **Embedded event queue (M1)** — Persistent in-process queue for rotation, scrub and repair jobs and alerts, behind the `Bus` trait. `foundation/crypthix-bus`
- [ ] **CLI v0** — `crypthix init / put / get / verify / rotate / status`. `apps/crypthix-cli`

## Phase 2: Workspace MVP → 0.1 alpha

- [ ] **Daemon and local API** — `crypthixd` process that owns keys and wires all crates; JSON-over-Unix-socket API for CLI and extension. `apps/crypthixd`, `access/crypthix-api`
- [ ] **Transparent encrypted folder (A1)** — FUSE mount backed by the engine; open, read, write, rename, delete, mmap-safe; `crypthix mount`. `access/crypthix-fs`
- [ ] **Program identity resolution** — Caller PID → exe path, binary hash (cached), parent chain, uid, cgroup. `access/crypthix-policy`
- [ ] **Per-program policy engine (A2)** — `policy.toml` rules by program and path, most-specific-first matching, default ask for unknown programs and deny for secret paths. `access/crypthix-policy`
- [ ] **First-use prompts and deny log (A3, A4)** — Allow once / always / deny prompts via the API; every denial logged with its process tree. `access/crypthix-policy`, `access/crypthix-api`
- [ ] **Protected admin actions (A14)** — Loosening policy, unfreezing, deleting snapshots, adding devices and disabling the guard require user presence (passphrase or OS authentication), so malware running as the user cannot switch protection off. `access/crypthix-api`, `access/crypthix-policy`
- [ ] **AI coding agent guard (U1)** — Agent profiles matching process trees (Claude Code, Cursor, Codex); deny secrets, allow code; per-agent access feed. `access/crypthix-policy`
- [ ] **Secrets never on disk (U2)** — Secret-path presets (`.env*`, `.ssh/**`, `*.pem`, cloud credentials) readable only by named programs; import of existing secrets into the vault. `access/crypthix-policy`, `apps/crypthix-cli`
- [ ] **VS Code extension v1 (A5)** — Lock status, blocked-access feed, approve and revoke, agent profile editor, rotate now. `extensions/vscode`
- [ ] **MVP benchmarks and demo** — Build benchmark against plain disk and gocryptfs; scripted demo where a malicious `postinstall` and an AI agent fail to read `.env` while `python` and `git` work. `tests/bench`, `tests/demo`

## Phase 3: Immune system and recovery → 0.5 beta

- [ ] **Genome log (E12)** — Append-only, hash-chained, signed log of puts, rotations, repairs, guard actions, incidents and restores; `crypthix log --verify`; optional public log heads. Comes first in this phase because incidents and rollback read its timeline. `engine/crypthix-log`
- [ ] **Snapshots (E11)** — Copy-on-write snapshots of the manifest tree (hourly, plus one pinned on every freeze), immutable shards, retention policy, point-in-time restore of a file, folder or the whole vault. `engine/crypthix-snapshot`
- [ ] **Snapshot lock (E17)** — Snapshot deletion and retention changes are protected actions with a 7-day delay; snapshots tied to an open incident cannot be deleted. `engine/crypthix-snapshot`
- [ ] **Guard: canaries and honey keys (A6)** — Generate, place and watch decoy files and keys. `security/crypthix-guard`
- [ ] **Guard: behaviour detection (A7)** — Per-program baselines for read and write rate, renames and write entropy; scoring. `security/crypthix-guard`
- [ ] **Guard learning mode and tuning (A16)** — Alert-only period while baselines settle; per-program exceptions for noisy but legitimate tools. `security/crypthix-guard`
- [ ] **Response playbook (A8)** — Alert → throttle → freeze + snapshot → emergency rotation + revocation, configured in `guard.toml`; canary hits and unauthenticated admin attempts go straight to freeze. Until E8 and E14 land, emergency rotation means KEK rotation and revocation means withdrawing program approvals. `security/crypthix-guard`
- [ ] **Incident workflow (A15)** — Incident view with log timeline, process tree, files touched, suggested clean snapshot and one-click actions (roll back, rotate, revoke, unfreeze); incident report written to the log. `security/crypthix-guard`, `extensions/vscode`
- [ ] **Ransomware rollback (U3)** — Pick the last clean snapshot (before the first anomaly); restore only affected files or the whole vault while keeping clean edits; one click from CLI and extension. `engine/crypthix-snapshot`, `extensions/vscode`
- [ ] **Leak-path control (A9)** — Redirect or block editor swap and backup files, `__pycache__`, build caches and `/tmp` copies; warn on unencrypted swap. `access/crypthix-fs`
- [ ] **Self-sandbox (O2)** — Landlock, seccomp-bpf and no-new-privs for the daemon. `security/crypthix-hardening`
- [ ] **BPF-LSM guard (O4)** — Only the daemon may open shards; block `ptrace`, `process_vm_readv` and `/proc/<pid>/mem` into allowed programs; block foreign unmounts. `security/crypthix-hardening`
- [ ] **Binary integrity and eBPF telemetry (O5, O6)** — fs-verity and IMA checks on allowed programs and the daemon; process context fed to the guard. `security/crypthix-hardening`
- [ ] **TPM sealing (O3)** — Root share sealed to the boot state. `engine/crypthix-keys` (`tpm` feature)
- [ ] **Webhooks and SIEM bridge (M4)** — Push alerts and rotation reports to Slack, email or a SIEM. `foundation/crypthix-bus` (`webhooks` feature)

## Phase 4: Durability and sync

- [ ] **DEK rotation and epoch retirement (E8)** — Background re-encryption with rate budget and checkpoints; two-phase retirement with grace period; proof that retired keys decrypt nothing. Upgrades the playbook's emergency rotation to full re-encryption. `engine/crypthix-keys`
- [ ] **Anti-rollback and tamper detection (E18)** — Monotonic counter and log heads on every device (optionally TPM) detect a backend serving old or altered data; raises a guard alert. `engine/crypthix-log`, `engine/crypthix-store`
- [ ] **Erasure coding and placement (E9)** — Reed-Solomon k+m shards; placement policy across backends. `engine/crypthix-store`
- [ ] **Cloud backends** — S3, Google Drive and Dropbox implementations of the `Backend` trait. `engine/crypthix-store` (`s3`, `gdrive`, `dropbox` features)
- [ ] **Immutable cloud copies (E19)** — S3 Object Lock, bucket versioning and provider equivalents so stolen cloud credentials cannot delete backups. `engine/crypthix-store`
- [ ] **Metabolism (E10)** — Scrub scheduler, shard verification, automatic rebuild and rebalancing. `engine/crypthix-metabolism`
- [ ] **Self-repairing multi-cloud backup (U8)** — Shards spread over 2–3 providers with automatic repair and a health view. `engine/crypthix-store`, `engine/crypthix-metabolism`
- [ ] **Restore verification and drills (E20)** — `crypthix restore --verify` dry-run restore; scheduled monthly recovery drill with a pass/fail report. `engine/crypthix-snapshot`, `apps/crypthix-cli`
- [ ] **Post-quantum key wrapping (E13)** — Hybrid X25519 + ML-KEM-768 device and member keypairs. `foundation/crypthix-crypto`, `engine/crypthix-keys`
- [ ] **Capability tokens (E14)** — Biscuit tokens with attenuation, expiry and revocation lists; the playbook now revokes device and sync tokens too. `engine/crypthix-tokens`
- [ ] **Emergency access t-of-n (U7)** — Shamir split and recover of the root key; optional dead-man's switch. `engine/crypthix-keys`
- [ ] **Multi-device vault (U9)** — Enrol and revoke devices, per-device key shares and tokens, shared shard backends; revoking a lost device triggers emergency rotation. `sync/crypthix-sync`
- [ ] **Disaster recovery on a new machine (U10)** — `crypthix recover`: rebuild the root from t-of-n shares, pull shards from cloud backends, verify signatures and log freshness, remount. `sync/crypthix-sync`, `apps/crypthix-cli`
- [ ] **Encrypted git sync (U4)** — `git-remote-crypthix` remote helper; encrypted packs on GitHub, GitLab or S3; token-based clone. `sync/crypthix-git`, `apps/git-remote-crypthix`
- [ ] **VS Code extension v2** — Genome log viewer, durability and repair status, snapshot browser, device management. `extensions/vscode`
- [ ] **VS Code FileSystemProvider mode (A10)** — `crypthix://` URIs talking to the daemon, no mount needed. `extensions/vscode`

## 1.0 release gate

- [ ] **External security audit** — Cryptography and code audit; fix all high and critical findings.
- [ ] **1.0 release** — Signed, reproducible builds; packaging; docs; all success metrics in vision.md section 16 met. `deploy/`

## Phase 5: Teams and platforms (after 1.0)

- [ ] **RabbitMQ adapter (M2)** — AMQP backend for the `Bus` trait, topic exchange `crypthix.team`. `foundation/crypthix-bus` (`rabbitmq` feature)
- [ ] **Signed events (M3)** — Sign and verify every bus message; mirror into the genome log; compare log heads. `foundation/crypthix-bus`, `engine/crypthix-log`
- [ ] **Team folders with revocation (U6)** — Members, roles, per-member wrapped keys, removal-triggered rotation over the bus. `sync/crypthix-sync`
- [ ] **Windows support (A11)** — WinFsp drive; minifilter later. `access/crypthix-fs`
- [ ] **macOS support (A12)** — FSKit or macFUSE. `access/crypthix-fs`
- [ ] **Office status add-in (A13)** — Word side pane showing lock and access state. `extensions/office`
- [ ] **KMS plugins (E15)** — AWS, GCP, Azure Key Vault and HashiCorp Vault as a root share. `engine/crypthix-keys` (`kms` feature)
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
│   │   └── bus/               # crypthix-bus: Bus trait, embedded queue, RabbitMQ + webhooks (features)
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
├── docs/                      # vision.md, backlog.md, threat-model.md, format-spec.md, examples/
├── tests/                     # integration/, fuzz/, bench/, demo/, test-vectors/
└── deploy/                    # packaging, systemd unit, release signing, confidential-VM template
```

Folder names are short (`engine/keys`); package names keep the `crypthix-` prefix (`crypthix-keys`) so they are unique on crates.io.

### Group boundaries

Groups form layers. A crate may depend only on crates in its own group or in a lower layer.

| Layer | Group | Crates | May depend on |
| --- | --- | --- | --- |
| 0 | `crates/foundation` | types → crypto → bus | external crates only (in that order inside the group) |
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
5. **Inside a group, crates talk through traits from `crypthix-types`** (`Backend`, `KeyProvider`, `EventSink`); `snapshot` and `metabolism` may use the other engine crates directly.
6. **Only `apps/` wire things together.** Binaries create concrete types and inject them; library crates hold no global state.
7. **Platform code is isolated** in `access/crypthix-fs` and `security/crypthix-hardening` behind `cfg(target_os)`, with stubs elsewhere.
8. **Optional backends are Cargo features**: `s3`, `gdrive`, `dropbox`, `rabbitmq`, `webhooks`, `tpm`, `kms`, `bpf-lsm`. The default build is a single-user, single-binary laptop product.
9. **Keys never cross crate APIs as plain byte vectors**; use the zeroizing key types from `crypthix-crypto`.
10. **Every crate ships its own unit tests**; parsers and format code also ship fuzz targets in `tests/fuzz`. Cross-crate behaviour is tested in `tests/integration`.
11. **Formats are versioned in `crypthix-types`**, so any crate can read older manifests and log entries.
12. **Adding a crate means adding it to a group**, never directly under `crates/`. A new group needs a line in the table above.
