//! Architecture layer rules from `docs/backlog.md#architecture-rules`.

use std::fmt;
use std::path::Path;

/// The group a workspace package belongs to, decided by where it lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Group {
    Foundation,
    Engine,
    Security,
    Sync,
    Access,
    Apps,
    Tooling,
}

impl Group {
    fn layer(self) -> u8 {
        match self {
            Group::Foundation => 0,
            Group::Engine => 1,
            Group::Security | Group::Sync => 2,
            Group::Access => 3,
            Group::Apps | Group::Tooling => 4,
        }
    }
}

/// A workspace package placed in its group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Placement {
    pub(crate) name: String,
    pub(crate) group: Group,
    /// Folder name inside the group, e.g. `keys` for `crates/engine/keys`.
    pub(crate) folder: String,
}

/// Places a package by its manifest directory relative to the workspace root.
///
/// Returns `None` when the package is not in a known location, which is itself
/// a violation of rule 12.
pub(crate) fn place(name: &str, relative_dir: &Path) -> Option<Placement> {
    let parts: Vec<&str> = relative_dir
        .iter()
        .filter_map(|part| part.to_str())
        .collect();
    let (group, folder) = match parts.as_slice() {
        ["crates", group, folder] => {
            let group = match *group {
                "foundation" => Group::Foundation,
                "engine" => Group::Engine,
                "security" => Group::Security,
                "sync" => Group::Sync,
                "access" => Group::Access,
                _ => return None,
            };
            (group, *folder)
        }
        ["apps", folder] => (Group::Apps, *folder),
        ["xtask"] => (Group::Tooling, "xtask"),
        _ => return None,
    };
    Some(Placement {
        name: name.to_owned(),
        group,
        folder: folder.to_owned(),
    })
}

/// A dependency edge that breaks a layer rule.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Violation {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) reason: &'static str,
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} -> {}: {}", self.from, self.to, self.reason)
    }
}

/// Order of foundation crates: each may depend only on those before it.
const FOUNDATION_ORDER: [&str; 4] = ["types", "crypto", "bus", "testkit"];

/// Foundation crates that may only be dev-dependencies: test doubles must never reach a build.
const DEV_ONLY: [&str; 1] = ["testkit"];

/// Engine crates that may use other engine crates directly (rule 5).
const ENGINE_UPPER: [&str; 2] = ["snapshot", "metabolism"];

/// Checks one normal or build dependency edge between workspace packages.
pub(crate) fn check_edge(from: &Placement, to: &Placement) -> Result<(), Violation> {
    let violation = |reason: &'static str| Violation {
        from: from.name.clone(),
        to: to.name.clone(),
        reason,
    };

    if to.group == Group::Foundation && DEV_ONLY.contains(&to.folder.as_str()) {
        return Err(violation(
            "test support crates may only be dev-dependencies",
        ));
    }
    if from.group == Group::Tooling {
        return Ok(());
    }
    if matches!(to.group, Group::Apps | Group::Tooling) {
        return Err(violation("binaries and tooling cannot be dependencies"));
    }
    if to.group.layer() > from.group.layer() {
        return Err(violation("dependencies must point down the layers"));
    }
    if matches!(
        (from.group, to.group),
        (Group::Security, Group::Sync) | (Group::Sync, Group::Security)
    ) {
        return Err(violation("security and sync must not depend on each other"));
    }
    if from.group != to.group {
        return Ok(());
    }

    match from.group {
        Group::Foundation => {
            let rank = |folder: &str| FOUNDATION_ORDER.iter().position(|known| *known == folder);
            match (rank(&from.folder), rank(&to.folder)) {
                (Some(from_rank), Some(to_rank)) if to_rank < from_rank => Ok(()),
                _ => Err(violation(
                    "foundation order is types -> crypto -> bus -> testkit",
                )),
            }
        }
        Group::Engine => {
            if ENGINE_UPPER.contains(&from.folder.as_str()) {
                Ok(())
            } else {
                Err(violation(
                    "engine crates talk through crypthix-types traits; \
                     only snapshot and metabolism use other engine crates",
                ))
            }
        }
        Group::Security => {
            if from.folder == "guard" && to.folder == "hardening" {
                Ok(())
            } else {
                Err(violation(
                    "inside security only guard may depend on hardening",
                ))
            }
        }
        Group::Sync | Group::Access | Group::Apps | Group::Tooling => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{Group, Placement, check_edge, place};
    use std::path::Path;

    fn placed(name: &str, dir: &str) -> Placement {
        place(name, Path::new(dir)).expect("test paths are valid placements")
    }

    #[test]
    fn places_known_locations() {
        let keys = placed("crypthix-keys", "crates/engine/keys");
        assert_eq!(keys.group, Group::Engine);
        assert_eq!(keys.folder, "keys");
        assert_eq!(placed("crypthixd", "apps/crypthixd").group, Group::Apps);
    }

    #[test]
    fn rejects_crates_outside_a_group() {
        assert_eq!(place("loose", Path::new("crates/loose")), None);
        assert_eq!(place("odd", Path::new("crates/misc/odd")), None);
    }

    #[test]
    fn allows_downward_edges() {
        let fs = placed("crypthix-fs", "crates/access/fs");
        let core = placed("crypthix-core", "crates/engine/core");
        let types = placed("crypthix-types", "crates/foundation/types");
        assert!(check_edge(&fs, &core).is_ok());
        assert!(check_edge(&core, &types).is_ok());
    }

    #[test]
    fn rejects_upward_edges() {
        let core = placed("crypthix-core", "crates/engine/core");
        let fs = placed("crypthix-fs", "crates/access/fs");
        assert!(check_edge(&core, &fs).is_err());
    }

    #[test]
    fn rejects_security_and_sync_edges() {
        let guard = placed("crypthix-guard", "crates/security/guard");
        let sync = placed("crypthix-sync", "crates/sync/sync");
        assert!(check_edge(&guard, &sync).is_err());
        assert!(check_edge(&sync, &guard).is_err());
    }

    #[test]
    fn enforces_foundation_order() {
        let types = placed("crypthix-types", "crates/foundation/types");
        let crypto = placed("crypthix-crypto", "crates/foundation/crypto");
        assert!(check_edge(&crypto, &types).is_ok());
        assert!(check_edge(&types, &crypto).is_err());
    }

    #[test]
    fn testkit_is_last_in_the_foundation_order() {
        let types = placed("crypthix-types", "crates/foundation/types");
        let testkit = placed("crypthix-testkit", "crates/foundation/testkit");
        assert!(
            check_edge(&testkit, &types).is_ok(),
            "testkit builds on crypthix-types"
        );
    }

    #[test]
    fn testkit_is_never_a_normal_dependency() {
        let testkit = placed("crypthix-testkit", "crates/foundation/testkit");
        let store = placed("crypthix-store", "crates/engine/store");
        let daemon = placed("crypthixd", "apps/crypthixd");
        let xtask = placed("xtask", "xtask");
        assert!(check_edge(&store, &testkit).is_err(), "not from a library");
        assert!(check_edge(&daemon, &testkit).is_err(), "not from a binary");
        assert!(
            check_edge(&xtask, &testkit).is_err(),
            "not even from tooling"
        );
    }

    #[test]
    fn limits_engine_internal_edges() {
        let snapshot = placed("crypthix-snapshot", "crates/engine/snapshot");
        let store = placed("crypthix-store", "crates/engine/store");
        let keys = placed("crypthix-keys", "crates/engine/keys");
        assert!(check_edge(&snapshot, &store).is_ok());
        assert!(check_edge(&keys, &store).is_err());
    }

    #[test]
    fn allows_guard_to_use_hardening_only() {
        let guard = placed("crypthix-guard", "crates/security/guard");
        let hardening = placed("crypthix-hardening", "crates/security/hardening");
        assert!(check_edge(&guard, &hardening).is_ok());
        assert!(check_edge(&hardening, &guard).is_err());
    }

    #[test]
    fn rejects_depending_on_binaries() {
        let api = placed("crypthix-api", "crates/access/api");
        let daemon = placed("crypthixd", "apps/crypthixd");
        assert!(check_edge(&api, &daemon).is_err());
    }
}
