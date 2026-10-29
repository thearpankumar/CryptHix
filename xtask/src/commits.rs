//! `cargo xtask check-commits <base>`: commit messages follow the project style.
//!
//! A message is one line, `<type>[(<scope>)][!]: <summary>`, with no body and no trailers
//! (docs/CONTRIBUTING.md). Merge commits and commits by bots are skipped: GitHub and
//! Dependabot write their own bodies.

use crate::pre_commit::git;

/// The commit types a subject may start with.
const TYPES: [&str; 11] = [
    "feat", "fix", "docs", "chore", "test", "refactor", "ci", "perf", "build", "style", "revert",
];

/// Separates records and fields in the `git log` output.
const RECORD: char = '\u{1e}';
const FIELD: char = '\u{1f}';

/// Checks the commits after `base` up to `HEAD`.
pub(crate) fn check(base: &str) -> Result<(), String> {
    let format = format!("--format=%h{FIELD}%an{FIELD}%B{RECORD}");
    let output = git(&["log", "--no-merges", &format, &format!("{base}..HEAD")])?;
    let log = String::from_utf8_lossy(&output);
    let mut problems = Vec::new();
    let mut checked = 0;
    for record in log.split(RECORD) {
        let mut fields = record.trim_start_matches('\n').splitn(3, FIELD);
        let (Some(hash), Some(author), Some(message)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if author.ends_with("[bot]") {
            continue;
        }
        checked += 1;
        if let Err(problem) = check_message(message) {
            problems.push(format!("{hash}: {problem}"));
        }
    }
    if problems.is_empty() {
        println!("commit messages: {checked} checked");
        Ok(())
    } else {
        for problem in &problems {
            eprintln!("commit message: {problem}");
        }
        Err(
            "commit messages must be one line, `<type>: <summary>` (docs/CONTRIBUTING.md)"
                .to_owned(),
        )
    }
}

/// Checks one commit message.
fn check_message(message: &str) -> Result<(), String> {
    let message = message.trim_end();
    if message.contains('\n') {
        return Err("has a body or trailers; use a single line".to_owned());
    }
    let Some((prefix, summary)) = message.split_once(": ") else {
        return Err(format!("`{message}` has no `<type>: ` prefix"));
    };
    let prefix = prefix.strip_suffix('!').unwrap_or(prefix);
    let kind = match prefix.split_once('(') {
        Some((kind, scope)) => {
            let scope = scope
                .strip_suffix(')')
                .ok_or_else(|| format!("`{prefix}` has an unclosed scope"))?;
            if scope.is_empty() {
                return Err(format!("`{prefix}` has an empty scope"));
            }
            kind
        }
        None => prefix,
    };
    if !TYPES.contains(&kind) {
        return Err(format!("`{kind}` is not one of {}", TYPES.join(", ")));
    }
    if summary.trim().is_empty() {
        return Err("has an empty summary".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_one_line_conventional_subjects() {
        for message in [
            "feat: add the thing\n",
            "fix(cbor): reject long heads",
            "chore!: drop the old hook",
            "ci(fuzz)!: pin nightly",
        ] {
            assert_eq!(check_message(message), Ok(()), "{message:?}");
        }
    }

    #[test]
    fn rejects_bodies_trailers_and_bad_prefixes() {
        for message in [
            "feat: add\n\nwith a body",
            "feat: add\n\nCo-Authored-By: someone <a@b>",
            "add the thing",
            "feature: add",
            "fix(): empty scope",
            "fix(cbor: unclosed",
            "feat: ",
        ] {
            assert!(check_message(message).is_err(), "{message:?} accepted");
        }
    }
}
