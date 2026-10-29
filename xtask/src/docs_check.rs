//! `cargo xtask check-docs`: links, anchors and cross-reference IDs in the docs.
//!
//! - Every relative link in a tracked Markdown file points at a file that exists, and every
//!   `#anchor` at a heading in its target.
//! - The format spec defines its rules `**FS-1.**`, `**FS-2.**`, … once each, in order, with no
//!   gaps.
//! - Every `FS-n` and `TV-n` cited in the docs or the vector files is defined in the format
//!   spec, and every `M-n` and `T-n` in the threat model.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::pre_commit::git;
use crate::process::repo_root;

const FORMAT_SPEC: &str = "docs/format-spec.md";
const THREAT_MODEL: &str = "docs/threat-model.md";
/// Vector files cite rules and threats too.
const VECTOR_DIR: &str = "tests/test-vectors/crypthix";

/// An ID family: its prefix and the documents that define it.
struct Family {
    prefix: &'static str,
    defined_in: &'static str,
}

/// The ID families whose citations must resolve. `TV-n` and table-row IDs are defined by a
/// `| ID |` row; `FS-n` by its bold `**FS-n.**` rule.
const FAMILIES: [Family; 4] = [
    Family {
        prefix: "FS",
        defined_in: FORMAT_SPEC,
    },
    Family {
        prefix: "TV",
        defined_in: FORMAT_SPEC,
    },
    Family {
        prefix: "M",
        defined_in: THREAT_MODEL,
    },
    Family {
        prefix: "T",
        defined_in: THREAT_MODEL,
    },
];

/// Runs every check and reports the problems.
pub(crate) fn check() -> Result<(), String> {
    let root = repo_root();
    let files = tracked(&root, &["*.md"])?;
    let mut texts = HashMap::new();
    for file in &files {
        let text = fs::read_to_string(root.join(file))
            .map_err(|error| format!("cannot read {file}: {error}"))?;
        texts.insert(file.clone(), text);
    }
    let mut problems = Vec::new();
    check_links(&root, &texts, &mut problems);

    let spec = texts
        .get(FORMAT_SPEC)
        .ok_or_else(|| format!("{FORMAT_SPEC} is not tracked"))?;
    check_rule_order(spec, &mut problems);

    let mut citing: Vec<(String, String)> = texts
        .iter()
        .map(|(file, text)| (file.clone(), text.clone()))
        .collect();
    for file in tracked(&root, &[&format!("{VECTOR_DIR}/*.json")])? {
        let text = fs::read_to_string(root.join(&file))
            .map_err(|error| format!("cannot read {file}: {error}"))?;
        citing.push((file, text));
    }
    citing.sort();
    for family in &FAMILIES {
        let source = texts
            .get(family.defined_in)
            .ok_or_else(|| format!("{} is not tracked", family.defined_in))?;
        let defined = definitions(source, family.prefix);
        for (file, text) in &citing {
            for id in citations(text, family.prefix) {
                if !defined.contains(&id) {
                    problems.push(format!(
                        "{file}: {}-{id} is not defined in {}",
                        family.prefix, family.defined_in
                    ));
                }
            }
        }
    }

    if problems.is_empty() {
        println!(
            "docs: {} Markdown files, links and IDs resolve",
            files.len()
        );
        Ok(())
    } else {
        for problem in &problems {
            eprintln!("docs: {problem}");
        }
        Err(format!("{} documentation problems", problems.len()))
    }
}

/// Tracked files matching `patterns`, relative to the repository root.
fn tracked(root: &Path, patterns: &[&str]) -> Result<Vec<String>, String> {
    let mut args = vec!["-C", root.to_str().unwrap_or("."), "ls-files", "-z", "--"];
    args.extend(patterns);
    let output = git(&args)?;
    Ok(output
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .collect())
}

/// Checks the relative links and anchors in every file.
fn check_links(root: &Path, texts: &HashMap<String, String>, problems: &mut Vec<String>) {
    let anchors: HashMap<&str, BTreeSet<String>> = texts
        .iter()
        .map(|(file, text)| (file.as_str(), heading_anchors(text)))
        .collect();
    let mut files: Vec<&String> = texts.keys().collect();
    files.sort();
    for file in files {
        let dir = Path::new(file).parent().unwrap_or(Path::new(""));
        for link in links(&texts[file]) {
            if link.contains("://") || link.starts_with("mailto:") {
                continue;
            }
            let (path, anchor) = match link.split_once('#') {
                Some((path, anchor)) => (path, Some(anchor)),
                None => (link.as_str(), None),
            };
            let target = if path.is_empty() {
                PathBuf::from(file)
            } else {
                normalize(&dir.join(path))
            };
            let target_name = target.to_string_lossy().replace('\\', "/");
            if !root.join(&target).exists() {
                problems.push(format!("{file}: link to missing {target_name}"));
                continue;
            }
            let Some(anchor) = anchor else { continue };
            if let Some(known) = anchors.get(target_name.as_str())
                && !known.contains(anchor)
            {
                problems.push(format!("{file}: no heading #{anchor} in {target_name}"));
            }
        }
    }
}

/// Lines outside fenced code blocks.
fn prose_lines(text: &str) -> impl Iterator<Item = &str> {
    let mut fenced = false;
    text.lines().filter(move |line| {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            return false;
        }
        !fenced
    })
}

/// The anchors GitHub gives the headings of `text`, with `-1`, `-2` … on repeats.
fn heading_anchors(text: &str) -> BTreeSet<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut anchors = BTreeSet::new();
    for line in prose_lines(text) {
        let hashes = line.bytes().take_while(|byte| *byte == b'#').count();
        let Some(title) = line.get(hashes..).and_then(|rest| rest.strip_prefix(' ')) else {
            continue;
        };
        if !(1..=6).contains(&hashes) {
            continue;
        }
        let slug = slug(title);
        let count = seen.entry(slug.clone()).or_insert(0);
        anchors.insert(if *count == 0 {
            slug.clone()
        } else {
            format!("{slug}-{count}")
        });
        *count += 1;
    }
    anchors
}

/// GitHub's heading slug: lower case, punctuation dropped, spaces as hyphens.
fn slug(title: &str) -> String {
    title
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | ' '))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// The targets of the inline links `[text](target)` in `text`, outside code.
fn links(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for line in prose_lines(text) {
        // Inline code may hold `](` that is not a link.
        let line: String = line.split('`').step_by(2).collect::<Vec<_>>().join("");
        let mut rest = line.as_str();
        while let Some(start) = rest.find("](") {
            rest = &rest[start + 2..];
            let Some(end) = rest.find(')') else { break };
            if let Some(target) = rest[..end].split_whitespace().next() {
                targets.push(target.trim_matches(['<', '>']).to_owned());
            }
            rest = &rest[end..];
        }
    }
    targets
}

/// `path` with `.` and `..` resolved lexically.
fn normalize(path: &Path) -> PathBuf {
    let mut parts: Vec<Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir if matches!(parts.last(), Some(Component::Normal(_))) => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.iter().collect()
}

/// Checks the spec's `**FS-n.**` rules are defined once each, in order, from 1 with no gaps.
fn check_rule_order(spec: &str, problems: &mut Vec<String>) {
    let numbers = rule_definitions(spec);
    for (index, number) in numbers.iter().enumerate() {
        let expected = u32::try_from(index).map_or(u32::MAX, |index| index + 1);
        if *number != expected {
            problems.push(format!(
                "{FORMAT_SPEC}: rule FS-{number} is defined where FS-{expected} should be"
            ));
            return;
        }
    }
}

/// The numbers of the `**FS-n.**` rule definitions, in document order.
fn rule_definitions(spec: &str) -> Vec<u32> {
    let mut numbers = Vec::new();
    let mut rest = spec;
    while let Some(start) = rest.find("**FS-") {
        rest = &rest[start + 5..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if rest[digits.len()..].starts_with(".**")
            && let Ok(number) = digits.parse()
        {
            numbers.push(number);
        }
    }
    numbers
}

/// The IDs defined for `prefix` in `source`.
fn definitions(source: &str, prefix: &str) -> BTreeSet<u32> {
    if prefix == "FS" {
        return rule_definitions(source).into_iter().collect();
    }
    let row = format!("| {prefix}-");
    source
        .lines()
        .filter_map(|line| line.strip_prefix(&row))
        .filter_map(|rest| {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            rest[digits.len()..]
                .starts_with(" |")
                .then(|| digits.parse().ok())
                .flatten()
        })
        .collect()
}

/// The `prefix-n` IDs cited in `text`, where `prefix` starts a word.
fn citations(text: &str, prefix: &str) -> BTreeSet<u32> {
    let needle = format!("{prefix}-");
    let mut ids = BTreeSet::new();
    for (start, _) in text.match_indices(&needle) {
        let before = text[..start].chars().next_back();
        if before.is_some_and(|c| c.is_alphanumeric() || matches!(c, '-' | '_')) {
            continue;
        }
        let after = &text[start + needle.len()..];
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(id) = digits.parse() {
            ids.insert(id);
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_follow_github() {
        assert_eq!(slug("20. Test vectors"), "20-test-vectors");
        assert_eq!(slug("8. Threat model"), "8-threat-model");
        assert_eq!(slug("`Backend` trait (FS-87)"), "backend-trait-fs-87");
    }

    #[test]
    fn repeated_headings_get_numbered_anchors() {
        let anchors = heading_anchors("# Notes\n## Notes\n```\n# not a heading\n```\n");
        let expected: BTreeSet<String> = ["notes", "notes-1"].map(str::to_owned).into();
        assert_eq!(anchors, expected);
    }

    #[test]
    fn links_skip_code() {
        let text = "see [a](x.md#top) and `[b](y.md)`\n```\n[c](z.md)\n```\n[d](<w.md> \"t\")";
        assert_eq!(links(text), ["x.md#top", "w.md"]);
    }

    #[test]
    fn citations_start_a_word() {
        let ids = citations("T-01, AT-5, TV-3 and (T-12); UTF-8 M-T-4", "T");
        assert_eq!(
            ids,
            [1, 12].into(),
            "AT-5, TV-3 and M-T-4 are not T- citations"
        );
    }

    #[test]
    fn rules_must_run_in_order() {
        let mut problems = Vec::new();
        check_rule_order("**FS-1.** a **FS-2.** b **FS-4.** c", &mut problems);
        assert_eq!(problems.len(), 1, "{problems:?}");
        problems.clear();
        check_rule_order("**FS-1.** a, see FS-2 **FS-2.** b", &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn table_rows_define_ids() {
        let defined = definitions("| M-1 | x |\n| M-12 | y |\n|M-3| z\n", "M");
        assert_eq!(defined, [1, 12].into());
    }

    #[test]
    fn normalize_resolves_parent_components() {
        assert_eq!(
            normalize(Path::new("docs/../tests/./README.md")),
            PathBuf::from("tests/README.md")
        );
    }

    #[test]
    fn the_committed_docs_pass() {
        assert_eq!(check(), Ok(()), "the docs have broken links or IDs");
    }
}
