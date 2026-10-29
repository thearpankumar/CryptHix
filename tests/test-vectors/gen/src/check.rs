//! Compares the generated files with the committed ones.

use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::vector_set::sets;

/// A committed file that is not what the generator writes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mismatch {
    /// The file name.
    pub file: String,
    /// What is wrong with it.
    pub problem: Problem,
}

/// How a committed file differs from the generator.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Problem {
    /// The generator writes this file, but it is not there.
    Missing,
    /// The file could not be read.
    Unreadable(ErrorKind),
    /// The bytes differ, first on this 1-based line.
    Differs {
        /// The first line that differs.
        line: usize,
    },
    /// A `.json` file no generator set writes.
    Unexpected,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let file = &self.file;
        match &self.problem {
            Problem::Missing => write!(f, "{file} is missing"),
            Problem::Unreadable(kind) => write!(f, "{file} cannot be read: {kind}"),
            Problem::Differs { line } => {
                write!(f, "{file} differs from the generator at line {line}")
            }
            Problem::Unexpected => write!(f, "{file} is not written by any generator set"),
        }
    }
}

/// Regenerates every set in memory and compares it byte for byte with the files in `dir`.
///
/// Returns every file that differs, is missing or unreadable, and every `.json` file in `dir`
/// that no set writes; an empty list means the committed vectors are current.
#[must_use]
pub fn check(dir: &Path) -> Vec<Mismatch> {
    let sets = sets();
    let mut mismatches = Vec::new();
    for set in &sets {
        let expected = set.render();
        let problem = match fs::read(dir.join(set.file)) {
            Ok(actual) if actual == expected.as_bytes() => continue,
            Ok(actual) => Problem::Differs {
                line: first_differing_line(expected.as_bytes(), &actual),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => Problem::Missing,
            Err(error) => Problem::Unreadable(error.kind()),
        };
        mismatches.push(Mismatch {
            file: set.file.to_owned(),
            problem,
        });
    }
    if let Ok(entries) = fs::read_dir(dir) {
        let mut unexpected: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                let json = Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
                json && !sets.iter().any(|set| set.file == name)
            })
            .collect();
        unexpected.sort();
        mismatches.extend(unexpected.into_iter().map(|file| Mismatch {
            file,
            problem: Problem::Unexpected,
        }));
    }
    mismatches
}

/// The 1-based line of the first byte where `expected` and `actual` differ.
fn first_differing_line(expected: &[u8], actual: &[u8]) -> usize {
    let same = expected
        .iter()
        .zip(actual)
        .take_while(|(want, got)| want == got)
        .count();
    // Splitting on newlines gives one piece per line started so far.
    expected[..same].split(|byte| *byte == b'\n').count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differing_lines_are_counted_from_one() {
        assert_eq!(first_differing_line(b"a\nb\nc", b"a\nb\nx"), 3);
        assert_eq!(first_differing_line(b"abc", b"xbc"), 1);
        assert_eq!(first_differing_line(b"a\n", b"a\nmore"), 2);
    }
}
