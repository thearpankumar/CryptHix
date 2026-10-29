//! A vector set and the list of all sets.

use std::collections::BTreeSet;

use crate::json::Json;
use crate::test_case::TestCase;
use crate::{tv02, tv03, tv17};

/// What the generator writes into the `generator` field of a set with no randomness.
const GENERATOR: &str = "hand-written (crypthix-vector-gen reproduces it)";

/// One vector file.
#[derive(Clone, Debug)]
pub struct VectorSet {
    /// File name under `crypthix/v0/`.
    pub file: &'static str,
    pub(crate) set: &'static str,
    pub(crate) structure: &'static str,
    /// Header fields after the common ones, such as the limits a set runs with.
    pub(crate) extra: Vec<(&'static str, &'static str)>,
    /// Flag name, the rules and threats it cites, and its description.
    pub(crate) notes: Vec<(&'static str, &'static [&'static str], &'static str)>,
    pub(crate) groups: Vec<(&'static str, Vec<TestCase>)>,
}

impl VectorSet {
    /// Every test with its group type, in file order.
    pub(crate) fn tests(&self) -> impl Iterator<Item = (&'static str, &TestCase)> {
        self.groups
            .iter()
            .flat_map(|(group, tests)| tests.iter().map(move |test| (*group, test)))
    }

    /// The file contents.
    ///
    /// # Panics
    ///
    /// If a flag is used without a note or a note is never used: a bug in the set's source.
    #[must_use]
    pub fn render(&self) -> String {
        let used: BTreeSet<&str> = self
            .tests()
            .flat_map(|(_, test)| test.flags.iter().copied())
            .collect();
        let documented: BTreeSet<&str> = self.notes.iter().map(|(flag, _, _)| *flag).collect();
        assert_eq!(used, documented, "{}: flags and notes differ", self.set);

        let mut tc_id = 0;
        let groups = self
            .groups
            .iter()
            .map(|(group, tests)| {
                let tests = tests
                    .iter()
                    .map(|test| {
                        tc_id += 1;
                        test.to_json(tc_id)
                    })
                    .collect();
                Json::object([("type", Json::str(group)), ("tests", Json::Array(tests))])
            })
            .collect();

        let mut header = vec![
            ("set", Json::str(self.set)),
            ("structure", Json::str(self.structure)),
            ("formatVersion", Json::Int(0)),
            ("suiteId", Json::Int(1)),
            ("generator", Json::str(GENERATOR)),
        ];
        header.extend(
            self.extra
                .iter()
                .map(|(key, value)| (*key, Json::str(value))),
        );
        let notes = self.notes.iter().map(|(flag, cites, description)| {
            let note = Json::object([
                ("cites", Json::strs(cites)),
                ("description", Json::str(description)),
            ]);
            (*flag, note)
        });
        header.push(("notes", Json::object(notes)));
        header.push(("testGroups", Json::Array(groups)));
        header.push(("numberOfTests", Json::Int(tc_id)));
        Json::object(header).render()
    }
}

/// Every vector set the generator writes.
#[must_use]
pub fn sets() -> Vec<VectorSet> {
    vec![tv02::set(), tv03::set(), tv17::set()]
}
