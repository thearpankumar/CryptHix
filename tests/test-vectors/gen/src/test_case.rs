//! One test of a vector set.

use crate::json::Json;

/// One test: a comment, its flags, named inputs and the expected result.
#[derive(Clone, Debug)]
pub(crate) struct TestCase {
    pub(crate) comment: &'static str,
    pub(crate) flags: Vec<&'static str>,
    pub(crate) inputs: Vec<(&'static str, Input)>,
    pub(crate) expect: &'static str,
}

/// An input value. Byte inputs are written as lowercase hex.
#[derive(Clone, Debug)]
pub(crate) enum Input {
    Bytes(Vec<u8>),
    Text(String),
    Int(i64),
    Ints(Vec<i64>),
}

impl Input {
    pub(crate) fn to_json(&self) -> Json {
        match self {
            Input::Bytes(bytes) => Json::hex(bytes),
            Input::Text(text) => Json::str(text),
            Input::Int(value) => Json::Int(*value),
            Input::Ints(values) => Json::Array(values.iter().copied().map(Json::Int).collect()),
        }
    }
}

/// A test whose only input is the byte string `key`.
pub(crate) fn t(
    comment: &'static str,
    flags: &[&'static str],
    expect: &'static str,
    key: &'static str,
    bytes: Vec<u8>,
) -> TestCase {
    TestCase::new(comment, flags, expect, vec![(key, Input::Bytes(bytes))])
}

impl TestCase {
    pub(crate) fn new(
        comment: &'static str,
        flags: &[&'static str],
        expect: &'static str,
        inputs: Vec<(&'static str, Input)>,
    ) -> Self {
        Self {
            comment,
            flags: flags.to_vec(),
            inputs,
            expect,
        }
    }

    pub(crate) fn to_json(&self, tc_id: i64) -> Json {
        Json::object([
            ("tcId", Json::Int(tc_id)),
            ("comment", Json::str(self.comment)),
            ("flags", Json::strs(&self.flags)),
            (
                "inputs",
                Json::object(
                    self.inputs
                        .iter()
                        .map(|(key, input)| (*key, input.to_json())),
                ),
            ),
            ("expect", Json::str(self.expect)),
        ])
    }
}
