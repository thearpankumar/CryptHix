//! One test of a vector set.

use crate::json::Json;

/// One test: a comment, its flags, named inputs and the expected result.
#[derive(Clone, Debug)]
pub(crate) struct TestCase {
    pub(crate) comment: &'static str,
    pub(crate) flags: Vec<&'static str>,
    pub(crate) inputs: Vec<(&'static str, Input)>,
    pub(crate) expect: &'static str,
    /// Expected outputs written beside `expect`, such as a derived key or a sealed field.
    pub(crate) outputs: Vec<(&'static str, Input)>,
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
    /// A byte input, copied.
    pub(crate) fn bytes(bytes: &[u8]) -> Self {
        Input::Bytes(bytes.to_vec())
    }

    /// A text input, copied.
    pub(crate) fn text(text: &str) -> Self {
        Input::Text(text.to_owned())
    }

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
            outputs: Vec::new(),
        }
    }

    /// Adds expected outputs.
    pub(crate) fn with_outputs(mut self, outputs: Vec<(&'static str, Input)>) -> Self {
        self.outputs = outputs;
        self
    }

    pub(crate) fn to_json(&self, tc_id: i64) -> Json {
        let mut fields = vec![
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
        ];
        fields.extend(
            self.outputs
                .iter()
                .map(|(key, output)| (*key, output.to_json())),
        );
        Json::object(fields)
    }
}
