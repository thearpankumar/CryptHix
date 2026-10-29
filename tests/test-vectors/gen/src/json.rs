//! A JSON value and the exact text form of the vector files.

use std::fmt::Write;

/// A JSON value. Objects keep their keys in insertion order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Json {
    /// A string.
    Str(String),
    /// An integer.
    Int(i64),
    /// An array.
    Array(Vec<Json>),
    /// An object, in key order.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// A string value.
    #[must_use]
    pub fn str(value: &str) -> Self {
        Json::Str(value.to_owned())
    }

    /// Lowercase hex of `bytes`, the encoding of every byte input (FS-94).
    #[must_use]
    pub fn hex(bytes: &[u8]) -> Self {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        Json::Str(out)
    }

    /// An array of strings.
    #[must_use]
    pub fn strs(values: &[&str]) -> Self {
        Json::Array(values.iter().map(|value| Json::str(value)).collect())
    }

    /// An object from `(key, value)` pairs.
    #[must_use]
    pub fn object<K: Into<String>>(entries: impl IntoIterator<Item = (K, Json)>) -> Self {
        Json::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    /// The value with two-space indentation and a final newline.
    ///
    /// This is the form the committed files use, the same as Python's
    /// `json.dump(indent=2, ensure_ascii=False)`: non-ASCII text is written as is.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, indent: usize) {
        match self {
            Json::Str(value) => write_str(out, value),
            Json::Int(value) => {
                let _ = write!(out, "{value}");
            }
            Json::Array(items) if items.is_empty() => out.push_str("[]"),
            Json::Object(entries) if entries.is_empty() => out.push_str("{}"),
            Json::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    separator(out, index, indent + 1);
                    item.write(out, indent + 1);
                }
                newline(out, indent);
                out.push(']');
            }
            Json::Object(entries) => {
                out.push('{');
                for (index, (key, value)) in entries.iter().enumerate() {
                    separator(out, index, indent + 1);
                    write_str(out, key);
                    out.push_str(": ");
                    value.write(out, indent + 1);
                }
                newline(out, indent);
                out.push('}');
            }
        }
    }
}

fn separator(out: &mut String, index: usize, indent: usize) {
    if index > 0 {
        out.push(',');
    }
    newline(out, indent);
}

fn newline(out: &mut String, indent: usize) {
    out.push('\n');
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_str(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if u32::from(control) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(control));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_like_python_json_dump() {
        let value = Json::object([
            ("a", Json::Int(1)),
            ("b", Json::Array(vec![])),
            ("c", Json::strs(&["x", "ü"])),
            ("d", Json::object::<&str>([])),
            ("e", Json::str("q\"\\\n\u{1}")),
        ]);
        assert_eq!(
            value.render(),
            "{\n  \"a\": 1,\n  \"b\": [],\n  \"c\": [\n    \"x\",\n    \"ü\"\n  ],\n  \"d\": {},\n  \"e\": \"q\\\"\\\\\\n\\u0001\"\n}\n"
        );
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(Json::hex(&[0x0a, 0xff]), Json::str("0aff"));
    }
}
