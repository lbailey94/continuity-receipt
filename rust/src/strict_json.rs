//! JSON decoder which rejects duplicate object names before serde_json::Value
//! can silently overwrite them. Values are parsed by serde_json afterward, so
//! its arbitrary-precision number behavior stays identical to the verifier.
use std::collections::HashSet;

use serde_json::Value;

struct Scanner<'a> {
    input: &'a str,
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Scanner<'a> {
    fn whitespace(&mut self) {
        while self.bytes.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }

    fn string(&mut self) -> Result<&'a str, String> {
        let start = self.at;
        if self.bytes.get(self.at) != Some(&b'"') {
            return Err("expected JSON string".into());
        }
        self.at += 1;
        while let Some(byte) = self.bytes.get(self.at).copied() {
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(&self.input[start..self.at]);
                }
                b'\\' => self.at = (self.at + 2).min(self.bytes.len()),
                _ => self.at += 1,
            }
        }
        Err("unterminated JSON string".into())
    }

    fn value(&mut self, depth: usize) -> Result<(), String> {
        if depth > 128 {
            return Err("JSON nesting exceeds parser limit".into());
        }
        self.whitespace();
        match self.bytes.get(self.at) {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => { self.string()?; Ok(()) }
            Some(_) => {
                while let Some(byte) = self.bytes.get(self.at) {
                    if byte.is_ascii_whitespace() || matches!(byte, b',' | b']' | b'}') { break; }
                    self.at += 1;
                }
                Ok(())
            }
            None => Err("unexpected end of JSON input".into()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), String> {
        self.at += 1;
        self.whitespace();
        if self.bytes.get(self.at) == Some(&b'}') { self.at += 1; return Ok(()); }
        let mut names = HashSet::new();
        loop {
            self.whitespace();
            let encoded = self.string()?;
            let name: String = serde_json::from_str(encoded).map_err(|error| error.to_string())?;
            if !names.insert(name.clone()) {
                return Err(format!("duplicate JSON object member: {name:?}"));
            }
            self.whitespace();
            if self.bytes.get(self.at) != Some(&b':') { return Err("expected ':' after JSON object member".into()); }
            self.at += 1;
            self.value(depth)?;
            self.whitespace();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'}') => { self.at += 1; return Ok(()); }
                _ => return Err("expected ',' or '}' in JSON object".into()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), String> {
        self.at += 1;
        self.whitespace();
        if self.bytes.get(self.at) == Some(&b']') { self.at += 1; return Ok(()); }
        loop {
            self.value(depth)?;
            self.whitespace();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b']') => { self.at += 1; return Ok(()); }
                _ => return Err("expected ',' or ']' in JSON array".into()),
            }
        }
    }
}

/// Parse JSON with ordinary serde_json semantics while rejecting duplicate
/// names recursively. Escaped-equivalent names (for example `"a"` and
/// `"\u0061"`) count as duplicates.
pub fn from_str(input: &str) -> Result<Value, String> {
    let mut scanner = Scanner { input, bytes: input.as_bytes(), at: 0 };
    scanner.value(0)?;
    scanner.whitespace();
    if scanner.at != scanner.bytes.len() { return Err("trailing content after JSON value".into()); }
    serde_json::from_str(input).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::from_str;

    #[test]
    fn accepts_unique_members_and_rejects_duplicate_members_at_any_depth() {
        assert!(from_str(r#"{"a":1,"nested":{"b":2}}"#).is_ok());
        assert!(from_str(r#"{"a":1,"a":2}"#).is_err());
        assert!(from_str(r#"{"nested":{"b":1,"b":2}}"#).is_err());
        assert!(from_str(r#"{"a":1,"\u0061":2}"#).is_err());
        assert_eq!(from_str(r#"{"n":18446744073709551616}"#).unwrap()["n"].to_string(), "18446744073709551616");
    }
}
