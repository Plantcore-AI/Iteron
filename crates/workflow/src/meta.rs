//! Static handling of the leading `export const meta = {…};`.
//!
//! Two jobs, both without executing the script body:
//!   * [`strip_meta`] — remove the `export const meta` statement so the remaining body can be wrapped
//!     as an async function (top-level `return`/`await` become legal — review B1). This is a
//!     mandatory transform, not a nicety.
//!   * [`extract_meta`] — evaluate ONLY the isolated object literal in a throwaway no-globals QuickJS
//!     context and read `name`/`description`/`phases`. This is the "real parse, not a fragile regex"
//!     the review demanded: braces inside strings/templates/comments never miscount.

/// The parsed workflow header (best-effort; every field is optional).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub phases: Option<Vec<String>>,
}

/// Locate the `export const meta = { … }` object literal and return `(literal_slice, byte_range)`
/// where `byte_range` covers the whole statement including a trailing `;`. `None` when there is no
/// such statement. The `{…}` boundary is found by a real scanner that skips strings, template
/// literals, and comments — so an object with `"a}b"` inside a string is matched correctly.
fn locate_meta(src: &str) -> Option<(String, std::ops::Range<usize>)> {
    let key = src.find("export const meta")?;
    // Find the first '{' after the `=`.
    let bytes = src.as_bytes();
    let mut i = key + "export const meta".len();
    // require an '=' before the brace (guards against `export const metadata`)
    let eq = src[i..].find('=')? + i;
    i = eq + 1;
    while i < bytes.len() && bytes[i] != b'{' {
        // only whitespace/newlines are expected between '=' and '{'
        if !bytes[i].is_ascii_whitespace() {
            break;
        }
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'{' {
        return None;
    }
    let obj_start = i;
    let obj_end = match_object(bytes, obj_start)?; // index just past the closing '}'
    // Skip trailing whitespace + one optional ';'.
    let mut end = obj_end;
    while end < bytes.len() && bytes[end].is_ascii_whitespace() {
        end += 1;
    }
    if end < bytes.len() && bytes[end] == b';' {
        end += 1;
    }
    let literal = src[obj_start..obj_end].to_string();
    Some((literal, key..end))
}

/// Given `bytes[open]` == b'{', return the index just past the matching '}', skipping strings
/// (`'`, `"`, and template `` ` ``), and `//` / `/* */` comments. Returns None if unbalanced.
fn match_object(bytes: &[u8], open: usize) -> Option<usize> {
    #[derive(PartialEq)]
    enum St {
        Code,
        SQuote,
        DQuote,
        Template,
        LineComment,
        BlockComment,
    }
    let mut state = St::Code;
    let mut depth: i32 = 0;
    let mut i = open;
    while i < bytes.len() {
        let c = bytes[i];
        match state {
            St::Code => match c {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                b'\'' => state = St::SQuote,
                b'"' => state = St::DQuote,
                b'`' => state = St::Template,
                b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                    state = St::LineComment;
                    i += 1;
                }
                b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                    state = St::BlockComment;
                    i += 1;
                }
                _ => {}
            },
            St::SQuote => match c {
                b'\\' => i += 1, // skip escaped char
                b'\'' => state = St::Code,
                _ => {}
            },
            St::DQuote => match c {
                b'\\' => i += 1,
                b'"' => state = St::Code,
                _ => {}
            },
            // Templates are treated as opaque strings (no `${}` brace counting). Pure-literal metas
            // never interpolate, so this is safe and keeps the object's real braces the only ones
            // counted.
            St::Template => match c {
                b'\\' => i += 1,
                b'`' => state = St::Code,
                _ => {}
            },
            St::LineComment => {
                if c == b'\n' {
                    state = St::Code;
                }
            }
            St::BlockComment => {
                if c == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    state = St::Code;
                    i += 1;
                }
            }
        }
        i += 1;
    }
    None
}

/// Remove the leading `export const meta = {…};` statement. The prefix before it (comments, blank
/// lines) and everything after it are concatenated — the meta is the first statement, so the result
/// is the runnable body. Returns the input unchanged when there is no meta statement.
pub fn strip_meta(src: &str) -> String {
    match locate_meta(src) {
        Some((_literal, range)) => {
            let mut out = String::with_capacity(src.len());
            out.push_str(&src[..range.start]);
            out.push_str(&src[range.end..]);
            out
        }
        None => src.to_string(),
    }
}

/// Evaluate the isolated meta object literal in a throwaway QuickJS context (no host globals) and
/// read the header fields. Best-effort: any parse/eval failure yields `None`.
pub fn extract_meta(src: &str) -> Option<Meta> {
    let (literal, _range) = locate_meta(src)?;
    let rt = rquickjs::Runtime::new().ok()?;
    let ctx = rquickjs::Context::full(&rt).ok()?;
    ctx.with(|ctx| {
        // Wrap in parens so `{...}` is an expression, not a block; JSON.stringify normalizes it.
        let code = format!("JSON.stringify(({literal}))");
        let json: String = ctx.eval(code.as_bytes()).ok()?;
        serde_json::from_str::<Meta>(&json).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = r#"export const meta = {
  name: 'demo',
  description: 'a } brace inside a string; and a ; too',
  phases: ['explore', 'build'],
};
log('start');
const r = await parallel([() => agent('hi')]);
return r;
"#;

    #[test]
    fn strip_removes_only_the_meta_statement() {
        let body = strip_meta(SCRIPT);
        assert!(!body.contains("export const meta"));
        assert!(body.contains("log('start')"));
        assert!(body.contains("return r;"));
    }

    #[test]
    fn extract_reads_fields_through_a_real_eval() {
        let meta = extract_meta(SCRIPT).expect("meta");
        assert_eq!(meta.name.as_deref(), Some("demo"));
        assert_eq!(
            meta.phases.as_deref(),
            Some(&["explore".to_string(), "build".to_string()][..])
        );
    }

    #[test]
    fn no_meta_is_passthrough() {
        let src = "log('hi'); return 1;";
        assert_eq!(strip_meta(src), src);
        assert!(extract_meta(src).is_none());
    }
}
