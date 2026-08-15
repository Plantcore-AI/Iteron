//! Static handling of the leading `export const meta = {…};`.
//!
//! Two jobs, both without executing the script body:
//!   * [`strip_meta`] — remove the `export const meta` statement so the remaining body can be wrapped
//!     as an async function (top-level `return`/`await` become legal — review B1). This is a
//!     mandatory transform, not a nicety.
//!   * [`extract_meta`] — evaluate ONLY the isolated object literal in a throwaway no-globals QuickJS
//!     context and read `name`/`description`/`phases`. This is the "real parse, not a fragile regex"
//!     the review demanded: braces inside strings/templates/comments never miscount.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

const DEFAULT_COMPILE_CACHE_ENTRIES: usize = 256;

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

/// One immutable parse product shared by metadata discovery and execution.
#[derive(Debug)]
pub struct CompiledWorkflow {
    body: Arc<str>,
    meta: Option<Meta>,
}

impl CompiledWorkflow {
    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn meta(&self) -> Option<&Meta> {
        self.meta.as_ref()
    }
}

#[derive(Default)]
struct CompileCache {
    entries: HashMap<String, Arc<CompiledWorkflow>>,
    order: VecDeque<String>,
}

/// Parse a workflow once per source digest. The cache is bounded and contains only source-derived
/// metadata/body; execution state and authority never enter it.
pub fn compile(src: &str) -> Arc<CompiledWorkflow> {
    static CACHE: OnceLock<Mutex<CompileCache>> = OnceLock::new();
    let key = hex::encode(Sha256::digest(src.as_bytes()));
    let cache = CACHE.get_or_init(|| Mutex::new(CompileCache::default()));
    if let Some(compiled) = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entries
        .get(&key)
        .cloned()
    {
        return compiled;
    }

    let (body, meta) = compile_uncached(src);
    let compiled = Arc::new(CompiledWorkflow {
        body: Arc::from(body),
        meta,
    });
    let mut cache = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = cache.entries.get(&key) {
        return Arc::clone(existing);
    }
    let limit = iteron_tunables::param_usize(
        "workflow.meta.default_compile_cache_entries",
        DEFAULT_COMPILE_CACHE_ENTRIES,
    )
    .clamp(1, 4_096);
    while cache.entries.len() >= limit {
        if let Some(oldest) = cache.order.pop_front() {
            cache.entries.remove(&oldest);
        } else {
            break;
        }
    }
    cache.order.push_back(key.clone());
    cache.entries.insert(key, Arc::clone(&compiled));
    compiled
}

fn compile_uncached(src: &str) -> (String, Option<Meta>) {
    let Some((literal, range)) = locate_meta(src) else {
        return (src.to_owned(), None);
    };
    let mut body = String::with_capacity(src.len());
    body.push_str(&src[..range.start]);
    body.push_str(&src[range.end..]);
    let meta = rquickjs::Runtime::new().ok().and_then(|rt| {
        let ctx = rquickjs::Context::full(&rt).ok()?;
        ctx.with(|ctx| {
            let code = format!("JSON.stringify(({literal}))");
            let json: String = ctx.eval(code.as_bytes()).ok()?;
            serde_json::from_str::<Meta>(&json).ok()
        })
    });
    (body, meta)
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
    compile(src).body().to_owned()
}

/// Evaluate the isolated meta object literal in a throwaway QuickJS context (no host globals) and
/// read the header fields. Best-effort: any parse/eval failure yields `None`.
pub fn extract_meta(src: &str) -> Option<Meta> {
    compile(src).meta().cloned()
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
