//! The content-addressed resume cache key (design §2.6 + review B2).
//!
//! `key = "v2:" + hex(sha256(canonical_json(agent_input)))` where `agent_input` is the CALLER's
//! literal `agent(prompt, opts)` shape — `{prompt, label, phase, schema, model, effort, agentType}`
//! — never engine-derived display labels. Because the determinism traps fix the ordered sequence of
//! `agent()` calls and their content, this key is a pure function of `(script, args)`, so an
//! identical relaunch produces byte-identical keys and a 100% journal hit.
//!
//! `agent_id(key)` is the hex tail of the same hash (design's pinned choice, §6): journals dedup and
//! resume by content, matching Claude Code's `v2:<sha256>` semantics.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Compute the `v2:` cache key over the caller's raw agent input. All fields are the values the
/// script passed (or `None`), so two calls with identical input collapse to one key (content-hash
/// dedup) and a relaunch replays them.
#[allow(clippy::too_many_arguments)]
pub fn agent_key(
    prompt: &str,
    label: Option<&str>,
    phase: Option<&str>,
    schema: Option<&Value>,
    model: Option<&str>,
    effort: Option<&str>,
    agent_type: Option<&str>,
) -> String {
    let input = serde_json::json!({
        "prompt": prompt,
        "label": label,
        "phase": phase,
        "schema": schema,
        "model": model,
        "effort": effort,
        "agentType": agent_type,
    });
    let mut canonical = String::new();
    canonicalize(&input, &mut canonical);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("v2:{}", hex::encode(digest))
}

/// The hex agent id = the cache key with the `v2:` prefix stripped (the raw sha256 hex).
pub fn agent_id(key: &str) -> String {
    key.strip_prefix("v2:").unwrap_or(key).to_string()
}

/// Serialize a JSON value with object keys sorted recursively, so logically-equal inputs with
/// different key insertion order hash identically. (Determinism already fixes byte-order across
/// runs of the same script; this makes cross-call dedup robust too.)
fn canonicalize(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        // serde_json string serialization applies the correct JSON escaping.
        Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonicalize(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()));
                out.push(':');
                canonicalize(&map[*k], out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_stable_and_prefixed() {
        let k1 = agent_key("hello", None, None, None, None, None, None);
        let k2 = agent_key("hello", None, None, None, None, None, None);
        assert_eq!(k1, k2, "same input -> same key");
        assert!(k1.starts_with("v2:"));
        assert_eq!(agent_id(&k1), k1["v2:".len()..]);
    }

    #[test]
    fn different_prompt_changes_key() {
        let a = agent_key("a", None, None, None, None, None, None);
        let b = agent_key("b", None, None, None, None, None, None);
        assert_ne!(a, b);
    }

    #[test]
    fn schema_key_order_is_canonical() {
        // Two schemas that differ only in key order must produce the same key.
        let s1 = serde_json::json!({ "type": "object", "required": ["x"] });
        let s2 = serde_json::json!({ "required": ["x"], "type": "object" });
        let k1 = agent_key("p", None, None, Some(&s1), None, None, None);
        let k2 = agent_key("p", None, None, Some(&s2), None, None, None);
        assert_eq!(k1, k2, "canonicalization sorts nested object keys");
    }
}
