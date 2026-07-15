//! The edit tool: a minimal structured diff with a **uniqueness guard**.
//!
//! ADR-005: minimal structured diffs over whole-file rewrites. And the review's named defect
//! (`sec-apply-patch-homoglyph-mislanding`, Codex's first-match fuzzy patcher): the anchor
//! must be **unique**. If `old` appears zero times or more than once, the edit is refused,
//! not applied to a guessed location. That refusal is the whole safety property.

use crate::{Registry, ToolError, boxfut, err_result, ok_result, resolve_in_root};
use core_protocol::{Capability, Purity, ToolSpec};

/// Apply a unique-anchor replacement. Returns the new content, or an error describing why the
/// edit could not land unambiguously. Pure function — unit-testable, and this is where the
/// security-relevant guarantee lives.
pub fn apply_unique_edit(content: &str, old: &str, new: &str) -> Result<String, String> {
    if old.is_empty() {
        return Err("`old` is empty; refuse to anchor an edit on nothing".into());
    }
    // Reject invisible / bidi Unicode in the anchor (ADR-007 §6 / sec-apply-patch finding):
    // a homoglyph or bidi override could make the visible anchor differ from the byte anchor.
    if let Some(bad) = suspicious_unicode(old).or_else(|| suspicious_unicode(new)) {
        return Err(format!(
            "edit refused: suspicious Unicode (U+{bad:04X}) in the anchor or replacement"
        ));
    }
    let count = content.matches(old).count();
    match count {
        0 => Err("`old` not found; the anchor must match exactly".into()),
        1 => Ok(content.replacen(old, new, 1)),
        n => Err(format!(
            "`old` matches {n} locations; anchors must be unique. Include more surrounding \
             context so the match is unambiguous."
        )),
    }
}

/// Flag control / bidi / zero-width characters that make rendered text differ from bytes.
fn suspicious_unicode(s: &str) -> Option<u32> {
    s.chars().map(|c| c as u32).find(|&c| {
        matches!(c,
            0x200B..=0x200F | // zero-width + LRM/RLM
            0x202A..=0x202E | // bidi embeddings/overrides
            0x2066..=0x2069 | // bidi isolates
            0x00AD |          // soft hyphen
            0xFEFF            // BOM / zero-width no-break
        )
    })
}

pub(crate) fn register(r: &mut Registry) -> Result<(), ToolError> {
    r.push_tool(
        ToolSpec {
            name: "edit".into(),
            description: "Replace an exact, UNIQUE snippet in a file with new text. `old` must \
                          match exactly one location; if it matches zero or many, the edit is \
                          refused — include more surrounding context to disambiguate. Prefer \
                          small edits over rewriting whole files."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "path":{"type":"string"},
                    "old":{"type":"string","description":"exact unique snippet to replace"},
                    "new":{"type":"string","description":"replacement text"}
                },
                "required":["path","old","new"]
            }),
            purity: Purity::Effecting,
            capability: Capability::ReversibleLocal,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let path = call
                    .input
                    .get("path")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                let old = call.input.get("old").and_then(|x| x.as_str()).unwrap_or("");
                let new = call.input.get("new").and_then(|x| x.as_str()).unwrap_or("");
                let p = match resolve_in_root(&root, path) {
                    Ok(p) => p,
                    Err(e) => return err_result(id, e),
                };
                let content = match tokio::fs::read_to_string(&p).await {
                    Ok(c) => c,
                    Err(e) => return err_result(id, format!("read {path}: {e}")),
                };
                match apply_unique_edit(&content, old, new) {
                    Ok(updated) => match tokio::fs::write(&p, &updated).await {
                        Ok(()) => ok_result(id, format!("edited {path} (1 replacement)")),
                        Err(e) => err_result(id, format!("write {path}: {e}")),
                    },
                    Err(e) => err_result(id, format!("edit {path}: {e}")),
                }
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_anchor_applies() {
        let out =
            apply_unique_edit("let x = 1;\nlet y = 2;\n", "let y = 2;", "let y = 3;").unwrap();
        assert!(out.contains("let y = 3;"));
    }

    #[test]
    fn ambiguous_anchor_is_refused_not_guessed() {
        // The exact failure mode of a first-match fuzzy patcher: two matches -> refuse.
        let r = apply_unique_edit("a();\na();\n", "a();", "b();");
        assert!(
            r.is_err(),
            "an ambiguous anchor must be refused, never applied to match #1"
        );
    }

    #[test]
    fn missing_anchor_is_refused() {
        assert!(apply_unique_edit("hello", "world", "x").is_err());
    }

    #[test]
    fn bidi_override_in_anchor_is_refused() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — the classic homoglyph/bidi trick.
        let sneaky = "if admin \u{202E}// safe";
        assert!(apply_unique_edit("code", sneaky, "x").is_err());
    }
}
