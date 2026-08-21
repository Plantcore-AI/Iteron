//! The edit tool: a minimal structured diff with a **uniqueness guard**.
//!
//! ADR-005: minimal structured diffs over whole-file rewrites. And the review's named defect
//! (`sec-apply-patch-homoglyph-mislanding`, Codex's first-match fuzzy patcher): the anchor
//! must be **unique**. If `old` appears zero times or more than once, the edit is refused,
//! not applied to a guessed location. That refusal is the whole safety property.

use crate::fs_tools::EditableText;
use crate::write_file::{
    GuardedCommitFailure, StagedWrite, file_changed_json, read_existing_snapshot,
};
use crate::{Registry, ToolError, boxfut, err_result, ok_result, resolve_in_root};
use iteron_protocol::{Capability, Purity, ToolSpec};
use std::ops::Range;

pub(crate) const MAX_NORMALIZED_LINES: usize = 262_144;
const MAX_NORMALIZED_CANDIDATE_CHECKS: usize = 1_024;
const MAX_EDIT_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_EDIT_PATH_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UniqueEditError {
    EmptyAnchor,
    SuspiciousUnicode(u32),
    AnchorNotFound { nearest_line: Option<usize> },
    AmbiguousAnchor { count: usize, normalized: bool },
    NormalizationLimit(&'static str),
}

impl std::fmt::Display for UniqueEditError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyAnchor => {
                formatter.write_str("`old` is empty; refuse to anchor an edit on nothing")
            }
            Self::SuspiciousUnicode(codepoint) => write!(
                formatter,
                "edit refused: suspicious Unicode (U+{codepoint:04X}) in the anchor or replacement"
            ),
            Self::AnchorNotFound {
                nearest_line: Some(line),
            } => write!(
                formatter,
                "`old` not found after exact and whitespace-normalized matching; nearest \
                 normalized line starts at line {line}. Inspect it and retry with more context."
            ),
            Self::AnchorNotFound { nearest_line: None } => formatter.write_str(
                "`old` not found after exact and whitespace-normalized matching; retry with \
                     more surrounding context",
            ),
            Self::AmbiguousAnchor {
                count,
                normalized: false,
            } => write!(
                formatter,
                "`old` matches {count} locations; anchors must be unique. Include more surrounding \
                 context so the match is unambiguous."
            ),
            Self::AmbiguousAnchor {
                count,
                normalized: true,
            } => write!(
                formatter,
                "`old` has at least {count} whitespace-normalized candidates; anchors must be \
                 unique. Include non-whitespace context so the match is unambiguous."
            ),
            Self::NormalizationLimit(reason) => write!(
                formatter,
                "whitespace-normalized matching refused: {reason}"
            ),
        }
    }
}

pub(crate) struct UniqueEditPlan {
    pub(crate) span: Range<usize>,
    pub(crate) replacement: String,
}

#[derive(Clone, Debug)]
struct NormalizedLine {
    start: usize,
    content_end: usize,
    full_end: usize,
    core_start: usize,
    core_end: usize,
    hash: u64,
}

impl NormalizedLine {
    fn core<'a>(&self, text: &'a str) -> &'a str {
        &text[self.core_start..self.core_end]
    }

    fn has_eol(&self) -> bool {
        self.full_end > self.content_end
    }
}

/// Plan one unique edit without applying it. Exact matching remains the first tier. Only an exact
/// miss enters deterministic line-edge whitespace normalization; every accepted candidate still
/// maps back to one real byte range in `content`.
pub(crate) fn plan_unique_edit(
    content: &str,
    old: &str,
    new: &str,
) -> Result<UniqueEditPlan, UniqueEditError> {
    if old.is_empty() {
        return Err(UniqueEditError::EmptyAnchor);
    }
    if let Some(codepoint) = suspicious_unicode(old).or_else(|| suspicious_unicode(new)) {
        return Err(UniqueEditError::SuspiciousUnicode(codepoint));
    }
    let mut matches = content.match_indices(old).map(|(start, _)| start);
    if let Some(start) = matches.next() {
        if matches.next().is_some() {
            return Err(UniqueEditError::AmbiguousAnchor {
                count: 2 + matches.count(),
                normalized: false,
            });
        }
        return Ok(UniqueEditPlan {
            span: start..start + old.len(),
            replacement: new.into(),
        });
    }
    plan_normalized_edit(content, old, new)
}

/// Apply a unique-anchor replacement. Returns the new content, or an error describing why the
/// edit could not land unambiguously. Pure function — unit-testable, and this is where the
/// security-relevant guarantee lives.
pub fn apply_unique_edit(content: &str, old: &str, new: &str) -> Result<String, String> {
    let edit = plan_unique_edit(content, old, new).map_err(|error| error.to_string())?;
    let mut updated = content.to_owned();
    updated.replace_range(edit.span, &edit.replacement);
    Ok(updated)
}

fn plan_normalized_edit(
    content: &str,
    old: &str,
    new: &str,
) -> Result<UniqueEditPlan, UniqueEditError> {
    let content_lines = normalized_lines(content)?;
    let old_lines = normalized_lines(old)?;
    if old_lines.iter().all(|line| line.core(old).is_empty()) {
        return Err(UniqueEditError::AnchorNotFound { nearest_line: None });
    }
    let nearest_line = nearest_normalized_line(content, &content_lines, old, &old_lines);
    if old_lines.len() > content_lines.len() {
        return Err(UniqueEditError::AnchorNotFound { nearest_line });
    }

    let prefix = normalized_prefix_table(&old_lines);
    let max_candidate_checks = iteron_tunables::param_usize(
        "tools.edit.max_normalized_candidate_checks",
        iteron_tunables::param_integer(
            "tools.edit.max_normalized_candidate_checks",
            MAX_NORMALIZED_CANDIDATE_CHECKS,
        ),
    );
    let mut prefix_len = 0usize;
    let mut candidate_checks = 0usize;
    let mut unique_start = None;
    for (line_index, line) in content_lines.iter().enumerate() {
        while prefix_len > 0 && line.hash != old_lines[prefix_len].hash {
            prefix_len = prefix[prefix_len - 1];
        }
        if line.hash == old_lines[prefix_len].hash {
            prefix_len += 1;
        }
        if prefix_len != old_lines.len() {
            continue;
        }

        let start = line_index + 1 - old_lines.len();
        candidate_checks += 1;
        if candidate_checks > max_candidate_checks {
            return Err(UniqueEditError::NormalizationLimit(
                "candidate verification exceeds its bounded work limit",
            ));
        }
        if normalized_sequence_equal(content, &content_lines[start..=line_index], old, &old_lines)
            && (!old_lines.last().is_some_and(NormalizedLine::has_eol)
                || content_lines[line_index].has_eol())
        {
            if unique_start.is_some() {
                return Err(UniqueEditError::AmbiguousAnchor {
                    count: 2,
                    normalized: true,
                });
            }
            unique_start = Some(start);
        }
        prefix_len = prefix[prefix_len - 1];
    }

    let Some(start) = unique_start else {
        return Err(UniqueEditError::AnchorNotFound { nearest_line });
    };
    let matched = &content_lines[start..start + old_lines.len()];
    let span = matched.first().unwrap().core_start..matched.last().unwrap().core_end;
    let replacement = normalized_replacement(content, matched, new)?;
    Ok(UniqueEditPlan { span, replacement })
}

fn normalized_lines(text: &str) -> Result<Vec<NormalizedLine>, UniqueEditError> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0usize;
    let max_normalized_lines =
        iteron_tunables::param_usize("tools.edit.max_normalized_lines", MAX_NORMALIZED_LINES);
    while start < bytes.len() {
        if lines.len() == max_normalized_lines {
            return Err(UniqueEditError::NormalizationLimit(
                "line count exceeds 262144",
            ));
        }
        let newline = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| start + offset);
        let raw_content_end = newline.unwrap_or(bytes.len());
        let content_end = if newline.is_some()
            && raw_content_end > start
            && bytes[raw_content_end - 1] == b'\r'
        {
            raw_content_end - 1
        } else {
            raw_content_end
        };
        let full_end = newline.map_or(bytes.len(), |index| index + 1);
        let mut core_start = start;
        while core_start < content_end && matches!(bytes[core_start], b' ' | b'\t') {
            core_start += 1;
        }
        let mut core_end = content_end;
        while core_end > core_start && matches!(bytes[core_end - 1], b' ' | b'\t') {
            core_end -= 1;
        }
        lines.push(NormalizedLine {
            start,
            content_end,
            full_end,
            core_start,
            core_end,
            hash: stable_line_hash(&bytes[core_start..core_end]),
        });
        start = full_end;
    }
    Ok(lines)
}

fn stable_line_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn normalized_prefix_table(pattern: &[NormalizedLine]) -> Vec<usize> {
    let mut prefix = vec![0usize; pattern.len()];
    let mut matched = 0usize;
    for index in 1..pattern.len() {
        while matched > 0 && pattern[index].hash != pattern[matched].hash {
            matched = prefix[matched - 1];
        }
        if pattern[index].hash == pattern[matched].hash {
            matched += 1;
        }
        prefix[index] = matched;
    }
    prefix
}

fn normalized_sequence_equal(
    content: &str,
    candidate: &[NormalizedLine],
    old: &str,
    pattern: &[NormalizedLine],
) -> bool {
    candidate
        .iter()
        .zip(pattern)
        .all(|(actual, expected)| actual.core(content) == expected.core(old))
}

fn normalized_replacement(
    content: &str,
    matched: &[NormalizedLine],
    new: &str,
) -> Result<String, UniqueEditError> {
    let new_lines = normalized_lines(new)?;
    if new_lines.len() == matched.len() && !new_lines.is_empty() {
        let mut replacement = String::new();
        for (index, line) in new_lines.iter().enumerate() {
            replacement.push_str(line.core(new));
            if index + 1 < new_lines.len() {
                replacement
                    .push_str(&content[matched[index].core_end..matched[index + 1].core_start]);
            }
        }
        return Ok(replacement);
    }
    if new_lines.is_empty() {
        return Ok(String::new());
    }

    let eol = matched
        .iter()
        .find(|line| line.has_eol())
        .map(|line| &content[line.content_end..line.full_end])
        .unwrap_or("\n");
    let mut replacement = String::new();
    for (index, line) in new_lines.iter().enumerate() {
        let start = if index == 0 {
            line.core_start
        } else {
            line.start
        };
        let end = if index + 1 == new_lines.len() {
            line.core_end
        } else {
            line.content_end
        };
        replacement.push_str(&new[start.min(end)..end]);
        if index + 1 < new_lines.len() {
            replacement.push_str(eol);
        }
    }
    Ok(replacement)
}

fn nearest_normalized_line(
    content: &str,
    content_lines: &[NormalizedLine],
    old: &str,
    old_lines: &[NormalizedLine],
) -> Option<usize> {
    let target = old_lines
        .iter()
        .map(|line| line.core(old).as_bytes())
        .find(|core| !core.is_empty())?;
    let mut best: Option<(usize, usize, usize)> = None;
    for (index, line) in content_lines.iter().enumerate() {
        let candidate = line.core(content).as_bytes();
        let prefix = candidate
            .iter()
            .zip(target)
            .take_while(|(left, right)| left == right)
            .count();
        let suffix = candidate
            .iter()
            .rev()
            .zip(target.iter().rev())
            .take_while(|(left, right)| left == right)
            .count();
        let similarity = (prefix + suffix).min(candidate.len().min(target.len()));
        let length_delta = candidate.len().abs_diff(target.len());
        if best.is_none_or(|(_, best_similarity, best_delta)| {
            similarity > best_similarity
                || (similarity == best_similarity && length_delta < best_delta)
        }) {
            best = Some((index + 1, similarity, length_delta));
        }
    }
    best.map(|(line, _, _)| line)
}

/// Flag control / bidi / zero-width characters that make rendered text differ from bytes.
pub(crate) fn suspicious_unicode(s: &str) -> Option<u32> {
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

async fn edit_workspace_file(
    root: &std::path::Path,
    path: &str,
    old: &str,
    new: &str,
) -> Result<(), String> {
    edit_workspace_file_with_hook(root, path, old, new, |_| {}).await
}

pub(crate) async fn edit_workspace_file_with_hook<F>(
    root: &std::path::Path,
    path: &str,
    old: &str,
    new: &str,
    before_commit: F,
) -> Result<(), String>
where
    F: FnOnce(&std::path::Path),
{
    if path.is_empty()
        || path.len()
            > iteron_tunables::param_integer("tools.edit.max_edit_path_bytes", MAX_EDIT_PATH_BYTES)
    {
        return Err(format!(
            "edit path must contain 1..={MAX_EDIT_PATH_BYTES} bytes"
        ));
    }
    let max_edit_input_bytes =
        iteron_tunables::param_usize("tools.edit.max_edit_input_bytes", MAX_EDIT_INPUT_BYTES);
    if old
        .len()
        .checked_add(new.len())
        .is_none_or(|bytes| bytes > max_edit_input_bytes)
    {
        return Err(format!("edit input exceeds {max_edit_input_bytes} bytes"));
    }

    let target = resolve_in_root(root, path)?;
    let snapshot = read_existing_snapshot(&target)
        .await
        .map_err(|error| format!("read {path}: {error}"))?;
    let text =
        EditableText::parse(&snapshot.bytes).map_err(|error| format!("read {path}: {error}"))?;
    let replacement = text.normalize_replacement(new);
    let updated = apply_unique_edit(text.content(), old, &replacement)
        .map_err(|error| format!("edit {path}: {error}"))?;
    let encoded = text.encode(updated);
    let staged = StagedWrite::prepare(&target, &encoded)
        .await
        .map_err(|error| format!("stage {path}: {error}"))?;
    before_commit(&target);
    match staged.commit_if_unchanged(&snapshot.target).await {
        Ok(()) => Ok(()),
        Err(GuardedCommitFailure::Changed) => Err(file_changed_json("edit", path)),
        Err(GuardedCommitFailure::Inspect(error)) => {
            Err(format!("inspect {path} before commit: {error}"))
        }
        Err(GuardedCommitFailure::Commit(failure)) => {
            Err(format!("write {path}: {}", failure.error))
        }
    }
}

pub(crate) fn register(r: &mut Registry) -> Result<(), ToolError> {
    r.push_candidate_change_tool(
        ToolSpec {
            name: "edit".into(),
            description: "Replace one UNIQUE snippet in a file with new text. Exact matching is \
                          tried first; an exact miss may match after deterministic per-line \
                          indentation, trailing-space, and LF/CRLF normalization. Zero or multiple \
                          candidates are refused. The target's UTF-8 BOM, line-ending style, and \
                          trailing-newline state are retained. The replacement is crash-atomic and \
                          refused if the matched file changes while staging. Prefer small edits \
                          with surrounding context."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "path":{"type":"string"},
                    "old":{"type":"string","description":"unique exact or line-edge-whitespace-normalized snippet"},
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
                match edit_workspace_file(&root, path, old, new).await {
                    Ok(()) => ok_result(id, format!("edited {path} (1 replacement)")),
                    Err(error) => err_result(id, error),
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
    fn exact_anchor_preserves_legacy_byte_replacement_behavior() {
        let content = "\told();  \r\nkeep\r\n";

        let updated = apply_unique_edit(content, "\told();  \r\n", "new();\n").unwrap();

        assert_eq!(updated, "new();\nkeep\r\n");
    }

    #[test]
    fn normalized_multiline_landing_preserves_real_whitespace_envelopes() {
        let content = "  first(); \r\n\tsecond();\t\r\nuntouched  \r\n";
        let old = "\tfirst();\n    second();\n";
        let new = " FIRST();\n  SECOND();\n";

        let updated = apply_unique_edit(content, old, new).unwrap();

        assert_eq!(updated, "  FIRST(); \r\n\tSECOND();\t\r\nuntouched  \r\n");
    }

    #[test]
    fn ambiguous_exact_anchor_is_refused_not_guessed() {
        let result = plan_unique_edit("a();\na();\n", "a();", "b();");

        assert!(matches!(
            result,
            Err(UniqueEditError::AmbiguousAnchor {
                normalized: false,
                ..
            })
        ));
    }

    #[test]
    fn ambiguous_normalized_anchor_is_refused_not_guessed() {
        let result = plan_unique_edit("  a(); \r\n\ta();\t\r\n", "a();\n", "b();\n");

        assert!(matches!(
            result,
            Err(UniqueEditError::AmbiguousAnchor {
                normalized: true,
                ..
            })
        ));
    }

    #[test]
    fn interior_whitespace_drift_is_not_fuzzy_matched() {
        let result = plan_unique_edit(
            "call(left,  right);\n",
            "call(left, right);\n",
            "updated();\n",
        );

        assert!(matches!(
            result,
            Err(UniqueEditError::AnchorNotFound { .. })
        ));
    }

    #[test]
    fn missing_anchor_reports_deterministic_nearest_line() {
        let result = plan_unique_edit(
            "unrelated\ntarget_value = 41;\ntrailing\n",
            "target_value = 42;\n",
            "target_value = 43;\n",
        );

        assert!(matches!(
            result,
            Err(UniqueEditError::AnchorNotFound {
                nearest_line: Some(2)
            })
        ));
    }

    #[test]
    fn missing_anchor_is_refused() {
        assert!(apply_unique_edit("hello", "world", "x").is_err());
    }

    #[test]
    fn bidi_and_zero_width_are_refused_before_normalized_matching() {
        for (sneaky, expected) in [
            ("  if admin \u{202E}// safe\n", 0x202E),
            ("  if admin\u{200B} // safe\n", 0x200B),
        ] {
            let result = plan_unique_edit("if admin // safe\n", sneaky, "deny\n");

            assert!(matches!(
                result,
                Err(UniqueEditError::SuspiciousUnicode(codepoint)) if codepoint == expected
            ));
        }
    }
}
