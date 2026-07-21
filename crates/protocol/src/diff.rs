//! A structured file diff — shared between the kernel (which produces it from edit-tool output) and
//! the TUI (which renders it as an inline diff card). ADR-015: the TUI is a structured semantic
//! transcript, and an edit is one of its block types. Parsed from unified-diff text (ADR-015 R7: no
//! `ToolResult` contract change), so `EventKind` (the durable record) is untouched.

/// One line of a hunk: added / removed / unchanged context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DiffTag {
    Add,
    Del,
    Ctx,
}

/// One diff line: its tag and its text (without the leading +/-/space marker).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffLine {
    pub tag: DiffTag,
    pub text: String,
}

/// One hunk: its `@@ … @@` header and its lines.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hunk {
    pub header: String,
    pub lines: Vec<DiffLine>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_replacement_builds_one_hunk() {
        let d = FileDiff::from_replacement("src/a.rs", "let x = 1;", "let x = 2;\nlet y = 3;");
        assert_eq!(d.path, "src/a.rs");
        assert_eq!(d.dels, 1);
        assert_eq!(d.adds, 2);
        assert_eq!(d.hunks.len(), 1);
    }

    #[test]
    fn from_unified_parses_a_git_diff() {
        let text = "diff --git a/src/foo.rs b/src/foo.rs\nindex 111..222 100644\n--- a/src/foo.rs\n+++ b/src/foo.rs\n@@ -1,3 +1,3 @@\n fn main() {\n-    old();\n+    new();\n }\n";
        let ds = FileDiff::from_unified(text);
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].path, "src/foo.rs");
        assert_eq!(ds[0].adds, 1);
        assert_eq!(ds[0].dels, 1);
        assert_eq!(ds[0].hunks.len(), 1);
    }

    #[test]
    fn from_unified_is_robust_to_adversarial_input() {
        // must not panic on empty body lines, /dev/null, binary, no trailing content
        for text in [
            "",
            "@@ -0,0 @@\n\n\n", // hunk with blank body lines, no diff --git
            "diff --git a/x b/x\n--- a/x\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n",
            "diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n",
            "diff --git a/a b/b\nrename from a\nrename to b\n",
        ] {
            let _ = FileDiff::from_unified(text); // just must not panic
        }
    }

    #[test]
    fn from_unified_bounds_a_huge_diff() {
        let mut t = String::from("diff --git a/big b/big\n+++ b/big\n@@ -1,9999 +1,9999 @@\n");
        for i in 0..5000 {
            t.push_str(&format!("+line {i}\n"));
        }
        let ds = FileDiff::from_unified(&t);
        let total: usize = ds
            .iter()
            .flat_map(|f| f.hunks.iter())
            .map(|h| h.lines.len())
            .sum();
        assert!(total < 700, "huge diff must be bounded, got {total}");
    }

    #[test]
    fn d13_14_structured_diff_wire_is_strict_and_covers_every_tag() {
        let diff = FileDiff {
            path: "src/lib.rs".into(),
            adds: 1,
            dels: 1,
            hunks: vec![Hunk {
                header: "@@ -1,2 +1,2 @@".into(),
                lines: vec![
                    DiffLine {
                        tag: DiffTag::Del,
                        text: "old".into(),
                    },
                    DiffLine {
                        tag: DiffTag::Add,
                        text: "new".into(),
                    },
                    DiffLine {
                        tag: DiffTag::Ctx,
                        text: "context".into(),
                    },
                ],
            }],
        };
        let frozen = serde_json::json!({
            "path": "src/lib.rs",
            "adds": 1,
            "dels": 1,
            "hunks": [{
                "header": "@@ -1,2 +1,2 @@",
                "lines": [
                    {"tag": "Del", "text": "old"},
                    {"tag": "Add", "text": "new"},
                    {"tag": "Ctx", "text": "context"},
                ],
            }],
        });
        assert_eq!(serde_json::to_value(&diff).unwrap(), frozen);
        assert_eq!(serde_json::from_value::<FileDiff>(frozen).unwrap(), diff);

        for malformed in [
            serde_json::json!({
                "path": "src/lib.rs", "adds": 1, "dels": 1, "hunks": [], "extra": 1
            }),
            serde_json::json!({
                "path": "src/lib.rs", "adds": 1, "dels": 1,
                "hunks": [{"header": "@@", "lines": [], "extra": 1}]
            }),
            serde_json::json!({
                "path": "src/lib.rs", "adds": 1, "dels": 1,
                "hunks": [{"header": "@@", "lines": [{"tag": "Add", "text": "x", "extra": 1}]}]
            }),
        ] {
            assert!(
                serde_json::from_value::<FileDiff>(malformed).is_err(),
                "unknown nested diff fields must fail closed"
            );
        }
    }
}

/// A single file's diff: path, add/delete counts, and hunks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileDiff {
    pub path: String,
    pub adds: u32,
    pub dels: u32,
    pub hunks: Vec<Hunk>,
}

impl FileDiff {
    /// Build a minimal one-hunk diff from a single unique `old → new` replacement (the edit tool's
    /// exact change), without a full-file LCS: `old` lines become `Del`, `new` lines become `Add`.
    /// Bounded — caps the shown lines so a huge replacement can't grow the card unbounded.
    pub fn from_replacement(path: &str, old: &str, new: &str) -> FileDiff {
        const CAP: usize = 200;
        let mut lines = Vec::new();
        let mut dels = 0u32;
        for l in old.lines().take(CAP) {
            lines.push(DiffLine {
                tag: DiffTag::Del,
                text: l.to_string(),
            });
            dels += 1;
        }
        let mut adds = 0u32;
        for l in new.lines().take(CAP) {
            lines.push(DiffLine {
                tag: DiffTag::Add,
                text: l.to_string(),
            });
            adds += 1;
        }
        FileDiff {
            path: path.to_string(),
            adds,
            dels,
            hunks: vec![Hunk {
                header: format!("@@ {path} @@"),
                lines,
            }],
        }
    }

    /// Parse standard unified-diff text into per-file diffs. Robust to adversarial input (C-MINOR/18):
    /// empty body lines default to context (never index byte[0]), `/dev/null` / binary / rename lines
    /// are handled without a crash. Bounded to keep a giant diff from growing the card unbounded.
    pub fn from_unified(text: &str) -> Vec<FileDiff> {
        const MAX_LINES: usize = 600;
        let mut files: Vec<FileDiff> = Vec::new();
        let mut cur: Option<FileDiff> = None;
        let strip_prefix = |p: &str| {
            p.trim_start_matches("a/")
                .trim_start_matches("b/")
                .to_string()
        };
        let mut lines_seen = 0usize;
        for raw in text.lines() {
            if lines_seen >= MAX_LINES {
                break;
            }
            if let Some(rest) = raw.strip_prefix("diff --git ") {
                if let Some(f) = cur.take() {
                    files.push(f);
                }
                // "a/path b/path" — take the b/ side
                let path = rest
                    .split_whitespace()
                    .next_back()
                    .map(strip_prefix)
                    .unwrap_or_default();
                cur = Some(FileDiff {
                    path,
                    adds: 0,
                    dels: 0,
                    hunks: Vec::new(),
                });
                continue;
            }
            if let Some(p) = raw.strip_prefix("+++ ") {
                if let Some(f) = cur.as_mut() {
                    let p = p.trim();
                    if p != "/dev/null" {
                        f.path = strip_prefix(p);
                    }
                }
                continue;
            }
            if raw.starts_with("--- ") || raw.starts_with("index ") {
                continue;
            }
            if raw.starts_with("Binary files ") {
                if cur.is_none() {
                    cur = Some(FileDiff {
                        path: raw.trim_start_matches("Binary files ").to_string(),
                        adds: 0,
                        dels: 0,
                        hunks: Vec::new(),
                    });
                }
                continue;
            }
            if raw.starts_with("@@") {
                if let Some(f) = cur.as_mut() {
                    f.hunks.push(Hunk {
                        header: raw.to_string(),
                        lines: Vec::new(),
                    });
                }
                lines_seen += 1;
                continue;
            }
            // a body line: classify by first byte, defaulting to context (never index [0]).
            if let Some(f) = cur.as_mut()
                && let Some(h) = f.hunks.last_mut()
            {
                let (tag, text) = match raw.as_bytes().first() {
                    Some(b'+') => (DiffTag::Add, &raw[1..]),
                    Some(b'-') => (DiffTag::Del, &raw[1..]),
                    Some(b' ') => (DiffTag::Ctx, &raw[1..]),
                    _ => (DiffTag::Ctx, raw), // blank/other line — no marker to strip
                };
                match tag {
                    DiffTag::Add => f.adds += 1,
                    DiffTag::Del => f.dels += 1,
                    DiffTag::Ctx => {}
                }
                h.lines.push(DiffLine {
                    tag,
                    text: text.to_string(),
                });
                lines_seen += 1;
            }
        }
        if let Some(f) = cur.take() {
            files.push(f);
        }
        files.retain(|f| !f.hunks.is_empty() || !f.path.is_empty());
        files
    }
}
