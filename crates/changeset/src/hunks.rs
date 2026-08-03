//! Unified-diff parsing, with the header believed only after it has been checked.
//!
//! Hunk-level review is what lets an agent revert one change without reverting the others in the
//! same file. That only works if a hunk is trustworthy, and the failure mode here is quiet: a hunk
//! header declares how many lines it covers, and nothing in the format forces the body to agree.
//! A hunk whose body disagrees with its header still *looks* like a diff -- it applies at the wrong
//! offset, or silently drops a line, and the corruption surfaces later somewhere else.
//!
//! So every hunk's declared line counts are verified against its actual body here, and a mismatch
//! is a typed refusal rather than a best-effort parse. Everything else in this module exists to
//! make that check meaningful: binary and rename entries carry no line counts and must not be
//! mistaken for empty text diffs.

use crate::MAX_ENTRIES;

/// Ceilings. A diff is produced by git but reaches this parser as bytes, and a review surface that
/// can be made to allocate without limit is a denial-of-service on the agent reading it.
pub const MAX_DIFF_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_HUNKS_PER_FILE: usize = 2_000;
pub const MAX_BODY_LINES_PER_HUNK: usize = 100_000;
pub const MAX_LINE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiffError {
    #[error("hunk header {header:?} is malformed")]
    BadHeader { header: String },
    #[error("hunk {header:?} declares {declared} old lines but its body carries {actual}")]
    OldCountMismatch {
        header: String,
        declared: u32,
        actual: u32,
    },
    #[error("hunk {header:?} declares {declared} new lines but its body carries {actual}")]
    NewCountMismatch {
        header: String,
        declared: u32,
        actual: u32,
    },
    #[error("diff carries more than {limit} file entries")]
    TooManyFiles { limit: usize },
    #[error("diff is {len} bytes, over the {MAX_DIFF_BYTES}-byte ceiling")]
    DiffTooLarge { len: usize },
    #[error("file {path:?} carries more than {MAX_HUNKS_PER_FILE} hunks")]
    TooManyHunks { path: String },
    #[error("hunk {header:?} carries more than {MAX_BODY_LINES_PER_HUNK} body lines")]
    TooManyBodyLines { header: String },
    #[error("a diff line is {len} bytes, over the {MAX_LINE_BYTES}-byte ceiling")]
    LineTooLong { len: usize },
    #[error("path {raw:?} is git-quoted; a lossless source is required to parse it safely")]
    QuotedPath { raw: String },
}

/// What a file entry in a diff actually is. A binary change and a pure rename are real changes with
/// no line content, and treating either as a text diff with zero hunks would report "no changes".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileChange {
    Text {
        hunks: Vec<Hunk>,
    },
    Binary,
    /// Renamed or copied with no content change.
    RenameOnly,
    /// Only the file mode changed (e.g. chmod +x). Its own variant because reporting it as
    /// `Text { hunks: [] }` reads as "nothing changed" -- the same lie as a binary change with no
    /// hunks, and the reason `hunk_count()` returns `None` here too.
    ModeOnly {
        from: String,
        to: String,
    },
}

/// How a path came to exist, kept **independently of whether the content also changed**.
///
/// Folding this into a `RenameOnly` variant lost it exactly when it mattered: a rename that also
/// edits the file is the case a reviewer most needs to see as one change rather than as an
/// unrelated delete and add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub from: String,
    pub copied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDiff {
    pub path: String,
    /// Present for renames and copies, whether or not the content also changed.
    pub origin: Option<Origin>,
    pub change: FileChange,
}

impl FileDiff {
    /// A hunk count for display. Binary and rename-only entries report `None` rather than `0`,
    /// because "no hunks" and "not expressible as hunks" are different facts.
    pub fn hunk_count(&self) -> Option<usize> {
        match &self.change {
            FileChange::Text { hunks } => Some(hunks.len()),
            _ => None,
        }
    }

    /// True when this entry represents a real change of some kind. Every variant does -- the
    /// method exists so a caller cannot conclude "no hunks" means "no change".
    pub fn is_change(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    pub header: String,
    pub old_start: u32,
    pub old_lines: u32,
    pub new_start: u32,
    pub new_lines: u32,
    /// Body lines including their leading ' ', '+' or '-'.
    pub body: Vec<String>,
}

impl Hunk {
    pub fn added(&self) -> usize {
        self.body.iter().filter(|l| l.starts_with('+')).count()
    }

    pub fn removed(&self) -> usize {
        self.body.iter().filter(|l| l.starts_with('-')).count()
    }
}

/// Parse `@@ -old_start[,old_lines] +new_start[,new_lines] @@ [section]`.
///
/// The counts are optional in the format and default to 1 when omitted -- a single-line hunk is
/// written `@@ -3 +3 @@`. Defaulting them to 0 instead is the classic bug: every single-line hunk
/// then fails verification, or worse, passes a check that was comparing 0 to 0.
fn parse_header(line: &str) -> Option<(u32, u32, u32, u32)> {
    let rest = line.strip_prefix("@@ ")?;
    let end = rest.find(" @@")?;
    let (ranges, _) = rest.split_at(end);
    let (old, new) = ranges.split_once(' ')?;
    let old = old.strip_prefix('-')?;
    let new = new.strip_prefix('+')?;

    fn range(spec: &str) -> Option<(u32, u32)> {
        match spec.split_once(',') {
            Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
            None => Some((spec.parse().ok()?, 1)),
        }
    }
    let (os, ol) = range(old)?;
    let (ns, nl) = range(new)?;
    Some((os, ol, ns, nl))
}

/// Parse a unified diff into per-file entries, verifying every hunk against its own header.
///
/// `limit` is clamped to `MAX_ENTRIES`: a caller passing `usize::MAX` must not be able to opt out
/// of the bound, because the bound exists to protect the process, not the caller.
#[allow(
    unused_assignments,
    reason = "flush! is invoked mid-loop, where resetting per-file state is load-bearing, and once \
              after the loop, where the same reset is dead. Splitting it into two macros to satisfy \
              the lint would duplicate the entry-construction logic, which is the part worth having \
              in exactly one place."
)]
pub fn parse_unified(diff: &str, limit: usize) -> Result<Vec<FileDiff>, DiffError> {
    if diff.len() > MAX_DIFF_BYTES {
        return Err(DiffError::DiffTooLarge { len: diff.len() });
    }
    let limit = limit.min(MAX_ENTRIES);

    let mut files: Vec<FileDiff> = Vec::new();
    let mut path: Option<String> = None;
    let mut origin: Option<Origin> = None;
    let mut mode: Option<(String, String)> = None;
    let mut binary = false;
    let mut hunks: Vec<Hunk> = Vec::new();
    let mut current: Option<Hunk> = None;

    macro_rules! flush {
        () => {{
            if let Some(h) = current.take() {
                verify(&h)?;
                hunks.push(h);
            }
            if let Some(p) = path.take() {
                let change = if binary {
                    FileChange::Binary
                } else if !hunks.is_empty() {
                    FileChange::Text {
                        hunks: std::mem::take(&mut hunks),
                    }
                } else if let Some((from, to)) = mode.take() {
                    FileChange::ModeOnly { from, to }
                } else if origin.is_some() {
                    FileChange::RenameOnly
                } else {
                    FileChange::Text { hunks: Vec::new() }
                };
                files.push(FileDiff {
                    path: p,
                    origin: origin.take(),
                    change,
                });
                if files.len() > limit {
                    return Err(DiffError::TooManyFiles { limit });
                }
            }
            hunks.clear();
            // `origin` and `mode` were already cleared by `.take()` above; only this needs it.
            binary = false;
        }};
    }

    for line in diff.lines() {
        if line.len() > MAX_LINE_BYTES {
            return Err(DiffError::LineTooLong { len: line.len() });
        }
        if let Some(rest) = line.strip_prefix("diff --git ") {
            flush!();
            path = Some(parse_git_header_path(rest)?);
            continue;
        }
        if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            binary = true;
            continue;
        }
        if let Some(from) = line.strip_prefix("rename from ") {
            origin = Some(Origin {
                from: unquoted(from)?,
                copied: false,
            });
            continue;
        }
        if let Some(from) = line.strip_prefix("copy from ") {
            origin = Some(Origin {
                from: unquoted(from)?,
                copied: true,
            });
            continue;
        }
        if let Some(m) = line.strip_prefix("old mode ") {
            mode = Some((m.trim().to_owned(), String::new()));
            continue;
        }
        if let Some(m) = line.strip_prefix("new mode ")
            && let Some((from, _)) = mode.take()
        {
            mode = Some((from, m.trim().to_owned()));
            continue;
        }
        if line.starts_with("@@ ") {
            if let Some(h) = current.take() {
                verify(&h)?;
                hunks.push(h);
            }
            if hunks.len() >= MAX_HUNKS_PER_FILE {
                return Err(DiffError::TooManyHunks {
                    path: path.clone().unwrap_or_default(),
                });
            }
            let (os, ol, ns, nl) = parse_header(line).ok_or_else(|| DiffError::BadHeader {
                header: line.to_owned(),
            })?;
            current = Some(Hunk {
                header: line.to_owned(),
                old_start: os,
                old_lines: ol,
                new_start: ns,
                new_lines: nl,
                body: Vec::new(),
            });
            continue;
        }
        if let Some(h) = current.as_mut() {
            // `\ No newline at end of file` annotates the previous line and is not content. Body
            // lines always carry a ' ', '+' or '-' prefix, so a line starting with a backslash can
            // only be that marker.
            if line.starts_with('\\') {
                continue;
            }
            if line.starts_with(' ') || line.starts_with('+') || line.starts_with('-') {
                if h.body.len() >= MAX_BODY_LINES_PER_HUNK {
                    return Err(DiffError::TooManyBodyLines {
                        header: h.header.clone(),
                    });
                }
                h.body.push(line.to_owned());
            }
        }
    }
    flush!();
    Ok(files)
}

/// Extract the b-side path from a `diff --git a/x b/x` header.
///
/// Git quotes a path containing a space, quote, newline or non-UTF-8 byte as a C-style string.
/// Such a header cannot be split reliably on `" b/"`, so it is refused rather than mis-parsed --
/// guessing here silently attributes hunks to the wrong file, which is worse than declining.
fn parse_git_header_path(rest: &str) -> Result<String, DiffError> {
    if rest.starts_with('"') || rest.contains(" \"") {
        return Err(DiffError::QuotedPath {
            raw: rest.to_owned(),
        });
    }
    Ok(rest
        .split_once(" b/")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_else(|| rest.to_owned()))
}

fn unquoted(value: &str) -> Result<String, DiffError> {
    if value.starts_with('"') {
        return Err(DiffError::QuotedPath {
            raw: value.to_owned(),
        });
    }
    Ok(value.to_owned())
}

/// Check a hunk's body against the counts its own header declared.
fn verify(h: &Hunk) -> Result<(), DiffError> {
    let old = h
        .body
        .iter()
        .filter(|l| l.starts_with(' ') || l.starts_with('-'))
        .count() as u32;
    let new = h
        .body
        .iter()
        .filter(|l| l.starts_with(' ') || l.starts_with('+'))
        .count() as u32;
    if old != h.old_lines {
        return Err(DiffError::OldCountMismatch {
            header: h.header.clone(),
            declared: h.old_lines,
            actual: old,
        });
    }
    if new != h.new_lines {
        return Err(DiffError::NewCountMismatch {
            header: h.header.clone(),
            declared: h.new_lines,
            actual: new,
        });
    }
    Ok(())
}

pub fn parse_unified_default(diff: &str) -> Result<Vec<FileDiff>, DiffError> {
    parse_unified(diff, MAX_ENTRIES)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,3 +1,4 @@
 fn main() {
-    old();
+    new();
+    extra();
 }
";

    #[test]
    fn a_hunk_body_is_verified_against_its_declared_counts() {
        let files = parse_unified_default(SIMPLE).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/a.rs");
        let hunks = match &files[0].change {
            FileChange::Text { hunks } => hunks,
            other => panic!("expected text, got {other:?}"),
        };
        assert_eq!(hunks.len(), 1);
        assert_eq!((hunks[0].added(), hunks[0].removed()), (2, 1));
    }

    #[test]
    fn a_header_that_lies_about_its_line_counts_is_refused() {
        // The quiet corruption this prevents: nothing in the format forces the body to match the
        // header, and a mismatched hunk applies at the wrong offset instead of failing.
        let lying = SIMPLE.replace("@@ -1,3 +1,4 @@", "@@ -1,9 +1,4 @@");
        assert_eq!(
            parse_unified_default(&lying),
            Err(DiffError::OldCountMismatch {
                header: "@@ -1,9 +1,4 @@".into(),
                declared: 9,
                actual: 3,
            })
        );
    }

    #[test]
    fn a_new_side_mismatch_is_refused_too() {
        let lying = SIMPLE.replace("@@ -1,3 +1,4 @@", "@@ -1,3 +1,9 @@");
        assert!(matches!(
            parse_unified_default(&lying),
            Err(DiffError::NewCountMismatch { declared: 9, .. })
        ));
    }

    #[test]
    fn an_omitted_count_means_one_not_zero() {
        // `@@ -3 +3 @@` is a legal single-line hunk. Defaulting the count to 0 makes every one of
        // these fail verification.
        let diff = "\
diff --git a/x b/x
@@ -3 +3 @@
-a
+b
";
        let files = parse_unified_default(diff).unwrap();
        let FileChange::Text { hunks } = &files[0].change else {
            panic!("expected text")
        };
        assert_eq!((hunks[0].old_lines, hunks[0].new_lines), (1, 1));
    }

    #[test]
    fn a_no_newline_marker_is_not_counted_as_content() {
        let diff = "\
diff --git a/x b/x
@@ -1 +1 @@
-a
\\ No newline at end of file
+b
";
        assert!(parse_unified_default(diff).is_ok());
    }

    #[test]
    fn a_binary_change_is_not_an_empty_text_diff() {
        // Reporting this as `Text { hunks: [] }` would read as "nothing changed".
        let diff = "\
diff --git a/img.png b/img.png
Binary files a/img.png and b/img.png differ
";
        let files = parse_unified_default(diff).unwrap();
        assert_eq!(files[0].change, FileChange::Binary);
        assert_eq!(files[0].hunk_count(), None, "not zero -- inexpressible");
    }

    #[test]
    fn a_pure_rename_is_distinguished_from_a_file_with_no_hunks() {
        let diff = "\
diff --git a/old.rs b/new.rs
similarity index 100%
rename from old.rs
rename to new.rs
";
        let files = parse_unified_default(diff).unwrap();
        assert_eq!(files[0].change, FileChange::RenameOnly);
        assert_eq!(files[0].origin.as_ref().unwrap().from, "old.rs");
        assert_eq!(files[0].hunk_count(), None);
    }

    #[test]
    fn a_rename_that_also_edits_keeps_its_provenance() {
        // Previously folded into a `RenameOnly` variant, so provenance was lost exactly when it
        // mattered: a reviewer needs this as one change, not an unrelated delete plus add.
        let diff = "\
diff --git a/old.rs b/new.rs
similarity index 88%
rename from old.rs
rename to new.rs
@@ -1,2 +1,2 @@
-a
+b
 c
";
        let files = parse_unified_default(diff).unwrap();
        assert_eq!(files[0].path, "new.rs");
        assert_eq!(files[0].origin.as_ref().unwrap().from, "old.rs");
        assert!(!files[0].origin.as_ref().unwrap().copied);
        assert_eq!(files[0].hunk_count(), Some(1), "content change kept too");
    }

    #[test]
    fn a_copy_is_distinguished_from_a_rename() {
        let diff = "\
diff --git a/src.rs b/dst.rs
copy from src.rs
copy to dst.rs
";
        let files = parse_unified_default(diff).unwrap();
        assert!(files[0].origin.as_ref().unwrap().copied);
    }

    #[test]
    fn a_mode_only_change_is_not_an_empty_text_diff() {
        // chmod +x with no content change. `Text { hunks: [] }` would read as "nothing changed" --
        // the same lie as a binary change with no hunks.
        let diff = "\
diff --git a/run.sh b/run.sh
old mode 100644
new mode 100755
";
        let files = parse_unified_default(diff).unwrap();
        assert_eq!(
            files[0].change,
            FileChange::ModeOnly {
                from: "100644".into(),
                to: "100755".into()
            }
        );
        assert_eq!(files[0].hunk_count(), None, "not Some(0)");
    }

    #[test]
    fn a_git_quoted_path_is_refused_rather_than_mis_split() {
        // Git quotes paths containing a space, quote or newline. Splitting such a header on " b/"
        // silently attributes hunks to the wrong file, which is worse than declining.
        let diff = "diff --git \"a/we ird.rs\" \"b/we ird.rs\"\n@@ -1 +1 @@\n-a\n+b\n";
        assert!(matches!(
            parse_unified_default(diff),
            Err(DiffError::QuotedPath { .. })
        ));
    }

    #[test]
    fn an_arbitrary_limit_cannot_opt_out_of_the_bound() {
        // The ceiling protects the process, not the caller, so `usize::MAX` is clamped.
        let mut diff = String::new();
        for i in 0..(MAX_ENTRIES + 5) {
            diff.push_str(&format!(
                "diff --git a/f{i} b/f{i}\nBinary files a/f{i} and b/f{i} differ\n"
            ));
        }
        assert!(matches!(
            parse_unified(&diff, usize::MAX),
            Err(DiffError::TooManyFiles { .. })
        ));
    }

    #[test]
    fn an_oversized_diff_is_refused_before_parsing() {
        let huge = "x".repeat(MAX_DIFF_BYTES + 1);
        assert!(matches!(
            parse_unified_default(&huge),
            Err(DiffError::DiffTooLarge { .. })
        ));
    }

    #[test]
    fn an_overlong_line_is_refused() {
        let diff = format!("diff --git a/x b/x\n{}\n", "y".repeat(MAX_LINE_BYTES + 1));
        assert!(matches!(
            parse_unified_default(&diff),
            Err(DiffError::LineTooLong { .. })
        ));
    }

    #[test]
    fn several_files_and_several_hunks_are_kept_separate() {
        let diff = format!(
            "{SIMPLE}\
diff --git a/src/b.rs b/src/b.rs
@@ -10,2 +10,2 @@
-x
+y
 z
@@ -20 +20 @@
-p
+q
"
        );
        let files = parse_unified_default(&diff).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[1].path, "src/b.rs");
        assert_eq!(files[1].hunk_count(), Some(2));
    }

    #[test]
    fn a_malformed_header_is_refused_rather_than_skipped() {
        let diff = "diff --git a/x b/x\n@@ not-a-range @@\n-a\n+b\n";
        assert!(matches!(
            parse_unified_default(diff),
            Err(DiffError::BadHeader { .. })
        ));
    }

    #[test]
    fn the_file_count_is_bounded() {
        let mut diff = String::new();
        for i in 0..5 {
            diff.push_str(&format!(
                "diff --git a/f{i} b/f{i}\nBinary files a/f{i} and b/f{i} differ\n"
            ));
        }
        assert_eq!(
            parse_unified(&diff, 2),
            Err(DiffError::TooManyFiles { limit: 2 })
        );
    }

    #[test]
    fn an_empty_diff_is_no_files_not_an_error() {
        assert_eq!(parse_unified_default(""), Ok(Vec::new()));
    }
}
