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
}

/// What a file entry in a diff actually is. A binary change and a pure rename are real changes with
/// no line content, and treating either as a text diff with zero hunks would report "no changes".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileChange {
    Text {
        hunks: Vec<Hunk>,
    },
    Binary,
    /// Rename or copy with no content change.
    RenameOnly {
        from: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDiff {
    pub path: String,
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
pub fn parse_unified(diff: &str, limit: usize) -> Result<Vec<FileDiff>, DiffError> {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut path: Option<String> = None;
    let mut rename_from: Option<String> = None;
    let mut binary = false;
    let mut hunks: Vec<Hunk> = Vec::new();
    let mut current: Option<Hunk> = None;

    fn flush(
        files: &mut Vec<FileDiff>,
        path: &mut Option<String>,
        rename_from: &mut Option<String>,
        binary: &mut bool,
        hunks: &mut Vec<Hunk>,
        current: &mut Option<Hunk>,
    ) -> Result<(), DiffError> {
        if let Some(h) = current.take() {
            verify(&h)?;
            hunks.push(h);
        }
        if let Some(p) = path.take() {
            let change = if *binary {
                FileChange::Binary
            } else if hunks.is_empty() && rename_from.is_some() {
                FileChange::RenameOnly {
                    from: rename_from.clone().unwrap(),
                }
            } else {
                FileChange::Text {
                    hunks: std::mem::take(hunks),
                }
            };
            files.push(FileDiff { path: p, change });
        }
        hunks.clear();
        *binary = false;
        *rename_from = None;
        Ok(())
    }

    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            flush(
                &mut files,
                &mut path,
                &mut rename_from,
                &mut binary,
                &mut hunks,
                &mut current,
            )?;
            if files.len() > limit {
                return Err(DiffError::TooManyFiles { limit });
            }
            // `a/<path> b/<path>`; take the b-side, which is the current name.
            path = rest
                .split_once(" b/")
                .map(|(_, b)| b.to_owned())
                .or_else(|| Some(rest.to_owned()));
            continue;
        }
        if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            binary = true;
            continue;
        }
        if let Some(from) = line.strip_prefix("rename from ") {
            rename_from = Some(from.to_owned());
            continue;
        }
        if line.starts_with("@@ ") {
            if let Some(h) = current.take() {
                verify(&h)?;
                hunks.push(h);
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
            // "\ No newline at end of file" annotates the previous line and is not itself content.
            if line.starts_with('\\') {
                continue;
            }
            if line.starts_with(' ') || line.starts_with('+') || line.starts_with('-') {
                h.body.push(line.to_owned());
            }
        }
    }
    flush(
        &mut files,
        &mut path,
        &mut rename_from,
        &mut binary,
        &mut hunks,
        &mut current,
    )?;
    if files.len() > limit {
        return Err(DiffError::TooManyFiles { limit });
    }
    Ok(files)
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
        assert_eq!(
            files[0].change,
            FileChange::RenameOnly {
                from: "old.rs".into()
            }
        );
        assert_eq!(files[0].hunk_count(), None);
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
