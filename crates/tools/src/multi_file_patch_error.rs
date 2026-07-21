//! Structured, model-correctable failures for multi-file patch planning and commit.

#[derive(Debug)]
pub(crate) struct PatchFailure {
    kind: &'static str,
    phase: &'static str,
    file_index: Option<usize>,
    hunk_index: Option<usize>,
    conflicting_hunk_index: Option<usize>,
    nearest_line: Option<u32>,
    path: Option<Box<str>>,
    message: Box<str>,
}

impl PatchFailure {
    pub(crate) fn global(
        kind: &'static str,
        phase: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            phase,
            file_index: None,
            hunk_index: None,
            conflicting_hunk_index: None,
            nearest_line: None,
            path: None,
            message: message.into().into_boxed_str(),
        }
    }

    pub(crate) fn file(
        kind: &'static str,
        phase: &'static str,
        file_index: usize,
        path: &str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            phase,
            file_index: Some(file_index + 1),
            hunk_index: None,
            conflicting_hunk_index: None,
            nearest_line: None,
            path: Some(path.into()),
            message: message.into().into_boxed_str(),
        }
    }

    pub(crate) fn hunk(
        kind: &'static str,
        file_index: usize,
        hunk_index: usize,
        path: &str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            phase: "validate",
            file_index: Some(file_index + 1),
            hunk_index: Some(hunk_index + 1),
            conflicting_hunk_index: None,
            nearest_line: None,
            path: Some(path.into()),
            message: message.into().into_boxed_str(),
        }
    }

    pub(crate) fn anchor_not_found(
        file_index: usize,
        hunk_index: usize,
        path: &str,
        nearest_line: Option<usize>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind: "anchor_not_found",
            phase: "validate",
            file_index: Some(file_index + 1),
            hunk_index: Some(hunk_index + 1),
            conflicting_hunk_index: None,
            nearest_line: nearest_line.and_then(|line| u32::try_from(line).ok()),
            path: Some(path.into()),
            message: message.into().into_boxed_str(),
        }
    }

    pub(crate) fn conflict(
        file_index: usize,
        hunk_index: usize,
        conflicting_hunk_index: usize,
        path: &str,
    ) -> Self {
        Self {
            kind: "overlapping_hunks",
            phase: "validate",
            file_index: Some(file_index + 1),
            hunk_index: Some(hunk_index + 1),
            conflicting_hunk_index: Some(conflicting_hunk_index + 1),
            nearest_line: None,
            path: Some(path.into()),
            message: format!(
                "hunk {} overlaps hunk {} in the original file snapshot",
                hunk_index + 1,
                conflicting_hunk_index + 1
            )
            .into_boxed_str(),
        }
    }

    pub(crate) fn model_json(&self) -> String {
        serde_json::json!({
            "error": "multi_file_patch_failed",
            "kind": self.kind,
            "phase": self.phase,
            "file_index": self.file_index,
            "hunk_index": self.hunk_index,
            "conflicting_hunk_index": self.conflicting_hunk_index,
            "nearest_line": self.nearest_line,
            "path": self.path,
            "message": self.message,
        })
        .to_string()
    }
}
