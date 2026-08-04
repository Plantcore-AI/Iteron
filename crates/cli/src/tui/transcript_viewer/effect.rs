//! Revision-bound clipboard and export requests emitted by the transcript viewer.

use super::Viewer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportScope {
    Filtered,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    Copy {
        text: String,
        subject: &'static str,
        snapshot_revision: u64,
    },
    Export {
        scope: ExportScope,
        snapshot_revision: u64,
    },
}

impl Effect {
    pub(crate) fn snapshot_revision(&self) -> u64 {
        match self {
            Self::Copy {
                snapshot_revision, ..
            }
            | Self::Export {
                snapshot_revision, ..
            } => *snapshot_revision,
        }
    }
}

impl Viewer {
    pub(crate) fn export_ids(
        &self,
        scope: ExportScope,
        snapshot_revision: u64,
    ) -> Result<Option<Vec<u64>>, String> {
        if self.work_pending() {
            return Err("transcript index is updating; export snapshot is not ready".into());
        }
        if self.authority_revision != Some(snapshot_revision) {
            return Err("transcript changed before the export snapshot was captured".into());
        }
        match scope {
            ExportScope::All => Ok(None),
            ExportScope::Filtered if self.query.is_empty() => Ok(None),
            ExportScope::Filtered if self.incomplete_entries > 0 => Err(format!(
                "filtered export refused: search is incomplete for {} blocks",
                self.incomplete_entries
            )),
            ExportScope::Filtered if self.results_truncated => {
                Err("filtered export refused: matching results exceed the 512-result cap".into())
            }
            ExportScope::Filtered => Ok(Some(self.results.clone())),
        }
    }
}
