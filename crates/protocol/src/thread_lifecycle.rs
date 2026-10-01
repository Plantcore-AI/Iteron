//! Workspace-scoped history controls. Thread creation/turn admission use their own contracts.

use crate::{RunId, SessionId};
use serde::{Deserialize, Serialize};

pub const THREAD_LIFECYCLE_VERSION: u32 = 1;
pub const MAX_THREAD_TITLE_BYTES: usize = 256;
pub const MAX_THREAD_EXPORT_BYTES: usize = 1024 * 1024;
pub const MAX_THREAD_RUN_ID_BYTES: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ThreadLifecycleCommandV1 {
    /// Operator-only repair of the trusted resident record index. No locator or metadata input.
    Reindex {
        thread_id: SessionId,
        run_id: RunId,
    },
    List {
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_page_size")]
        limit: u16,
    },
    Read {
        run_id: RunId,
    },
    Inspect {
        run_id: RunId,
    },
    TraceRead {
        run_id: RunId,
        #[serde(default)]
        after_seq: Option<u64>,
        #[serde(default = "default_page_size")]
        limit: u16,
    },
    Rename {
        run_id: RunId,
        title: String,
    },
    Archive {
        run_id: RunId,
        archived: bool,
    },
    Pin {
        run_id: RunId,
        pinned: bool,
    },
    Export {
        run_id: RunId,
    },
    /// Permanent erasure has no undo; archive is the reversible removal operation.
    Delete {
        run_id: RunId,
        confirm_permanent_erasure: bool,
    },
}

impl ThreadLifecycleCommandV1 {
    pub fn run_id(&self) -> Option<&RunId> {
        match self {
            Self::List { .. } => None,
            Self::Reindex { run_id, .. }
            | Self::Read { run_id }
            | Self::Inspect { run_id }
            | Self::TraceRead { run_id, .. }
            | Self::Rename { run_id, .. }
            | Self::Archive { run_id, .. }
            | Self::Pin { run_id, .. }
            | Self::Export { run_id }
            | Self::Delete { run_id, .. } => Some(run_id),
        }
    }

    pub fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::List { .. }
                | Self::Read { .. }
                | Self::Inspect { .. }
                | Self::TraceRead { .. }
                | Self::Export { .. }
        )
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if let Self::List { cursor, limit } = self {
            return if (1..=100).contains(limit)
                && cursor.as_ref().is_none_or(|cursor| cursor.len() <= 1024)
            {
                Ok(())
            } else {
                Err("thread list page or cursor exceeds its bound")
            };
        }
        let run = &self
            .run_id()
            .expect("non-list commands contain an exact identity")
            .0;
        if run.is_empty()
            || run.len() > MAX_THREAD_RUN_ID_BYTES
            || run.chars().any(char::is_control)
            || run.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
            || matches!(run.as_str(), "." | "..")
            || run.ends_with(['.', ' '])
        {
            return Err("invalid run identity");
        }
        if let Self::Reindex { thread_id, .. } = self
            && (thread_id.0.is_empty()
                || thread_id.0.len() > 256
                || thread_id.0.chars().any(char::is_control))
        {
            return Err("invalid resident thread identity");
        }
        if let Self::Rename { title, .. } = self
            && (title.trim().is_empty()
                || title.len() > MAX_THREAD_TITLE_BYTES
                || title.chars().any(char::is_control))
        {
            return Err("title must be bounded visible text");
        }
        if let Self::TraceRead { limit, .. } = self
            && !(1..=64).contains(limit)
        {
            return Err("trace page exceeds its bound");
        }
        if let Self::Delete {
            confirm_permanent_erasure,
            ..
        } = self
            && !confirm_permanent_erasure
        {
            return Err(
                "permanent erasure requires explicit confirmation; use archive for reversible removal",
            );
        }
        Ok(())
    }
}

fn default_page_size() -> u16 {
    25
}

#[cfg(test)]
mod repair_tests {
    use super::*;
    #[test]
    fn repair_is_operator_only_and_accepts_no_authority_fields() {
        let command: ThreadLifecycleCommandV1 = serde_json::from_str(
            r#"{"type":"reindex","thread_id":"session-selected","run_id":"selected"}"#,
        )
        .unwrap();
        assert!(command.validate().is_ok());
        assert!(!command.is_read_only());
        assert_eq!(command.run_id().unwrap().0, "selected");
        for field in ["path", "tenant", "workspace", "metadata", "config"] {
            assert!(
                serde_json::from_value::<ThreadLifecycleCommandV1>(
                    serde_json::json!({"type":"reindex","thread_id":"session-selected","run_id":"selected",(field):"untrusted"})
                )
                .is_err()
            );
        }
        assert!(
            ThreadLifecycleCommandV1::List {
                cursor: None,
                limit: 25
            }
            .is_read_only()
        );
    }
}
