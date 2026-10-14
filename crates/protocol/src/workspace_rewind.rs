//! Operator workspace restore targets retain the verified physical journal identity.
use crate::{RunId, Seq, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewindScopeV1 {
    CodeAndConversation,
    CodeOnly,
    ConversationOnly,
}
impl RewindScopeV1 {
    pub fn touches_files(self) -> bool {
        self != Self::ConversationOnly
    }
    pub fn touches_conversation(self) -> bool {
        self != Self::CodeOnly
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewindUnrecordedV1 {
    Keep,
    Delete,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewindTargetV1 {
    pub run_id: RunId,
    pub seq: Seq,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkspaceRewindCommandV1 {
    List {
        thread_id: SessionId,
        run_id: RunId,
    },
    Preview {
        thread_id: SessionId,
        run_id: RunId,
        target: RewindTargetV1,
        scope: RewindScopeV1,
        unrecorded: RewindUnrecordedV1,
    },
    Apply {
        thread_id: SessionId,
        run_id: RunId,
        target: RewindTargetV1,
        scope: RewindScopeV1,
        unrecorded: RewindUnrecordedV1,
    },
}
impl WorkspaceRewindCommandV1 {
    pub fn thread_id(&self) -> &SessionId {
        match self {
            Self::List { thread_id, .. }
            | Self::Preview { thread_id, .. }
            | Self::Apply { thread_id, .. } => thread_id,
        }
    }
    pub fn run_id(&self) -> &RunId {
        match self {
            Self::List { run_id, .. }
            | Self::Preview { run_id, .. }
            | Self::Apply { run_id, .. } => run_id,
        }
    }
    pub fn is_read_only(&self) -> bool {
        !matches!(self, Self::Apply { .. })
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.thread_id().0.is_empty()
            || self.thread_id().0.len() > 256
            || self.thread_id().0.chars().any(char::is_control)
            || self.run_id().0.is_empty()
            || self.run_id().0.len() > 200
        {
            return Err("invalid rewind scope identity");
        }
        crate::session_navigation::SessionNavigationV1::Fork {
            thread_id: self.thread_id().clone(),
            run_id: self.run_id().clone(),
            through_seq: None,
        }
        .validate()?;
        if let Self::Preview { target, .. } | Self::Apply { target, .. } = self {
            if target.run_id.0.is_empty() || target.run_id.0.len() > 200 {
                return Err("invalid rewind target identity");
            }
            crate::thread_lifecycle::ThreadLifecycleCommandV1::Read {
                run_id: target.run_id.clone(),
            }
            .validate()?;
            if target.seq.0 == 0 {
                return Err("rewind requires a verified positive physical sequence");
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewindPointV1 {
    pub target: RewindTargetV1,
    pub turn: u32,
    pub file_checkpoint: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewindPreviewV1 {
    pub target: RewindTargetV1,
    pub checkpoint: Option<RewindTargetV1>,
    pub scope: RewindScopeV1,
    pub unrecorded: RewindUnrecordedV1,
    pub conclusive: bool,
    pub overlay: bool,
    pub overwritten_paths: usize,
    pub deleted_paths: usize,
    pub preserved_unrecorded_paths: usize,
    pub path_display: Vec<String>,
    pub omitted_paths: usize,
    pub protected_runtime_state: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewindFilesV1 {
    NotRequested,
    Restored,
    RolledBack,
    NotStarted,
    ReconciliationNeeded,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewindExecutionV1 {
    pub files: RewindFilesV1,
    /// Real current-run durable receipts, independent of the selected/ancestor target sequence.
    pub intent_seq: Option<Seq>,
    pub safety_checkpoint_seq: Option<Seq>,
    pub terminal_seq: Option<Seq>,
    pub retained_child_run: Option<RunId>,
    pub conversation_adopted: bool,
    pub reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRewindReplyV1 {
    pub version: u32,
    pub thread_id: SessionId,
    pub origin_run_id: RunId,
    pub points: Vec<RewindPointV1>,
    pub omitted_points: usize,
    pub preview: Option<RewindPreviewV1>,
    pub execution: Option<RewindExecutionV1>,
}

#[cfg(test)]
mod tests {
    use super::WorkspaceRewindCommandV1;
    use serde_json::json;
    #[test]
    fn clients_supply_only_scoped_targets_and_cannot_claim_authority_or_results() {
        let base = json!({"action":"apply","thread_id":"t","run_id":"r","target":{"run_id":"ancestor","seq":3},"scope":"conversation_only","unrecorded":"keep"});
        assert!(
            serde_json::from_value::<WorkspaceRewindCommandV1>(base.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        for name in [
            "workspace",
            "path",
            "tenant",
            "actor",
            "effects_known",
            "approved",
            "tree_ref",
            "terminal_seq",
        ] {
            let mut forged = base.clone();
            forged[name] = json!(true);
            assert!(
                serde_json::from_value::<WorkspaceRewindCommandV1>(forged).is_err(),
                "{name}"
            );
        }
        let mut invalid = base;
        invalid["target"]["run_id"] = json!("../other");
        assert!(
            serde_json::from_value::<WorkspaceRewindCommandV1>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
