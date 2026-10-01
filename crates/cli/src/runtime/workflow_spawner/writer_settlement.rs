//! Isolated writer settlement over actual worktree phases and immutable host configuration.

use iteron_protocol::ActivityDetailCode;
use iteron_workflow::AgentOutcome;

use super::worktree::{WriterSettlementProof, WriterWorktree};
use crate::runtime::turn_activity::{ActivitySink, ActivityStage};

pub(super) struct NativeWriterSettlement<'a> {
    pub(super) activity: &'a ActivitySink,
    pub(super) command: Option<&'a str>,
    pub(super) sensitive_env_names: &'a [String],
    pub(super) output_tail_bytes: usize,
}

impl NativeWriterSettlement<'_> {
    pub(super) async fn run(
        &self,
        worktree: &mut WriterWorktree,
        child_done: bool,
        result: &mut AgentOutcome,
    ) -> WriterSettlementProof {
        if !child_done || !matches!(result, AgentOutcome::Text { .. }) {
            self.discard(worktree, result).await;
            return worktree.settlement_proof();
        }
        let preparing = self.activity.span(ActivityStage::PreparingPatch, None);
        let receipt = match worktree.prepare_patch().await {
            Ok(receipt) => receipt,
            Err(error) => {
                preparing.fail(ActivityDetailCode::Checkpoint);
                *result = AgentOutcome::null(error.public_summary());
                self.discard(worktree, result).await;
                return worktree.settlement_proof();
            }
        };
        preparing.complete();
        if receipt.patch_bytes == 0 {
            self.discard(worktree, result).await;
            if let AgentOutcome::Text {
                last_tool_summary, ..
            } = result
            {
                *last_tool_summary = Some("isolated writer produced no patch".into());
            }
            return worktree.settlement_proof();
        }
        let verification = self.activity.span(ActivityStage::HostVerification, None);
        if let Err(error) = worktree
            .verify(
                &receipt,
                self.command,
                self.sensitive_env_names,
                self.output_tail_bytes,
            )
            .await
        {
            verification.fail(ActivityDetailCode::Verification);
            *result = AgentOutcome::null(error.public_summary());
            self.discard(worktree, result).await;
            return worktree.settlement_proof();
        }
        verification.complete();
        let merging = self.activity.span(ActivityStage::Merging, None);
        match worktree.merge(&receipt).await {
            Ok(()) => {
                merging.complete();
                if let AgentOutcome::Text {
                    last_tool_summary, ..
                } = result
                {
                    *last_tool_summary = Some(format!(
                        "verified + merged isolated patch · {} bytes · {}",
                        receipt.patch_bytes,
                        receipt
                            .patch_digest_sha256
                            .as_deref()
                            .unwrap_or("sha256:unknown")
                    ));
                }
            }
            Err(error) => {
                merging.fail(ActivityDetailCode::RecordCommit);
                *result = AgentOutcome::null(error.public_summary());
                self.discard(worktree, result).await;
            }
        }
        worktree.settlement_proof()
    }

    async fn discard(&self, worktree: &mut WriterWorktree, result: &mut AgentOutcome) {
        let discarding = self.activity.span(ActivityStage::Discarding, None);
        match worktree.discard().await {
            Ok(()) => discarding.complete(),
            Err(error) => {
                discarding.fail(ActivityDetailCode::WorkflowResultPersist);
                *result = AgentOutcome::null(error.public_summary());
            }
        }
    }
}

#[cfg(all(test, unix))]
#[path = "writer_settlement_tests.rs"]
mod tests;
