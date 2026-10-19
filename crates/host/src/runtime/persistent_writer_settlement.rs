//! Resident writer physical cleanup and controller workspace evidence settlement.

use std::path::PathBuf;
use std::sync::Arc;

use super::persistent_agents::AgentControlPort;
use super::workflow_spawner::worktree::persistent::PersistentWriterWorktree;
use super::workflow_spawner::worktree::{MergeFailure, WriterSettlementProof};

pub(super) struct PersistentWriterConfig {
    pub(super) parent: PathBuf,
    pub(super) state: PathBuf,
    pub(super) lock: Arc<tokio::sync::Mutex<()>>,
    pub(super) verify: Option<String>,
    pub(super) env: Vec<String>,
    pub(super) oracle_tail: usize,
    pub(super) admitted: bool,
}

pub(super) struct WriterTerminal {
    pub(super) proof: WriterSettlementProof,
    pub(super) failure: Option<String>,
}

pub(super) struct PersistentWriterSettlement<'a> {
    pub(super) config: &'a PersistentWriterConfig,
    pub(super) control: Option<Arc<dyn AgentControlPort>>,
}

impl PersistentWriterSettlement<'_> {
    pub(super) async fn run(
        &self,
        worktree: &mut PersistentWriterWorktree,
        completed: bool,
    ) -> WriterTerminal {
        if !completed {
            return self.discard(worktree, None).await;
        }
        let receipt = match worktree.prepare_patch().await {
            Ok(receipt) => receipt,
            Err(error) => return self.discard(worktree, Some(error)).await,
        };
        if receipt.patch_bytes == 0 {
            return self.discard(worktree, None).await;
        }
        if let Err(error) = worktree
            .verify(
                &receipt,
                self.config.verify.as_deref(),
                &self.config.env,
                self.config.oracle_tail,
            )
            .await
        {
            return self.discard(worktree, Some(error)).await;
        }
        let Some(control) = self.control.as_ref() else {
            return self
                .unavailable(worktree, "writer controller is unavailable")
                .await;
        };
        let witness = match control.workspace_witness() {
            Ok(Some(witness)) => witness,
            _ => {
                return self
                    .unavailable(worktree, "writer workspace evidence is unavailable")
                    .await;
            }
        };
        let next = match worktree
            .merge(&receipt, witness.clone(), self.config.state.clone())
            .await
        {
            Ok(next) => next,
            Err(error) => return self.discard(worktree, Some(error)).await,
        };
        // Native apply and cleanup are already observed. A failed durable witness still closes
        // future writer admission; neither a model summary nor a later discard repairs that CAS.
        if control
            .record_workspace_witness(Some(&witness), next)
            .is_err()
        {
            return WriterTerminal {
                proof: WriterSettlementProof::Unknown,
                failure: Some("writer workspace publication requires reconciliation".into()),
            };
        }
        worktree.confirm_workspace_witness();
        WriterTerminal {
            proof: worktree.settlement_proof(),
            failure: None,
        }
    }

    async fn unavailable(
        &self,
        worktree: &mut PersistentWriterWorktree,
        reason: &str,
    ) -> WriterTerminal {
        let mut terminal = self.discard(worktree, None).await;
        terminal.failure = Some(reason.to_owned());
        terminal
    }

    async fn discard(
        &self,
        worktree: &mut PersistentWriterWorktree,
        failure: Option<MergeFailure>,
    ) -> WriterTerminal {
        let mut failure = failure.map(|error| error.public_summary());
        if let Err(error) = worktree.discard().await {
            failure = Some(error.public_summary());
        }
        WriterTerminal {
            proof: worktree.settlement_proof(),
            failure,
        }
    }
}
