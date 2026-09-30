//! Operator restore admission and physical journal receipts. Native filesystem work never gets
//! Agent, policy, a record writer, or the ability to publish its own durable terminal.
use super::effect_descriptor::effect_workspace;
use super::effect_journal_owner::UnknownCause;
use super::permission_policy::{OperationPolicy, evaluate_operation};
use super::{Agent, KernelError};
use iteron_kernel::{effect_class, effects};
use iteron_protocol::{Capability, Event, EventKind, RunId, Seq, TenantId, Trust, Verdict};
use iteron_record::{RecordError, Snapshot};
use iteron_tools::{EffectKnowledge, OperationEffects};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

pub(crate) struct WorkspaceRewindTicket {
    ticket: effects::EffectTicket,
    scope: WorkspaceRewindPermit,
    dispatched: bool,
}
/// Minted only after the real operation gate and intent append. No public constructor,
/// deserializer or Clone; one physical work item can consume the permit once.
pub(crate) struct WorkspaceRewindPermit {
    run: RunId,
    tenant: TenantId,
    workspace: PathBuf,
    runtime_state: PathBuf,
    target_run: RunId,
    target_seq: Seq,
    target_tree: String,
    intent_seq: Seq,
}
impl WorkspaceRewindPermit {
    pub(crate) fn matches(
        &self,
        run: &RunId,
        tenant: &TenantId,
        workspace: &Path,
        snapshot: &Snapshot,
    ) -> bool {
        &self.run == run
            && &self.tenant == tenant
            && self.workspace == workspace
            && self.target_run == snapshot.run
            && self.target_seq == snapshot.at
            && self.target_tree == snapshot.tree_ref
    }
    pub(crate) fn runtime_state(&self) -> &Path {
        &self.runtime_state
    }
    pub(crate) fn intent_sequence(&self) -> Seq {
        self.intent_seq
    }
}
impl WorkspaceRewindTicket {
    pub(crate) fn intent_sequence(&self) -> Seq {
        self.ticket.intent_sequence()
    }
    pub(crate) fn take_permit(&mut self) -> Option<WorkspaceRewindPermit> {
        if self.dispatched {
            return None;
        }
        self.dispatched = true;
        Some(WorkspaceRewindPermit {
            run: self.scope.run.clone(),
            tenant: self.scope.tenant.clone(),
            workspace: self.scope.workspace.clone(),
            runtime_state: self.scope.runtime_state.clone(),
            target_run: self.scope.target_run.clone(),
            target_seq: self.scope.target_seq,
            target_tree: self.scope.target_tree.clone(),
            intent_seq: self.scope.intent_seq,
        })
    }
}
#[derive(Clone, Copy)]
pub(crate) enum RewindTerminal {
    Restored,
    FailedAndRolledBack,
    NotStarted,
    ReconciliationNeeded,
}

impl Agent {
    pub(crate) fn admit_workspace_rewind(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<WorkspaceRewindTicket, KernelError> {
        if self.record_failed {
            return Err(KernelError::EffectBoundary(
                "restore refused after a record barrier failure".into(),
            ));
        }
        // A captured cohort can keep writing after its parent's turn. Never restore under it.
        if self.persistent_agents.is_some() {
            return Err(KernelError::EffectBoundary(
                "restore requires a session without an installed persistent-agent cohort".into(),
            ));
        }
        if self.registry.process_control().is_some_and(|port| {
            let health = port.health();
            health.active_jobs != 0 || health.cleanup_unknown_jobs != 0
        }) {
            return Err(KernelError::EffectBoundary(
                "restore requires all owned processes to have observed terminals".into(),
            ));
        }
        // A complete tree can include AGENTS/configuration. The host conservatively requires
        // trust authority for every file restore; ordinary edit permission cannot grant it.
        let effects = OperationEffects {
            required: iteron_protocol::capability_set::CapabilitySet::from_iter_capabilities([
                Capability::ReversibleLocal,
                Capability::TrustMutating,
            ]),
            knowledge: EffectKnowledge::Classified,
            targets: Vec::new(),
            canonical_tool: None,
            extension_ceiling: None,
            reason: "complete workspace restoration can rewrite trust configuration",
        };
        let admission = evaluate_operation(
            "workspace_rewind",
            &effects,
            OperationPolicy {
                mode: self.permission_mode,
                rules: &self.permission_rules,
                bypass: self.bypass_permissions,
                task_ceiling: self.authority_ceiling,
                policy_capabilities: self.policy_capabilities,
                governing_trust: Trust::Trusted,
                authority: self.operator_authority(),
            },
        );
        if admission.verdict != Verdict::Auto {
            return Err(KernelError::EffectBoundary(match admission.verdict {
                Verdict::Ask => "workspace restore requires an explicit workspace_rewind/trust permission grant",
                _ => "workspace restore is denied by the actual permission mode, rule or capability ceiling",
            }.into()));
        }
        self.effect_journal
            .guard_recovery(&mut self.rollout, &mut self.ledger)?;
        let workspace = self.workspace.canonicalize().map_err(RecordError::Io)?;
        let runtime_state = self
            .runtime_state_dir
            .canonicalize()
            .map_err(RecordError::Io)?;
        if !self
            .rollout
            .path()
            .canonicalize()
            .map_err(RecordError::Io)?
            .starts_with(&runtime_state)
        {
            return Err(KernelError::EffectBoundary(
                "active writer is outside the protected runtime root".into(),
            ));
        }
        let turn = self.current_turn_id();
        let class = effect_class::EffectClass::WorkspaceRestore;
        let ordinal = self.effect_journal.next_ordinal(turn, class);
        let started = Instant::now();
        let opened = self.effect_journal.open(&mut self.rollout, effects::BrokeredEffect {
            turn, effect_id: effect_class::effect_id(turn, class, ordinal),
            tool_use_id: effect_class::harness_correlation_id(turn, class, ordinal),
            kind: "workspace_restore".into(), capability: Capability::TrustMutating,
            audit_arguments: serde_json::json!({"target_run":snapshot.run,"target_seq":snapshot.at,"scope":"editable-workspace-excluding-runtime-state"}),
            workspace: effect_workspace(&workspace), provider_route_attempt: None,
        });
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        let ticket = opened.map_err(|error| self.rewind_boundary_error(error))?;
        self.effect_journal.note_workspace_mutation();
        let scope = WorkspaceRewindPermit {
            run: self.rollout.run_id().clone(),
            tenant: self.rollout.tenant().clone(),
            workspace,
            runtime_state,
            target_run: snapshot.run.clone(),
            target_seq: snapshot.at,
            target_tree: snapshot.tree_ref.clone(),
            intent_seq: ticket.intent_sequence(),
        };
        Ok(WorkspaceRewindTicket {
            ticket,
            scope,
            dispatched: false,
        })
    }

    /// Publish the actual pre-mutation tree before native restore begins. The sequence is checked
    /// against the append receipt; the snapshot's previous reference sequence is never proof.
    pub(crate) fn publish_rewind_safety(
        &mut self,
        ticket: &WorkspaceRewindTicket,
        snapshot: &mut Snapshot,
    ) -> Result<Seq, KernelError> {
        self.check_rewind_scope(ticket)?;
        if snapshot.run != ticket.scope.run {
            return Err(KernelError::EffectBoundary(
                "restore safety snapshot belongs to another run".into(),
            ));
        }
        let expected = self.rollout.next_sequence();
        let started = Instant::now();
        let appended = self.rollout.append(&Event {
            seq: Seq::ZERO,
            turn: ticket.ticket.turn(),
            kind: EventKind::Checkpoint {
                at: expected,
                tree_ref: snapshot.tree_ref.clone(),
            },
        });
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        let source = appended.map_err(|error| self.rewind_record_error(error))?;
        if source != expected {
            return Err(self.rewind_record_error(RecordError::InvalidAppendBatch {
                reason: "restore safety sequence differs from the physical append receipt",
            }));
        }
        snapshot.at = source;
        Ok(source)
    }
    pub(crate) fn settle_workspace_rewind(
        &mut self,
        ticket: WorkspaceRewindTicket,
        terminal: RewindTerminal,
    ) -> Result<Seq, KernelError> {
        self.check_rewind_scope(&ticket)?;
        if !matches!(terminal, RewindTerminal::NotStarted) {
            // A prior automatic rollback point must not replace an operator-restored workspace.
            // Clearing observation state grants no authority and forces the next real capture.
            self.workspace_checkpoints.invalidate_after_restore();
        }
        let id = ticket.ticket.effect_id().clone();
        let settlement = match terminal {
            RewindTerminal::Restored => effects::Settlement::Definite(EventKind::EffectDone {id,tool:"workspace_restore".into(),duration_ms:None,provider_route_attempt:None}),
            RewindTerminal::FailedAndRolledBack | RewindTerminal::NotStarted => effects::Settlement::Definite(EventKind::EffectFailed {id,tool:"workspace_restore".into(),reason:if matches!(terminal,RewindTerminal::NotStarted) {"restore did not start"} else {"restore failed; the native safety rollback completed"}.into(),duration_ms:None,provider_route_attempt:None}),
            RewindTerminal::ReconciliationNeeded => effects::Settlement::Unknown("workspace restore or safety rollback has no confirmed native terminal; inspect the durable safety checkpoint and reconcile before retry".into()),
        };
        let started = Instant::now();
        let appended = self.effect_journal.settle_with_sequence(
            &mut self.rollout,
            ticket.ticket,
            settlement,
            UnknownCause::Unobserved,
        );
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        appended.map_err(|error| self.rewind_boundary_error(error))
    }
    fn check_rewind_scope(&self, ticket: &WorkspaceRewindTicket) -> Result<(), KernelError> {
        if self.rollout.run_id() != &ticket.scope.run
            || self.rollout.tenant() != &ticket.scope.tenant
        {
            return Err(KernelError::EffectBoundary(
                "restore receipt belongs to a different physical writer".into(),
            ));
        }
        Ok(())
    }
    fn rewind_record_error(&mut self, error: RecordError) -> KernelError {
        self.record_failed = true;
        self.diagnostics
            .emit(iteron_kernel::diagnostics::KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
    fn rewind_boundary_error(&mut self, error: effects::BrokerError) -> KernelError {
        match error {
            effects::BrokerError::Record(error) => self.rewind_record_error(error),
            other => KernelError::EffectBoundary(other.to_string()),
        }
    }
}
