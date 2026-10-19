//! Single accepted-response publication lifetime. Physical provider/early-tool ownership is
//! retained until logical usage, the existing optional observer barrier and transcript commit.
use super::KernelError;
use super::context_runtime::ContextBudgetInspection;
use super::context_usage_reconciliation::ContextUsageReconciliation;
use super::early_tool_collection::{EarlyToolCollection, EarlyToolCollectionScope};
use super::frontend_events::UiEvent;
use super::pricing::{ProviderAttemptGuard, SharedUsdBudget};
use super::provider_response_recovery::{AcceptedProviderResponse, ProviderResponseJournal};
use super::provider_usage_journal::ProviderUsageJournal;
use super::session_transcript::TranscriptAdmissionJournal;
use iteron_ctx::{CompactionPolicy, ContextEstimate};
use iteron_obs::PricingPort;
use iteron_protocol::{Block, CostAttribution, Message, Role, Trust, TurnId, Usage};
use iteron_provider::EffortApplication;
use std::sync::Arc;
use std::time::Duration;

pub(super) struct ProviderCommitScope {
    pub(super) turn: TurnId,
    pub(super) usd: Option<Arc<SharedUsdBudget>>,
    pub(super) pricing: Option<Arc<dyn PricingPort>>,
    pub(super) attribution: Option<CostAttribution>,
    pub(super) estimate: ContextEstimate,
    pub(super) inspection: ContextBudgetInspection,
    pub(super) window: Option<u64>,
    pub(super) compaction: CompactionPolicy,
    pub(super) effort: EffortApplication,
}
pub(super) struct ProviderOutputState<'a> {
    pub(super) last_text: &'a mut String,
    pub(super) run_text: &'a mut String,
    pub(super) observed_trust: &'a mut Trust,
}
pub(super) struct ProviderCommitSession<'a> {
    pub(super) journal: ProviderResponseJournal<'a>,
    pub(super) early: EarlyToolCollectionScope<'a>,
    pub(super) context: ContextUsageReconciliation<'a>,
    pub(super) output: ProviderOutputState<'a>,
    pub(super) scope: ProviderCommitScope,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommitPhase {
    Fresh,
    UsageRecorded,
    Reconciled,
    Complete,
    Failed,
}
pub(super) struct ProviderResponseCommit {
    response: Option<AcceptedProviderResponse>,
    phase: CommitPhase,
    usage: Option<Usage>,
    guard: Option<ProviderAttemptGuard>,
    stream_elapsed: Duration,
}
impl ProviderResponseCommit {
    pub(super) fn new(response: AcceptedProviderResponse, guard: ProviderAttemptGuard) -> Self {
        let stream_elapsed = response.round.stream_started().elapsed();
        Self {
            response: Some(response),
            phase: CommitPhase::Fresh,
            usage: None,
            guard: Some(guard),
            stream_elapsed,
        }
    }
    pub(super) fn stream_elapsed(&self) -> Duration {
        self.stream_elapsed
    }
    pub(super) async fn record_usage(
        &mut self,
        mut session: ProviderCommitSession<'_>,
    ) -> Result<(), KernelError> {
        self.require(CommitPhase::Fresh)?;
        self.phase = CommitPhase::Failed;
        let response = self.response.as_mut().ok_or_else(boundary)?;
        *session.output.last_text = response.result.text();
        session.output.run_text.push_str(session.output.last_text);
        let model_ms = iteron_obs::duration_ms_ceil(response.route.active());
        let timing = response
            .round
            .observations()
            .timing(response.round.stream_started());
        let turn = session.scope.turn;
        let result = session.usage_journal().record(
            turn,
            response.result.usage,
            model_ms,
            &response.usage_evidence,
            timing,
        );
        match result {
            Ok(usage) => {
                self.usage = usage;
                self.phase = CommitPhase::UsageRecorded;
                Ok(())
            }
            Err(error) => {
                session.abort(response).await?;
                Err(error)
            }
        }
    }
    // Called only after the host has crossed the existing optional observer barrier. The UI is
    // returned to its actual frontend owner, preserving SDK observer and queue semantics.
    pub(super) fn reconcile(
        &mut self,
        mut session: ProviderCommitSession<'_>,
    ) -> Result<UiEvent, KernelError> {
        self.require(CommitPhase::UsageRecorded)?;
        self.phase = CommitPhase::Failed;
        let response = self.response.as_ref().ok_or_else(boundary)?;
        let event = if let Some(usage) = self.usage {
            self.guard.take().ok_or_else(boundary)?.complete();
            for id in ["model.usage_reported", "model.usage_reconciled"] {
                if id == "model.usage_reconciled" {
                    session.context.observe(session.scope.turn, usage);
                }
                session.context.events.emit(
                    session.scope.turn,
                    id,
                    iteron_protocol::LifecyclePayload {
                        magnitude: Some(usage.input.saturating_add(usage.output)),
                        ..Default::default()
                    },
                );
            }
            let mut observed_context = session.scope.estimate;
            observed_context.components = Some(session.scope.inspection.usage());
            UiEvent::TurnEnd {
                cost: session.journal.tools.ledger.cost_state(),
                usage,
                context: observed_context,
                model_context_window: session.scope.window,
                reserved_output_tokens: response.route.request().max_tokens,
                compaction_trigger_tokens: session.scope.compaction.effective_trigger_tokens(
                    session.scope.window.filter(|window| *window > 0),
                    response.route.request().max_tokens,
                ),
                effort: session.scope.effort,
            }
        } else {
            UiEvent::Notice(
                iteron_tunables::param_str(
                    "cli.runtime.incomplete_usage_notice",
                    super::INCOMPLETE_USAGE_NOTICE,
                )
                .into(),
            )
        };
        self.phase = CommitPhase::Reconciled;
        Ok(event)
    }
    pub(super) async fn commit_assistant(
        &mut self,
        mut session: ProviderCommitSession<'_>,
        messages: &mut Vec<Message>,
    ) -> Result<(), KernelError> {
        self.require(CommitPhase::Reconciled)?;
        self.phase = CommitPhase::Failed;
        let response = self.response.as_mut().ok_or_else(boundary)?;
        let message = Message {
            role: Role::Assistant,
            content: response.result.blocks.clone(),
        };
        if !response.recovered || !message.content.is_empty() {
            let turn = session.scope.turn;
            match session.transcript().message(turn, message.clone()) {
                Ok(source) => {
                    *session.journal.assistant_source = Some(source);
                    if let Some(trust) =
                        Trust::governing(message.content.iter().filter_map(|block| match block {
                            Block::ToolResult(result) => Some(result.trust),
                            Block::ToolImage(image) => Some(image.trust()),
                            _ => None,
                        }))
                    {
                        *session.output.observed_trust =
                            (*session.output.observed_trust).min(trust);
                    }
                    messages.push(message);
                }
                Err(error) => {
                    session.abort(response).await?;
                    return Err(error);
                }
            }
        }
        self.phase = CommitPhase::Complete;
        Ok(())
    }
    pub(super) async fn abort(
        &mut self,
        mut session: ProviderCommitSession<'_>,
    ) -> Result<(), KernelError> {
        self.phase = CommitPhase::Failed;
        if let Some(response) = &mut self.response {
            session.abort(response).await?;
        }
        Ok(())
    }
    pub(super) fn complete(mut self) -> Result<AcceptedProviderResponse, KernelError> {
        self.require(CommitPhase::Complete)?;
        self.response.take().ok_or_else(boundary)
    }
    fn require(&self, phase: CommitPhase) -> Result<(), KernelError> {
        if self.phase == phase {
            Ok(())
        } else {
            Err(boundary())
        }
    }
}
impl ProviderCommitSession<'_> {
    fn transcript(&mut self) -> TranscriptAdmissionJournal<'_> {
        TranscriptAdmissionJournal {
            rollout: &mut *self.journal.tools.rollout,
            ledger: &mut *self.journal.tools.ledger,
            record_failed: &mut *self.journal.tools.record_failed,
            diagnostics: self.journal.tools.diagnostics,
            publications: &mut *self.journal.publications,
            #[cfg(test)]
            fault: &mut *self.journal.tools.fault,
        }
    }
    fn usage_journal(&mut self) -> ProviderUsageJournal<'_> {
        let usd = self.scope.usd.clone();
        let pricing = self.scope.pricing.clone();
        let attribution = self.scope.attribution.clone();
        let events = self.early.events.clone();
        ProviderUsageJournal {
            transcript: self.transcript(),
            usd,
            pricing,
            attribution,
            events,
        }
    }
    async fn abort(&mut self, response: &mut AcceptedProviderResponse) -> Result<(), KernelError> {
        let mut early = response.round.take_early_for_cleanup();
        let scope = EarlyToolCollectionScope {
            turn: self.early.turn,
            registry: self.early.registry,
            hooks: self.early.hooks.clone(),
            events: self.early.events.clone(),
            deadline: self.early.deadline,
        };
        let journal = super::tool_execution_journal::ToolExecutionJournal {
            rollout: &mut *self.journal.tools.rollout,
            effects: &mut *self.journal.tools.effects,
            ledger: &mut *self.journal.tools.ledger,
            failed_actions: &mut *self.journal.tools.failed_actions,
            record_failed: &mut *self.journal.tools.record_failed,
            diagnostics: self.journal.tools.diagnostics,
            #[cfg(test)]
            fault: &mut *self.journal.tools.fault,
        };
        EarlyToolCollection { journal, scope }
            .abort_all(&mut early)
            .await
    }
}
fn boundary() -> KernelError {
    KernelError::EffectBoundary(
        "accepted provider response cannot be committed outside its retained phase".into(),
    )
}
