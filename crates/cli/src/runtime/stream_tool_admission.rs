//! Actual synchronous streamed-tool admission coordinator. The frozen scope supplies trusted
//! policy; disjoint physical ports commit decisions/intents before an executor can be polled.
//! It never borrows Agent, dispatches a provider or invents recovery/completion evidence.
use super::KernelError;
use super::artifact_publication::ToolOutputPublicationFactory;
use super::early_tool_executor::{AdmittedEarlyTool, EarlyToolExecutionScope, EarlyToolExecutor};
use super::failed_action_cache::FailedActionCache;
use super::hooks::{HookEvent, Hooks, journal::HookEffectJournal};
use super::permission_policy::OperationPolicy;
use super::strategy_runtime;
use super::stream_tool_events::StreamToolEvents;
use super::stream_tool_journal::StreamToolJournal;
pub(super) use super::stream_tools::StreamToolControl;
use super::stream_tools::early_capability;
use super::submitted_turn_state::SubmittedTurnState;
use super::tool_output_spill::ToolOutputSpillStore;
use super::tool_turn::{EarlyHookEffectTickets, ToolTurnOwner};
use iteron_kernel::effect_class;
use iteron_protocol::slot::StrategySlot;
use iteron_protocol::{Capability, LifecyclePayload, Purity, ToolUse, Trust, TurnId};
use iteron_sched::Governor;
use iteron_tools::Registry;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;

pub(super) struct StreamToolScope<'a> {
    pub(super) turn: TurnId,
    pub(super) workspace: &'a Path,
    pub(super) registry: &'a Registry,
    pub(super) strategy: &'a dyn StrategySlot,
    pub(super) operation: OperationPolicy<'a>,
    pub(super) trust: Trust,
    pub(super) failed_actions: &'a FailedActionCache,
    pub(super) recovered: &'a SubmittedTurnState,
    pub(super) overlap: bool,
    pub(super) early_effects: bool,
    pub(super) compatibility_hook: bool,
    pub(super) lifecycle_hook: bool,
    pub(super) hooks: Hooks,
    pub(super) hook_journal: Option<HookEffectJournal>,
    pub(super) governor: Governor,
    pub(super) queued: Arc<AtomicUsize>,
    pub(super) execution_gate: Arc<tokio::sync::RwLock<()>>,
    pub(super) control: StreamToolControl,
    pub(super) publication: Arc<dyn ToolOutputPublicationFactory>,
    pub(super) spill: Option<Arc<ToolOutputSpillStore>>,
    pub(super) events: StreamToolEvents,
}

pub(super) struct StreamToolAdmission<'a> {
    state: &'a mut ToolTurnOwner,
    journal: StreamToolJournal<'a>,
    scope: StreamToolScope<'a>,
}
impl<'a> StreamToolAdmission<'a> {
    pub(super) fn new(
        state: &'a mut ToolTurnOwner,
        journal: StreamToolJournal<'a>,
        scope: StreamToolScope<'a>,
    ) -> Self {
        Self {
            state,
            journal,
            scope,
        }
    }

    pub(super) fn declare(&mut self, call: ToolUse) {
        let Some(index) = self.state.admit(&call) else {
            return;
        };
        if let Err(error) = self.admit(index, call) {
            self.state.latch_record_error(error);
        }
    }

    fn admit(&mut self, index: usize, call: ToolUse) -> Result<(), KernelError> {
        self.scope.events.declared(&call);
        let proposal = strategy_runtime::propose_tool(
            self.scope.registry,
            self.scope.strategy,
            call.clone(),
            self.scope.trust,
        );
        let draft = ToolTurnOwner::decision_draft(&call, &proposal, self.scope.trust)?;
        self.journal.record_decision(self.scope.turn, draft)?;
        if let Some((prior_call, prior_result)) = self.scope.recovered.recovered_tool(&call.id) {
            if prior_call != &call {
                return Err(iteron_provider::ProviderError::Decode(
                    "recovery reused a completed tool call ID with different arguments".into(),
                )
                .into());
            }
            self.state.retain_replay(index, prior_result.clone());
            self.state.defer((index, call, proposal));
            return Ok(());
        }
        let pure = proposal
            .as_ref()
            .is_ok_and(|proposal| proposal.intent.purity == Purity::Pure);
        let capability = proposal.as_ref().ok().and_then(|proposal| {
            early_capability(
                self.scope.registry,
                proposal,
                self.scope.operation,
                *self.journal.record_failed,
                &self.scope.control,
            )
        });
        let signature = format!("{}::{}", call.name, call.input);
        let early = self.scope.overlap
            && !self.state.has_deferred()
            && capability.is_some()
            && (pure
                || (self.scope.early_effects
                    && !self.scope.failed_actions.contains_key(&signature)
                    && !self.state.effect_reserved(&signature)));
        if !early {
            self.state.defer((index, call, proposal));
            return Ok(());
        }
        let capability = capability.expect("checked operation-specific authority");
        let proposal = proposal.expect("eligible registered stream proposal");
        if !pure {
            self.state.reserve_effect(signature);
        }
        let declared = proposal.intent.call.clone();
        let admitted = proposal.eligible;
        let intent = proposal.admit(admitted);
        let mut tickets = EarlyHookEffectTickets::default();
        if self.scope.compatibility_hook || self.scope.lifecycle_hook {
            self.scope.events.emit(
                "hook.started",
                None,
                LifecyclePayload {
                    count: Some(1),
                    ..LifecyclePayload::default()
                },
            );
        }
        // The future below cannot poll either configured hook until its actual universal intent
        // has crossed the durable writer. Missing hook journal remains a known predispatch refusal.
        if self.scope.hook_journal.is_some() {
            if self.scope.compatibility_hook {
                tickets.compatibility = Some(self.journal.open_hook(
                    self.scope.workspace,
                    self.scope.turn,
                    index,
                    HookEvent::PreToolUse.key(),
                )?);
            }
            if self.scope.lifecycle_hook {
                tickets.lifecycle = Some(self.journal.open_hook(
                    self.scope.workspace,
                    self.scope.turn,
                    index,
                    "tool.call_proposed",
                )?);
            }
        }
        if !pure {
            let effect = effect_class::effect_id(
                self.scope.turn,
                effect_class::EffectClass::RegistryTool,
                index,
            );
            self.scope.events.emit(
                "tool.call_proposed",
                Some(effect.clone()),
                LifecyclePayload::default(),
            );
            self.scope.events.emit(
                "tool.policy_evaluated",
                Some(effect.clone()),
                LifecyclePayload {
                    outcome_code: Some("admitted".into()),
                    ..LifecyclePayload::default()
                },
            );
            tickets.tool = Some(self.journal.open_tool(
                self.scope.workspace,
                self.scope.turn,
                index,
                &declared,
                capability,
            )?);
            self.scope.events.tool_start(&declared, effect);
        }
        let source = match &tickets.tool {
            Some(ticket) => ticket.intent_sequence(),
            None => self
                .journal
                .append_ready(self.scope.turn, &declared, pure)?,
        };
        let publication = self.scope.publication.for_call(&declared, source);
        let executor = EarlyToolExecutor::new(EarlyToolExecutionScope {
            governor: self.scope.governor.clone(),
            queued: self.scope.queued.clone(),
            execution_gate: self.scope.execution_gate.clone(),
            hooks: self.scope.hooks.clone(),
            hook_journal: self.scope.hook_journal.clone(),
            interrupt: self.scope.control.interrupt.clone(),
            force_cancel: self.scope.control.force_cancel.clone(),
            drain: self.scope.control.drain.clone(),
            publication,
        });
        let future = self.scope.registry.dispatch_stream_intent_captured(intent);
        let task = executor.spawn(
            AdmittedEarlyTool {
                call: declared.clone(),
                is_pure: pure,
                supports_parallel: pure || capability == Capability::CodeExecuting,
                compatibility_pre_hook: self.scope.compatibility_hook,
                lifecycle_pre_hook: self.scope.lifecycle_hook,
                compatibility_context: serde_json::json!({
                    "event":"PreToolUse","tool":declared.name,"input":declared.input,
                })
                .to_string(),
                lifecycle_context: serde_json::json!({
                    "catalog_version":iteron_protocol::lifecycle::LIFECYCLE_CATALOG_VERSION.0,
                    "event_id":"tool.call_proposed","turn_id":self.scope.turn.0,
                })
                .to_string(),
                spill_store: self.scope.spill.clone(),
            },
            future,
        );
        self.state
            .retain_early((index, declared, task, Instant::now(), tickets));
        Ok(())
    }
}
