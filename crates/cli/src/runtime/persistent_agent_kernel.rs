//! Adapter from the persistent controller's runtime port to real resident Iteron Agents.

use super::persistent_agents::{
    AgentControlPort, AgentObservation, AgentSettlement, LiveAgentMailbox, PersistentAgentHost,
    PersistentAgentRuntime,
};
use super::persistent_writer_settlement::{PersistentWriterConfig, PersistentWriterSettlement};
use super::pricing::SharedUsdBudget;
use super::workflow_spawner::worktree::persistent::PersistentWriterWorktree;
use super::workflow_spawner::{KernelSpawner, KernelSpawnerContext};
use super::{Agent, KernelError};
use async_trait::async_trait;
use iteron_agents::{
    AgentActor, AgentController, AgentControllerConfig, AgentFileJournal, AgentMailboxMessage,
    ControllerError,
};
use iteron_obs::CostState;
use iteron_protocol::agent_control::{
    AgentCommandV1, AgentControlReplyV1, AgentEpochV1, AgentIdV1, AgentMessageIdV1, AgentViewV1,
};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{Capability, EventKind, Purity, ToolResult, ToolSpec, Trust};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

type Resident = Arc<tokio::sync::Mutex<Agent>>;
mod budget;
mod profiles;
mod recovery;

pub(super) struct KernelPersistentRuntime {
    spawner: Mutex<KernelSpawner>,
    residents: Mutex<BTreeMap<AgentIdV1, Resident>>,
    completed_ledgers: Mutex<super::child_ledger_evidence::CompletedChildLedgers>,
    control: OnceLock<Weak<dyn AgentControlPort>>,
    writer: PersistentWriterConfig,
    money: Option<Arc<SharedUsdBudget>>,
    agent_money: Mutex<BTreeMap<AgentIdV1, Arc<SharedUsdBudget>>>,
    pricing: Option<Arc<dyn iteron_obs::PricingPort>>,
    readonly_ceiling: Option<iteron_protocol::Budget>,
    writer_ceiling: iteron_protocol::Budget,
    // Own every inactive Main writer lock while this single host drives the cohort.
    main_rollout_owners: Mutex<Vec<iteron_record::Rollout>>,
    #[cfg(test)]
    fixture: Option<Arc<dyn Fn(&mut Agent) + Send + Sync>>,
}

impl KernelPersistentRuntime {
    pub(super) fn new(context: KernelSpawnerContext) -> Self {
        Self {
            writer: PersistentWriterConfig {
                parent: context.workspace.clone(),
                state: context.runtime_state_dir.clone(),
                lock: context.writer_merge_lock.clone(),
                verify: context.verify_command.clone(),
                env: context.sensitive_env_names.clone(),
                oracle_tail: context.verification_feedback.oracle_output_bytes,
                admitted: cfg!(any(target_os = "linux", target_os = "macos"))
                    && context.writer_merge_policy.admit_child(true, true).is_ok(),
            },
            money: context.usd_budget.clone(),
            agent_money: Mutex::new(BTreeMap::new()),
            pricing: context.pricing_port.clone(),
            readonly_ceiling: context
                .execution_policy
                .child_ceiling
                .map(|ceiling| ceiling.narrow_budget(context.budget.clone())),
            writer_ceiling: context.budget.clone(),
            main_rollout_owners: Mutex::new(Vec::new()),
            spawner: Mutex::new(KernelSpawner::new(context)),
            residents: Mutex::new(BTreeMap::new()),
            completed_ledgers: Mutex::new(Default::default()),
            control: OnceLock::new(),
            #[cfg(test)]
            fixture: None,
        }
    }

    pub(super) fn bind(&self, control: &Arc<dyn AgentControlPort>) -> Result<(), ControllerError> {
        self.control
            .set(Arc::downgrade(control))
            .map_err(|_| ControllerError::Invalid("persistent runtime control is already bound"))
    }

    fn resident(
        &self,
        view: &AgentViewV1,
        writer_workspace: Option<&std::path::Path>,
        execution: Option<&iteron_agents::AgentEngineExecution>,
    ) -> Result<Resident, ControllerError> {
        let mut residents = self
            .residents
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        if let Some(resident) = residents.get(&view.agent_id) {
            return Ok(resident.clone());
        }
        if residents.len() >= 64 {
            return Err(ControllerError::Capacity);
        }
        let call = iteron_workflow::AgentCall {
            prompt: String::new(),
            label: Some(view.label.clone()),
            phase: Some("persistent".into()),
            model: execution.map(|binding| binding.model_id.clone()),
            effort: execution.map(|binding| binding.effort),
            agent_type: Some(execution.map_or_else(
                || {
                    if writer_workspace.is_some() {
                        iteron_agents::ISOLATED_WRITER_NAME.into()
                    } else {
                        "generic".into()
                    }
                },
                |binding| binding.profile.clone(),
            )),
            schema: None,
            cancel: Default::default(),
        };
        let mut construction = view.clone();
        construction.reserved = Default::default();
        let mut child = self
            .spawner
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .build_persistent_child(&call, &construction, writer_workspace, execution)
            .map_err(|_| ControllerError::Invalid("persistent child construction failed"))?;
        child.narrow_policy_capabilities(view.capabilities);
        child.authority_ceiling = child.authority_ceiling.intersect(view.capabilities);
        if writer_workspace.is_some() {
            child
                .registry
                .set_inherited_write_scope(view.write_paths.clone())
                .map_err(|_| ControllerError::Permission)?;
        }
        let control = self
            .control
            .get()
            .and_then(Weak::upgrade)
            .ok_or(ControllerError::Closed)?;
        if let Some(pool) = self.monetary_pool(view)? {
            child.usd_budget = Some(pool);
        }
        child
            .install_persistent_agents(control, view.agent_id)
            .map_err(|_| {
                ControllerError::Invalid("persistent child controls could not be installed")
            })?;
        child.persistent_agents = None; // Child tools retain only a Weak host port; avoid an owner cycle.
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            fixture(&mut child);
        }
        let resident = Arc::new(tokio::sync::Mutex::new(child));
        residents.insert(view.agent_id, resident.clone());
        Ok(resident)
    }
}

#[async_trait]
impl PersistentAgentRuntime for KernelPersistentRuntime {
    fn completed_ledger(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
    ) -> Result<Option<super::child_ledger_evidence::AgentRuntimeLedger>, ControllerError> {
        Ok(self
            .completed_ledgers
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .read(id, epoch))
    }
    fn prepare_engine_child(
        &self,
        request: &super::persistent_agents::AgentEngineRequest,
        origin: iteron_agents::AgentEngineOrigin,
    ) -> Result<iteron_agents::AgentEngineExecution, ControllerError> {
        self.prepare_child_profile(request, origin)
    }
    fn validate_engine_child(
        &self,
        execution: &iteron_agents::AgentEngineExecution,
    ) -> Result<(), ControllerError> {
        self.validate_child_profile(execution)
    }
    fn monetary_remaining(&self) -> Result<Option<u64>, ControllerError> {
        if self.pricing.is_none() {
            return Ok(None);
        }
        self.money
            .as_ref()
            .map(|pool| {
                pool.remaining_microusd()
                    .map_err(|_| ControllerError::RecoveryRequired)
            })
            .transpose()
    }

    fn validate_spawn(&self, command: &AgentCommandV1) -> Result<(), ControllerError> {
        if let AgentCommandV1::Spawn {
            capabilities,
            write_paths,
            budget,
            ..
        } = command
        {
            let supported = CapabilitySet::from_iter_capabilities([
                Capability::ReadOnly,
                Capability::ReversibleLocal,
            ]);
            if !capabilities.is_subset_of(supported) || !capabilities.contains(Capability::ReadOnly)
            {
                return Err(ControllerError::Permission);
            }
            let writer = capabilities.contains(Capability::ReversibleLocal);
            let ceiling = if writer {
                Some(&self.writer_ceiling)
            } else {
                self.readonly_ceiling.as_ref()
            }
            .ok_or(ControllerError::Permission)?;
            if budget.turns > ceiling.max_turns
                || budget.wall_ms > ceiling.max_wall_secs.saturating_mul(1000)
                || ceiling
                    .max_tokens
                    .is_some_and(|tokens| budget.tokens > tokens)
                || ceiling
                    .max_usd
                    .is_some_and(|cost| budget.cost_microusd as f64 / 1_000_000.0 > cost)
            {
                return Err(ControllerError::Budget);
            }
            if writer
                && (!self.writer.admitted
                    || write_paths.is_empty()
                    || self
                        .writer
                        .verify
                        .as_ref()
                        .is_none_or(|verify| verify.trim().is_empty()))
            {
                return Err(ControllerError::Invalid(
                    "persistent writer needs finite write paths and a host-admitted verification command",
                ));
            }
            if !writer && !write_paths.is_empty() {
                return Err(ControllerError::Permission);
            }
        }
        Ok(())
    }

    async fn execute(
        &self,
        view: AgentViewV1,
        epoch: AgentEpochV1,
        initial: Vec<AgentMailboxMessage>,
        mailbox: LiveAgentMailbox,
    ) -> AgentSettlement {
        let execution = match mailbox.engine_execution() {
            Ok(Some(binding)) => {
                if self.validate_engine_child(&binding).is_err() {
                    return profiles::refused(
                        "committed child profile does not match native evidence",
                    );
                }
                Some(binding)
            }
            Ok(None) => None,
            Err(_) => return profiles::refused("committed child profile evidence is unavailable"),
        };
        let writer_requested = view.capabilities.contains(Capability::ReversibleLocal);
        let _writer_lane = if writer_requested {
            Some(self.writer.lock.lock().await)
        } else {
            None
        };
        let mut worktree = if writer_requested {
            let id = match self.spawner.lock() {
                Ok(spawner) => spawner.mint_run_id(view.agent_id.0).0,
                Err(_) => return unknown_settlement("Persistent writer identity lock failed"),
            };
            let Some(control) = self.control.get().and_then(Weak::upgrade) else {
                return unknown_settlement("Persistent writer owner is unavailable");
            };
            let witness = match control.workspace_witness() {
                Ok(witness) => witness,
                Err(_) => {
                    return unknown_settlement("Persistent writer durable evidence is unavailable");
                }
            };
            match PersistentWriterWorktree::provision(
                self.writer.parent.clone(),
                self.writer.state.clone(),
                id,
                witness.clone(),
            )
            .await
            {
                Ok((mut worktree, initialized)) => {
                    if control
                        .record_workspace_witness(witness.as_ref(), initialized)
                        .is_err()
                    {
                        let _ = worktree.discard().await;
                        return unknown_settlement(
                            "Persistent writer baseline could not be persisted",
                        );
                    }
                    Some(worktree)
                }
                Err(_) => {
                    return unknown_settlement(
                        "Persistent writer worktree provisioning failed; recovery required",
                    );
                }
            }
        } else {
            None
        };
        let lifetime = match self
            .control
            .get()
            .and_then(Weak::upgrade)
            .and_then(|control| control.inspect(AgentActor::Operator, view.agent_id).ok())
        {
            Some(lifetime) => lifetime,
            None => return unknown_settlement("Persistent agent lifetime identity is unavailable"),
        };
        let resident = match self.resident(
            &lifetime,
            worktree.as_ref().map(PersistentWriterWorktree::path),
            execution.as_ref(),
        ) {
            Ok(resident) => resident,
            Err(_) => {
                if let Some(worktree) = &mut worktree {
                    let _ = worktree.discard().await;
                }
                return AgentSettlement {
                    turns: 0,
                    summary: "Persistent agent setup failed before provider execution".into(),
                    tokens: 0,
                    cost_microusd: 0,
                    effects_known: false,
                    accounting_known: false,
                    terminal: iteron_agents::AgentWorkflowTerminal::Failed,
                };
            }
        };
        let mut retained = resident.lock().await;
        retained.registry.invalidate_workspace_reads();
        let mut child = match budget::TurnBudget::admit(&mut retained, &view) {
            Ok(child) => child,
            Err(_) => {
                return unknown_settlement("Persistent execution budget could not be admitted");
            }
        };
        let tokens_before = total_tokens(child.ledger.usage);
        let cost_before = known_cost(&child.ledger.cost_state());
        child.persistent_mailbox = Some(mailbox.clone());
        // Each accepted epoch owns fresh stop surfaces. Never clear the prior epoch's caller
        // signal: an inherited parent/sibling may still be quiescing behind its own terminal.
        let _epoch_deadline = match mailbox.execution_deadline().and_then(|deadline| {
            child
                .run_deadline
                .tighten(deadline)
                .map_err(|_| ControllerError::Capacity)
        }) {
            Ok(lease) => lease,
            Err(_) => {
                return unknown_settlement("Persistent epoch deadline evidence is unavailable");
            }
        };
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        child.inherit_interrupt(stop.clone());
        child.inherit_force_cancel(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        child.control.reset_after_adoption();
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        child.set_inbound_control(rx);
        let task = match mailbox.render_initial(&initial) {
            Ok(text) => text,
            Err(_) => {
                return AgentSettlement {
                    turns: 0,
                    summary: "Persistent mailbox rendering failed".into(),
                    tokens: 0,
                    cost_microusd: 0,
                    effects_known: false,
                    accounting_known: false,
                    terminal: iteron_agents::AgentWorkflowTerminal::StoppedRecovery,
                };
            }
        };
        let mut started_before =
            child.ledger.provider_attempts > 0 || child.transcript_state.working().is_some();
        if !started_before && child.transcript_state.restored().is_some() {
            started_before = true;
        }
        let result = {
            let execution = async {
                if started_before {
                    child.stage_follow_up_transcript().await?;
                    expire_restored(&mut child, &mailbox)?;
                }
                // execute owns a newly admitted durable controller epoch. Refresh only here;
                // provider retries and empty replay within run_leaf retain that epoch's context.
                // Isolated children without an installed memory namespace take the no-IO path.
                child.begin_user_memory_decision();
                if let Some(admission) = mailbox
                    .source_admission(&initial, &task)
                    .map_err(KernelError::AgentControl)?
                {
                    child.emit_durable(
                        iteron_protocol::TurnId(child.seq_turn),
                        EventKind::AgentInputAdmittedV1 {
                            admission: admission.clone(),
                        },
                    )?;
                    child.observed_trust = child.observed_trust.min(Trust::Untrusted);
                    mailbox
                        .confirm_source_admission(&admission)
                        .map_err(KernelError::AgentControl)?;
                }
                child.run_leaf(&task).await
            };
            tokio::pin!(execution);
            loop {
                match tokio::time::timeout(Duration::from_millis(20), &mut execution).await {
                    Ok(result) => break result,
                    Err(_) => {
                        if mailbox.stop_requested() {
                            stop.store(true, Ordering::Release);
                        }
                        if let Ok(inputs) = mailbox.receive() {
                            for input in inputs {
                                let Ok((text, activation)) = mailbox.steer_activation(&input)
                                else {
                                    stop.store(true, Ordering::Release);
                                    break;
                                };
                                if tx
                                    .try_send(super::inbound_control::TurnSubmission::agent_steer(
                                        text, activation,
                                    ))
                                    .is_err()
                                {
                                    stop.store(true, Ordering::Release);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        };
        let _ = child.take_unadmitted_steers_with_client_count();
        let _ = child.inbox.take_receiver();
        let processes_settled = child.settle_persistent_owned_processes().await;
        let cleaned = expire_unrequested(&mut child, &mailbox).is_ok();
        child.persistent_mailbox = None;
        let finalized = child.finalize_policy_run().is_ok();
        let writer_terminal = if let Some(worktree) = &mut worktree {
            Some(
                PersistentWriterSettlement {
                    config: &self.writer,
                    control: self.control.get().and_then(Weak::upgrade),
                }
                .run(
                    worktree,
                    matches!(&result, Ok(iteron_protocol::Outcome::Done)),
                )
                .await,
            )
        } else {
            None
        };
        let writer_known = writer_terminal
            .as_ref()
            .is_none_or(|terminal| terminal.proof.known());
        let writer_succeeded = writer_terminal
            .as_ref()
            .is_none_or(|terminal| terminal.failure.is_none() && terminal.proof.known());
        let summary = match &result {
            Ok(outcome) => {
                let answer = child
                    .transcript_state
                    .working()
                    .as_ref()
                    .and_then(|messages| {
                        messages
                            .iter()
                            .rev()
                            .find(|message| message.role == iteron_protocol::Role::Assistant)
                    })
                    .map(|message| {
                        message
                            .content
                            .iter()
                            .filter_map(|block| match block {
                                iteron_protocol::Block::Text { text } => Some(text.as_str()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_else(|| format!("Agent turn settled: {outcome:?}"));
                super::strict_utf8_head(
                    &iteron_record::redact::scrub(&answer),
                    iteron_protocol::agent_control::MAX_AGENT_TEXT_BYTES,
                )
            }
            Err(error) => error.public_summary(),
        };
        let summary = writer_terminal
            .as_ref()
            .and_then(|terminal| terminal.failure.as_ref())
            .cloned()
            .unwrap_or(summary);
        let cost_after = known_cost(&child.ledger.cost_state());
        let tokens = total_tokens(child.ledger.usage).saturating_sub(tokens_before);
        let cost = child.physical_cost().or_else(|| {
            child
                .usd_budget
                .is_none()
                .then(|| {
                    cost_before
                        .zip(cost_after)
                        .and_then(|(before, after)| after.checked_sub(before))
                })
                .flatten()
        });
        let terminal = match &result {
            Ok(iteron_protocol::Outcome::Done) if writer_succeeded => {
                iteron_agents::AgentWorkflowTerminal::Succeeded
            }
            Ok(iteron_protocol::Outcome::Interrupted | iteron_protocol::Outcome::Drained) => {
                iteron_agents::AgentWorkflowTerminal::Cancelled
            }
            _ => iteron_agents::AgentWorkflowTerminal::Failed,
        };
        let effects_known = cleaned
            && processes_settled
            && child.parent_effects_known()
            && finalized
            && writer_known
            && !matches!(
                result,
                Err(KernelError::UnknownEffects { .. }
                    | KernelError::Record(_)
                    | KernelError::AgentControl(_))
            );
        if effects_known && let Ok(mut completed) = self.completed_ledgers.lock() {
            let _ = completed.capture(
                view.agent_id,
                epoch,
                child.rollout.tenant(),
                child.rollout.run_id(),
                &child.ledger,
            );
        }
        AgentSettlement {
            turns: child.attempts(),
            terminal,
            summary,
            tokens,
            cost_microusd: cost.unwrap_or(0),
            effects_known,
            accounting_known: cost.is_some() && child.ledger.child_accounting_complete(),
        }
    }
}

fn known_cost(cost: &CostState) -> Option<u64> {
    match cost {
        CostState::Zero => Some(0),
        CostState::Known {
            amount_microusd, ..
        } => Some(*amount_microusd),
        CostState::Unknown { .. } => None,
    }
}

fn unknown_settlement(summary: &str) -> AgentSettlement {
    AgentSettlement {
        turns: 0,
        summary: summary.into(),
        tokens: 0,
        cost_microusd: 0,
        effects_known: false,
        accounting_known: false,
        terminal: iteron_agents::AgentWorkflowTerminal::StoppedRecovery,
    }
}

fn total_tokens(usage: iteron_protocol::Usage) -> u64 {
    usage
        .input
        .saturating_add(usage.output)
        .saturating_add(usage.cache_creation)
        .saturating_add(usage.cache_read)
        .saturating_add(usage.thinking)
}

pub(super) fn expire_restored(
    child: &mut Agent,
    mailbox: &LiveAgentMailbox,
) -> Result<(), KernelError> {
    let Some(mut messages) = child.transcript_state.restored().clone() else {
        return Ok(());
    };
    if !mailbox
        .expire_restored(&mut messages)
        .map_err(KernelError::AgentControl)?
    {
        return Ok(());
    }
    child.emit_durable(
        iteron_protocol::TurnId(child.seq_turn),
        EventKind::Compaction {
            messages: messages.clone(),
        },
    )?;
    child.transcript_state.replace_restored(Some(messages));
    child.context_estimator.invalidate_transcript();
    Ok(())
}

pub(super) fn expire_unrequested(
    child: &mut Agent,
    mailbox: &LiveAgentMailbox,
) -> Result<(), KernelError> {
    let Some(mut messages) = child.transcript_state.working().clone() else {
        return Ok(());
    };
    if !mailbox
        .expire_unrequested(&mut messages)
        .map_err(KernelError::AgentControl)?
    {
        return Ok(());
    }
    child.emit_durable(
        iteron_protocol::TurnId(child.seq_turn),
        EventKind::Compaction {
            messages: messages.clone(),
        },
    )?;
    child.transcript_state.replace_working(Some(messages));
    child.context_estimator.invalidate_transcript();
    Ok(())
}

impl Agent {
    /// Explicit composition entry point. No optional controller is initialized for ordinary turns.
    pub(crate) fn enable_persistent_agents(
        &mut self,
        config: AgentControllerConfig,
        parallel: usize,
    ) -> Result<(), KernelError> {
        if self.persistent_agents.is_some() {
            return Err(KernelError::AgentControl(ControllerError::Invalid(
                "persistent agents already enabled",
            )));
        }
        if !config
            .root_capabilities
            .is_subset_of(self.authority_ceiling.intersect(self.policy_capabilities))
        {
            return Err(KernelError::AgentControl(ControllerError::Permission));
        }
        let replay = self.capture_cohort_replay()?;
        if replay.forked && replay.installation.is_none() {
            return Err(KernelError::AgentControl(ControllerError::Invalid(
                "fork cohort ancestry lacks a durable installation locator",
            )));
        }
        let scope = self.provider_scope();
        let expected_origin = replay
            .installation
            .as_ref()
            .map(|installed| installed.origin.clone());
        let directory = self.runtime_state_dir.join(match &expected_origin {
            Some(origin) => origin.directory_component(),
            None => format!("agents-{}", self.subagent_run_id("controller", 0, 0).0),
        });
        // Fresh installation uses the same fully pinned/barrier-confirmed namespace as the
        // actual journal. An inherited locator opens existing-only and cannot create genesis.
        let mut journal = match &expected_origin {
            Some(_) => AgentFileJournal::open(&directory),
            None => AgentFileJournal::provision(&directory),
        }
        .map_err(|error| KernelError::AgentControl(ControllerError::Store(error)))?;
        let snapshot = iteron_agents::AgentControllerJournal::load(&mut journal)
            .map_err(|error| KernelError::AgentControl(ControllerError::Store(error)))?;
        if let Some(origin) = &expected_origin {
            let durable = snapshot
                .as_ref()
                .ok_or(KernelError::AgentControl(ControllerError::RecoveryRequired))?;
            if durable.cohort_origin() != Some(origin) || durable.config() != &config {
                return Err(KernelError::AgentControl(ControllerError::RequestConflict));
            }
        }
        let primary_scope = expected_origin
            .as_ref()
            .map_or_else(|| scope.clone(), |origin| origin.provider_scope());
        let existing = snapshot
            .as_ref()
            .map(|snapshot| snapshot.provider_budget_baseline(&primary_scope))
            .transpose()
            .map_err(KernelError::AgentControl)?
            .flatten();
        let financial_room = match &existing {
            Some(baseline) => baseline.financial_room_microusd,
            None => match &self.usd_budget {
                Some(parent) => parent
                    .remaining_microusd()
                    .map_err(KernelError::PricingLedger)?,
                None => config.root_budget.cost_microusd,
            },
        };
        let baseline = match &expected_origin {
            Some(_) => existing
                .clone()
                .ok_or(KernelError::AgentControl(ControllerError::RecoveryRequired))?,
            None => self.physical_provider_history_baseline(existing.as_ref(), financial_room)?,
        };
        // Existing cohort genesis never refills or tightens from a branch projection. Its durable
        // reservations govern all descendants; the current runtime/USD parents still enforce
        // this invocation's independently narrowed ceilings at every physical dispatch.
        if (expected_origin.is_none()
            && (config.root_budget.turns
                > self.budget.max_turns.saturating_sub(baseline.usage.turns)
                || self.budget.max_tokens.is_some_and(|limit| {
                    config.root_budget.tokens > limit.saturating_sub(baseline.usage.tokens)
                })
                || config.root_budget.wall_ms > self.budget.max_wall_secs.saturating_mul(1000)
                || self.budget.max_usd.is_some_and(|ceiling| {
                    config.root_budget.cost_microusd as f64 / 1_000_000.0
                        > (ceiling - baseline.usage.cost_microusd as f64 / 1_000_000.0).max(0.0)
                })
                || (existing.is_none()
                    && self.run_deadline.current().is_some_and(|deadline| {
                        config.root_budget.wall_ms as u128
                            > deadline
                                .saturating_duration_since(std::time::Instant::now())
                                .as_millis()
                    }))
                || config.root_budget.cost_microusd > baseline.financial_room_microusd))
            || parallel > config.max_agents
        {
            return Err(KernelError::AgentControl(ControllerError::Budget));
        }
        let route = self
            .provider_selection
            .selected()
            .ok_or(KernelError::InvalidRoute(
                "persistent agents need a durable selected route",
            ))?
            .route
            .clone();
        let mut context = self.kernel_spawner_context(&route, "persistent-agents");
        if let Some(origin) = &expected_origin {
            // Stable child runs retain the owning genesis namespace even while Main follows a fork.
            context.parent_run_id = origin.run_id.0.clone();
        }
        if config.root_budget.cost_microusd > 0 && context.pricing_port.is_none() {
            return Err(KernelError::InvalidRoute(
                "persistent agents with positive financial ceilings require verified route pricing",
            ));
        }
        context.usd_budget = Some(Arc::new(match &self.usd_budget {
            Some(parent) => {
                SharedUsdBudget::child(config.root_budget.cost_microusd, parent.clone())
                    .map_err(KernelError::PricingLedger)?
            }
            None => SharedUsdBudget::from_microusd(config.root_budget.cost_microusd),
        }));
        let runtime = Arc::new(KernelPersistentRuntime::new(context));
        let mut controller =
            AgentController::open(journal, config).map_err(KernelError::AgentControl)?;
        let baseline_sequence = baseline.through_sequence;
        controller
            .bind_provider_budget_baseline(&primary_scope, baseline)
            .map_err(KernelError::AgentControl)?;
        let origin = match expected_origin {
            Some(origin) => origin,
            None => iteron_protocol::agent_cohort::AgentCohortOriginV1 {
                version: iteron_protocol::agent_cohort::AGENT_COHORT_VERSION,
                tenant: self.rollout.tenant().clone(),
                run_id: self.rollout.run_id().clone(),
                config_sha256: controller
                    .snapshot()
                    .cohort_config_sha256()
                    .map_err(KernelError::AgentControl)?,
            },
        };
        controller
            .bind_cohort_origin(origin.clone())
            .map_err(KernelError::AgentControl)?;
        let root_id = controller.root_id();
        runtime.pin_main_rollouts(&controller, &self.runtime_state_dir, self.rollout.run_id())?;
        let root_path =
            super::cold_cohort::main_rollout_path(&self.runtime_state_dir, &origin.run_id);
        runtime.restore_provider_evidence(
            &mut controller,
            &root_path,
            &origin.tenant,
            &origin.run_id,
            baseline_sequence,
        )?;
        if *self.rollout.run_id() != origin.run_id {
            let existing_runs = controller.snapshot().cohort_main_runs();
            let existing_run = existing_runs.iter().find(|run| run.scope_sha256 == scope);
            let admission = replay.main_admission(
                self.rollout.tenant(),
                self.rollout.run_id(),
                existing_run,
            )?;
            controller
                .attach_cohort_main_run(admission)
                .map_err(KernelError::AgentControl)?;
        }
        self.publish_cohort_installation(origin)?;
        let host: Arc<dyn AgentControlPort> = Arc::new(
            PersistentAgentHost::new(controller, runtime.clone(), parallel)
                .map_err(KernelError::AgentControl)?,
        );
        runtime.bind(&host).map_err(KernelError::AgentControl)?;
        self.install_persistent_agents(host, root_id)
    }

    pub(super) fn install_persistent_agents(
        &mut self,
        control: Arc<dyn AgentControlPort>,
        actor: AgentIdV1,
    ) -> Result<(), KernelError> {
        register_agent_tools(&mut self.registry, control.clone(), actor).map_err(|_| {
            KernelError::AgentControl(ControllerError::Invalid("agent tools registration failed"))
        })?;
        self.persistent_agents = Some(control);

        Ok(())
    }

    fn persistent_control(&self) -> Result<&Arc<dyn AgentControlPort>, ControllerError> {
        self.persistent_agents
            .as_ref()
            .ok_or(ControllerError::Invalid(
                "persistent agents are disabled for this session",
            ))
    }

    pub(crate) fn persistent_agent_host_limits(
        &self,
    ) -> Result<super::persistent_agents::AgentHostLimits, ControllerError> {
        let mut limits = self.persistent_control()?.host_limits()?;
        limits.root.capabilities = limits
            .root
            .capabilities
            .intersect(self.authority_ceiling)
            .intersect(self.policy_capabilities);
        limits.remaining.turns = limits
            .remaining
            .turns
            .min(self.budget.remaining_turns(self.ledger.provider_attempts));
        if let Some(tokens) = self.remaining_provider_tokens() {
            limits.remaining.tokens = limits.remaining.tokens.min(tokens)
        }
        if let Some(parent) = &self.usd_budget {
            limits.remaining.cost_microusd = limits.remaining.cost_microusd.min(
                parent
                    .remaining_microusd()
                    .map_err(|_| ControllerError::RecoveryRequired)?,
            )
        }
        limits.remaining.wall_ms = limits
            .remaining
            .wall_ms
            .min(self.budget.max_wall_secs.saturating_mul(1000));
        if let Some(deadline) = self.run_deadline.current() {
            limits.remaining.wall_ms = limits.remaining.wall_ms.min(
                u64::try_from(
                    deadline
                        .saturating_duration_since(std::time::Instant::now())
                        .as_millis(),
                )
                .unwrap_or(u64::MAX),
            )
        }
        Ok(limits)
    }

    pub(crate) fn persistent_workflow_controller(
        &self,
    ) -> Result<Arc<dyn iteron_workflow::live_scheduler::WorkflowControllerPort>, ControllerError>
    {
        Ok(self.persistent_control()?.workflow_port())
    }
    pub(crate) fn persistent_workflow_completion(
        &self,
        task: &iteron_workflow::live_scheduler::ScheduledTaskV1,
    ) -> Result<Option<iteron_agents::AgentWorkflowCompletion>, ControllerError> {
        self.persistent_control()?.workflow_completion(task)
    }

    pub(crate) fn execute_agent_control(
        &self,
        request_id: &str,
        command: AgentCommandV1,
    ) -> Result<AgentControlReplyV1, ControllerError> {
        self.persistent_control()?
            .command(AgentActor::Operator, request_id, command)
    }
    pub(crate) fn list_persistent_agents(&self) -> Result<Vec<AgentViewV1>, ControllerError> {
        self.persistent_control()?.list(AgentActor::Operator)
    }
    pub(crate) fn inspect_persistent_agent(
        &self,
        id: AgentIdV1,
    ) -> Result<AgentViewV1, ControllerError> {
        self.persistent_control()?.inspect(AgentActor::Operator, id)
    }
    pub(crate) fn persistent_agent_message(
        &self,
        id: AgentMessageIdV1,
    ) -> Result<AgentMailboxMessage, ControllerError> {
        self.persistent_control()?.message(AgentActor::Operator, id)
    }
    pub(crate) async fn wait_persistent_agents(
        &self,
        revision: u64,
        timeout_ms: u64,
    ) -> Result<AgentObservation, ControllerError> {
        self.persistent_control()?
            .wait(AgentActor::Operator, revision, timeout_ms)
            .await
    }
}

fn register_agent_tools(
    registry: &mut iteron_tools::Registry,
    control: Arc<dyn AgentControlPort>,
    actor: AgentIdV1,
) -> Result<(), iteron_tools::ToolError> {
    for (name, capability) in [
        ("agent_control", Capability::ReadOnly),
        ("agent_task", Capability::IrreversibleExternal),
    ] {
        let control = Arc::downgrade(&control);
        registry.register_external(ToolSpec {
            name: name.into(), description: "Control an authorized persistent agent. The host binds sender identity; responses distinguish durable acceptance from request inclusion.".into(),
            input_schema: serde_json::json!({"type":"object","required":["request_id","command"],"properties":{"request_id":{"type":"string","minLength":1,"maxLength":128},"command":{"type":"object"}},"additionalProperties":false}),
            purity: Purity::Effecting, capability,
        }, move |call, _| {
            let control = control.clone();
            Box::pin(async move {
                let parsed = call.input.get("request_id").and_then(serde_json::Value::as_str)
                    .zip(call.input.get("command").cloned()).ok_or(ControllerError::Invalid("agent tool needs request_id and command"));
                let result = parsed.and_then(|(request, value)| {
                    let control = control.upgrade().ok_or(ControllerError::Closed)?;
                    let command: AgentCommandV1 = serde_json::from_value(value).map_err(|_| ControllerError::Invalid("agent command schema is invalid"))?;
                    let starts = matches!(command, AgentCommandV1::Spawn { .. } | AgentCommandV1::FollowupTask { .. });
                    if starts != (name == "agent_task") { return Err(ControllerError::Permission) }
                    control.command(AgentActor::Agent(actor), request, command).and_then(|reply| serde_json::to_value(reply).map_err(|_| ControllerError::Invalid("agent reply serialization failed")))
                });
                tool_result(call.id, result, Trust::Workspace)
            })
        })?;
    }
    for name in ["agent_inspect", "agent_message_receipt"] {
        let weak = Arc::downgrade(&control);
        registry.register_external(ToolSpec {
            name:name.into(),description:"Observe one authorized durable agent or message receipt. Accepted, Delivered and Consumed are distinct states.".into(),
            input_schema:serde_json::json!({"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1}},"additionalProperties":false}),
            purity:Purity::Effecting,capability:Capability::ReadOnly,
        },move|call,_| {
            let weak=weak.clone();
            Box::pin(async move {
                let result=(|| {
                    let control=weak.upgrade().ok_or(ControllerError::Closed)?;
                    let id=call.input.get("id").and_then(serde_json::Value::as_u64).filter(|id|*id>0).ok_or(ControllerError::Invalid("agent query id is invalid"))?;
                    if name=="agent_inspect" { serde_json::to_value(control.inspect(AgentActor::Agent(actor),AgentIdV1(id))?) }
                    else { serde_json::to_value(control.message(AgentActor::Agent(actor),AgentMessageIdV1(id))?) }
                    .map_err(|_|ControllerError::Invalid("agent query serialization failed"))
                })();
                tool_result(call.id,result, Trust::Untrusted)
            })
        })?;
    }
    let control_for_list = Arc::downgrade(&control);
    registry.register_external(ToolSpec {
        name: "agent_list".into(), description: "Observe current authorized agent state without polling a model.".into(),
        input_schema: serde_json::json!({"type":"object","properties":{},"additionalProperties":false}),
        purity: Purity::Effecting, capability: Capability::ReadOnly,
    }, move |call, _| {
        let control = control_for_list.clone();
        Box::pin(async move {
            let result = control.upgrade().ok_or(ControllerError::Closed)
                .and_then(|control| control.list(AgentActor::Agent(actor)))
                .and_then(|views| serde_json::to_value(views)
                    .map_err(|_| ControllerError::Invalid("agent view serialization failed")));
            tool_result(call.id, result, Trust::Untrusted)
        })
    })?;
    let control_for_wait = Arc::downgrade(&control);
    registry.register_external(ToolSpec {
        name: "agent_wait".into(), description: "Wait for a bounded agent state revision without spending another model request.".into(),
        input_schema: serde_json::json!({"type":"object","required":["after_revision","timeout_ms"],"properties":{"after_revision":{"type":"integer","minimum":0},"timeout_ms":{"type":"integer","minimum":1,"maximum":60000}},"additionalProperties":false}),
        purity: Purity::Effecting, capability: Capability::ReadOnly,
    }, move |call, _| {
        let control = control_for_wait.clone();
        Box::pin(async move {
            let result = match call.input.get("after_revision").and_then(serde_json::Value::as_u64).zip(call.input.get("timeout_ms").and_then(serde_json::Value::as_u64)) {
                Some((revision, timeout)) => match control.upgrade() {
                    Some(control) => control.wait(AgentActor::Agent(actor), revision, timeout).await.map(|observation| serde_json::json!({"revision":observation.revision,"agents":observation.agents,"timed_out":observation.timed_out})),
                    None => Err(ControllerError::Closed),
                },
                None => Err(ControllerError::Invalid("agent wait arguments are invalid")),
            };
            tool_result(call.id, result, Trust::Untrusted)
        })
    })
}

fn tool_result(
    id: String,
    result: Result<serde_json::Value, ControllerError>,
    success_trust: Trust,
) -> ToolResult {
    // Host receipt metadata and agent-authored payloads have different producers. Classify from
    // the typed tool path; never recognize an authority prefix or inspect model-authored JSON.
    let (content, is_error, trust) = match result {
        Ok(value) => (value.to_string(), false, success_trust),
        Err(error) => (error.to_string(), true, Trust::Workspace),
    };
    ToolResult {
        tool_use_id: id,
        content,
        is_error,
        trust,
        latency_ms: 0,
    }
}

#[cfg(test)]
mod tests;
