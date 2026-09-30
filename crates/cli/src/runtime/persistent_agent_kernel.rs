//! Adapter from the persistent controller's runtime port to real resident Iteron Agents.

use super::persistent_agents::{
    AgentControlPort, AgentObservation, AgentSettlement, LiveAgentMailbox, PersistentAgentHost,
    PersistentAgentRuntime,
};
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
use iteron_protocol::{Capability, EventKind, Op, Purity, ToolResult, ToolSpec, Trust};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

type Resident = Arc<tokio::sync::Mutex<Agent>>;

pub(super) struct KernelPersistentRuntime {
    spawner: Mutex<KernelSpawner>,
    residents: Mutex<BTreeMap<AgentIdV1, Resident>>,
    control: OnceLock<Weak<dyn AgentControlPort>>,
    writer: PersistentWriterConfig,
    money: Option<Arc<SharedUsdBudget>>,
    pricing: Option<Arc<dyn iteron_obs::PricingPort>>,
    #[cfg(test)]
    fixture: Option<Arc<dyn Fn(&mut Agent) + Send + Sync>>,
}

struct PersistentWriterConfig {
    parent: std::path::PathBuf,
    state: std::path::PathBuf,
    lock: Arc<tokio::sync::Mutex<()>>,
    verify: Option<String>,
    env: Vec<String>,
    oracle_tail: usize,
    admitted: bool,
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
            pricing: context.pricing_port.clone(),
            spawner: Mutex::new(KernelSpawner::new(context)),
            residents: Mutex::new(BTreeMap::new()),
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

    fn restore_monetary(&self, views: &[AgentViewV1], root: AgentIdV1) -> Result<(), KernelError> {
        let Some(pool) = &self.money else {
            return Ok(());
        };
        let spawner = self
            .spawner
            .lock()
            .map_err(|_| KernelError::AgentControl(ControllerError::Poisoned))?;
        for view in views
            .iter()
            .filter(|view| view.agent_id != root && view.usage.turns > 0)
        {
            if matches!(
                view.state,
                iteron_protocol::agent_control::AgentStateV1::RecoveryRequired { .. }
            ) {
                pool.mark_unknown()
            }
            let path = self
                .writer
                .state
                .join("subagents")
                .join(format!("{}.jsonl", spawner.mint_run_id(view.agent_id.0).0));
            if !path.exists() {
                return Err(KernelError::AgentControl(ControllerError::RecoveryRequired));
            }
            let scoped = super::replay_scoped_rollout(&path)?;
            let replay = super::route_attempt_accounting::replay_route_charges(
                &scoped,
                self.pricing.as_deref(),
            )?;
            pool.merge_recovered_charges(&replay.ledger)
                .map_err(KernelError::PricingLedger)?;
        }
        Ok(())
    }

    fn resident(
        &self,
        view: &AgentViewV1,
        writer_workspace: Option<&std::path::Path>,
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
            model: None,
            effort: None,
            agent_type: Some(if writer_workspace.is_some() {
                iteron_agents::ISOLATED_WRITER_NAME.into()
            } else {
                "generic".into()
            }),
            schema: None,
            cancel: Default::default(),
        };
        let mut child = self
            .spawner
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .build_persistent_child(&call, view, writer_workspace)
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
        _: AgentEpochV1,
        initial: Vec<AgentMailboxMessage>,
        mailbox: LiveAgentMailbox,
    ) -> AgentSettlement {
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
        let resident =
            match self.resident(&view, worktree.as_ref().map(PersistentWriterWorktree::path)) {
                Ok(resident) => resident,
                Err(_) => {
                    if let Some(worktree) = &mut worktree {
                        let _ = worktree.discard().await;
                    }
                    return AgentSettlement {
                        summary: "Persistent agent setup failed before provider execution".into(),
                        tokens: 0,
                        cost_microusd: 0,
                        effects_known: false,
                        terminal: iteron_agents::AgentWorkflowTerminal::Failed,
                    };
                }
            };
        let mut child = resident.lock().await;
        child.registry.invalidate_workspace_reads();
        // Descendant reservations remain unavailable to the parent's own provider requests.
        child.budget.max_turns = child
            .budget
            .max_turns
            .min(view.budget.turns.saturating_sub(view.reserved.turns));
        child.budget.max_tokens = Some(
            child
                .budget
                .max_tokens
                .unwrap_or(u64::MAX)
                .min(view.budget.tokens.saturating_sub(view.reserved.tokens)),
        );
        let cost_ceiling = view
            .budget
            .cost_microusd
            .saturating_sub(view.reserved.cost_microusd);
        child.budget.max_usd = Some(
            child
                .budget
                .max_usd
                .unwrap_or(f64::MAX)
                .min(cost_ceiling as f64 / 1_000_000.0),
        );
        let tokens_before = total_tokens(child.ledger.usage);
        let cost_before = known_cost(&child.ledger.cost_state());
        child.persistent_mailbox = Some(mailbox.clone());
        let stop = child
            .interrupt
            .clone()
            .unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicBool::new(false)));
        child.set_interrupt(stop.clone());
        stop.store(false, Ordering::Release);
        child.force_cancel.store(false, Ordering::Release);
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        child.set_inbound_control(rx);
        let task = match initial
            .iter()
            .map(|input| mailbox.render(input))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(texts) => texts.join("\n\n"),
            Err(_) => {
                return AgentSettlement {
                    summary: "Persistent mailbox rendering failed".into(),
                    tokens: 0,
                    cost_microusd: 0,
                    effects_known: false,
                    terminal: iteron_agents::AgentWorkflowTerminal::StoppedRecovery,
                };
            }
        };
        let mut started_before = child.ledger.provider_attempts > 0 || child.working_set.is_some();
        if !started_before && child.resumed.is_some() {
            started_before = true;
        }
        let result = {
            let execution = async {
                if started_before {
                    child.stage_follow_up_transcript().await?;
                    expire_restored(&mut child, &mailbox)?;
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
                                let Ok(text) = mailbox.render(&input) else {
                                    stop.store(true, Ordering::Release);
                                    break;
                                };
                                if tx
                                    .try_send(super::inbound_control::TurnSubmission::current(
                                        Op::Steer { text },
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
        child.approvals_rx = None;
        let cleaned = expire_unrequested(&mut child, &mailbox).is_ok();
        child.persistent_mailbox = None;
        let finalized = child.finalize_policy_run().is_ok();
        let writer_settled = if let Some(worktree) = &mut worktree {
            settle_writer(
                worktree,
                &self.writer,
                matches!(&result, Ok(iteron_protocol::Outcome::Done)),
                self.control.get().and_then(Weak::upgrade),
            )
            .await
            .is_ok()
        } else {
            true
        };
        let summary = match &result {
            Ok(outcome) => {
                let answer = child
                    .working_set
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
        let cost_after = known_cost(&child.ledger.cost_state());
        let tokens = total_tokens(child.ledger.usage).saturating_sub(tokens_before);
        let cost = cost_before
            .zip(cost_after)
            .and_then(|(before, after)| after.checked_sub(before));
        let terminal = match &result {
            Ok(iteron_protocol::Outcome::Done) if writer_settled => {
                iteron_agents::AgentWorkflowTerminal::Succeeded
            }
            Ok(iteron_protocol::Outcome::Interrupted | iteron_protocol::Outcome::Drained) => {
                iteron_agents::AgentWorkflowTerminal::Cancelled
            }
            _ => iteron_agents::AgentWorkflowTerminal::Failed,
        };
        AgentSettlement {
            terminal,
            summary,
            tokens,
            cost_microusd: cost.unwrap_or(0),
            effects_known: cleaned
                && finalized
                && writer_settled
                && cost.is_some()
                && !matches!(
                    result,
                    Err(KernelError::UnknownEffects { .. }
                        | KernelError::Record(_)
                        | KernelError::AgentControl(_))
                ),
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
        summary: summary.into(),
        tokens: 0,
        cost_microusd: 0,
        effects_known: false,
        terminal: iteron_agents::AgentWorkflowTerminal::StoppedRecovery,
    }
}
async fn settle_writer(
    worktree: &mut PersistentWriterWorktree,
    config: &PersistentWriterConfig,
    completed: bool,
    control: Option<Arc<dyn AgentControlPort>>,
) -> Result<(), ()> {
    if !completed {
        return worktree.discard().await.map_err(|_| ());
    }
    let receipt = worktree.prepare_patch().await.map_err(|_| ())?;
    if receipt.patch_bytes == 0 {
        return worktree.discard().await.map_err(|_| ());
    }
    worktree
        .verify(
            &receipt,
            config.verify.as_deref(),
            &config.env,
            config.oracle_tail,
        )
        .await
        .map_err(|_| ())?;
    let control = control.ok_or(())?;
    let witness = control.workspace_witness().map_err(|_| ())?.ok_or(())?;
    let next = worktree
        .merge(&receipt, witness.clone(), config.state.clone())
        .await
        .map_err(|_| ())?;
    control
        .record_workspace_witness(Some(&witness), next)
        .map_err(|_| ())
}

fn total_tokens(usage: iteron_protocol::Usage) -> u64 {
    usage
        .input
        .saturating_add(usage.output)
        .saturating_add(usage.cache_creation)
        .saturating_add(usage.cache_read)
        .saturating_add(usage.thinking)
}

fn expire_restored(child: &mut Agent, mailbox: &LiveAgentMailbox) -> Result<(), KernelError> {
    let Some(mut messages) = child.resumed.clone() else {
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
    child.resumed = Some(messages);
    child.context_estimator.invalidate_transcript();
    Ok(())
}

fn expire_unrequested(child: &mut Agent, mailbox: &LiveAgentMailbox) -> Result<(), KernelError> {
    let Some(mut messages) = child.working_set.clone() else {
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
    child.working_set = Some(messages);
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
        if config.root_budget.turns > self.budget.remaining_turns(self.seq_turn)
            || self.budget.max_tokens.is_some_and(|limit| {
                config.root_budget.tokens > limit.saturating_sub(total_tokens(self.ledger.usage))
            })
            || config.root_budget.wall_ms > self.budget.max_wall_secs.saturating_mul(1000)
            || self.budget.max_usd.is_some_and(|ceiling| {
                config.root_budget.cost_microusd as f64 / 1_000_000.0 > ceiling
            })
            || self.run_deadline.is_some_and(|deadline| {
                config.root_budget.wall_ms as u128
                    > deadline
                        .saturating_duration_since(std::time::Instant::now())
                        .as_millis()
            })
            || parallel > config.max_agents
        {
            return Err(KernelError::AgentControl(ControllerError::Budget));
        }
        let route = self
            .selected_route
            .as_ref()
            .ok_or(KernelError::InvalidRoute(
                "persistent agents need a durable selected route",
            ))?
            .route
            .clone();
        let mut context = self.kernel_spawner_context(&route, "persistent-agents");
        if config.root_budget.cost_microusd > 0 && context.pricing_port.is_none() {
            return Err(KernelError::InvalidRoute(
                "persistent agents with positive financial ceilings require verified route pricing",
            ));
        }
        context.usd_budget = Some(Arc::new(match &self.usd_budget {
            Some(parent) => {
                if config.root_budget.cost_microusd
                    > parent
                        .remaining_microusd()
                        .map_err(KernelError::PricingLedger)?
                {
                    return Err(KernelError::AgentControl(ControllerError::Budget));
                }
                SharedUsdBudget::child(config.root_budget.cost_microusd, parent.clone())
                    .map_err(KernelError::PricingLedger)?
            }
            None => SharedUsdBudget::from_microusd(config.root_budget.cost_microusd),
        }));
        let runtime = Arc::new(KernelPersistentRuntime::new(context));
        let directory = self.runtime_state_dir.join(format!(
            "agents-{}",
            self.subagent_run_id("controller", 0, 0).0
        ));
        provision_private_directory(&directory).map_err(KernelError::AgentControl)?;
        let journal = AgentFileJournal::open(&directory)
            .map_err(|error| KernelError::AgentControl(ControllerError::Store(error)))?;
        let controller =
            AgentController::open(journal, config).map_err(KernelError::AgentControl)?;
        let root_id = controller.root_id();
        runtime.restore_monetary(
            &controller
                .list(AgentActor::Operator)
                .map_err(KernelError::AgentControl)?,
            root_id,
        )?;
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
        if let Some(deadline) = self.run_deadline {
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

fn provision_private_directory(path: &std::path::Path) -> Result<(), ControllerError> {
    #[cfg(windows)]
    {
        return iteron_support::durable_windows_state::provision_private_directory(path)
            .map_err(|_| ControllerError::Permission);
    }
    #[cfg(not(windows))]
    {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                return Err(ControllerError::Invalid(
                    "private agent state directory could not be provisioned",
                ));
            }
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|_| {
            ControllerError::Invalid("private agent state directory is unavailable")
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ControllerError::Permission);
        }
        Ok(())
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
                tool_result(call.id, result)
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
                tool_result(call.id,result)
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
        Box::pin(async move { tool_result(call.id, control.upgrade().ok_or(ControllerError::Closed).and_then(|control| control.list(AgentActor::Agent(actor))).and_then(|views| serde_json::to_value(views).map_err(|_| ControllerError::Invalid("agent view serialization failed")))) })
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
            tool_result(call.id, result)
        })
    })
}

fn tool_result(id: String, result: Result<serde_json::Value, ControllerError>) -> ToolResult {
    let (content, is_error) = match result {
        Ok(value) => (value.to_string(), false),
        Err(error) => (error.to_string(), true),
    };
    ToolResult {
        tool_use_id: id,
        content,
        is_error,
        trust: Trust::Workspace,
        latency_ms: 0,
    }
}

#[cfg(test)]
mod tests;
