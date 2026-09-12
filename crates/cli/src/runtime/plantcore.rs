use super::Agent;
use iteron_protocol::{
    ArtifactDeclaration, FiveClassUsage, Metering, MeteringPolicySnapshot, PlantcoreRunBootstrapV1,
    PlantcoreTerminalOutcome, ProductResult, ProviderRouteAttemptAccounting,
    ProviderRouteUsageTruth, ProviderRouteUsageUnknownReason, Question, TurnUsage,
    UsageUnavailableReason,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[cfg(test)]
use iteron_protocol::FiveClassCeilPolicyV1;

#[derive(Debug, Default)]
pub(super) struct PlantcoreRuntime {
    enabled: bool,
    run_id: Option<String>,
    output_root: Option<PathBuf>,
    artifact_policy: Option<iteron_protocol::ArtifactPolicy>,
    conversation_segments: Vec<iteron_protocol::ConversationSegment>,
    product_result: Option<ProductResult>,
    artifacts: Vec<ArtifactDeclaration>,
    turns: BTreeMap<u64, TurnUsageAccumulator>,
    cumulative_usage: FiveClassUsage,
    metering_policy: Option<MeteringPolicySnapshot>,
    limits: Option<iteron_protocol::EffectiveRunLimits>,
    absorbing_reasons: BTreeSet<UsageUnavailableReason>,
    pending_terminal: Option<PlantcoreTerminal>,
    dispatch_gate: Option<Arc<DispatchGate>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchGatePhase {
    NotAdmitted,
    Open,
    PauseRequested,
    Paused,
    ResumePending(u64),
    Terminal,
}

#[derive(Debug)]
struct DispatchGateState {
    phase: DispatchGatePhase,
    in_flight: usize,
    next_resume_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResumeActivation(u64);

/// One reversible dispatch authority shared by the PlantCore transport and every external-call
/// entrance owned by the resident runtime. It carries no Control connection or reconnect state.
#[derive(Debug)]
pub(crate) struct DispatchGate {
    state: Mutex<DispatchGateState>,
    changed: Notify,
    recording_pause_checkpoint: Option<PathBuf>,
}

impl DispatchGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(DispatchGateState {
                phase: DispatchGatePhase::NotAdmitted,
                in_flight: 0,
                next_resume_generation: 0,
            }),
            changed: Notify::new(),
            recording_pause_checkpoint: std::env::var_os("ITERON_RECORDING_PAUSE_CHECKPOINT")
                .map(PathBuf::from),
        })
    }

    pub(crate) fn admit(&self) -> Result<(), &'static str> {
        let mut state = self.state.lock().expect("dispatch gate mutex poisoned");
        if state.phase != DispatchGatePhase::NotAdmitted {
            return Err("dispatch gate was already admitted");
        }
        state.phase = DispatchGatePhase::Open;
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    pub(crate) async fn pause_after_safe_point(&self) -> Result<(), &'static str> {
        loop {
            let changed = self.changed.notified();
            let (pending, pause_requested) = {
                let mut state = self.state.lock().expect("dispatch gate mutex poisoned");
                match state.phase {
                    DispatchGatePhase::NotAdmitted => return Err("run_not_admitted"),
                    DispatchGatePhase::Terminal => return Err("session_terminal"),
                    DispatchGatePhase::Paused => return Ok(()),
                    DispatchGatePhase::Open if state.in_flight == 0 => {
                        state.phase = DispatchGatePhase::Paused;
                        (false, false)
                    }
                    DispatchGatePhase::Open => {
                        state.phase = DispatchGatePhase::PauseRequested;
                        (true, true)
                    }
                    DispatchGatePhase::PauseRequested => (true, false),
                    DispatchGatePhase::ResumePending(_) => {
                        return Err("dispatch_resume_pending");
                    }
                }
            };
            if pause_requested {
                self.record_pause_requested()?;
            }
            if !pending {
                self.changed.notify_waiters();
                return Ok(());
            }
            changed.await;
        }
    }

    fn record_pause_requested(&self) -> Result<(), &'static str> {
        let Some(bridge) = self.recording_bridge()? else {
            return Ok(());
        };
        let path = bridge.join("iteron.dispatch-pause-requested");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| "recording_pause_checkpoint_failed")?;
        file.write_all(b"observed\n")
            .map_err(|_| "recording_pause_checkpoint_failed")?;
        file.sync_all()
            .map_err(|_| "recording_pause_checkpoint_failed")
    }

    fn recording_bridge(&self) -> Result<Option<&Path>, &'static str> {
        let Some(path) = &self.recording_pause_checkpoint else {
            return Ok(None);
        };
        if path != Path::new("/run/plantcore/bridge/iteron.dispatch-pause-requested") {
            return Err("recording_pause_checkpoint_invalid");
        }
        path.parent()
            .map(Some)
            .ok_or("recording_pause_checkpoint_invalid")
    }

    pub(super) async fn await_recording_provider_usage_settled(&self) -> Result<(), &'static str> {
        let Some(bridge) = self.recording_bridge()? else {
            return Ok(());
        };
        self.await_recording_provider_usage_settled_in(bridge).await
    }

    async fn await_recording_provider_usage_settled_in(
        &self,
        bridge: &Path,
    ) -> Result<(), &'static str> {
        let enabled = bridge.join("iteron.provider-usage-settled.enabled");
        match std::fs::symlink_metadata(&enabled) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Ok(metadata) if metadata.file_type().is_file() => {}
            _ => return Err("recording_provider_usage_settled_enable_invalid"),
        }

        let checkpoint = bridge.join("iteron.provider-usage-settled");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(checkpoint)
            .map_err(|_| "recording_provider_usage_settled_checkpoint_failed")?;
        file.write_all(b"observed\n")
            .map_err(|_| "recording_provider_usage_settled_checkpoint_failed")?;
        file.sync_all()
            .map_err(|_| "recording_provider_usage_settled_checkpoint_failed")?;

        let release = bridge.join("iteron.provider-usage-settled.release");
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                match std::fs::symlink_metadata(&release) {
                    Ok(metadata) if metadata.file_type().is_file() => return Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err("recording_provider_usage_settled_release_invalid"),
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "recording_provider_usage_settled_release_timeout")?
    }

    pub(crate) fn prepare_resume(&self) -> Result<ResumeActivation, &'static str> {
        let mut state = self.state.lock().expect("dispatch gate mutex poisoned");
        match state.phase {
            DispatchGatePhase::Paused => {}
            DispatchGatePhase::Terminal => return Err("session_terminal"),
            DispatchGatePhase::NotAdmitted => return Err("run_not_admitted"),
            DispatchGatePhase::Open
            | DispatchGatePhase::PauseRequested
            | DispatchGatePhase::ResumePending(_) => {
                return Err("dispatch_gate_not_paused");
            }
        }
        state.next_resume_generation = state
            .next_resume_generation
            .checked_add(1)
            .ok_or("dispatch_resume_generation_exhausted")?;
        let activation = ResumeActivation(state.next_resume_generation);
        state.phase = DispatchGatePhase::ResumePending(activation.0);
        Ok(activation)
    }

    pub(crate) fn activate_resume(&self, activation: ResumeActivation) -> Result<(), &'static str> {
        let mut state = self.state.lock().expect("dispatch gate mutex poisoned");
        match state.phase {
            DispatchGatePhase::ResumePending(generation) if generation == activation.0 => {
                state.phase = DispatchGatePhase::Open;
            }
            DispatchGatePhase::Open => return Ok(()),
            DispatchGatePhase::Terminal => return Err("session_terminal"),
            DispatchGatePhase::NotAdmitted => return Err("run_not_admitted"),
            DispatchGatePhase::PauseRequested
            | DispatchGatePhase::Paused
            | DispatchGatePhase::ResumePending(_) => return Err("dispatch_resume_not_pending"),
        }
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    pub(crate) fn terminal(&self) {
        let mut state = self.state.lock().expect("dispatch gate mutex poisoned");
        state.phase = DispatchGatePhase::Terminal;
        drop(state);
        self.changed.notify_waiters();
    }

    pub(crate) fn terminalize_if_accepted<T, E>(
        &self,
        submit: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, &'static str> {
        let mut state = self.state.lock().expect("dispatch gate mutex poisoned");
        match state.phase {
            DispatchGatePhase::NotAdmitted => return Err("run_not_admitted"),
            DispatchGatePhase::Terminal => return Err("session_terminal"),
            DispatchGatePhase::Open
            | DispatchGatePhase::PauseRequested
            | DispatchGatePhase::Paused
            | DispatchGatePhase::ResumePending(_) => {}
        }
        let result = submit();
        if result.is_ok() {
            state.phase = DispatchGatePhase::Terminal;
        }
        drop(state);
        if result.is_ok() {
            self.changed.notify_waiters();
        }
        Ok(result)
    }

    pub(crate) fn submit_if_admitted<T, E>(
        &self,
        submit: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, &'static str> {
        let state = self.state.lock().expect("dispatch gate mutex poisoned");
        match state.phase {
            DispatchGatePhase::NotAdmitted => return Err("run_not_admitted"),
            DispatchGatePhase::Terminal => return Err("session_terminal"),
            DispatchGatePhase::Open
            | DispatchGatePhase::PauseRequested
            | DispatchGatePhase::Paused
            | DispatchGatePhase::ResumePending(_) => {}
        }
        Ok(submit())
    }

    pub(super) async fn enter(self: &Arc<Self>) -> Option<DispatchPermit> {
        loop {
            let changed = self.changed.notified();
            {
                let mut state = self.state.lock().expect("dispatch gate mutex poisoned");
                match state.phase {
                    DispatchGatePhase::Open => {
                        state.in_flight = state.in_flight.checked_add(1)?;
                        return Some(DispatchPermit { gate: self.clone() });
                    }
                    DispatchGatePhase::PauseRequested
                    | DispatchGatePhase::Paused
                    | DispatchGatePhase::ResumePending(_) => {}
                    DispatchGatePhase::NotAdmitted | DispatchGatePhase::Terminal => return None,
                }
            }
            changed.await;
        }
    }
}

#[derive(Debug)]
pub(super) struct DispatchPermit {
    gate: Arc<DispatchGate>,
}

impl Drop for DispatchPermit {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .expect("dispatch gate mutex poisoned");
        state.in_flight = state
            .in_flight
            .checked_sub(1)
            .expect("dispatch permits are balanced");
        let paused = state.in_flight == 0 && state.phase == DispatchGatePhase::PauseRequested;
        if paused {
            state.phase = DispatchGatePhase::Paused;
        }
        drop(state);
        if paused {
            self.gate.changed.notify_waiters();
        }
    }
}

#[derive(Debug, Default)]
struct TurnUsageAccumulator {
    dispatched_attempt_count: u64,
    counters: FiveClassUsage,
    reasons: BTreeSet<UsageUnavailableReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlantcoreTerminal {
    Budget(&'static str),
    UsageUnavailable,
}

impl Agent {
    pub(crate) fn arm_recording_harness_error(&mut self) {
        self.recording_harness_error_armed = true;
    }

    pub(crate) fn install_plantcore_dispatch_gate(&mut self, gate: Arc<DispatchGate>) {
        self.plantcore.dispatch_gate = Some(gate);
    }

    pub(super) fn plantcore_dispatch_gate(&self) -> Option<Arc<DispatchGate>> {
        self.plantcore.dispatch_gate.clone()
    }

    pub(super) fn is_plantcore_mcp_dispatch(&self, name: &str) -> bool {
        self.registry.is_mcp_effect(name)
            || self.plantcore_runtime_enabled() && name == "plantcore-run-gateway__tool_search"
    }

    pub(super) async fn enter_plantcore_external_dispatch(
        &self,
    ) -> Result<Option<DispatchPermit>, ()> {
        match self.plantcore.dispatch_gate.as_ref() {
            Some(gate) => gate.enter().await.map(Some).ok_or(()),
            None => Ok(None),
        }
    }

    pub(super) async fn cross_plantcore_logical_turn_gate(&self) -> Result<(), ()> {
        drop(self.enter_plantcore_external_dispatch().await?);
        Ok(())
    }

    pub(crate) fn terminalize_plantcore_dispatch_gate(&self) {
        if let Some(gate) = &self.plantcore.dispatch_gate {
            gate.terminal();
        }
    }

    pub(crate) fn plantcore_runtime_enabled(&self) -> bool {
        self.plantcore.enabled
    }

    pub(crate) fn plantcore_conversation_segments(
        &self,
    ) -> &[iteron_protocol::ConversationSegment] {
        &self.plantcore.conversation_segments
    }

    pub(crate) fn enable_plantcore_runtime(
        &mut self,
        payload: &PlantcoreRunBootstrapV1,
    ) -> Result<(), &'static str> {
        if self.injected.is_some() {
            return Err("Agent context was already resolved");
        }
        let dispatch_gate = self.plantcore.dispatch_gate.clone();
        self.plantcore = PlantcoreRuntime {
            enabled: true,
            run_id: Some(payload.run_id.clone()),
            output_root: Some(PathBuf::from(&payload.workspace.output)),
            artifact_policy: Some(payload.artifact_policy.clone()),
            conversation_segments: payload.conversation_segments.clone(),
            product_result: None,
            artifacts: Vec::new(),
            turns: BTreeMap::new(),
            cumulative_usage: FiveClassUsage::default(),
            metering_policy: payload.metering_policy.clone(),
            limits: Some(payload.limits.clone()),
            absorbing_reasons: BTreeSet::new(),
            pending_terminal: None,
            dispatch_gate,
        };
        // Sole-call enforcement cannot coexist with speculative mid-stream tool execution: the
        // complete response is the authority for whether request_user_input was alone.
        self.pure_overlap_enabled = false;
        // PlantCore owns the complete provider-visible profile. Startup may have discovered
        // ordinary CLI context before the resident bootstrap arrived; none of it may supplement
        // the immutable AgentRuntimeProfile or turn typed continuation facts into prompt text.
        self.instruction_context = Some((String::new(), iteron_protocol::Trust::Trusted));
        self.composition_instruction_context = self.instruction_context.clone();
        self.environment_context = None;
        self.composition_environment_context = None;
        self.memory_workspace = None;
        self.context_home_dir = None;
        self.dependency_skill_dirs.clear();
        self.injected = Some(String::new());
        self.injected_trust = Some(iteron_protocol::Trust::Trusted);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_plantcore_bootstrap_append_for_test(&mut self) {
        self.fail_next_durable_append = Some(super::DurableAppendFault::TurnCeiling);
    }

    pub(crate) fn take_product_result(&mut self) -> Option<ProductResult> {
        self.plantcore.product_result.take()
    }

    pub(super) fn complete_plantcore_product(&mut self) -> Result<(), &'static str> {
        if !self.plantcore.enabled {
            return Ok(());
        }
        if let Some(policy) = &self.plantcore.artifact_policy {
            validate_required_artifacts(policy, &self.plantcore.artifacts)?;
        }
        if self.plantcore.product_result.is_some() {
            return Ok(());
        }
        let product = completed_product(&self.run_assistant_text, &self.plantcore.artifacts);
        validate_product_result(&product)?;
        self.plantcore.product_result = Some(product);
        Ok(())
    }

    pub(super) fn observe_plantcore_provider_attempt(
        &mut self,
        turn: iteron_protocol::TurnId,
        accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), &'static str> {
        if !self.plantcore.enabled {
            return Ok(());
        }
        let turn_number = u64::from(turn.0);
        if turn_number == 0 {
            return Err("PlantCore provider turn must be positive");
        }
        record_provider_attempt(&mut self.plantcore, turn_number, accounting)
    }

    pub(super) fn plantcore_terminal(&self) -> Option<PlantcoreTerminal> {
        self.plantcore.pending_terminal
    }

    pub(super) fn close_plantcore_turn_usage(
        &mut self,
        turn: iteron_protocol::TurnId,
    ) -> Result<Option<TurnUsage>, &'static str> {
        if !self.plantcore.enabled {
            return Ok(None);
        }
        let turn_number = u64::from(turn.0);
        if turn_number == 0 {
            return Err("PlantCore provider turn must be positive");
        }
        close_turn_usage(&mut self.plantcore, turn_number)
    }

    pub(super) fn emit_plantcore_turn_usage(
        &mut self,
        turn: iteron_protocol::TurnId,
    ) -> Result<(), super::KernelError> {
        if let Some(usage) = self
            .close_plantcore_turn_usage(turn)
            .map_err(|reason| super::KernelError::ContextResolution(reason.into()))?
        {
            self.ui(super::UiEvent::PlantcoreUsage(usage));
        }
        Ok(())
    }

    pub(super) fn request_plantcore_input(
        &mut self,
        tool_use_id: &str,
        prompt_utf8: String,
    ) -> Result<(), &'static str> {
        if !self.plantcore.enabled {
            return Err("request_user_input is available only in an admitted PlantCore Run");
        }
        if prompt_utf8.is_empty() || prompt_utf8.len() > iteron_protocol::MAX_QUESTION_PROMPT_BYTES
        {
            return Err("prompt_utf8 must contain 1 through 65536 UTF-8 bytes");
        }
        let run_id = self
            .plantcore
            .run_id
            .as_deref()
            .ok_or("PlantCore Run identity is absent")?;
        let artifact_policy = self
            .plantcore
            .artifact_policy
            .as_ref()
            .ok_or("PlantCore artifact policy is absent")?;
        validate_required_artifacts(artifact_policy, &self.plantcore.artifacts)?;
        let question = build_question(run_id, tool_use_id, prompt_utf8);
        question.validate()?;
        let result = ProductResult::NeedsInput {
            assistant_text: self.run_assistant_text.clone(),
            question,
            artifacts: self.plantcore.artifacts.clone(),
        };
        validate_product_result(&result)?;
        self.plantcore.product_result = Some(result);
        Ok(())
    }

    pub(super) fn request_plantcore_input_from_value(
        &mut self,
        tool_use_id: &str,
        input: serde_json::Value,
    ) -> Result<(), String> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Arguments {
            prompt_utf8: String,
        }
        let arguments: Arguments = serde_json::from_value(input)
            .map_err(|error| format!("invalid request_user_input arguments: {error}"))?;
        self.request_plantcore_input(tool_use_id, arguments.prompt_utf8)
            .map_err(str::to_owned)
    }

    pub(super) fn add_plantcore_artifact(
        &mut self,
        artifact: ArtifactDeclaration,
    ) -> Result<(), &'static str> {
        if !self.plantcore.enabled {
            return Err("publish_artifact is available only in an admitted PlantCore Run");
        }
        let policy = self
            .plantcore
            .artifact_policy
            .as_ref()
            .ok_or("PlantCore artifact policy is absent")?;
        insert_artifact(&mut self.plantcore.artifacts, policy, artifact)
    }

    pub(super) async fn snapshot_plantcore_artifact(
        &mut self,
        input: serde_json::Value,
    ) -> Result<ArtifactDeclaration, String> {
        if !self.plantcore.enabled {
            return Err("publish_artifact is available only in an admitted PlantCore Run".into());
        }
        let arguments: PublishArtifactArguments = serde_json::from_value(input)
            .map_err(|error| format!("invalid publish_artifact arguments: {error}"))?;
        validate_artifact_arguments(&arguments)?;
        let output_root = self
            .plantcore
            .output_root
            .clone()
            .ok_or_else(|| "PlantCore output root is unavailable".to_owned())?;
        let artifact_policy = self
            .plantcore
            .artifact_policy
            .clone()
            .ok_or_else(|| "PlantCore artifact policy is unavailable".to_owned())?;
        let existing_artifacts = self.plantcore.artifacts.clone();
        let artifact = tokio::task::spawn_blocking(move || {
            snapshot_artifact(
                &output_root,
                arguments,
                &artifact_policy,
                &existing_artifacts,
            )
        })
        .await
        .map_err(|_| "artifact snapshot worker stopped unexpectedly".to_owned())??;
        self.add_plantcore_artifact(artifact.clone())
            .map_err(str::to_owned)?;
        Ok(artifact)
    }
}

fn record_provider_attempt(
    runtime: &mut PlantcoreRuntime,
    turn_number: u64,
    accounting: &ProviderRouteAttemptAccounting,
) -> Result<(), &'static str> {
    let accumulator = runtime.turns.entry(turn_number).or_default();
    match accounting.usage {
        ProviderRouteUsageTruth::NotDispatched => return Ok(()),
        ProviderRouteUsageTruth::Known { usage } => {
            accumulator.dispatched_attempt_count = accumulator
                .dispatched_attempt_count
                .checked_add(1)
                .ok_or("PlantCore attempt count overflowed")?;
            add_usage(&mut accumulator.counters, usage)?;
            add_usage(&mut runtime.cumulative_usage, usage)?;
        }
        ProviderRouteUsageTruth::Unknown { reason } => {
            accumulator.dispatched_attempt_count = accumulator
                .dispatched_attempt_count
                .checked_add(1)
                .ok_or("PlantCore attempt count overflowed")?;
            accumulator.reasons.insert(match reason {
                ProviderRouteUsageUnknownReason::ProviderOmitted => {
                    UsageUnavailableReason::ProviderOmitted
                }
                ProviderRouteUsageUnknownReason::CacheCreationUnreported => {
                    UsageUnavailableReason::CacheCreationUnreported
                }
                ProviderRouteUsageUnknownReason::ProvenFailureWithoutUsage => {
                    UsageUnavailableReason::ProvenFailureWithoutUsage
                }
                ProviderRouteUsageUnknownReason::OutcomeUnobservable => {
                    UsageUnavailableReason::OutcomeUnobservable
                }
            });
        }
    }
    refresh_terminal(runtime)
}

fn refresh_terminal(runtime: &mut PlantcoreRuntime) -> Result<(), &'static str> {
    let Some(limits) = runtime.limits.as_ref() else {
        return Ok(());
    };
    if runtime.turns.values().any(|turn| !turn.reasons.is_empty())
        && (limits.max_tokens.is_some() || limits.max_usd_micros.is_some())
    {
        runtime.pending_terminal = Some(PlantcoreTerminal::UsageUnavailable);
        return Ok(());
    }
    let tokens = runtime
        .cumulative_usage
        .total_tokens()
        .ok_or("PlantCore cumulative token total overflowed")?;
    if limits.max_tokens.is_some_and(|limit| tokens >= limit) {
        runtime.pending_terminal = Some(PlantcoreTerminal::Budget("max_tokens"));
        return Ok(());
    }
    if let (Some(limit), Some(policy)) = (limits.max_usd_micros, runtime.metering_policy.as_ref()) {
        let amount = metered_amount(&runtime.cumulative_usage, policy)?;
        if amount >= limit {
            runtime.pending_terminal = Some(PlantcoreTerminal::Budget("max_usd"));
        }
    }
    Ok(())
}

fn close_turn_usage(
    runtime: &mut PlantcoreRuntime,
    turn_number: u64,
) -> Result<Option<TurnUsage>, &'static str> {
    let Some(mut accumulator) = runtime.turns.remove(&turn_number) else {
        return Ok(None);
    };
    if accumulator.dispatched_attempt_count == 0 {
        return Ok(None);
    }
    runtime.absorbing_reasons.append(&mut accumulator.reasons);
    if !runtime.absorbing_reasons.is_empty() {
        return Ok(Some(TurnUsage::Unavailable {
            turn: turn_number,
            dispatched_attempt_count: accumulator.dispatched_attempt_count,
            reasons: runtime.absorbing_reasons.iter().copied().collect(),
        }));
    }
    accumulator.counters.validate()?;
    let cumulative_metering = runtime
        .metering_policy
        .as_ref()
        .map(|policy| {
            Ok::<Metering, &'static str>(Metering {
                policy_version: policy.version.clone(),
                policy_digest_sha256: policy.policy_digest_sha256.into_bytes(),
                calculator_contract_version: policy.calculator_contract_version.clone(),
                cumulative_amount: metered_amount(&runtime.cumulative_usage, policy)?,
            })
        })
        .transpose()?;
    Ok(Some(TurnUsage::Complete {
        turn: turn_number,
        dispatched_attempt_count: accumulator.dispatched_attempt_count,
        counters: accumulator.counters,
        cumulative_metering,
    }))
}

fn completed_product(assistant_text: &str, artifacts: &[ArtifactDeclaration]) -> ProductResult {
    ProductResult::Completed {
        assistant_text: assistant_text.to_owned(),
        artifacts: artifacts.to_vec(),
    }
}

fn validate_product_result(product: &ProductResult) -> Result<(), &'static str> {
    product.validate()?;
    crate::output::v7_result(&PlantcoreTerminalOutcome::Done(product.clone()))
        .map(|_| ())
        .map_err(|_| "product result exceeds the canonical v7 event limit")
}

fn insert_artifact(
    artifacts: &mut Vec<ArtifactDeclaration>,
    policy: &iteron_protocol::ArtifactPolicy,
    artifact: ArtifactDeclaration,
) -> Result<(), &'static str> {
    artifact.validate()?;
    if artifacts.contains(&artifact) {
        return Ok(());
    }
    if artifacts.iter().any(|existing| {
        existing.logical_name == artifact.logical_name
            && existing.relative_path == artifact.relative_path
            && existing != &artifact
    }) {
        return Err("artifact declaration conflicts with an earlier declaration");
    }
    validate_artifact_against_policy(policy, &artifact)?;
    if artifacts.len() >= policy.max_artifact_count as usize {
        return Err("artifact declaration count exceeds the admitted policy");
    }
    let total = artifacts
        .iter()
        .try_fold(artifact.size_bytes, |total, existing| {
            total.checked_add(existing.size_bytes)
        });
    if total.is_none_or(|total| total > policy.max_total_artifact_bytes) {
        return Err("artifact declaration bytes exceed the admitted total policy");
    }
    artifacts.push(artifact);
    Ok(())
}

fn validate_artifact_against_policy(
    policy: &iteron_protocol::ArtifactPolicy,
    artifact: &ArtifactDeclaration,
) -> Result<(), &'static str> {
    if artifact.size_bytes > policy.max_artifact_bytes {
        return Err("artifact size exceeds the admitted per-artifact policy");
    }
    for requirement in &policy.required_artifacts {
        let name_matches = requirement.logical_name == artifact.logical_name;
        let path_matches = requirement.relative_path == artifact.relative_path;
        if name_matches || path_matches {
            if !name_matches
                || !path_matches
                || artifact.size_bytes > requirement.max_size_bytes
                || !requirement
                    .allowed_media_types
                    .contains(&artifact.media_type)
            {
                return Err("artifact declaration does not match its admitted requirement");
            }
            break;
        }
    }
    Ok(())
}

fn validate_required_artifacts(
    policy: &iteron_protocol::ArtifactPolicy,
    artifacts: &[ArtifactDeclaration],
) -> Result<(), &'static str> {
    if policy.required_artifacts.iter().all(|requirement| {
        artifacts.iter().any(|artifact| {
            artifact.logical_name == requirement.logical_name
                && artifact.relative_path == requirement.relative_path
                && artifact.size_bytes <= requirement.max_size_bytes
                && requirement
                    .allowed_media_types
                    .contains(&artifact.media_type)
        })
    }) {
        Ok(())
    } else {
        Err("required PlantCore artifacts were not published")
    }
}

fn build_question(run_id: &str, tool_use_id: &str, prompt_utf8: String) -> Question {
    let mut material = Vec::with_capacity(run_id.len() + tool_use_id.len() + 48);
    material.extend_from_slice(b"plantcore.iteron.question.v1\0");
    material.extend_from_slice(&(run_id.len() as u32).to_be_bytes());
    material.extend_from_slice(run_id.as_bytes());
    material.extend_from_slice(&(tool_use_id.len() as u32).to_be_bytes());
    material.extend_from_slice(tool_use_id.as_bytes());
    Question {
        question_id: format!("iteron-question-{}", lower_hex(&Sha256::digest(&material))),
        prompt_sha256: Sha256::digest(prompt_utf8.as_bytes()).into(),
        prompt_utf8,
    }
}

fn add_usage(
    target: &mut FiveClassUsage,
    usage: iteron_protocol::Usage,
) -> Result<(), &'static str> {
    target.input_tokens = target
        .input_tokens
        .checked_add(usage.input)
        .ok_or("input token counter overflowed")?;
    target.output_tokens = target
        .output_tokens
        .checked_add(usage.output)
        .ok_or("output token counter overflowed")?;
    target.cache_creation_tokens = target
        .cache_creation_tokens
        .checked_add(usage.cache_creation)
        .ok_or("cache creation token counter overflowed")?;
    target.cache_read_tokens = target
        .cache_read_tokens
        .checked_add(usage.cache_read)
        .ok_or("cache read token counter overflowed")?;
    target.thinking_tokens = target
        .thinking_tokens
        .checked_add(usage.thinking)
        .ok_or("thinking token counter overflowed")?;
    target.validate()
}

fn metered_amount(
    usage: &FiveClassUsage,
    policy: &MeteringPolicySnapshot,
) -> Result<u64, &'static str> {
    usage.validate()?;
    let rates = &policy.five_class_ceil_v1;
    let non_thinking_output = usage
        .output_tokens
        .checked_sub(usage.thinking_tokens)
        .ok_or("thinking tokens exceed output tokens")?;
    let classes = [
        (usage.input_tokens, rates.input_units_per_million),
        (non_thinking_output, rates.output_units_per_million),
        (
            usage.cache_creation_tokens,
            rates.cache_creation_units_per_million,
        ),
        (usage.cache_read_tokens, rates.cache_read_units_per_million),
        (usage.thinking_tokens, rates.thinking_units_per_million),
    ];
    let mut total = 0_u128;
    for (tokens, rate) in classes {
        let product = u128::from(tokens)
            .checked_mul(u128::from(rate))
            .ok_or("PlantCore metering multiplication overflowed")?;
        let amount = product
            .checked_add(999_999)
            .ok_or("PlantCore metering rounding overflowed")?
            / 1_000_000;
        total = total
            .checked_add(amount)
            .ok_or("PlantCore metering total overflowed")?;
    }
    u64::try_from(total).map_err(|_| "PlantCore metering total exceeds u64")
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishArtifactArguments {
    logical_name: String,
    relative_path: String,
    media_type: String,
}

fn validate_artifact_arguments(input: &PublishArtifactArguments) -> Result<(), String> {
    let provisional = ArtifactDeclaration {
        logical_name: input.logical_name.clone(),
        relative_path: input.relative_path.clone(),
        media_type: input.media_type.clone(),
        size_bytes: 0,
        content_sha256: [0; 32],
    };
    provisional.validate().map_err(str::to_owned)?;
    let path = std::path::Path::new(&input.relative_path);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || path
            .components()
            .any(|component| component.as_os_str() == ".plantcore-staging")
    {
        return Err(
            "relative_path must stay beneath /workspace/output and outside .plantcore-staging"
                .into(),
        );
    }
    Ok(())
}

static NEXT_SNAPSHOT: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
fn snapshot_artifact(
    output_root: &std::path::Path,
    input: PublishArtifactArguments,
    artifact_policy: &iteron_protocol::ArtifactPolicy,
    existing_artifacts: &[ArtifactDeclaration],
) -> Result<ArtifactDeclaration, String> {
    use std::ffi::{CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    fn c_string(value: &OsStr) -> Result<CString, String> {
        CString::new(value.as_bytes()).map_err(|_| "artifact path contains NUL".into())
    }
    fn open_dir_at(parent: i32, name: &OsStr) -> Result<std::fs::File, String> {
        let name = c_string(name)?;
        // SAFETY: parent is a live directory descriptor and name is NUL-terminated for this call.
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(
                "artifact path directory could not be opened without following links".into(),
            );
        }
        // SAFETY: successful openat returns one owned descriptor.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
    fn open_regular_at(parent: i32, name: &OsStr) -> Result<std::fs::File, String> {
        let name = c_string(name)?;
        // SAFETY: parent is a live directory descriptor and name is NUL-terminated for this call.
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("artifact source could not be opened without following links".into());
        }
        // SAFETY: successful openat returns one owned descriptor.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let metadata = file
            .metadata()
            .map_err(|_| "artifact source metadata is unavailable".to_owned())?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err("artifact source must be one regular, non-hard-linked file".into());
        }
        Ok(file)
    }

    let root_name = c_string(output_root.as_os_str())?;
    // SAFETY: root_name is NUL-terminated and the returned descriptor is checked below.
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err("/workspace/output is not an available no-follow directory".into());
    }
    // SAFETY: successful open returns one owned descriptor.
    let root = unsafe { std::fs::File::from_raw_fd(root_fd) };
    let root_device = root
        .metadata()
        .map_err(|_| "output root metadata is unavailable".to_owned())?
        .dev();
    let path = std::path::Path::new(&input.relative_path);
    let mut components = path.components().peekable();
    let mut parent = root.try_clone().map_err(|error| error.to_string())?;
    let mut leaf = None;
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err("artifact path is not a safe relative path".into());
        };
        if components.peek().is_none() {
            leaf = Some(name.to_owned());
            break;
        }
        parent = open_dir_at(parent.as_raw_fd(), name)?;
        if parent.metadata().map_err(|error| error.to_string())?.dev() != root_device {
            return Err("artifact path crosses a mount boundary".into());
        }
    }
    let leaf = leaf.ok_or_else(|| "artifact path must name a file".to_owned())?;
    let mut source = open_regular_at(parent.as_raw_fd(), &leaf)?;
    if source.metadata().map_err(|error| error.to_string())?.dev() != root_device {
        return Err("artifact source crosses a mount boundary".into());
    }

    let staging_name = c_string(OsStr::new(".plantcore-staging"))?;
    // SAFETY: root and component remain live; EEXIST is handled by the following no-follow open.
    let mkdir = unsafe { libc::mkdirat(root.as_raw_fd(), staging_name.as_ptr(), 0o700) };
    if mkdir < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
        return Err("artifact staging directory could not be created".into());
    }
    let staging = open_dir_at(root.as_raw_fd(), OsStr::new(".plantcore-staging"))?;
    if staging.metadata().map_err(|error| error.to_string())?.dev() != root_device {
        return Err("artifact staging directory crosses a mount boundary".into());
    }
    let ordinal = NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed);
    let temporary_name = format!(".snapshot-{}-{ordinal}", std::process::id());
    let temporary_c = c_string(OsStr::new(&temporary_name))?;
    // SAFETY: staging and name remain live; create_new semantics come from O_EXCL.
    let temporary_fd = unsafe {
        libc::openat(
            staging.as_raw_fd(),
            temporary_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if temporary_fd < 0 {
        return Err("artifact snapshot temporary file could not be created".into());
    }
    // SAFETY: successful openat returns one owned descriptor.
    let mut temporary = unsafe { std::fs::File::from_raw_fd(temporary_fd) };
    let result = (|| {
        let mut digest = Sha256::new();
        let mut size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = source
                .read(&mut buffer)
                .map_err(|_| "artifact source read failed".to_owned())?;
            if read == 0 {
                break;
            }
            size = size
                .checked_add(read as u64)
                .ok_or_else(|| "artifact size overflowed".to_owned())?;
            if size > artifact_policy.max_artifact_bytes {
                return Err("artifact exceeds the admitted per-artifact policy".into());
            }
            digest.update(&buffer[..read]);
            temporary
                .write_all(&buffer[..read])
                .map_err(|_| "artifact snapshot write failed".to_owned())?;
        }
        let digest: [u8; 32] = digest.finalize().into();
        let artifact = ArtifactDeclaration {
            logical_name: input.logical_name,
            relative_path: input.relative_path,
            media_type: input.media_type,
            size_bytes: size,
            content_sha256: digest,
        };
        let mut admitted = existing_artifacts.to_vec();
        insert_artifact(&mut admitted, artifact_policy, artifact.clone()).map_err(str::to_owned)?;
        temporary
            .sync_all()
            .map_err(|_| "artifact snapshot fsync failed".to_owned())?;
        let final_name = lower_hex(&digest);
        let final_c = c_string(OsStr::new(&final_name))?;
        // Linux release artifacts use renameat2(RENAME_NOREPLACE), which publishes the fully
        // synced temporary file under its digest name without an overwrite window.
        #[cfg(target_os = "linux")]
        let published = unsafe {
            libc::renameat2(
                staging.as_raw_fd(),
                temporary_c.as_ptr(),
                staging.as_raw_fd(),
                final_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        // Other Unix development hosts retain equivalent no-replace publication via linkat.
        #[cfg(not(target_os = "linux"))]
        let published = unsafe {
            libc::linkat(
                staging.as_raw_fd(),
                temporary_c.as_ptr(),
                staging.as_raw_fd(),
                final_c.as_ptr(),
                0,
            )
        };
        if published < 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
                return Err("artifact snapshot could not be published atomically".into());
            }
            let mut existing = open_regular_at(staging.as_raw_fd(), OsStr::new(&final_name))?;
            let mut existing_digest = Sha256::new();
            let mut existing_size = 0u64;
            loop {
                let read = existing
                    .read(&mut buffer)
                    .map_err(|_| "existing artifact snapshot read failed".to_owned())?;
                if read == 0 {
                    break;
                }
                existing_size = existing_size.saturating_add(read as u64);
                existing_digest.update(&buffer[..read]);
            }
            if existing_size != size || <[u8; 32]>::from(existing_digest.finalize()) != digest {
                return Err("existing artifact snapshot conflicts with its digest name".into());
            }
            // SAFETY: the conflicting temporary name belongs to this invocation.
            if unsafe { libc::unlinkat(staging.as_raw_fd(), temporary_c.as_ptr(), 0) } < 0 {
                return Err("artifact snapshot temporary name could not be removed".into());
            }
        } else {
            #[cfg(not(target_os = "linux"))]
            // SAFETY: linkat leaves the unique temporary directory entry in place.
            if unsafe { libc::unlinkat(staging.as_raw_fd(), temporary_c.as_ptr(), 0) } < 0 {
                return Err("artifact snapshot temporary name could not be removed".into());
            }
        }
        staging
            .sync_all()
            .map_err(|_| "artifact staging directory fsync failed".to_owned())?;
        Ok(artifact)
    })();
    if result.is_err() {
        // SAFETY: best-effort cleanup addresses only the unique name created above.
        unsafe {
            libc::unlinkat(staging.as_raw_fd(), temporary_c.as_ptr(), 0);
        }
    }
    result
}

#[cfg(not(unix))]
fn snapshot_artifact(
    _output_root: &std::path::Path,
    _input: PublishArtifactArguments,
    _artifact_policy: &iteron_protocol::ArtifactPolicy,
    _existing_artifacts: &[ArtifactDeclaration],
) -> Result<ArtifactDeclaration, String> {
    Err("PlantCore artifact snapshots require descriptor-relative no-follow filesystem APIs".into())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        rendered.push(char::from(HEX[usize::from(byte >> 4)]));
        rendered.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    rendered
}

pub(super) fn artifact_result_content(artifact: &ArtifactDeclaration) -> String {
    serde_json::json!({
        "status": "declared",
        "logical_name": artifact.logical_name,
        "relative_path": artifact.relative_path,
        "media_type": artifact.media_type,
        "size_bytes": artifact.size_bytes,
        "content_sha256": lower_hex(&artifact.content_sha256),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recording_provider_usage_checkpoint_waits_for_driver_release() {
        let bridge = std::env::temp_dir().join(format!(
            "iteron-provider-usage-settled-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&bridge).unwrap();
        let gate = DispatchGate::new();
        gate.await_recording_provider_usage_settled_in(&bridge)
            .await
            .unwrap();
        assert!(!bridge.join("iteron.provider-usage-settled").exists());

        std::fs::write(
            bridge.join("iteron.provider-usage-settled.enabled"),
            b"enabled\n",
        )
        .unwrap();
        let waiting_gate = gate.clone();
        let waiting_bridge = bridge.clone();
        let mut waiting = tokio::spawn(async move {
            waiting_gate
                .await_recording_provider_usage_settled_in(&waiting_bridge)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !bridge.join("iteron.provider-usage-settled").is_file() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiting)
                .await
                .is_err(),
            "the checkpoint must hold the runtime until the driver releases it"
        );

        std::fs::write(
            bridge.join("iteron.provider-usage-settled.release"),
            b"released\n",
        )
        .unwrap();
        assert_eq!(waiting.await.unwrap(), Ok(()));
        std::fs::remove_dir_all(bridge).unwrap();
    }

    #[tokio::test]
    async fn dispatch_gate_pauses_only_after_the_in_flight_safe_point() {
        let gate = DispatchGate::new();
        assert_eq!(gate.pause_after_safe_point().await, Err("run_not_admitted"));
        gate.admit().unwrap();
        let permit = gate.enter().await.expect("open gate admits one dispatch");

        let pause_gate = gate.clone();
        let mut pause = tokio::spawn(async move { pause_gate.pause_after_safe_point().await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut pause)
                .await
                .is_err(),
            "pause acknowledgement must wait for the issued call"
        );

        drop(permit);
        assert_eq!(pause.await.unwrap(), Ok(()));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), gate.enter())
                .await
                .is_err(),
            "the effective gate refuses to begin another external dispatch"
        );
        let activation = gate.prepare_resume().unwrap();
        gate.activate_resume(activation).unwrap();
        assert!(gate.enter().await.is_some());
    }

    #[tokio::test]
    async fn dispatch_gate_resumes_only_after_the_reply_is_written() {
        let gate = DispatchGate::new();
        gate.admit().unwrap();
        gate.pause_after_safe_point().await.unwrap();

        let activation = gate.prepare_resume().unwrap();
        let waiting_gate = gate.clone();
        let mut waiting = tokio::spawn(async move { waiting_gate.enter().await.is_some() });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiting)
                .await
                .is_err(),
            "preparing an accepted reply must not release external dispatch"
        );

        gate.activate_resume(activation).unwrap();
        assert!(waiting.await.unwrap());
    }

    #[tokio::test]
    async fn terminal_is_absorbing_and_wakes_paused_dispatches() {
        let gate = DispatchGate::new();
        gate.admit().unwrap();
        gate.pause_after_safe_point().await.unwrap();
        let activation = gate.prepare_resume().unwrap();
        let waiting_gate = gate.clone();
        let waiting = tokio::spawn(async move { waiting_gate.enter().await.is_some() });
        gate.terminal();
        assert!(!waiting.await.unwrap());
        assert_eq!(gate.activate_resume(activation), Err("session_terminal"));
        assert_eq!(gate.prepare_resume(), Err("session_terminal"));
        assert_eq!(gate.pause_after_safe_point().await, Err("session_terminal"));
    }

    #[tokio::test]
    async fn terminal_submission_closes_the_gate_only_when_the_sq_accepts_it() {
        let gate = DispatchGate::new();
        gate.admit().unwrap();
        gate.pause_after_safe_point().await.unwrap();
        assert_eq!(
            gate.terminalize_if_accepted(|| Err::<(), _>("busy")),
            Ok(Err("busy"))
        );
        let activation = gate.prepare_resume().unwrap();
        gate.activate_resume(activation).unwrap();
        gate.pause_after_safe_point().await.unwrap();
        assert_eq!(gate.terminalize_if_accepted(|| Ok::<_, ()>(17)), Ok(Ok(17)));
        assert_eq!(gate.prepare_resume(), Err("session_terminal"));
    }

    #[test]
    fn terminal_submission_is_rejected_before_run_admission() {
        let gate = DispatchGate::new();
        let submitted = std::cell::Cell::new(false);
        assert_eq!(
            gate.terminalize_if_accepted(|| {
                submitted.set(true);
                Ok::<_, ()>(())
            }),
            Err("run_not_admitted")
        );
        assert!(!submitted.get());
        gate.admit().unwrap();
    }

    #[test]
    fn reversible_submission_requires_a_live_admitted_run() {
        let gate = DispatchGate::new();
        let submitted = std::cell::Cell::new(0);
        assert_eq!(
            gate.submit_if_admitted(|| {
                submitted.set(submitted.get() + 1);
                Ok::<_, ()>(())
            }),
            Err("run_not_admitted")
        );
        gate.admit().unwrap();
        assert_eq!(
            gate.submit_if_admitted(|| {
                submitted.set(submitted.get() + 1);
                Ok::<_, ()>(17)
            }),
            Ok(Ok(17))
        );
        gate.terminal();
        assert_eq!(
            gate.submit_if_admitted(|| {
                submitted.set(submitted.get() + 1);
                Ok::<_, ()>(())
            }),
            Err("session_terminal")
        );
        assert_eq!(submitted.get(), 1);
    }

    #[test]
    fn submission_rejects_prebootstrap_and_terminal_sessions() {
        let gate = DispatchGate::new();
        assert_eq!(
            gate.submit_if_admitted(|| Ok::<_, ()>(())),
            Err("run_not_admitted")
        );
        gate.admit().unwrap();
        gate.terminal();
        assert_eq!(
            gate.submit_if_admitted(|| Ok::<_, ()>(())),
            Err("session_terminal")
        );
    }

    fn artifact_policy() -> iteron_protocol::ArtifactPolicy {
        iteron_protocol::ArtifactPolicy {
            output_root: "/workspace/output".into(),
            max_artifact_bytes: iteron_protocol::MAX_ARTIFACT_BYTES,
            max_artifact_count: iteron_protocol::MAX_ARTIFACTS as u32,
            max_total_artifact_bytes: iteron_protocol::MAX_TOTAL_ARTIFACT_BYTES,
            max_upload_chunk_bytes: iteron_protocol::MAX_UPLOAD_CHUNK_BYTES,
            required_artifacts: Vec::new(),
            policy_digest_sha256: iteron_protocol::HexSha256::digest(b"test-policy"),
        }
    }

    fn accounting(
        physical_attempt: u32,
        usage: ProviderRouteUsageTruth,
    ) -> ProviderRouteAttemptAccounting {
        let cost = match usage {
            ProviderRouteUsageTruth::NotDispatched => {
                iteron_protocol::ProviderRouteCostTruth::NotDispatched
            }
            ProviderRouteUsageTruth::Known { .. } => {
                iteron_protocol::ProviderRouteCostTruth::Unknown {
                    reason: iteron_protocol::ProviderRouteCostUnknownReason::RateCardUnavailable,
                }
            }
            ProviderRouteUsageTruth::Unknown { .. } => {
                iteron_protocol::ProviderRouteCostTruth::Unknown {
                    reason: iteron_protocol::ProviderRouteCostUnknownReason::UsageIncomplete,
                }
            }
        };
        ProviderRouteAttemptAccounting {
            version: iteron_protocol::ProviderRouteAttemptAccountingVersion::V1,
            route_id: format!("sha256:{}", "0".repeat(64)),
            physical_attempt,
            max_cost_reservation_microusd: None,
            usage,
            cost,
        }
    }

    fn accounting_runtime(
        limits: iteron_protocol::EffectiveRunLimits,
        metering_policy: Option<MeteringPolicySnapshot>,
    ) -> PlantcoreRuntime {
        PlantcoreRuntime {
            enabled: true,
            limits: Some(limits),
            metering_policy,
            ..PlantcoreRuntime::default()
        }
    }

    fn metering_policy(rates: FiveClassCeilPolicyV1) -> MeteringPolicySnapshot {
        MeteringPolicySnapshot {
            version: "policy-v1".into(),
            provider: "plantcore".into(),
            model: "qwen".into(),
            effective_from_unix_ms: 0,
            effective_until_unix_ms: 1,
            calculator_contract_version: "plantcore.metering.five-class-ceil.v1".into(),
            metering_unit: "USD_MICRO".into(),
            policy_digest_sha256: iteron_protocol::HexSha256::digest(b"policy"),
            five_class_ceil_v1: rates,
        }
    }

    #[test]
    fn question_identity_is_domain_separated_and_stable() {
        let mut material = Vec::new();
        material.extend_from_slice(b"plantcore.iteron.question.v1\0");
        material.extend_from_slice(&5_u32.to_be_bytes());
        material.extend_from_slice(b"run-1");
        material.extend_from_slice(&6_u32.to_be_bytes());
        material.extend_from_slice(b"tool-1");
        let id = format!("iteron-question-{}", lower_hex(&Sha256::digest(material)));
        assert_eq!(id.len(), 80);
        assert!(id.starts_with("iteron-question-"));
    }

    #[test]
    fn product_text_and_question_hash_preserve_exact_utf8_bytes() {
        let secret_shaped = "sk-123456789012345678901234567890中文";
        let product = completed_product(secret_shaped, &[]);
        let ProductResult::Completed { assistant_text, .. } = product else {
            unreachable!();
        };
        assert_eq!(assistant_text, secret_shaped);

        let question = build_question("run-1", "tool-1", secret_shaped.into());
        assert_eq!(question.prompt_utf8, secret_shaped);
        assert_eq!(
            question.prompt_sha256,
            <[u8; 32]>::from(Sha256::digest(secret_shaped.as_bytes()))
        );
    }

    #[test]
    fn product_validation_includes_the_complete_v7_event_envelope() {
        let product = completed_product(
            &"a ".repeat(iteron_protocol::MAX_ASSISTANT_TEXT_BYTES / 2),
            &[],
        );
        assert!(product.validate().is_ok());
        assert_eq!(
            validate_product_result(&product),
            Err("product result exceeds the canonical v7 event limit")
        );
        assert!(validate_product_result(&completed_product("bounded", &[])).is_ok());
    }

    #[test]
    fn continuation_facts_remain_structured_and_keep_provenance() {
        let segment = iteron_protocol::ConversationSegment {
            sequence: 7,
            source_run_id: "source-run".into(),
            fact_digest_sha256: iteron_protocol::HexSha256::digest(b"fact"),
            fact: iteron_protocol::ConversationFact::QuestionAnswer {
                question_id: "question-1".into(),
                question_digest_sha256: iteron_protocol::HexSha256::digest(b"question"),
                answer_utf8: "exact answer".into(),
                answer_sha256: iteron_protocol::HexSha256::digest(b"exact answer"),
                answered_by_actor_id: "actor-1".into(),
                answered_at_unix_ms: 123,
            },
        };
        let value = serde_json::to_value(&segment).unwrap();
        assert_eq!(value, serde_json::to_value(segment).unwrap());
        assert_eq!(value["fact"]["kind"], "question_answer");
        assert!(value.get("role").is_none());
    }

    #[test]
    fn five_class_metering_rounds_each_class_from_cumulative_counters() {
        let policy = metering_policy(FiveClassCeilPolicyV1 {
            input_units_per_million: 1_000_000,
            output_units_per_million: 500_000,
            cache_creation_units_per_million: 1,
            cache_read_units_per_million: 0,
            thinking_units_per_million: 2_000_000,
        });
        assert_eq!(metered_amount(&FiveClassUsage::default(), &policy), Ok(0));
        assert_eq!(
            metered_amount(
                &FiveClassUsage {
                    input_tokens: 2,
                    output_tokens: 5,
                    cache_creation_tokens: 1,
                    cache_read_tokens: 99,
                    thinking_tokens: 3,
                },
                &policy,
            ),
            // 2 + ceil((5 - 3) / 2) + ceil(1 / 1_000_000) + 0 + 6
            Ok(10)
        );
    }

    #[test]
    fn five_class_metering_rejects_invalid_or_unrepresentable_totals() {
        let policy = metering_policy(FiveClassCeilPolicyV1 {
            input_units_per_million: u64::MAX,
            output_units_per_million: u64::MAX,
            cache_creation_units_per_million: u64::MAX,
            cache_read_units_per_million: u64::MAX,
            thinking_units_per_million: u64::MAX,
        });
        assert_eq!(
            metered_amount(
                &FiveClassUsage {
                    input_tokens: u64::MAX,
                    output_tokens: u64::MAX,
                    cache_creation_tokens: u64::MAX,
                    cache_read_tokens: u64::MAX,
                    thinking_tokens: 0,
                },
                &policy,
            ),
            Err("five-class token total exceeds u64")
        );
        assert_eq!(
            metered_amount(
                &FiveClassUsage {
                    output_tokens: 1,
                    thinking_tokens: 2,
                    ..FiveClassUsage::default()
                },
                &policy,
            ),
            Err("thinking_tokens must not exceed output_tokens")
        );
    }

    #[test]
    fn logical_turn_aggregates_dispatched_attempts_and_ignores_non_dispatch() {
        let limits = iteron_protocol::EffectiveRunLimits {
            max_turns: 8,
            max_tokens: None,
            max_usd_micros: None,
            max_wall_secs: 300,
            metering_policy_version: None,
            limits_digest_sha256: iteron_protocol::HexSha256::digest(b"limits"),
        };
        let mut runtime = accounting_runtime(limits, None);
        record_provider_attempt(
            &mut runtime,
            1,
            &accounting(1, ProviderRouteUsageTruth::NotDispatched),
        )
        .unwrap();
        record_provider_attempt(
            &mut runtime,
            1,
            &accounting(
                2,
                ProviderRouteUsageTruth::Known {
                    usage: iteron_protocol::Usage {
                        input: 5,
                        output: 4,
                        cache_creation: 2,
                        cache_read: 1,
                        thinking: 3,
                    },
                },
            ),
        )
        .unwrap();
        record_provider_attempt(
            &mut runtime,
            1,
            &accounting(
                3,
                ProviderRouteUsageTruth::Known {
                    usage: iteron_protocol::Usage {
                        input: 7,
                        output: 6,
                        cache_creation: 0,
                        cache_read: 3,
                        thinking: 1,
                    },
                },
            ),
        )
        .unwrap();
        assert_eq!(
            close_turn_usage(&mut runtime, 1).unwrap(),
            Some(TurnUsage::Complete {
                turn: 1,
                dispatched_attempt_count: 2,
                counters: FiveClassUsage {
                    input_tokens: 12,
                    output_tokens: 10,
                    cache_creation_tokens: 2,
                    cache_read_tokens: 4,
                    thinking_tokens: 4,
                },
                cumulative_metering: None,
            })
        );
        assert_eq!(close_turn_usage(&mut runtime, 2), Ok(None));
    }

    #[test]
    fn unavailable_reasons_are_ordered_deduplicated_and_absorbing() {
        let limits = iteron_protocol::EffectiveRunLimits {
            max_turns: 8,
            max_tokens: None,
            max_usd_micros: None,
            max_wall_secs: 300,
            metering_policy_version: None,
            limits_digest_sha256: iteron_protocol::HexSha256::digest(b"limits"),
        };
        let mut runtime = accounting_runtime(limits, None);
        for (attempt, reason) in [
            (1, ProviderRouteUsageUnknownReason::OutcomeUnobservable),
            (2, ProviderRouteUsageUnknownReason::ProviderOmitted),
            (3, ProviderRouteUsageUnknownReason::ProviderOmitted),
        ] {
            record_provider_attempt(
                &mut runtime,
                1,
                &accounting(attempt, ProviderRouteUsageTruth::Unknown { reason }),
            )
            .unwrap();
        }
        assert_eq!(
            close_turn_usage(&mut runtime, 1).unwrap(),
            Some(TurnUsage::Unavailable {
                turn: 1,
                dispatched_attempt_count: 3,
                reasons: vec![
                    UsageUnavailableReason::ProviderOmitted,
                    UsageUnavailableReason::OutcomeUnobservable,
                ],
            })
        );
        record_provider_attempt(
            &mut runtime,
            2,
            &accounting(
                1,
                ProviderRouteUsageTruth::Known {
                    usage: iteron_protocol::Usage {
                        input: 1,
                        output: 1,
                        ..iteron_protocol::Usage::default()
                    },
                },
            ),
        )
        .unwrap();
        assert!(matches!(
            close_turn_usage(&mut runtime, 2).unwrap(),
            Some(TurnUsage::Unavailable { reasons, .. })
                if reasons == vec![
                    UsageUnavailableReason::ProviderOmitted,
                    UsageUnavailableReason::OutcomeUnobservable,
                ]
        ));
    }

    #[test]
    fn token_and_usd_gates_trigger_at_equality_after_attempt_settlement() {
        let mut token_runtime = accounting_runtime(
            iteron_protocol::EffectiveRunLimits {
                max_turns: 8,
                max_tokens: Some(2),
                max_usd_micros: None,
                max_wall_secs: 300,
                metering_policy_version: None,
                limits_digest_sha256: iteron_protocol::HexSha256::digest(b"limits"),
            },
            None,
        );
        record_provider_attempt(
            &mut token_runtime,
            1,
            &accounting(
                1,
                ProviderRouteUsageTruth::Known {
                    usage: iteron_protocol::Usage {
                        input: 1,
                        output: 1,
                        ..iteron_protocol::Usage::default()
                    },
                },
            ),
        )
        .unwrap();
        assert_eq!(
            token_runtime.pending_terminal,
            Some(PlantcoreTerminal::Budget("max_tokens"))
        );

        let policy = metering_policy(FiveClassCeilPolicyV1 {
            input_units_per_million: 1_000_000,
            output_units_per_million: 0,
            cache_creation_units_per_million: 0,
            cache_read_units_per_million: 0,
            thinking_units_per_million: 0,
        });
        let mut usd_runtime = accounting_runtime(
            iteron_protocol::EffectiveRunLimits {
                max_turns: 8,
                max_tokens: None,
                max_usd_micros: Some(2),
                max_wall_secs: 300,
                metering_policy_version: Some("policy-v1".into()),
                limits_digest_sha256: iteron_protocol::HexSha256::digest(b"limits"),
            },
            Some(policy),
        );
        record_provider_attempt(
            &mut usd_runtime,
            1,
            &accounting(
                1,
                ProviderRouteUsageTruth::Known {
                    usage: iteron_protocol::Usage {
                        input: 2,
                        ..iteron_protocol::Usage::default()
                    },
                },
            ),
        )
        .unwrap();
        assert_eq!(
            usd_runtime.pending_terminal,
            Some(PlantcoreTerminal::Budget("max_usd"))
        );
        let usage = close_turn_usage(&mut usd_runtime, 1).unwrap().unwrap();
        assert!(matches!(
            usage,
            TurnUsage::Complete {
                cumulative_metering: Some(Metering {
                    cumulative_amount: 2,
                    ..
                }),
                ..
            }
        ));
    }

    #[test]
    fn incomplete_usage_closes_positive_token_budget_but_still_emits_usage() {
        let limits = iteron_protocol::EffectiveRunLimits {
            max_turns: 8,
            max_tokens: Some(10),
            max_usd_micros: None,
            max_wall_secs: 300,
            metering_policy_version: None,
            limits_digest_sha256: iteron_protocol::HexSha256::digest(b"limits"),
        };
        let mut runtime = accounting_runtime(limits, None);
        record_provider_attempt(
            &mut runtime,
            1,
            &accounting(
                1,
                ProviderRouteUsageTruth::Unknown {
                    reason: ProviderRouteUsageUnknownReason::ProvenFailureWithoutUsage,
                },
            ),
        )
        .unwrap();
        assert_eq!(
            runtime.pending_terminal,
            Some(PlantcoreTerminal::UsageUnavailable)
        );
        assert!(matches!(
            close_turn_usage(&mut runtime, 1).unwrap(),
            Some(TurnUsage::Unavailable {
                dispatched_attempt_count: 1,
                ..
            })
        ));
    }

    #[test]
    fn artifact_arguments_reject_staging_and_path_escape() {
        for relative_path in [
            "",
            "/tmp/report",
            "../report",
            "nested/../report",
            ".plantcore-staging/x",
        ] {
            let input = PublishArtifactArguments {
                logical_name: "report".into(),
                relative_path: relative_path.into(),
                media_type: "application/octet-stream".into(),
            };
            assert!(
                validate_artifact_arguments(&input).is_err(),
                "{relative_path}"
            );
        }
    }

    #[test]
    fn artifact_declarations_are_idempotent_but_metadata_conflicts_fail() {
        let first = ArtifactDeclaration {
            logical_name: "report".into(),
            relative_path: "report.txt".into(),
            media_type: "text/plain".into(),
            size_bytes: 3,
            content_sha256: Sha256::digest(b"one").into(),
        };
        let mut artifacts = Vec::new();
        let policy = artifact_policy();
        assert_eq!(
            insert_artifact(&mut artifacts, &policy, first.clone()),
            Ok(())
        );
        assert_eq!(
            insert_artifact(&mut artifacts, &policy, first.clone()),
            Ok(())
        );
        assert_eq!(artifacts, vec![first.clone()]);

        let conflicting = ArtifactDeclaration {
            size_bytes: 4,
            content_sha256: Sha256::digest(b"two!").into(),
            ..first
        };
        assert_eq!(
            insert_artifact(&mut artifacts, &policy, conflicting),
            Err("artifact declaration conflicts with an earlier declaration")
        );
        assert_eq!(artifacts.len(), 1);
    }

    #[test]
    fn artifact_policy_enforces_count_total_and_required_metadata() {
        let mut policy = artifact_policy();
        policy.max_artifact_bytes = 4;
        policy.max_artifact_count = 2;
        policy.max_total_artifact_bytes = 5;
        policy.required_artifacts = vec![iteron_protocol::ArtifactRequirement {
            logical_name: "report".into(),
            relative_path: "report.txt".into(),
            allowed_media_types: vec!["text/plain".into()],
            max_size_bytes: 3,
        }];
        let mut artifacts = Vec::new();
        let report = ArtifactDeclaration {
            logical_name: "report".into(),
            relative_path: "report.txt".into(),
            media_type: "text/plain".into(),
            size_bytes: 3,
            content_sha256: [1; 32],
        };
        assert_eq!(insert_artifact(&mut artifacts, &policy, report), Ok(()));
        assert_eq!(validate_required_artifacts(&policy, &artifacts), Ok(()));
        assert_eq!(
            validate_required_artifacts(&policy, &[]),
            Err("required PlantCore artifacts were not published")
        );
        assert_eq!(
            insert_artifact(
                &mut artifacts,
                &policy,
                ArtifactDeclaration {
                    logical_name: "other".into(),
                    relative_path: "other.bin".into(),
                    media_type: "application/octet-stream".into(),
                    size_bytes: 3,
                    content_sha256: [2; 32],
                }
            ),
            Err("artifact declaration bytes exceed the admitted total policy")
        );
        assert_eq!(
            insert_artifact(
                &mut Vec::new(),
                &policy,
                ArtifactDeclaration {
                    logical_name: "report".into(),
                    relative_path: "renamed.txt".into(),
                    media_type: "text/plain".into(),
                    size_bytes: 1,
                    content_sha256: [3; 32],
                }
            ),
            Err("artifact declaration does not match its admitted requirement")
        );
    }

    #[cfg(unix)]
    #[test]
    fn artifact_snapshot_is_content_addressed_and_immune_to_source_changes() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "iteron-plantcore-artifact-{}-{}",
            std::process::id(),
            NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&root).unwrap();
        let policy = artifact_policy();
        std::fs::write(root.join("empty.bin"), []).unwrap();
        let empty = snapshot_artifact(
            &root,
            PublishArtifactArguments {
                logical_name: "empty".into(),
                relative_path: "empty.bin".into(),
                media_type: "application/octet-stream".into(),
            },
            &policy,
            &[],
        )
        .unwrap();
        assert_eq!(empty.size_bytes, 0);
        assert_eq!(empty.content_sha256, Sha256::digest([]).as_slice());

        std::fs::write(root.join("report.txt"), b"version one").unwrap();
        let declaration = snapshot_artifact(
            &root,
            PublishArtifactArguments {
                logical_name: "report".into(),
                relative_path: "report.txt".into(),
                media_type: "text/plain".into(),
            },
            &policy,
            &[],
        )
        .unwrap();
        std::fs::write(root.join("report.txt"), b"version two").unwrap();
        let snapshot = root
            .join(".plantcore-staging")
            .join(lower_hex(&declaration.content_sha256));
        assert_eq!(std::fs::read(snapshot).unwrap(), b"version one");
        std::fs::remove_file(root.join("report.txt")).unwrap();
        assert_eq!(
            std::fs::read(
                root.join(".plantcore-staging")
                    .join(lower_hex(&declaration.content_sha256))
            )
            .unwrap(),
            b"version one"
        );

        std::fs::write(root.join("report.txt"), b"replacement").unwrap();
        symlink(root.join("report.txt"), root.join("linked.txt")).unwrap();
        let linked = snapshot_artifact(
            &root,
            PublishArtifactArguments {
                logical_name: "linked".into(),
                relative_path: "linked.txt".into(),
                media_type: "text/plain".into(),
            },
            &policy,
            &[],
        );
        assert!(linked.is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn artifact_snapshot_accepts_exact_100_mib_and_cleans_oversize_failure() {
        use std::os::unix::fs::OpenOptionsExt;

        let root = std::env::temp_dir().join(format!(
            "iteron-plantcore-artifact-boundary-{}-{}",
            std::process::id(),
            NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&root).unwrap();
        let policy = artifact_policy();
        let source_path = root.join("boundary.bin");
        let source = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source_path)
            .unwrap();
        source.set_len(iteron_protocol::MAX_ARTIFACT_BYTES).unwrap();
        drop(source);

        let exact = snapshot_artifact(
            &root,
            PublishArtifactArguments {
                logical_name: "boundary".into(),
                relative_path: "boundary.bin".into(),
                media_type: "application/octet-stream".into(),
            },
            &policy,
            &[],
        )
        .unwrap();
        assert_eq!(exact.size_bytes, iteron_protocol::MAX_ARTIFACT_BYTES);

        std::fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .unwrap()
            .set_len(iteron_protocol::MAX_ARTIFACT_BYTES + 1)
            .unwrap();
        let oversized = snapshot_artifact(
            &root,
            PublishArtifactArguments {
                logical_name: "oversized".into(),
                relative_path: "boundary.bin".into(),
                media_type: "application/octet-stream".into(),
            },
            &policy,
            &[],
        );
        assert_eq!(
            oversized.unwrap_err(),
            "artifact exceeds the admitted per-artifact policy"
        );
        let staging_entries = std::fs::read_dir(root.join(".plantcore-staging"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            staging_entries,
            vec![std::ffi::OsString::from(lower_hex(&exact.content_sha256))]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn artifact_snapshot_checks_run_quota_before_publishing_digest_name() {
        let root = std::env::temp_dir().join(format!(
            "iteron-plantcore-artifact-quota-{}-{}",
            std::process::id(),
            NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("second.bin"), b"second").unwrap();
        let mut policy = artifact_policy();
        policy.max_artifact_count = 1;
        let existing = ArtifactDeclaration {
            logical_name: "first".into(),
            relative_path: "first.bin".into(),
            media_type: "application/octet-stream".into(),
            size_bytes: 1,
            content_sha256: [1; 32],
        };

        let error = snapshot_artifact(
            &root,
            PublishArtifactArguments {
                logical_name: "second".into(),
                relative_path: "second.bin".into(),
                media_type: "application/octet-stream".into(),
            },
            &policy,
            &[existing],
        )
        .unwrap_err();
        assert_eq!(
            error,
            "artifact declaration count exceeds the admitted policy"
        );
        assert_eq!(
            std::fs::read_dir(root.join(".plantcore-staging"))
                .unwrap()
                .count(),
            0,
            "a quota refusal must remove its temporary and publish no digest snapshot"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn artifact_snapshot_rejects_fifo_without_leaving_a_declaration_snapshot() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let root = std::env::temp_dir().join(format!(
            "iteron-plantcore-artifact-fifo-{}-{}",
            std::process::id(),
            NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&root).unwrap();
        let policy = artifact_policy();
        let fifo_path = root.join("pipe");
        let fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo is a valid NUL-terminated path and the return value is checked.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let error = snapshot_artifact(
            &root,
            PublishArtifactArguments {
                logical_name: "pipe".into(),
                relative_path: "pipe".into(),
                media_type: "application/octet-stream".into(),
            },
            &policy,
            &[],
        )
        .unwrap_err();
        assert_eq!(
            error,
            "artifact source must be one regular, non-hard-linked file"
        );
        assert!(!root.join(".plantcore-staging").exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
