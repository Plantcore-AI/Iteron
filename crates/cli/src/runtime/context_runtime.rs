use super::*;

const TOKEN_CALIBRATION_FILE: &str = "token-calibration-v1.json";
const TOKEN_CALIBRATION_MAX_BYTES: u64 = 64 * 1024;

fn token_calibration_max_bytes() -> u64 {
    iteron_tunables::param_integer(
        "cli.runtime.context_runtime.token_calibration_max_bytes",
        TOKEN_CALIBRATION_MAX_BYTES,
    )
    .clamp(1, TOKEN_CALIBRATION_MAX_BYTES)
}

pub(super) fn load_token_calibration(
    runtime_state_dir: &std::path::Path,
) -> iteron_ctx::TokenCalibrationStore {
    if runtime_state_dir.as_os_str().is_empty() {
        return iteron_ctx::TokenCalibrationStore::default();
    }
    let path = runtime_state_dir.join(TOKEN_CALIBRATION_FILE);
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        return iteron_ctx::TokenCalibrationStore::default();
    };
    if !metadata.file_type().is_file() || metadata.len() > token_calibration_max_bytes() {
        return iteron_ctx::TokenCalibrationStore::default();
    }
    let Ok(bytes) = std::fs::read(path) else {
        return iteron_ctx::TokenCalibrationStore::default();
    };
    serde_json::from_slice::<iteron_ctx::TokenCalibrationSnapshot>(&bytes)
        .ok()
        .and_then(|snapshot| iteron_ctx::TokenCalibrationStore::restore(snapshot).ok())
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
pub(super) struct AdvertisedToolSpecsCache {
    revision: u64,
    task: String,
    admitted_names: std::collections::BTreeSet<String>,
    eager_limit: Option<usize>,
    strategy: investigation_convergence::InvestigationToolStrategy,
    authority_visible: usize,
    prepared: PreparedToolSchemas,
}

/// Active-task token count charged when the transcript holds no user text message to attribute.
const NO_ACTIVE_TASK_TOKENS: usize = 0;

/// Attachment token count charged when the turn carries no input-file evidence.
const NO_ATTACHMENT_TOKENS: usize = 0;

/// Per-submission guard for the component-budget recovery bridge. Component admission runs again
/// after compaction, but a later refusal in the same agent loop must fail closed instead of
/// recursively compacting.
#[derive(Debug, Default)]
pub(super) struct ContextBudgetRecoveryGuard {
    attempted: bool,
}

impl ContextBudgetRecoveryGuard {
    pub(super) fn claim(&mut self, violation: &iteron_ctx::ContextBudgetViolation) -> bool {
        if self.attempted || !violation.is_transcript_compaction_recoverable() {
            return false;
        }
        self.attempted = true;
        true
    }
}

/// Content-free component accounting captured at one provider-admission boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ContextBudgetInspection {
    usage: iteron_ctx::ContextComponentUsage,
    violation: Option<iteron_ctx::ContextBudgetViolation>,
}

/// Per-turn model-visible result caps derived from the remaining component partitions. Physical
/// tools and private spill retention keep their own independent ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TurnResultProjectionBudget {
    tool_result_bytes: usize,
    lsp_result_bytes: usize,
}

impl TurnResultProjectionBudget {
    pub(super) fn visible_bytes_for(self, tool_name: &str) -> usize {
        match iteron_ctx::result_budget_class(tool_name) {
            iteron_ctx::ContextBudgetClass::LspResults => self.lsp_result_bytes,
            _ => self.tool_result_bytes,
        }
    }
}

impl ContextBudgetInspection {
    pub(super) fn violation(self) -> Option<iteron_ctx::ContextBudgetViolation> {
        self.violation
    }

    pub(super) fn component_tokens(self, class: iteron_ctx::ContextBudgetClass) -> usize {
        match class {
            iteron_ctx::ContextBudgetClass::StablePrefix => self.usage.stable_prefix_tokens,
            iteron_ctx::ContextBudgetClass::Instructions => self.usage.instruction_tokens,
            iteron_ctx::ContextBudgetClass::TaskContext => self.usage.task_context_tokens,
            iteron_ctx::ContextBudgetClass::Memory => self.usage.memory_tokens,
            iteron_ctx::ContextBudgetClass::Transcript => self.usage.transcript_tokens,
            iteron_ctx::ContextBudgetClass::Attachments => self.usage.attachment_tokens,
            iteron_ctx::ContextBudgetClass::ToolSchemas => self.usage.tool_schema_tokens,
            iteron_ctx::ContextBudgetClass::ToolResults => self.usage.tool_result_tokens,
            iteron_ctx::ContextBudgetClass::LspResults => self.usage.lsp_result_tokens,
            // Multimodal admission is a separate preflight and is never recovered by transcript
            // compaction. Keep this branch total without pretending image bytes were measured here.
            iteron_ctx::ContextBudgetClass::Multimodal => 0,
        }
    }

    pub(super) const fn usage(self) -> iteron_ctx::ContextComponentUsage {
        self.usage
    }
}

/// Existing registered lifecycle events reused by component-budget recovery. `Considered` remains
/// a brokered gate at the call site. The terminal variants deliberately use segment-budget events:
/// the compaction machinery already emits its own completed/failed transition exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ContextBudgetRecoveryStage {
    Considered,
    Started,
    Completed,
    Failed,
}

impl ContextBudgetRecoveryStage {
    pub(super) const fn event_id(self) -> &'static str {
        match self {
            Self::Considered => "context.compaction.considered",
            Self::Started => "context.compaction.started",
            Self::Completed => "context.segment.budget_granted",
            Self::Failed => "context.segment.budget_denied",
        }
    }
}

impl Agent {
    pub(super) fn token_calibration_route(&self) -> (&str, &str) {
        self.selected_route.as_ref().map_or_else(
            || {
                (
                    self.provider.provider_instance_id().unwrap_or("unbound"),
                    self.model.as_str(),
                )
            },
            |selected| {
                (
                    selected.route.provider_id.as_str(),
                    selected.route.model_id.as_str(),
                )
            },
        )
    }

    pub(super) fn calibrated_context_estimate(
        &self,
        mut estimate: ContextEstimate,
    ) -> ContextEstimate {
        let (provider_id, model_id) = self.token_calibration_route();
        let conservative = u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX);
        let calibrated =
            self.token_calibration
                .calibrated_estimate(provider_id, model_id, conservative);
        let calibrated = usize::try_from(calibrated).unwrap_or(usize::MAX);
        let baseline = estimate.total_tokens;
        if baseline == 0 || calibrated == baseline {
            return estimate;
        }
        let scale = |value: usize| {
            value
                .saturating_mul(calibrated)
                .saturating_add(baseline.saturating_sub(1))
                / baseline
        };
        estimate.system_tokens = scale(estimate.system_tokens);
        estimate.tool_tokens = scale(estimate.tool_tokens);
        estimate.conversation_tokens = scale(estimate.conversation_tokens);
        estimate.tool_result_tokens = scale(estimate.tool_result_tokens);
        estimate.lsp_result_tokens = scale(estimate.lsp_result_tokens);
        estimate.transcript_tokens = estimate
            .conversation_tokens
            .saturating_add(estimate.tool_result_tokens)
            .saturating_add(estimate.lsp_result_tokens);
        estimate.framing_tokens = scale(estimate.framing_tokens);
        estimate.total_tokens = estimate
            .system_tokens
            .saturating_add(estimate.tool_tokens)
            .saturating_add(estimate.transcript_tokens)
            .saturating_add(estimate.framing_tokens);
        estimate
    }

    pub(super) fn remember_token_estimate_baseline(&mut self, turn: TurnId, tokens: usize) {
        if let Some(existing) = self
            .token_estimate_baselines
            .iter_mut()
            .find(|(candidate, _)| *candidate == turn)
        {
            existing.1 = u64::try_from(tokens).unwrap_or(u64::MAX);
            return;
        }
        const MAX_PENDING_BASELINES: usize = 64;
        if self.token_estimate_baselines.len()
            == iteron_tunables::param_integer(
                "cli.runtime.context_runtime.max_pending_baselines",
                MAX_PENDING_BASELINES,
            )
            .clamp(1, MAX_PENDING_BASELINES)
        {
            self.token_estimate_baselines.pop_front();
        }
        self.token_estimate_baselines
            .push_back((turn, u64::try_from(tokens).unwrap_or(u64::MAX)));
    }

    pub(super) fn take_token_estimate_baseline(&mut self, turn: TurnId) -> Option<u64> {
        let index = self
            .token_estimate_baselines
            .iter()
            .position(|(candidate, _)| *candidate == turn)?;
        self.token_estimate_baselines
            .remove(index)
            .map(|(_, tokens)| tokens)
    }

    pub(super) fn persist_token_calibration(&self) -> bool {
        use std::io::Write as _;

        if self.runtime_state_dir.as_os_str().is_empty() {
            return false;
        }
        let Ok(bytes) = serde_json::to_vec(&self.token_calibration.snapshot()) else {
            return false;
        };
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > token_calibration_max_bytes()
            || std::fs::create_dir_all(&self.runtime_state_dir).is_err()
        {
            return false;
        }
        let target = self.runtime_state_dir.join(TOKEN_CALIBRATION_FILE);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let temporary = self.runtime_state_dir.join(format!(
            ".token-calibration-v1.{}.{}.tmp",
            std::process::id(),
            nonce
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let Ok(mut file) = options.open(&temporary) else {
            return false;
        };
        let written = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .is_ok();
        drop(file);
        if !written || std::fs::rename(&temporary, &target).is_err() {
            let _ = std::fs::remove_file(&temporary);
            return false;
        }
        std::fs::File::open(&self.runtime_state_dir)
            .and_then(|directory| directory.sync_all())
            .is_ok()
    }

    /// Project the aggregate provider-wire estimate back onto the non-overlapping source classes
    /// owned by this admitted request. The source evidence was captured when the immutable
    /// injection was materialized; the active task and attachment evidence belong to this one
    /// submission. No class may borrow unused capacity from another class.
    pub(super) fn context_component_usage(
        &self,
        messages: &[iteron_protocol::Message],
        estimate: &iteron_ctx::ContextEstimate,
    ) -> iteron_ctx::ContextComponentUsage {
        let mut instruction_tokens = 0usize;
        let mut memory_tokens = 0usize;
        let mut injected_task_tokens = 0usize;
        for segment in &self.context_source_evidence {
            if !matches!(
                segment.decision,
                iteron_ctx::ContextDecision::Selected
                    | iteron_ctx::ContextDecision::Truncated
                    | iteron_ctx::ContextDecision::Compacted
            ) {
                continue;
            }
            let tokens = usize::try_from(segment.estimated_tokens).unwrap_or(usize::MAX);
            match segment.source_class {
                iteron_ctx::ContextSourceClass::OperatorInstructions
                | iteron_ctx::ContextSourceClass::ProjectInstructions
                | iteron_ctx::ContextSourceClass::DirectoryInstructions => {
                    instruction_tokens = instruction_tokens.saturating_add(tokens);
                }
                iteron_ctx::ContextSourceClass::UserMemory
                | iteron_ctx::ContextSourceClass::WorkspaceMemory
                | iteron_ctx::ContextSourceClass::SessionMemory => {
                    memory_tokens = memory_tokens.saturating_add(tokens);
                }
                iteron_ctx::ContextSourceClass::Environment
                | iteron_ctx::ContextSourceClass::WorkspaceOutline
                | iteron_ctx::ContextSourceClass::SkillIndex
                | iteron_ctx::ContextSourceClass::SkillReference
                | iteron_ctx::ContextSourceClass::WorkflowEvidence
                | iteron_ctx::ContextSourceClass::SubagentEvidence
                | iteron_ctx::ContextSourceClass::Steering
                | iteron_ctx::ContextSourceClass::QueuedSubmission => {
                    injected_task_tokens = injected_task_tokens.saturating_add(tokens);
                }
                _ => {}
            }
        }

        let active_task_with_attachments = messages
            .iter()
            .rfind(|message| {
                message.role == iteron_protocol::Role::User
                    && message
                        .content
                        .iter()
                        .any(|block| matches!(block, iteron_protocol::Block::Text { .. }))
            })
            .map(|message| {
                message
                    .content
                    .iter()
                    .filter_map(|block| match block {
                        iteron_protocol::Block::Text { text } => {
                            Some(self.context_estimator.estimate_text(text))
                        }
                        _ => None,
                    })
                    .fold(0usize, usize::saturating_add)
            })
            .unwrap_or(iteron_tunables::param_integer(
                "cli.runtime.context_runtime.no_active_task_tokens",
                NO_ACTIVE_TASK_TOKENS,
            ));
        let attachment_tokens = self
            .input_file_evidence
            .map(|evidence| usize::try_from(evidence.estimated_tokens).unwrap_or(usize::MAX))
            .unwrap_or(iteron_tunables::param_integer(
                "cli.runtime.context_runtime.no_attachment_tokens",
                NO_ATTACHMENT_TOKENS,
            ))
            .min(active_task_with_attachments);
        let active_task_tokens = active_task_with_attachments.saturating_sub(attachment_tokens);
        let classified_system = instruction_tokens
            .saturating_add(memory_tokens)
            .saturating_add(injected_task_tokens);

        iteron_ctx::ContextComponentUsage {
            stable_prefix_tokens: estimate.system_tokens.saturating_sub(classified_system),
            instruction_tokens,
            task_context_tokens: injected_task_tokens.saturating_add(active_task_tokens),
            memory_tokens,
            transcript_tokens: estimate
                .conversation_tokens
                .saturating_sub(active_task_with_attachments),
            attachment_tokens,
            tool_schema_tokens: estimate.tool_tokens,
            tool_result_tokens: estimate.tool_result_tokens,
            lsp_result_tokens: estimate.lsp_result_tokens,
        }
    }

    /// Inspect the exact source-separated projection used by provider admission. The policy's
    /// deterministic class order makes `violation` the first breached component, which is the
    /// only recovery candidate for this one-shot attempt.
    pub(super) fn inspect_context_budget(
        &self,
        messages: &[iteron_protocol::Message],
        estimate: &iteron_ctx::ContextEstimate,
    ) -> ContextBudgetInspection {
        let usage = self.context_component_usage(messages, estimate);
        let violation = self.context_budget_policy.admit_components(&usage).err();
        ContextBudgetInspection { usage, violation }
    }

    /// Allocate the remaining transcript-owned result budgets fairly across the calls emitted in
    /// this model turn. This runs after the provider terminal, when the complete call set is known,
    /// but before any result terminal is recorded or appended to the next request.
    pub(super) fn turn_result_projection_budget(
        &self,
        inspection: ContextBudgetInspection,
        calls: &[iteron_protocol::ToolUse],
    ) -> TurnResultProjectionBudget {
        let configured_max = self.tool_output_spill.as_ref().map_or(
            tool_output_spill::DEFAULT_TOOL_OUTPUT_MEMORY_THRESHOLD_BYTES,
            |store| store.visible_threshold_bytes(),
        );
        let (ordinary, lsp) = calls
            .iter()
            .fold((0usize, 0usize), |(ordinary, lsp), call| {
                if iteron_ctx::result_budget_class(&call.name)
                    == iteron_ctx::ContextBudgetClass::LspResults
                {
                    (ordinary, lsp.saturating_add(1))
                } else {
                    (ordinary.saturating_add(1), lsp)
                }
            });
        TurnResultProjectionBudget {
            tool_result_bytes: self.context_budget_policy.fair_result_visible_bytes(
                iteron_ctx::ContextBudgetClass::ToolResults,
                inspection.component_tokens(iteron_ctx::ContextBudgetClass::ToolResults),
                ordinary,
                configured_max,
            ),
            lsp_result_bytes: self.context_budget_policy.fair_result_visible_bytes(
                iteron_ctx::ContextBudgetClass::LspResults,
                inspection.component_tokens(iteron_ctx::ContextBudgetClass::LspResults),
                lsp,
                configured_max,
            ),
        }
    }

    pub(super) fn observe_tool_result_projection(&self, turn: TurnId, visible_bytes: usize) {
        self.lifecycle_event(
            "context.source.truncated",
            Some(turn),
            LifecyclePayload {
                count: Some(1),
                magnitude: Some(u64::try_from(visible_bytes).unwrap_or(u64::MAX)),
                reason_code: Some("tool_result_pressure_projection".into()),
                ..LifecyclePayload::default()
            },
        );
    }

    /// Standard payload for component-triggered compaction. `magnitude` is the measured usage of
    /// the breached component at this stage and `count` is its fixed ceiling. Paired pre/post
    /// events therefore expose before/after tokens without recording transcript content.
    pub(super) fn context_budget_recovery_payload(
        violation: &iteron_ctx::ContextBudgetViolation,
        observed_tokens: usize,
    ) -> LifecyclePayload {
        LifecyclePayload {
            reason_code: Some(violation.reason_code().into()),
            count: Some(u64::try_from(violation.ceiling).unwrap_or(u64::MAX)),
            magnitude: Some(u64::try_from(observed_tokens).unwrap_or(u64::MAX)),
            ..LifecyclePayload::default()
        }
    }

    /// Emit one non-gating recovery transition. `Considered` callers must use
    /// `brokered_lifecycle_gate` with [`Self::context_budget_recovery_payload`] instead so Hooks
    /// retain their existing ability to deny compaction. The terminal transition attributes
    /// success/failure to the component budget without duplicating compaction's own terminal event.
    pub(super) fn emit_context_budget_recovery_event(
        &self,
        turn: TurnId,
        stage: ContextBudgetRecoveryStage,
        violation: &iteron_ctx::ContextBudgetViolation,
        observed_tokens: usize,
    ) {
        self.lifecycle_event(
            stage.event_id(),
            Some(turn),
            Self::context_budget_recovery_payload(violation, observed_tokens),
        );
    }

    /// Bind attachments to one admitted top-level submission. A route without verified image
    /// support refuses the whole submission before its text is recorded; silently stripping the
    /// binary payload would make the model answer placeholders as if it saw the image.
    pub(super) fn admit_input_images<'a>(
        &self,
        input_images: &'a [iteron_protocol::ImageContent],
    ) -> Result<&'a [iteron_protocol::ImageContent], KernelError> {
        if input_images.is_empty() {
            return Ok(input_images);
        }
        // Capability admission owns the route before any payload work. Besides making an
        // unsupported submission's reason truthful, this ensures a route that cannot consume
        // images performs no binary decode/inspection, token estimation, or component-budget
        // admission on them.
        if !self.provider.supports_image_input() {
            self.lifecycle_event(
                "context.source.rejected",
                Some(TurnId(self.seq_turn)),
                LifecyclePayload {
                    count: Some(u64::try_from(input_images.len()).unwrap_or(u64::MAX)),
                    reason_code: Some("image_input_unsupported".into()),
                    ..LifecyclePayload::default()
                },
            );
            return Err(KernelError::InvalidSubmission(iteron_tunables::param_str(
                "cli.runtime.image_input_unsupported_reason",
                IMAGE_INPUT_UNSUPPORTED_REASON,
            )));
        }

        let reject = || {
            self.lifecycle_event(
                "context.source.rejected",
                Some(TurnId(self.seq_turn)),
                LifecyclePayload {
                    count: Some(u64::try_from(input_images.len()).unwrap_or(u64::MAX)),
                    reason_code: Some("multimodal_decode_envelope_rejected".into()),
                    ..LifecyclePayload::default()
                },
            );
            KernelError::InvalidSubmission(iteron_tunables::param_str(
                "cli.runtime.image_input_inspection_failed_reason",
                IMAGE_INPUT_INSPECTION_FAILED_REASON,
            ))
        };
        if input_images.len() > self.multimodal_decode_envelope.max_images {
            return Err(reject());
        }
        let mut aggregate_raw_bytes = 0usize;
        for image in input_images {
            let raw_bytes = self
                .binary_media_policy
                .inspect_content_with_envelope(image, self.multimodal_decode_envelope)
                .map_err(|_| reject())?;
            aggregate_raw_bytes = aggregate_raw_bytes
                .checked_add(raw_bytes)
                .filter(|total| *total <= self.multimodal_decode_envelope.aggregate_raw_bytes)
                .ok_or_else(&reject)?;
        }
        let estimated_tokens = input_images.iter().fold(0usize, |total, image| {
            total.saturating_add(
                self.context_estimator
                    .estimate_image(image.data.encoded_len()),
            )
        });
        self.context_budget_policy
            .admit_multimodal(estimated_tokens)
            .map_err(|error| KernelError::ContextBudget(error.to_string()))?;
        Ok(input_images)
    }

    /// The system prompt for a turn: the base plus ONCE-resolved context (REC-INJECT).
    /// This reads `self.injected` (resolved at run start, recorded, reused from the record on
    /// resume) — it does NOT touch the disk, so the stable prefix is byte-stable across a run and a
    /// replay reproduces instructions, memory, and skills exactly.
    pub(super) fn effective_system(&self) -> String {
        iteron_ctx::assemble_system_prompt(&self.system, self.injected.as_deref())
    }

    /// The tool set advertised to the model for this turn.
    ///
    /// I-63: a measured nine-token task paid 3671 prompt tokens, 2730 of them tool schemas, while
    /// the fleet average is 8967 input tokens per turn. Describing a tool the current posture can
    /// NEVER admit is pure waste — every call the model makes to it is refused by the gate.
    ///
    /// Only the two UNCONDITIONAL denials are filtered, so nothing that could be admitted is
    /// hidden: `iteron_protocol::gate` makes Plan a hard read-only overlay that no session rule may
    /// punch through (and `bypass_permissions` explicitly excludes Plan), and
    /// `iteron_kernel::admission::constrain` denies any capability outside the intersection of the
    /// admitted task ceiling and the selected policy manifest. An `Ask` is not filtered: the
    /// operator can still answer it.
    ///
    /// The ceiling test is over every capability a call to the tool can PRESENT, not just the
    /// declared one. `effective_capability` elevates a `ReversibleLocal` write to `TrustMutating`
    /// when the path is trust-mutating, and a `CapabilitySet` is a set rather than a downward-closed
    /// prefix, so a ceiling holding `TrustMutating` without `ReversibleLocal` still admits that
    /// tool for exactly those paths. Filtering on the declared capability alone would hide it.
    ///
    /// Stated cost: `TurnRequest.tools` now depends on the permission mode, so entering or leaving
    /// Plan rewrites the stable prefix and breaks the prompt cache for that one turn. That is a
    /// rare operator action; carrying an unusable schema block on every turn of a read-only session
    /// is not.
    #[cfg(test)]
    pub(super) fn advertised_tool_specs(&mut self) -> PreparedToolSchemas {
        self.advertised_tool_specs_for_task("")
    }

    pub(super) fn advertised_tool_specs_for_task(&mut self, task: &str) -> PreparedToolSchemas {
        self.advertised_tool_specs_for_task_with_strategy(
            task,
            investigation_convergence::InvestigationToolStrategy::Full,
        )
    }

    pub(super) fn advertised_tool_specs_for_task_with_strategy(
        &mut self,
        task: &str,
        strategy: investigation_convergence::InvestigationToolStrategy,
    ) -> PreparedToolSchemas {
        let admitted = self.authority_ceiling.intersect(self.policy_capabilities);
        let base = self.registry.spec_snapshot();
        let total = base.specs().len();
        self.lifecycle_event(
            "context.tool_catalog.discovered",
            Some(TurnId(self.seq_turn)),
            LifecyclePayload {
                count: Some(u64::try_from(total).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        let mut admitted_names = base
            .specs()
            .iter()
            .filter(|spec| {
                let reachable = admitted.contains(spec.capability)
                    || (spec.capability == Capability::ReversibleLocal
                        && admitted.contains(Capability::TrustMutating));
                reachable
                    && (spec.capability == Capability::ReadOnly
                        || self.permission_mode != PermissionMode::Plan)
            })
            .map(|spec| spec.name.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let authority_visible = admitted_names.len();
        if strategy == investigation_convergence::InvestigationToolStrategy::CandidateChangeOnly {
            admitted_names.retain(|name| self.registry.is_candidate_change_tool(name));
        }
        let strategy_visible = admitted_names.len();
        let strategy_filtered = authority_visible.saturating_sub(strategy_visible);
        let cached = self.advertised_tool_specs_cache.as_ref().filter(|cached| {
            cached.revision == base.revision()
                && cached.task == task
                && cached.admitted_names == admitted_names
                && cached.eager_limit == self.deferred_tool_eager_limit
                && cached.strategy == strategy
        });
        let cache_hit = cached.is_some();
        let (visible, schema_tokens) = if let Some(cached) = cached {
            debug_assert_eq!(cached.authority_visible, authority_visible);
            debug_assert!(
                !cached.prepared.canonical_json().is_empty() || cached.prepared.is_empty()
            );
            (cached.prepared.clone(), cached.prepared.estimated_tokens())
        } else {
            let snapshot = self.registry.specs_for_task_snapshot(
                &admitted_names,
                task,
                self.deferred_tool_eager_limit,
            );
            let specs: std::sync::Arc<[iteron_protocol::ToolSpec]> =
                snapshot.iter().cloned().collect::<Vec<_>>().into();
            let schema_tokens = snapshot.estimated_tokens();
            let prepared = PreparedToolSchemas::new(
                specs,
                std::sync::Arc::clone(snapshot.serialized_json()),
                schema_tokens,
                snapshot.revision(),
            );
            self.advertised_tool_specs_cache = Some(AdvertisedToolSpecsCache {
                revision: snapshot.revision(),
                task: task.to_owned(),
                admitted_names: admitted_names.clone(),
                eager_limit: self.deferred_tool_eager_limit,
                strategy,
                authority_visible,
                prepared: prepared.clone(),
            });
            (prepared, schema_tokens)
        };
        let authority_filtered = total.saturating_sub(authority_visible);
        let relevance_deferred = strategy_visible.saturating_sub(visible.len());
        let filtered = authority_filtered;
        if filtered > 0 {
            let payload = LifecyclePayload {
                count: Some(u64::try_from(filtered).unwrap_or(u64::MAX)),
                reason_code: Some("authority_or_permission".into()),
                ..LifecyclePayload::default()
            };
            self.lifecycle_event(
                "context.tool_catalog.filtered",
                Some(TurnId(self.seq_turn)),
                payload.clone(),
            );
            self.lifecycle_event(
                "context.tool_schema.rejected",
                Some(TurnId(self.seq_turn)),
                payload,
            );
        }
        if strategy_filtered > 0 {
            self.lifecycle_event(
                "context.tool_schema.rejected",
                Some(TurnId(self.seq_turn)),
                LifecyclePayload {
                    count: Some(u64::try_from(strategy_filtered).unwrap_or(u64::MAX)),
                    reason_code: Some("strategy_candidate_action_required".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        if relevance_deferred > 0 {
            self.lifecycle_event(
                "context.tool_schema.rejected",
                Some(TurnId(self.seq_turn)),
                LifecyclePayload {
                    count: Some(u64::try_from(relevance_deferred).unwrap_or(u64::MAX)),
                    reason_code: Some("task_relevance_lazy_discovery".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        // MCP resource/prompt extension tools are the catalog's real lazy-discovery routes: the
        // provider sees one bounded schema now and asks the configured server for concrete
        // resources or prompts only if it needs them. Count only those entry points; ordinary MCP
        // tools are already eager schemas and must not be mislabeled as lazy.
        let lazy_routes = visible
            .iter()
            .filter(|spec| {
                [
                    "__resources_list",
                    "__resources_read",
                    "__prompts_list",
                    "__prompts_get",
                ]
                .iter()
                .any(|suffix| spec.name.ends_with(suffix))
            })
            .count();
        if lazy_routes > 0 {
            self.lifecycle_event(
                "context.tool_catalog.lazy_route",
                Some(TurnId(self.seq_turn)),
                LifecyclePayload {
                    count: Some(u64::try_from(lazy_routes).unwrap_or(u64::MAX)),
                    reason_code: Some("mcp_resource_or_prompt_discovery".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        self.lifecycle_event(
            "context.tool_schema.admitted",
            Some(TurnId(self.seq_turn)),
            LifecyclePayload {
                count: Some(u64::try_from(visible.len()).unwrap_or(u64::MAX)),
                magnitude: Some(u64::try_from(schema_tokens).unwrap_or(u64::MAX)),
                outcome_code: Some("snapshot_resolved".into()),
                reason_code: Some(if cache_hit { "cache_hit" } else { "cache_miss" }.into()),
                ..LifecyclePayload::default()
            },
        );
        visible
    }

    pub fn set_deferred_tool_eager_limit(&mut self, limit: Option<usize>) {
        self.deferred_tool_eager_limit = limit.filter(|limit| *limit > 0);
        self.advertised_tool_specs_cache = None;
    }

    pub fn set_context_runtime_policy(
        &mut self,
        budget: iteron_ctx::ContextBudgetPolicy,
        materialization: iteron_ctx::ContextMaterializationPolicy,
    ) -> Result<(), KernelError> {
        self.context_materialization_policy = materialization
            .validate()
            .map_err(|reason| KernelError::ContextBudget(reason.into()))?;
        self.context_budget_policy = budget;
        Ok(())
    }

    pub(super) fn proposed_durable_frontend_context(
        &self,
        genesis_environment: Option<&DurableEnvironmentContext>,
    ) -> Option<DurableInstructionContext> {
        let environment = genesis_environment.cloned().or_else(|| {
            self.environment_context
                .as_ref()
                .map(|(text, trust)| DurableEnvironmentContext {
                    text: text.clone(),
                    trust: *trust,
                })
        });
        match &self.instruction_context {
            Some((text, trust)) => Some(DurableInstructionContext {
                text: text.clone(),
                trust: *trust,
                environment,
            }),
            None if environment.is_some() => Some(DurableInstructionContext {
                text: String::new(),
                trust: Trust::Trusted,
                environment,
            }),
            None => None,
        }
    }

    pub(super) fn clear_frontend_context_proposals(&mut self) {
        self.instruction_context = None;
        self.environment_context = None;
    }

    /// REC-INJECT (R5-review item 1; ADR-011 context seam). Resolve the complete context segment for
    /// this run EXACTLY ONCE and record it, so replay re-materializes context from the record, never
    /// from live instruction/memory/skill files. Idempotent: a follow-up keeps the cached segment.
    pub(super) fn resolve_injection(
        &mut self,
        turn: TurnId,
        task: &str,
    ) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Ok(());
        }
        let resolution_started = Instant::now();
        // Resume/replay: complete durable instruction bytes are authoritative. A legacy event has
        // only memory/skills in `text`; combine it with the live proposal once, append an upgraded
        // event before provider admission, and use that event on every later resume.
        let recorded = self.recorded_context_history()?;
        if !self.context_refresh_requested
            && let Some((context_text, context_trust, durable_instructions)) = recorded.injection
        {
            if let Some(instructions) = durable_instructions {
                let (text, trust) = iteron_ctx::assemble_recorded_context(
                    &instructions,
                    context_text,
                    context_trust,
                );
                self.observe_recorded_context(turn, &text, trust);
                self.injected = Some(text);
                self.injected_trust = Some(trust);
                self.clear_frontend_context_proposals();
                return Ok(());
            }
            if let Some(instructions) =
                self.proposed_durable_frontend_context(recorded.genesis_environment.as_ref())
            {
                self.emit_durable(
                    turn,
                    EventKind::ContextInjection {
                        text: context_text.clone(),
                        trust: context_trust,
                        instructions: Some(instructions.clone()),
                    },
                )?;
                let (text, trust) = iteron_ctx::assemble_recorded_context(
                    &instructions,
                    context_text,
                    context_trust,
                );
                self.observe_recorded_context(turn, &text, trust);
                self.injected = Some(text);
                self.injected_trust = Some(trust);
                self.clear_frontend_context_proposals();
                return Ok(());
            }
            self.observe_recorded_context(turn, &context_text, context_trust);
            self.injected = Some(context_text);
            self.injected_trust = Some(context_trust);
            self.clear_frontend_context_proposals();
            return Ok(());
        }

        let durable_instructions = self.proposed_durable_frontend_context(
            (!self.context_refresh_requested)
                .then_some(recorded.genesis_environment.as_ref())
                .flatten(),
        );
        let mut context_text = String::new();
        let mut context_sources = Vec::with_capacity(2);

        if let Some(ws) = self.memory_workspace.clone() {
            // The frontend already owns instruction/environment gathering. Preserve that durable
            // split while routing the remaining lexical-memory + skill-index selection through
            // the pure frozen slot and the injected world adapter.
            let context_opportunity =
                self.begin_policy_decision(policy_evidence::CONTEXT_SLOT, Some(turn))?;
            let resolved = match strategy_runtime::resolve_live_context(
                self.context_strategy.as_ref(),
                self.memory_strategy.as_ref(),
                self.context_port.as_ref(),
                strategy_runtime::LiveContextRequest {
                    workspace: &ws,
                    home_dir: self.context_home_dir.as_deref(),
                    dependency_skill_dirs: &self.dependency_skill_dirs,
                    turn,
                    task,
                    memory_benchmark_scope: self.memory_benchmark_scope,
                    materialization: self.context_materialization_policy,
                },
            ) {
                Ok(resolved) => {
                    self.append_policy_decision(
                        context_opportunity,
                        policy_evidence::PolicyDecisionDraft::selected(
                            policy_evidence::CONTEXT_SLOT,
                            &[iteron_protocol::PolicyActionV1::ContextMaterialize],
                            iteron_protocol::PolicyActionV1::ContextMaterialize,
                            "iteron:context-features-v1",
                            &(&resolved.policy_observation, &resolved.policy_plan),
                            &"world_reads_remain_in_context_port",
                        )?,
                    )?;
                    resolved
                }
                Err(error) => {
                    self.append_policy_decision(
                        context_opportunity,
                        policy_evidence::PolicyDecisionDraft::abstained(
                            policy_evidence::CONTEXT_SLOT,
                            &[iteron_protocol::PolicyActionV1::ContextMaterialize],
                            "iteron:context-features-v1",
                            &(turn.0, task.len()),
                            &"context_failure_is_fail_closed",
                        )?,
                    )?;
                    return Err(KernelError::ContextResolution(error));
                }
            };
            if let Some(audit) = &resolved.memory_audit {
                use iteron_ctx::MemoryRecallDisposition;
                if audit.disposition != MemoryRecallDisposition::NotInvokedScopeDenied {
                    let memory_opportunity =
                        self.begin_policy_decision(policy_evidence::MEMORY_SLOT, Some(turn))?;
                    let eligible = [
                        iteron_protocol::PolicyActionV1::MemoryNoRecall,
                        iteron_protocol::PolicyActionV1::MemoryRecall,
                    ];
                    let features = (&audit.observation, &audit.selected, &audit.scores_ppm);
                    let draft = match audit.disposition {
                        MemoryRecallDisposition::Selected => {
                            policy_evidence::PolicyDecisionDraft::selected(
                                policy_evidence::MEMORY_SLOT,
                                &eligible,
                                if audit.selected.is_empty() {
                                    iteron_protocol::PolicyActionV1::MemoryNoRecall
                                } else {
                                    iteron_protocol::PolicyActionV1::MemoryRecall
                                },
                                "iteron:memory-features-v1",
                                &features,
                                &"selection_is_bounded_to_gathered_candidates",
                            )?
                        }
                        MemoryRecallDisposition::Abstained => {
                            policy_evidence::PolicyDecisionDraft::abstained(
                                policy_evidence::MEMORY_SLOT,
                                &eligible,
                                "iteron:memory-features-v1",
                                &features,
                                &"invalid_or_refused_memory_plans_inject_no_bodies",
                            )?
                        }
                        MemoryRecallDisposition::NotInvokedScopeDenied => unreachable!(
                            "outer scope denial is filtered before opening an opportunity"
                        ),
                    };
                    self.append_policy_decision(memory_opportunity, draft)?;
                }
            }
            let memory_benchmark_scope = self.memory_benchmark_scope;
            self.observe_resolved_context(decision_observability::ResolvedContextObservation {
                turn,
                task,
                segments: &resolved.segments,
                materialization: &resolved.materialization_audit,
                memory_audit: resolved.memory_audit.as_ref(),
                memory_benchmark_scope: memory_benchmark_scope.as_ref(),
                benchmark_memory_rejections: resolved.benchmark_memory_rejections,
                elapsed_us: elapsed_us(resolution_started),
            });
            if !resolved.text.is_empty() {
                context_sources.push(resolved.governing_trust);
                context_text.push_str(&resolved.text);
            }
        }

        let context_trust =
            Trust::governing(context_sources).unwrap_or(if context_text.is_empty() {
                Trust::Trusted
            } else {
                // Non-empty bytes without provenance are a bug, never Trusted by default.
                Trust::Untrusted
            });
        let should_record = self.context_refresh_requested
            || durable_instructions.is_some()
            || !context_text.is_empty();
        if should_record {
            self.emit_durable(
                turn,
                EventKind::ContextInjection {
                    text: context_text.clone(),
                    trust: context_trust,
                    instructions: durable_instructions.clone(),
                },
            )?;
        }
        let (text, trust) = match &durable_instructions {
            Some(instructions) => {
                let (text, trust) = iteron_ctx::assemble_recorded_context(
                    instructions,
                    context_text,
                    context_trust,
                );
                (text, Some(trust))
            }
            None => (context_text, should_record.then_some(context_trust)),
        };
        self.injected = Some(text);
        self.injected_trust = trust;
        self.context_refresh_requested = false;
        self.clear_frontend_context_proposals();
        Ok(())
    }

    /// The last `ContextInjection` plus the latest inherited genesis environment snapshot, if any.
    /// Reads one fork-aware logical projection, never live instruction, memory, clock, or Git
    /// sources. Genesis is the crash-safe fallback only until ContextInjection becomes durable;
    /// any record/replay failure propagates instead of reopening a live-context fallback.
    pub(super) fn recorded_context_history(&self) -> Result<RecordedContextHistory, KernelError> {
        // Route through the fork-aware loader (not a raw child-file replay) so a FORKED run finds
        // the parent's recorded ContextInjection instead of silently re-deriving from live disk —
        // the exact disk re-derivation REC-INJECT exists to prevent (code review).
        let events = replay_logical_rollout(self.rollout.path())?;
        let mut history = RecordedContextHistory::default();
        for e in events {
            match e.kind {
                EventKind::RunStart {
                    environment: Some(environment),
                    ..
                } => history.genesis_environment = Some(environment),
                EventKind::ContextInjection {
                    text,
                    trust,
                    instructions,
                } => history.injection = Some((text, trust, instructions)),
                _ => {}
            }
        }
        Ok(history)
    }

    /// Coarse ADR-007 taint projection for the context that can influence the next proposal.
    /// Direct operator/system text is Trusted; injected sources and tool observations can lower
    /// it. Empty provenance explicitly means only direct input is in scope.
    pub(super) fn governing_turn_trust(&self, messages: &[Message]) -> Trust {
        let tool_trust = messages.iter().flat_map(|message| {
            message.content.iter().filter_map(|block| match block {
                Block::ToolResult(result) => Some(result.trust),
                _ => None,
            })
        });
        Trust::governing(
            std::iter::once(self.system_trust)
                .chain(std::iter::once(self.observed_trust))
                .chain(self.injected_trust)
                .chain(tool_trust),
        )
        .unwrap_or(Trust::Trusted)
    }
}

#[cfg(test)]
mod context_budget_recovery_tests {
    use super::*;

    fn violation(class: iteron_ctx::ContextBudgetClass) -> iteron_ctx::ContextBudgetViolation {
        iteron_ctx::ContextBudgetViolation {
            class,
            used: 25_666,
            ceiling: 18_000,
        }
    }

    #[test]
    fn recovery_guard_claims_a_recoverable_violation_only_once() {
        let violation = violation(iteron_ctx::ContextBudgetClass::ToolResults);
        let mut guard = ContextBudgetRecoveryGuard::default();

        assert!(guard.claim(&violation));
        assert!(!guard.claim(&violation));
    }

    #[test]
    fn recovery_guard_rejects_non_compactable_components() {
        let violation = violation(iteron_ctx::ContextBudgetClass::StablePrefix);
        let mut guard = ContextBudgetRecoveryGuard::default();

        assert!(!guard.claim(&violation));
    }

    #[test]
    fn inspection_preserves_first_violation_and_component_usage() {
        let violation = violation(iteron_ctx::ContextBudgetClass::ToolResults);
        let inspection = ContextBudgetInspection {
            usage: iteron_ctx::ContextComponentUsage {
                tool_result_tokens: violation.used,
                ..iteron_ctx::ContextComponentUsage::default()
            },
            violation: Some(violation),
        };

        assert_eq!(inspection.violation(), Some(violation));
        assert_eq!(
            inspection.component_tokens(iteron_ctx::ContextBudgetClass::ToolResults),
            25_666
        );
    }

    #[test]
    fn recovery_payload_is_content_free_and_token_attributed() {
        let violation = violation(iteron_ctx::ContextBudgetClass::ToolResults);
        let payload = Agent::context_budget_recovery_payload(&violation, 9_000);

        assert_eq!(
            payload.reason_code.as_deref(),
            Some(violation.reason_code())
        );
        assert_eq!(payload.count, Some(18_000));
        assert_eq!(payload.magnitude, Some(9_000));
        assert!(payload.outcome_code.is_none());
    }

    #[test]
    fn recovery_stages_reuse_registered_compaction_events() {
        assert_eq!(
            ContextBudgetRecoveryStage::Considered.event_id(),
            "context.compaction.considered"
        );
        assert_eq!(
            ContextBudgetRecoveryStage::Started.event_id(),
            "context.compaction.started"
        );
        assert_eq!(
            ContextBudgetRecoveryStage::Completed.event_id(),
            "context.segment.budget_granted"
        );
        assert_eq!(
            ContextBudgetRecoveryStage::Failed.event_id(),
            "context.segment.budget_denied"
        );
    }
}
