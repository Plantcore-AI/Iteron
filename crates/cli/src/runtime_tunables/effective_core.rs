//! Runtime projection for the composition-root families owned by iteron-cli.
//!
//! This decoder is intentionally the only place that turns the immutable resolver/checkpoint
//! representation back into kernel types. Fresh and resumed runs therefore use the same bytes;
//! neither path gets to rediscover a default from `Budget`, `CompactionPolicy`, or config.

use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use iteron_protocol::{
    Budget, Capability, Effort, PermissionMode, PermissionRules, Verdict,
    capability_set::CapabilitySet,
};
use iteron_sched::BackoffPolicy;
use iteron_tunables::{DecimalValue, ResolutionValue, RuntimeGetterId};

#[derive(Debug, Clone)]
pub(crate) struct EffectiveCoreSettings {
    pub provider_id: String,
    pub model_id: String,
    pub base_url: String,
    pub effort: Effort,
    pub budget: Budget,
    pub allow_code: bool,
    pub permission_mode: PermissionMode,
    pub permission_rules: PermissionRules,
    pub bypass_permissions: bool,
    pub retry: BackoffPolicy,
    pub token_estimator: iteron_ctx::TokenEstimatorPolicy,
    pub compaction: iteron_ctx::CompactionPolicy,
    pub verify_command: Option<String>,
    pub verification: iteron_verify::VerificationRuntimePolicy,
    pub memory_enabled: bool,
    pub session_spawn_cap: usize,
    pub deferred_tool_eager_limit: Option<usize>,
    /// Exact model context authority captured in family 96. `None` means the owner was unknown at
    /// genesis; resume must not replace it with a newly discovered machine value.
    pub model_context_window: Option<u64>,
    /// Exact provider response cap captured in family 19 after all parent ceilings were applied.
    pub request_output_cap: Option<u32>,
    pub context_budget: iteron_ctx::ContextBudgetPolicy,
    pub context_materialization: iteron_ctx::ContextMaterializationPolicy,
    pub provider_governor: crate::config::ResolvedProviderGovernorConfig,
    pub mcp: super::effective_mcp::EffectiveMcpSettings,
    pub mcp_exposure: super::effective_mcp::McpCapabilityExposure,
    pub execution: super::execution_policy::ExecutionRuntimePolicy,
    pub session_isolation: crate::session_isolation::SessionIsolationPolicy,
    pub app_server_queue: crate::app_server::AppServerQueuePolicy,
    pub binary_media: crate::image_input::BinaryMediaInspectionPolicy,
    pub multimodal_decode: crate::image_input::MultimodalDecodeEnvelope,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EffectiveCoreError {
    #[error(transparent)]
    View(#[from] EffectiveViewError),
    #[error("effective tunable `{family}` is outside the runtime type range")]
    Range { family: &'static str },
    #[error("effective tunable `{family}` contains unknown value `{value}`")]
    UnknownValue { family: &'static str, value: String },
    #[error("effective tunable `{family}` is missing object field `{field}`")]
    MissingField {
        family: &'static str,
        field: &'static str,
    },
    #[error("effective tunable `{family}` object field `{field}` has the wrong type")]
    WrongFieldType {
        family: &'static str,
        field: &'static str,
    },
    #[error("effective budget is invalid: {0}")]
    InvalidBudget(String),
}

impl EffectiveCoreSettings {
    pub(crate) fn decode(view: &EffectiveTunablesView) -> Result<Self, EffectiveCoreError> {
        view.with_getter(RuntimeGetterId::EffectiveCore, || Self::decode_inner(view))
    }

    fn decode_inner(view: &EffectiveTunablesView) -> Result<Self, EffectiveCoreError> {
        let budget = Budget {
            max_turns: u32v(view.integer("max_turns")?, "max_turns")?,
            max_usd: optional_decimal(view, "max_usd")?.map(decimal_to_f64),
            max_tokens: optional_integer(view, "max_tokens")?
                .map(|value| u64v(value, "max_tokens"))
                .transpose()?,
            max_wall_secs: u64v(view.integer("max_wall_secs")?, "max_wall_secs")?,
            max_consecutive_tool_errors: u32v(
                view.integer("max_consecutive_tool_errors")?,
                "max_consecutive_tool_errors",
            )?,
        };
        budget
            .validate()
            .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;

        let effort_label = view.enumeration("effort")?;
        let effort = Effort::parse(effort_label).ok_or_else(|| unknown("effort", effort_label))?;
        let mode_label = view.enumeration("permission_mode")?;
        let permission_mode = PermissionMode::parse(mode_label)
            .ok_or_else(|| unknown("permission_mode", mode_label))?;

        let (context_budget, context_materialization, model_context_window) =
            decode_context_policies(view)?;
        let request_output_cap = optional_integer(view, "request_output_cap")?
            .map(|value| u32v(value, "request_output_cap"))
            .transpose()?;
        let (allow_code, permission_rules) = decode_governance(view)?;
        let prompt_cache_enabled = optional_boolean(view, "prompt_cache")?.unwrap_or(false);
        let provider_governor = constrain_prompt_cache(
            super::effective_provider::decode(view)?,
            prompt_cache_enabled,
        );
        let mcp = super::effective_mcp::EffectiveMcpSettings::decode(view)
            .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
        let mcp_exposure = super::effective_mcp::McpCapabilityExposure::decode(view)
            .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
        let execution = super::effective_execution::decode(view)
            .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
        if budget.max_usd.is_some_and(|ceiling| ceiling > 0.0)
            && execution.workflow.max_concurrency != 1
        {
            return Err(EffectiveCoreError::InvalidBudget(
                "a positive USD ceiling requires checkpointed workflow max_concurrency=1 until signed per-attempt reservations are available"
                    .into(),
            ));
        }
        let app_server_queue = super::effective_app_server::decode(view)
            .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
        let binary_media = super::effective_binary_media::decode(view)
            .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
        let multimodal_decode = super::effective_binary_media::decode_multimodal(view)
            .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
        let profile = view.runtime_profile()?;
        let isolation_label = view.enumeration("session_isolation_profile")?;
        let session_isolation =
            crate::session_isolation::SessionIsolationPolicy::from_label(isolation_label)
                .ok_or_else(|| unknown("session_isolation_profile", isolation_label))?;
        session_isolation
            .validate_profile(profile)
            .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
        let verify_command = optional_text(view, "verify_command")?;
        let verification = decode_verification(view, verify_command.as_deref())?;
        let token_estimator = decode_token_estimator(view)?;
        Ok(Self {
            provider_id: view.enumeration("provider")?.to_owned(),
            model_id: view.enumeration("model")?.to_owned(),
            base_url: view.text("base_url")?.to_owned(),
            effort,
            budget,
            allow_code,
            permission_mode,
            permission_rules,
            bypass_permissions: view.boolean("bypass_permissions")?,
            retry: BackoffPolicy {
                base_ms: u64v(view.integer("retry_backoff_base")?, "retry_backoff_base")?,
                cap_ms: u64v(view.integer("retry_backoff_cap")?, "retry_backoff_cap")?,
                max_attempts: u32v(view.integer("retry_max_attempts")?, "retry_max_attempts")?,
            },
            token_estimator,
            compaction: decode_compaction(view)?,
            verify_command,
            verification,
            memory_enabled: view.boolean("memory_enable")?,
            session_spawn_cap: usizev(
                view.integer("per_session_spawn_cap")?,
                "per_session_spawn_cap",
            )?,
            deferred_tool_eager_limit: optional_integer(view, "deferred_discovery_threshold")?
                .map(|value| usizev(value, "deferred_discovery_threshold"))
                .transpose()?
                .filter(|value| *value > 0),
            model_context_window,
            request_output_cap,
            context_budget,
            context_materialization,
            provider_governor,
            mcp,
            mcp_exposure,
            execution,
            session_isolation,
            app_server_queue,
            binary_media,
            multimodal_decode,
        })
    }

    pub(crate) fn verify_route(
        &self,
        provider_id: &str,
        model_id: &str,
        base_url: &str,
    ) -> Result<(), EffectiveCoreError> {
        let primary = self.provider_id == provider_id && self.model_id == model_id;
        // A non-primary route may be either an immutable fallback or a later operator-selected
        // route. Resume derives this pair from the rollout's durable `ModelSelected` chain, then
        // composition revalidates the live adapter capabilities and installs a fresh bounded
        // governor containing this exact current route plus only the remaining fallbacks.
        if primary && self.base_url != base_url {
            return Err(EffectiveCoreError::UnknownValue {
                family: "base_url",
                value: format!("checkpoint={}; selected={base_url}", self.base_url),
            });
        }
        Ok(())
    }

    /// Prove that today's adapter can execute the immutable route ceilings without allowing its
    /// newly discovered metadata to replace them. Capability growth is harmless but still runs at
    /// the checkpoint value; a known capability below a recorded ceiling is a pre-effect refusal.
    /// An unknown response cap preserves family 19's pinned conservative fallback rather than
    /// fabricating provider evidence, while an unknown context window cannot attest family 96.
    pub(crate) fn verify_model_capability_ceiling(
        &self,
        live_context_window: Option<u64>,
        live_output_cap: Option<u32>,
    ) -> Result<(), EffectiveCoreError> {
        verify_model_capability_ceiling(
            self.model_context_window,
            self.request_output_cap,
            live_context_window,
            live_output_cap,
        )
    }

    /// Intersect the caller's already-admitted authority with the immutable family-9 gate.
    ///
    /// `allow_code=true` deliberately returns the caller's ceiling unchanged: a boolean grant in
    /// the tunables checkpoint is never itself authority. `false` removes only CodeExecuting and
    /// is therefore inherited by every child through the ordinary parent-ceiling copy paths.
    pub(crate) fn constrain_authority_ceiling(&self, ceiling: CapabilitySet) -> CapabilitySet {
        constrain_code_execution_authority(self.allow_code, ceiling)
    }
}

fn verify_model_capability_ceiling(
    required_context_window: Option<u64>,
    required_output_cap: Option<u32>,
    live_context_window: Option<u64>,
    live_output_cap: Option<u32>,
) -> Result<(), EffectiveCoreError> {
    if required_context_window
        .is_some_and(|required| live_context_window.is_none_or(|live| live < required))
    {
        return Err(EffectiveCoreError::UnknownValue {
            family: "context_window_override_reserve",
            value: "live provider no longer attests the checkpoint context window".into(),
        });
    }
    if matches!(
        (required_output_cap, live_output_cap),
        (Some(required), Some(live)) if live < required
    ) {
        return Err(EffectiveCoreError::UnknownValue {
            family: "request_output_cap",
            value: "live provider no longer attests the checkpoint response cap".into(),
        });
    }
    Ok(())
}

fn constrain_code_execution_authority(allow_code: bool, ceiling: CapabilitySet) -> CapabilitySet {
    if allow_code {
        return ceiling;
    }
    ceiling.intersect(CapabilitySet::from_iter_capabilities([
        Capability::ReadOnly,
        Capability::ReversibleLocal,
        Capability::TrustMutating,
        Capability::IrreversibleExternal,
    ]))
}

pub(crate) fn constrain_prompt_cache(
    mut provider: crate::config::ResolvedProviderGovernorConfig,
    prompt_cache_enabled: bool,
) -> crate::config::ResolvedProviderGovernorConfig {
    if !prompt_cache_enabled {
        // Family 23 is the outer, route-construction gate. Family 158 may choose TTL,
        // breakpoint, invalidation and scope only inside that gate; it cannot turn caching back on
        // for an adapter instance the operator built with caching disabled.
        provider.controls.prompt_cache = iteron_provider::PromptCacheControl::default();
    }
    provider
}

fn decode_governance(
    view: &EffectiveTunablesView,
) -> Result<(bool, PermissionRules), EffectiveCoreError> {
    let allow_code = view.boolean("allow_code")?;
    let permission_rules = decode_permission_rules(view)?;
    Ok((allow_code, permission_rules))
}

fn decode_verification(
    view: &EffectiveTunablesView,
    configured_command: Option<&str>,
) -> Result<iteron_verify::VerificationRuntimePolicy, EffectiveCoreError> {
    use iteron_verify::{
        FlakyQuarantinePolicy, UnknownVerificationRetryAction, VerificationCheckpointPolicy,
        VerificationFailureClass, VerificationQuorumPolicy, VerificationRestorePolicy,
        VerificationRetryPolicy, VerificationRollbackMode, VerificationRuntimePolicy,
        VerificationSelectionMode,
    };

    let selection = match optional_enum(view, "incremental_versus_full_verification")? {
        Some("incremental") => VerificationSelectionMode::Incremental,
        Some("impacted") => VerificationSelectionMode::Impacted,
        Some("full") | None => VerificationSelectionMode::Full,
        Some(other) => return Err(unknown("incremental_versus_full_verification", other)),
    };
    let (required_commands, max_commands) =
        if let Some(strategy) = optional_object(view, "test_selection_strategy")? {
            (
                text_list_field(strategy, "test_selection_strategy", "required_commands")?,
                u16::try_from(integer_field(
                    strategy,
                    "test_selection_strategy",
                    "max_commands",
                )?)
                .map_err(|_| EffectiveCoreError::Range {
                    family: "test_selection_strategy",
                })?,
            )
        } else {
            (
                configured_command
                    .map(|command| vec![command.to_owned()])
                    .unwrap_or_default(),
                1,
            )
        };

    let flaky_fields = optional_object(view, "flaky_test_detection_quarantine")?;
    let flaky = match flaky_fields {
        Some(fields) => FlakyQuarantinePolicy {
            repeat_count: u8::try_from(integer_field(
                fields,
                "flaky_test_detection_quarantine",
                "repeat_count",
            )?)
            .map_err(|_| EffectiveCoreError::Range {
                family: "flaky_test_detection_quarantine",
            })?,
            minimum_disagreements: u8::try_from(integer_field(
                fields,
                "flaky_test_detection_quarantine",
                "minimum_disagreements",
            )?)
            .map_err(|_| EffectiveCoreError::Range {
                family: "flaky_test_detection_quarantine",
            })?,
            quarantine_seconds: u32v(
                integer_field(
                    fields,
                    "flaky_test_detection_quarantine",
                    "quarantine_seconds",
                )?,
                "flaky_test_detection_quarantine",
            )?,
            report_disagreement: boolean_field(
                fields,
                "flaky_test_detection_quarantine",
                "report_disagreement",
            )?,
        },
        None => FlakyQuarantinePolicy::default(),
    };

    let quorum = match optional_object(view, "verification_quorum_consensus")? {
        Some(fields) => VerificationQuorumPolicy {
            verifiers: u8::try_from(integer_field(
                fields,
                "verification_quorum_consensus",
                "verifiers",
            )?)
            .map_err(|_| EffectiveCoreError::Range {
                family: "verification_quorum_consensus",
            })?,
            required_agreement: u8::try_from(integer_field(
                fields,
                "verification_quorum_consensus",
                "required_agreement",
            )?)
            .map_err(|_| EffectiveCoreError::Range {
                family: "verification_quorum_consensus",
            })?,
            strong_veto: boolean_field(fields, "verification_quorum_consensus", "strong_veto")?,
        },
        None => VerificationQuorumPolicy::default(),
    };

    let checkpoint = match optional_object(view, "workspace_checkpoint_cadence")? {
        Some(fields) => VerificationCheckpointPolicy {
            turn_boundary: boolean_field(fields, "workspace_checkpoint_cadence", "turn_boundary")?,
            before_verification: boolean_field(
                fields,
                "workspace_checkpoint_cadence",
                "before_verification",
            )?,
            before_drain: boolean_field(fields, "workspace_checkpoint_cadence", "before_drain")?,
            minimum_turn_interval: u32v(
                integer_field(
                    fields,
                    "workspace_checkpoint_cadence",
                    "minimum_turn_interval",
                )?,
                "workspace_checkpoint_cadence",
            )?,
        },
        None => VerificationCheckpointPolicy::default(),
    };

    let rollback = match optional_enum(view, "rollback_on_verification_failure")? {
        Some("off") | None => VerificationRollbackMode::Off,
        Some("selected_paths") => VerificationRollbackMode::SelectedPaths,
        Some("workspace") => VerificationRollbackMode::Workspace,
        Some(other) => return Err(unknown("rollback_on_verification_failure", other)),
    };
    let restore = match optional_object(view, "selective_restore_scope")? {
        Some(fields) => {
            let declared_mode = match enum_field(fields, "selective_restore_scope", "mode")? {
                "selected_paths" => VerificationRollbackMode::SelectedPaths,
                "workspace" => VerificationRollbackMode::Workspace,
                other => return Err(unknown("selective_restore_scope", other)),
            };
            if rollback != VerificationRollbackMode::Off && rollback != declared_mode {
                return Err(EffectiveCoreError::InvalidBudget(
                    "rollback mode and selective restore scope disagree".into(),
                ));
            }
            VerificationRestorePolicy {
                mode: rollback,
                paths: optional_text_list_field(fields, "selective_restore_scope", "paths")?
                    .unwrap_or_default(),
                // Confirmation is not a serializable tunable. It is a hard runtime invariant;
                // the restore seam additionally requires one exact durable operator approval.
                require_operator_confirmation: true,
            }
        }
        None => VerificationRestorePolicy {
            mode: rollback,
            ..VerificationRestorePolicy::default()
        },
    };

    let feedback = decode_verification_feedback(view)?;
    let verifier_timeout_secs = optional_integer(view, "verifier_timeout")?
        .map(|value| u64v(value, "verifier_timeout"))
        .transpose()?
        .unwrap_or(iteron_verify::DEFAULT_VERIFIER_TIMEOUT_SECS);
    let retry = match optional_object(view, "retry_eligibility_policy")? {
        Some(fields) => {
            let eligible_classes =
                text_list_field(fields, "retry_eligibility_policy", "eligible_classes")?
                    .into_iter()
                    .map(|class| match class.as_str() {
                        "verification.test_failure" => Ok(VerificationFailureClass::TestFailure),
                        "verification.timed_out" => Ok(VerificationFailureClass::TimedOut),
                        "verification.infrastructure_failure" => {
                            Ok(VerificationFailureClass::InfrastructureFailure)
                        }
                        "verification.cancelled" => Ok(VerificationFailureClass::Cancelled),
                        other => Err(unknown("retry_eligibility_policy", other)),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            VerificationRetryPolicy {
                eligible_classes,
                max_attempts: u32::try_from(integer_field(
                    fields,
                    "retry_eligibility_policy",
                    "max_attempts",
                )?)
                .map_err(|_| EffectiveCoreError::Range {
                    family: "retry_eligibility_policy",
                })?,
                unknown: match enum_field(fields, "retry_eligibility_policy", "unknown")? {
                    "stop" => UnknownVerificationRetryAction::Stop,
                    "operator" => UnknownVerificationRetryAction::Operator,
                    other => return Err(unknown("retry_eligibility_policy", other)),
                },
            }
        }
        None => VerificationRetryPolicy::default(),
    };

    let policy = VerificationRuntimePolicy {
        verifier_timeout_secs,
        selection,
        required_commands,
        max_commands,
        flaky,
        quorum,
        checkpoint,
        restore,
        feedback,
        retry,
    };
    policy
        .validate()
        .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
    Ok(policy)
}

pub(crate) fn decode_verification_feedback(
    view: &EffectiveTunablesView,
) -> Result<iteron_verify::VerificationFeedbackTailPolicy, EffectiveCoreError> {
    view.with_getter(RuntimeGetterId::VerificationFeedback, || {
        decode_verification_feedback_inner(view)
    })
}

fn decode_verification_feedback_inner(
    view: &EffectiveTunablesView,
) -> Result<iteron_verify::VerificationFeedbackTailPolicy, EffectiveCoreError> {
    let feedback_fields = view.object("verifier_feedback_tails")?;
    Ok(iteron_verify::VerificationFeedbackTailPolicy {
        command_output_bytes: usizev(
            integer_field(
                feedback_fields,
                "verifier_feedback_tails",
                "command_output_bytes",
            )?,
            "verifier_feedback_tails",
        )?,
        oracle_output_bytes: usizev(
            integer_field(
                feedback_fields,
                "verifier_feedback_tails",
                "oracle_output_bytes",
            )?,
            "verifier_feedback_tails",
        )?,
        total_bytes: usizev(
            integer_field(feedback_fields, "verifier_feedback_tails", "total_bytes")?,
            "verifier_feedback_tails",
        )?,
    })
}

fn decode_context_policies(
    view: &EffectiveTunablesView,
) -> Result<
    (
        iteron_ctx::ContextBudgetPolicy,
        iteron_ctx::ContextMaterializationPolicy,
        Option<u64>,
    ),
    EffectiveCoreError,
> {
    let trigger = view.object("compaction_trigger")?;
    let fallback_output_reserve = u32v(
        integer_field(trigger, "compaction_trigger", "output_reserve_tokens")?,
        "compaction_trigger",
    )?;
    let (window, model_context_window, output_reserve, verification_reserve, component_overrides) =
        match view.optional_value("context_window_override_reserve") {
            Some(ResolutionValue::Object { fields }) => {
                let window_value = integer_field(
                    fields,
                    "context_window_override_reserve",
                    "model_window_tokens",
                )?;
                let window = usizev(window_value, "context_window_override_reserve")?;
                let model_context_window = u64v(window_value, "context_window_override_reserve")?;
                let output = u32v(
                    integer_field(
                        fields,
                        "context_window_override_reserve",
                        "output_reserve_tokens",
                    )?,
                    "context_window_override_reserve",
                )?;
                let verification = u32v(
                    integer_field(
                        fields,
                        "context_window_override_reserve",
                        "verification_reserve_tokens",
                    )?,
                    "context_window_override_reserve",
                )?;
                (
                    window,
                    Some(model_context_window),
                    output,
                    verification,
                    Some(fields),
                )
            }
            Some(_) => {
                return Err(EffectiveViewError::WrongType {
                    family: "context_window_override_reserve".into(),
                    expected: "object",
                }
                .into());
            }
            None => (
                usizev(
                    integer_field(trigger, "compaction_trigger", "fallback_trigger_tokens")?,
                    "compaction_trigger",
                )?
                .saturating_add(usize::try_from(fallback_output_reserve).unwrap_or(usize::MAX)),
                None,
                fallback_output_reserve,
                0,
                None,
            ),
        };
    let mut budget = iteron_ctx::ContextBudgetPolicy::for_usable_window(
        window,
        output_reserve,
        verification_reserve,
    );
    if let Some(value) = optional_integer(view, "system_prefix_budget")? {
        budget.stable_prefix_tokens = usizev(value, "system_prefix_budget")?;
    }
    if let Some(value) = optional_integer(view, "conversation_history_budget")? {
        budget.transcript_tokens = usizev(value, "conversation_history_budget")?;
    }
    if let Some(value) = optional_integer(view, "tool_result_history_budget")? {
        budget.tool_result_tokens = usizev(value, "tool_result_history_budget")?;
    }
    budget.multimodal_tokens = optional_integer(view, "multimodal_token_budget")?
        .map(|value| usizev(value, "multimodal_token_budget"))
        .transpose()?
        .unwrap_or(0);
    budget.lsp_result_tokens = optional_integer(view, "lsp_result_context_budget")?
        .map(|value| usizev(value, "lsp_result_context_budget"))
        .transpose()?
        .unwrap_or(0);

    let memory = view.object("memory_budgets")?;
    let instruction_discovery = decode_instruction_discovery(view)?;
    let materialization = iteron_ctx::ContextMaterializationPolicy {
        max_bytes: iteron_protocol::context::MAX_CONTEXT_GRANT_BYTES,
        memory: iteron_ctx::MemBudget {
            recall_bytes: usizev(
                integer_field(memory, "memory_budgets", "recall_bytes")?,
                "memory_budgets",
            )?,
            index_bytes: usizev(
                integer_field(memory, "memory_budgets", "index_bytes")?,
                "memory_budgets",
            )?,
            instr_bytes: usizev(
                integer_field(memory, "memory_budgets", "instruction_bytes")?,
                "memory_budgets",
            )?,
            total: usizev(
                integer_field(memory, "memory_budgets", "total_bytes")?,
                "memory_budgets",
            )?,
        },
        memory_retrieval: decode_memory_retrieval(view)?,
        skill_listing_bytes: usizev(
            view.integer("skill_listing_budget")?,
            "skill_listing_budget",
        )?,
        instruction_discovery,
    }
    .validate()
    .map_err(|reason| EffectiveCoreError::InvalidBudget(reason.into()))?;
    let component_override = |field| {
        component_overrides
            .map(|fields| optional_integer_field(fields, "context_window_override_reserve", field))
            .transpose()
            .map(|value| value.flatten())
    };
    budget.instruction_tokens = component_override("instruction_budget_tokens")?
        .map(|value| usizev(value, "context_window_override_reserve"))
        .transpose()?
        .unwrap_or_else(|| estimated_tokens_for_byte_ceiling(materialization.memory.instr_bytes));
    budget.task_context_tokens = component_override("task_context_budget_tokens")?
        .map(|value| usizev(value, "context_window_override_reserve"))
        .transpose()?
        .unwrap_or(budget.task_context_tokens);
    budget.memory_tokens = component_override("memory_budget_tokens")?
        .map(|value| usizev(value, "context_window_override_reserve"))
        .transpose()?
        .unwrap_or_else(|| {
            estimated_tokens_for_byte_ceiling(
                materialization
                    .memory
                    .index_bytes
                    .saturating_add(materialization.memory.recall_bytes),
            )
        });
    budget.attachment_tokens = component_override("attachment_budget_tokens")?
        .map(|value| usizev(value, "context_window_override_reserve"))
        .transpose()?
        .unwrap_or(budget.attachment_tokens);
    budget.tool_schema_tokens = component_override("tool_schema_budget_tokens")?
        .map(|value| usizev(value, "context_window_override_reserve"))
        .transpose()?
        .unwrap_or(budget.tool_schema_tokens);
    budget
        .validate_for_window(window)
        .map_err(|reason| EffectiveCoreError::InvalidBudget(reason.into()))?;
    Ok((budget, materialization, model_context_window))
}

fn decode_instruction_discovery(
    view: &EffectiveTunablesView,
) -> Result<iteron_ctx::InstructionDiscoveryPolicy, EffectiveCoreError> {
    let fields = view.object("instruction_discovery_render")?;
    iteron_ctx::InstructionDiscoveryPolicy::try_new(
        usizev(
            integer_field(fields, "instruction_discovery_render", "max_depth")?,
            "instruction_discovery_render",
        )?,
        usizev(
            integer_field(fields, "instruction_discovery_render", "max_files")?,
            "instruction_discovery_render",
        )?,
        usizev(
            integer_field(fields, "instruction_discovery_render", "per_file_bytes")?,
            "instruction_discovery_render",
        )?,
        usizev(
            integer_field(fields, "instruction_discovery_render", "total_bytes")?,
            "instruction_discovery_render",
        )?,
    )
    .map_err(|reason| EffectiveCoreError::InvalidBudget(reason.into()))
}

fn estimated_tokens_for_byte_ceiling(bytes: usize) -> usize {
    // ceil(bytes / 3.5) == ceil(bytes * 2 / 7), without floating-point or overflow.
    bytes.saturating_mul(2).saturating_add(6) / 7
}

fn decode_memory_retrieval(
    view: &EffectiveTunablesView,
) -> Result<iteron_ctx::MemoryRetrievalPolicy, EffectiveCoreError> {
    let mut policy = iteron_ctx::MemoryRetrievalPolicy::default();
    for (parameter, value) in view.map("bm25")? {
        let ResolutionValue::Decimal { value } = value else {
            return Err(EffectiveCoreError::WrongFieldType {
                family: "bm25",
                field: "entry",
            });
        };
        match parameter.as_str() {
            "k1" => policy.bm25_k1_milli = decimal_scaled_u32(*value, 1_000, "bm25")?,
            "b" => policy.bm25_b_ppm = decimal_ppm(*value, "bm25")?,
            "recall_limit" => policy.recall_limit = decimal_scaled_u32(*value, 1, "bm25")?,
            other => return Err(unknown("bm25", other)),
        }
    }
    if let Some(value) = view.optional_value("hybrid_retrieval_fusion_weights") {
        let ResolutionValue::Map { entries } = value else {
            return Err(EffectiveViewError::WrongType {
                family: "hybrid_retrieval_fusion_weights".into(),
                expected: "map",
            }
            .into());
        };
        for (signal, value) in entries {
            let ResolutionValue::Decimal { value } = value else {
                return Err(EffectiveCoreError::WrongFieldType {
                    family: "hybrid_retrieval_fusion_weights",
                    field: "entry",
                });
            };
            let weight = decimal_ppm(*value, "hybrid_retrieval_fusion_weights")?;
            match signal.as_str() {
                "lexical" => policy.lexical_weight_ppm = weight,
                "structural" => policy.structural_weight_ppm = weight,
                "vector" => policy.vector_weight_ppm = weight,
                "reranker" => policy.reranker_weight_ppm = weight,
                other => return Err(unknown("hybrid_retrieval_fusion_weights", other)),
            }
        }
    }
    if let Some(value) = optional_decimal(view, "retrieval_recency_decay")? {
        policy.recency_decay_ppm = decimal_ppm(value, "retrieval_recency_decay")?;
    }
    if let Some(value) = optional_decimal(view, "context_novelty_dedup_threshold")? {
        policy.novelty_dedup_threshold_ppm = decimal_ppm(value, "context_novelty_dedup_threshold")?;
    }
    policy
        .validate()
        .map_err(|reason| EffectiveCoreError::InvalidBudget(reason.into()))
}

fn decode_permission_rules(
    view: &EffectiveTunablesView,
) -> Result<PermissionRules, EffectiveCoreError> {
    let mut rules = PermissionRules::new();
    for (key, value) in view.map("permission_rules")? {
        let ResolutionValue::Enum { value } = value else {
            return Err(EffectiveCoreError::WrongFieldType {
                family: "permission_rules",
                field: "entry",
            });
        };
        let verdict = match value.as_str() {
            "allow" => Verdict::Auto,
            "ask" => Verdict::Ask,
            "deny" => Verdict::Deny,
            other => return Err(unknown("permission_rules", other)),
        };
        if let Some(name) = key.strip_prefix("capability:") {
            rules.set_cap(parse_capability(name)?, verdict);
        } else if let Some(tool) = key.strip_prefix("tool:") {
            rules.set_tool(tool, verdict);
        } else {
            return Err(unknown("permission_rules", key));
        }
    }
    Ok(rules)
}

fn parse_capability(value: &str) -> Result<Capability, EffectiveCoreError> {
    match value {
        "read_only" => Ok(Capability::ReadOnly),
        "reversible_local" => Ok(Capability::ReversibleLocal),
        "code_executing" => Ok(Capability::CodeExecuting),
        "trust_mutating" => Ok(Capability::TrustMutating),
        "irreversible_external" => Ok(Capability::IrreversibleExternal),
        other => Err(unknown("permission_rules", other)),
    }
}

fn decode_token_estimator(
    view: &EffectiveTunablesView,
) -> Result<iteron_ctx::TokenEstimatorPolicy, EffectiveCoreError> {
    let family = "token_estimator";
    let fields = view.object(family)?;
    if decimal_ppm(decimal_field(fields, family, "safety_margin")?, family)? != 0 {
        return Err(EffectiveCoreError::InvalidBudget(
            "the checkpointed token estimator safety margin is not physically implemented".into(),
        ));
    }
    match enum_field(fields, family, "estimator")? {
        iteron_ctx::ROUTE_AWARE_ESTIMATOR_POLICY_ID => {
            Ok(iteron_ctx::TokenEstimatorPolicy::RouteAwareV2)
        }
        other => Err(unknown(family, other)),
    }
}

fn decode_compaction(
    view: &EffectiveTunablesView,
) -> Result<iteron_ctx::CompactionPolicy, EffectiveCoreError> {
    let family = "compaction_trigger";
    let trigger = view.object(family)?;
    let mode = enum_field(trigger, family, "mode")?;
    let fallback = usizev(
        integer_field(trigger, family, "fallback_trigger_tokens")?,
        family,
    )?;
    let keep_recent = usizev(
        view.integer("compaction_keep_recent")?,
        "compaction_keep_recent",
    )?;
    let adaptive_family = "compaction_adaptive";
    let adaptive = view.object(adaptive_family)?;
    let adaptive_ratio = decimal_ppm(
        decimal_field(adaptive, adaptive_family, "usable_window_ratio")?,
        adaptive_family,
    )?;
    let adaptive_keep_recent = usizev(
        integer_field(adaptive, adaptive_family, "keep_recent_messages")?,
        adaptive_family,
    )?;
    let adaptive_output_reserve = u32v(
        integer_field(adaptive, adaptive_family, "output_reserve_tokens")?,
        adaptive_family,
    )?;
    let trigger_output_reserve = u32v(
        integer_field(trigger, family, "output_reserve_tokens")?,
        family,
    )?;
    if adaptive_ratio != 800_000
        || adaptive_keep_recent != keep_recent
        || adaptive_output_reserve != trigger_output_reserve
    {
        return Err(EffectiveCoreError::InvalidBudget(
            "compaction adaptive owner disagrees with its physical 4/5 trigger, recent tail, or output reserve"
                .into(),
        ));
    }
    let mut policy = iteron_ctx::CompactionPolicy::default();
    policy.trigger_tokens = fallback;
    policy.keep_recent = keep_recent;
    policy.enabled = optional_boolean(view, "auto_compaction_enable")?.unwrap_or(true);
    let summary = view.object("summary_profile")?;
    let summary_effort = enum_field(summary, "summary_profile", "effort")?;
    policy.summary_profile = iteron_ctx::SummaryProfile {
        max_output_tokens: u32v(
            integer_field(summary, "summary_profile", "max_output_tokens")?,
            "summary_profile",
        )?,
        effort: Effort::parse(summary_effort)
            .ok_or_else(|| unknown("summary_profile", summary_effort))?,
        preserve_tool_evidence: boolean_field(
            summary,
            "summary_profile",
            "preserve_tool_evidence",
        )?,
    }
    .validate()
    .map_err(|reason| EffectiveCoreError::InvalidBudget(reason.into()))?;
    if let Some(fields) = optional_object(view, "compaction_cooldown_hysteresis")? {
        policy.hysteresis = iteron_ctx::CompactionHysteresis {
            cooldown_turns: u32v(
                integer_field(fields, "compaction_cooldown_hysteresis", "cooldown_turns")?,
                "compaction_cooldown_hysteresis",
            )?,
            enter_ratio_ppm: decimal_ppm(
                decimal_field(fields, "compaction_cooldown_hysteresis", "enter_ratio")?,
                "compaction_cooldown_hysteresis",
            )?,
            exit_ratio_ppm: decimal_ppm(
                decimal_field(fields, "compaction_cooldown_hysteresis", "exit_ratio")?,
                "compaction_cooldown_hysteresis",
            )?,
        }
        .validate()
        .map_err(|reason| EffectiveCoreError::InvalidBudget(reason.into()))?;
    }
    if let Some(topology) = optional_enum(view, "multi_stage_summary_topology")? {
        policy.summary_topology = iteron_ctx::SummaryTopology::parse(topology)
            .ok_or_else(|| unknown("multi_stage_summary_topology", topology))?;
    }
    policy.coverage_check =
        optional_boolean(view, "summary_consistency_coverage_check")?.unwrap_or(false);
    match mode {
        "adaptive" => {}
        "fixed" => policy.set_fixed_trigger_tokens(fallback),
        other => return Err(unknown(family, other)),
    }
    Ok(policy)
}

fn boolean_field(
    fields: &std::collections::BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<bool, EffectiveCoreError> {
    match fields
        .get(field)
        .ok_or(EffectiveCoreError::MissingField { family, field })?
    {
        ResolutionValue::Boolean { value } => Ok(*value),
        _ => Err(EffectiveCoreError::WrongFieldType { family, field }),
    }
}

fn decimal_field(
    fields: &std::collections::BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<DecimalValue, EffectiveCoreError> {
    match fields
        .get(field)
        .ok_or(EffectiveCoreError::MissingField { family, field })?
    {
        ResolutionValue::Decimal { value } => Ok(*value),
        _ => Err(EffectiveCoreError::WrongFieldType { family, field }),
    }
}

fn decimal_ppm(value: DecimalValue, family: &'static str) -> Result<u32, EffectiveCoreError> {
    let denominator = 10_i128.pow(u32::from(value.scale));
    let scaled = i128::from(value.coefficient)
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_div(denominator))
        .ok_or(EffectiveCoreError::Range { family })?;
    u32::try_from(scaled).map_err(|_| EffectiveCoreError::Range { family })
}

fn decimal_scaled_u32(
    value: DecimalValue,
    multiplier: u32,
    family: &'static str,
) -> Result<u32, EffectiveCoreError> {
    let denominator = 10_i128.pow(u32::from(value.scale));
    let numerator = i128::from(value.coefficient)
        .checked_mul(i128::from(multiplier))
        .ok_or(EffectiveCoreError::Range { family })?;
    if numerator % denominator != 0 {
        return Err(EffectiveCoreError::Range { family });
    }
    u32::try_from(numerator / denominator).map_err(|_| EffectiveCoreError::Range { family })
}

fn optional_object<'a>(
    view: &'a EffectiveTunablesView,
    family: &'static str,
) -> Result<Option<&'a std::collections::BTreeMap<String, ResolutionValue>>, EffectiveCoreError> {
    match view.optional_value(family) {
        None => Ok(None),
        Some(ResolutionValue::Object { fields }) => Ok(Some(fields)),
        Some(_) => Err(EffectiveViewError::WrongType {
            family: family.into(),
            expected: "object",
        }
        .into()),
    }
}

fn optional_enum<'a>(
    view: &'a EffectiveTunablesView,
    family: &'static str,
) -> Result<Option<&'a str>, EffectiveCoreError> {
    match view.optional_value(family) {
        None => Ok(None),
        Some(ResolutionValue::Enum { value }) => Ok(Some(value)),
        Some(_) => Err(EffectiveViewError::WrongType {
            family: family.into(),
            expected: "enum",
        }
        .into()),
    }
}

fn integer_field(
    fields: &std::collections::BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<i64, EffectiveCoreError> {
    match fields
        .get(field)
        .ok_or(EffectiveCoreError::MissingField { family, field })?
    {
        ResolutionValue::Integer { value } => Ok(*value),
        _ => Err(EffectiveCoreError::WrongFieldType { family, field }),
    }
}

fn optional_integer_field(
    fields: &std::collections::BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<Option<i64>, EffectiveCoreError> {
    match fields.get(field) {
        None => Ok(None),
        Some(ResolutionValue::Integer { value }) => Ok(Some(*value)),
        Some(_) => Err(EffectiveCoreError::WrongFieldType { family, field }),
    }
}

fn enum_field<'a>(
    fields: &'a std::collections::BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<&'a str, EffectiveCoreError> {
    match fields
        .get(field)
        .ok_or(EffectiveCoreError::MissingField { family, field })?
    {
        ResolutionValue::Enum { value } => Ok(value),
        _ => Err(EffectiveCoreError::WrongFieldType { family, field }),
    }
}

fn text_list_field(
    fields: &std::collections::BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<Vec<String>, EffectiveCoreError> {
    optional_text_list_field(fields, family, field)?
        .ok_or(EffectiveCoreError::MissingField { family, field })
}

fn optional_text_list_field(
    fields: &std::collections::BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<Option<Vec<String>>, EffectiveCoreError> {
    let Some(value) = fields.get(field) else {
        return Ok(None);
    };
    let ResolutionValue::List { items } = value else {
        return Err(EffectiveCoreError::WrongFieldType { family, field });
    };
    items
        .iter()
        .map(|item| match item {
            ResolutionValue::Text { value } => Ok(value.clone()),
            _ => Err(EffectiveCoreError::WrongFieldType { family, field }),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn optional_integer(
    view: &EffectiveTunablesView,
    family: &'static str,
) -> Result<Option<i64>, EffectiveCoreError> {
    match view.optional_value(family) {
        None => Ok(None),
        Some(ResolutionValue::Integer { value }) => Ok(Some(*value)),
        Some(_) => Err(EffectiveViewError::WrongType {
            family: family.to_owned(),
            expected: "integer",
        }
        .into()),
    }
}

fn optional_decimal(
    view: &EffectiveTunablesView,
    family: &'static str,
) -> Result<Option<DecimalValue>, EffectiveCoreError> {
    match view.optional_value(family) {
        None => Ok(None),
        Some(ResolutionValue::Decimal { value }) => Ok(Some(*value)),
        Some(_) => Err(EffectiveViewError::WrongType {
            family: family.to_owned(),
            expected: "decimal",
        }
        .into()),
    }
}

fn optional_boolean(
    view: &EffectiveTunablesView,
    family: &'static str,
) -> Result<Option<bool>, EffectiveCoreError> {
    match view.optional_value(family) {
        None => Ok(None),
        Some(ResolutionValue::Boolean { value }) => Ok(Some(*value)),
        Some(_) => Err(EffectiveViewError::WrongType {
            family: family.to_owned(),
            expected: "boolean",
        }
        .into()),
    }
}

fn optional_text(
    view: &EffectiveTunablesView,
    family: &'static str,
) -> Result<Option<String>, EffectiveCoreError> {
    match view.optional_value(family) {
        None => Ok(None),
        Some(ResolutionValue::Text { value }) => Ok(Some(value.clone())),
        Some(_) => Err(EffectiveViewError::WrongType {
            family: family.to_owned(),
            expected: "text",
        }
        .into()),
    }
}

fn decimal_to_f64(value: DecimalValue) -> f64 {
    value.coefficient as f64 / 10_f64.powi(i32::from(value.scale))
}

fn u32v(value: i64, family: &'static str) -> Result<u32, EffectiveCoreError> {
    u32::try_from(value).map_err(|_| EffectiveCoreError::Range { family })
}

fn u64v(value: i64, family: &'static str) -> Result<u64, EffectiveCoreError> {
    u64::try_from(value).map_err(|_| EffectiveCoreError::Range { family })
}

fn usizev(value: i64, family: &'static str) -> Result<usize, EffectiveCoreError> {
    usize::try_from(value).map_err(|_| EffectiveCoreError::Range { family })
}

fn unknown(family: &'static str, value: &str) -> EffectiveCoreError {
    EffectiveCoreError::UnknownValue {
        family,
        value: value.to_owned(),
    }
}

#[cfg(test)]
mod memory_schema_agreement_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn decimal(coefficient: i64, scale: u8) -> ResolutionValue {
        ResolutionValue::Decimal {
            value: DecimalValue { coefficient, scale },
        }
    }

    #[test]
    fn canonical_memory_values_decode_without_a_later_runtime_rejection() {
        let values = BTreeMap::from([
            (
                "bm25".to_owned(),
                ResolutionValue::Map {
                    entries: BTreeMap::from([
                        ("b".to_owned(), decimal(75, 2)),
                        ("k1".to_owned(), decimal(12, 1)),
                        ("recall_limit".to_owned(), decimal(32, 0)),
                    ]),
                },
            ),
            (
                "hybrid_retrieval_fusion_weights".to_owned(),
                ResolutionValue::Map {
                    entries: BTreeMap::from([
                        ("lexical".to_owned(), decimal(5, 1)),
                        ("structural".to_owned(), decimal(5, 1)),
                    ]),
                },
            ),
        ]);
        let policy = decode_memory_retrieval(&EffectiveTunablesView::from_test_values(values))
            .expect("every canonical resolver-accepted memory value must decode");
        assert_eq!(policy.bm25_k1_milli, 1_200);
        assert_eq!(policy.bm25_b_ppm, 750_000);
        assert_eq!(policy.recall_limit, 32);
        assert_eq!(policy.lexical_weight_ppm, 500_000);
        assert_eq!(policy.structural_weight_ppm, 500_000);
        assert_eq!(policy.vector_weight_ppm, 0);
        assert_eq!(policy.reranker_weight_ppm, 0);
    }

    #[test]
    fn allow_code_is_an_outer_authority_gate_even_when_inner_rules_say_auto() {
        let all = CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::ReversibleLocal,
            Capability::CodeExecuting,
            Capability::TrustMutating,
            Capability::IrreversibleExternal,
        ]);
        assert_eq!(constrain_code_execution_authority(true, all), all);
        let denied = constrain_code_execution_authority(false, all);
        assert!(!denied.contains(Capability::CodeExecuting));
        assert!(denied.contains(Capability::ReadOnly));
        assert!(denied.contains(Capability::IrreversibleExternal));

        let contradictory = EffectiveTunablesView::from_test_values(BTreeMap::from([
            (
                "allow_code".to_owned(),
                ResolutionValue::Boolean { value: false },
            ),
            (
                "permission_rules".to_owned(),
                ResolutionValue::Map {
                    entries: BTreeMap::from([(
                        "capability:code_executing".to_owned(),
                        ResolutionValue::Enum {
                            value: "allow".to_owned(),
                        },
                    )]),
                },
            ),
        ]));
        let (allow_code, inner_rules) = decode_governance(&contradictory).unwrap();
        assert!(!allow_code);
        assert_eq!(
            inner_rules.cap_rule(Capability::CodeExecuting),
            Some(Verdict::Auto),
            "the family-11 checkpoint remains exact rather than being rewritten in memory"
        );
        assert!(
            !constrain_code_execution_authority(allow_code, all)
                .contains(Capability::CodeExecuting),
            "the independent family-9 authority ceiling wins before permission rules are read"
        );

        let narrowed = EffectiveTunablesView::from_test_values(BTreeMap::from([
            (
                "allow_code".to_owned(),
                ResolutionValue::Boolean { value: false },
            ),
            (
                "permission_rules".to_owned(),
                ResolutionValue::Map {
                    entries: BTreeMap::new(),
                },
            ),
        ]));
        assert!(matches!(decode_governance(&narrowed), Ok((false, _))));
    }

    #[test]
    fn prompt_cache_route_gate_can_only_disable_family_158_controls() {
        use iteron_provider::{
            CacheBreakpoint, CacheScope, GovernorPolicy, PromptCacheControl,
            ProviderRequestControls,
        };

        let configured = crate::config::ResolvedProviderGovernorConfig {
            fallback_routes: Vec::new(),
            policy: GovernorPolicy::default(),
            controls: ProviderRequestControls {
                prompt_cache: PromptCacheControl {
                    ttl_seconds: 300,
                    breakpoint: CacheBreakpoint::Rolling,
                    invalidate_on_tool_change: true,
                    scope: CacheScope::Tenant,
                },
                ..ProviderRequestControls::default()
            },
        };
        let enabled = constrain_prompt_cache(configured.clone(), true);
        assert_eq!(
            enabled.controls.prompt_cache,
            configured.controls.prompt_cache
        );

        let disabled = constrain_prompt_cache(configured, false);
        assert_eq!(
            disabled.controls.prompt_cache,
            PromptCacheControl::default(),
            "family 158 cannot re-enable cache controls outside the family-23 route gate"
        );
    }

    #[test]
    fn checkpoint_model_limits_are_execution_values_and_live_capabilities_only_narrow_admission() {
        assert!(
            verify_model_capability_ceiling(
                Some(120_000),
                Some(8_192),
                Some(120_000),
                Some(8_192),
            )
            .is_ok()
        );
        assert!(
            verify_model_capability_ceiling(
                Some(120_000),
                Some(8_192),
                Some(256_000),
                Some(16_384),
            )
            .is_ok(),
            "a larger live capability must not replace or reject the pinned lower execution value"
        );
        assert!(matches!(
            verify_model_capability_ceiling(Some(120_000), Some(8_192), Some(64_000), Some(8_192),),
            Err(EffectiveCoreError::UnknownValue {
                family: "context_window_override_reserve",
                ..
            })
        ));
        assert!(
            verify_model_capability_ceiling(Some(120_000), Some(8_192), Some(120_000), None,)
                .is_ok(),
            "unknown output metadata preserves the checkpoint's conservative execution cap"
        );
        assert!(matches!(
            verify_model_capability_ceiling(Some(120_000), Some(8_192), Some(120_000), Some(4_096),),
            Err(EffectiveCoreError::UnknownValue {
                family: "request_output_cap",
                ..
            })
        ));
        assert!(
            verify_model_capability_ceiling(None, None, Some(256_000), Some(16_384)).is_ok(),
            "newly discovered capabilities cannot activate a family absent at genesis"
        );
    }
}
