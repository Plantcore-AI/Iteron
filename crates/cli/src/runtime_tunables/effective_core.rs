//! Runtime projection for the composition-root families owned by iteron-cli.
//!
//! This decoder is intentionally the only place that turns the immutable resolver/checkpoint
//! representation back into kernel types. Fresh and resumed runs therefore use the same bytes;
//! neither path gets to rediscover a default from `Budget`, `CompactionPolicy`, or config.

use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use iteron_protocol::{Budget, Capability, Effort, PermissionMode, PermissionRules, Verdict};
use iteron_sched::BackoffPolicy;
use iteron_tunables::{DecimalValue, ResolutionValue};

#[derive(Debug, Clone)]
pub(crate) struct EffectiveCoreSettings {
    pub profile: iteron_tunables::RuntimeProfile,
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
    pub compaction: iteron_ctx::CompactionPolicy,
    pub verify_command: Option<String>,
    pub verification: iteron_verify::VerificationRuntimePolicy,
    pub prompt_cache_enabled: bool,
    pub memory_enabled: bool,
    pub session_spawn_cap: usize,
    pub deferred_tool_eager_limit: Option<usize>,
    pub context_budget: iteron_ctx::ContextBudgetPolicy,
    pub context_materialization: iteron_ctx::ContextMaterializationPolicy,
    pub provider_governor: crate::config::ResolvedProviderGovernorConfig,
    pub mcp: super::effective_mcp::EffectiveMcpSettings,
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

        let (context_budget, context_materialization) = decode_context_policies(view)?;
        let provider_governor = super::effective_provider::decode(view)?;
        let mcp = super::effective_mcp::EffectiveMcpSettings::decode(view)
            .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
        let verify_command = optional_text(view, "verify_command")?;
        let verification = decode_verification(view, verify_command.as_deref())?;
        Ok(Self {
            profile: view.runtime_profile()?,
            provider_id: view.enumeration("provider")?.to_owned(),
            model_id: view.enumeration("model")?.to_owned(),
            base_url: view.text("base_url")?.to_owned(),
            effort,
            budget,
            allow_code: view.boolean("allow_code")?,
            permission_mode,
            permission_rules: decode_permission_rules(view)?,
            bypass_permissions: view.boolean("bypass_permissions")?,
            retry: BackoffPolicy {
                base_ms: u64v(view.integer("retry_backoff_base")?, "retry_backoff_base")?,
                cap_ms: u64v(view.integer("retry_backoff_cap")?, "retry_backoff_cap")?,
                max_attempts: u32v(view.integer("retry_max_attempts")?, "retry_max_attempts")?,
            },
            compaction: decode_compaction(view)?,
            verify_command,
            verification,
            prompt_cache_enabled: optional_boolean(view, "prompt_cache")?.unwrap_or(false),
            memory_enabled: view.boolean("memory_enable")?,
            session_spawn_cap: usizev(
                view.integer("per_session_spawn_cap")?,
                "per_session_spawn_cap",
            )?,
            deferred_tool_eager_limit: optional_integer(view, "deferred_discovery_threshold")?
                .map(|value| usizev(value, "deferred_discovery_threshold"))
                .transpose()?
                .filter(|value| *value > 0),
            context_budget,
            context_materialization,
            provider_governor,
            mcp,
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
}

fn decode_verification(
    view: &EffectiveTunablesView,
    configured_command: Option<&str>,
) -> Result<iteron_verify::VerificationRuntimePolicy, EffectiveCoreError> {
    use iteron_verify::{
        FlakyQuarantinePolicy, VerificationCheckpointPolicy, VerificationQuorumPolicy,
        VerificationRestorePolicy, VerificationRollbackMode, VerificationRuntimePolicy,
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
                require_operator_confirmation: boolean_field(
                    fields,
                    "selective_restore_scope",
                    "require_operator_confirmation",
                )?,
            }
        }
        None => VerificationRestorePolicy {
            mode: rollback,
            ..VerificationRestorePolicy::default()
        },
    };

    let policy = VerificationRuntimePolicy {
        selection,
        required_commands,
        max_commands,
        flaky,
        quorum,
        checkpoint,
        restore,
    };
    policy
        .validate()
        .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
    Ok(policy)
}

fn decode_context_policies(
    view: &EffectiveTunablesView,
) -> Result<
    (
        iteron_ctx::ContextBudgetPolicy,
        iteron_ctx::ContextMaterializationPolicy,
    ),
    EffectiveCoreError,
> {
    let trigger = view.object("compaction_trigger")?;
    let fallback_output_reserve = u32v(
        integer_field(trigger, "compaction_trigger", "output_reserve_tokens")?,
        "compaction_trigger",
    )?;
    let (window, output_reserve, verification_reserve, component_overrides) =
        match view.optional_value("context_window_override_reserve") {
            Some(ResolutionValue::Object { fields }) => {
                let window = usizev(
                    integer_field(
                        fields,
                        "context_window_override_reserve",
                        "model_window_tokens",
                    )?,
                    "context_window_override_reserve",
                )?;
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
                (window, output, verification, Some(fields))
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
    Ok((budget, materialization))
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
