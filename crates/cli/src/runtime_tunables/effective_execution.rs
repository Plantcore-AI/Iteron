//! Decode the orchestration owner from the immutable effective tunables snapshot.

use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use super::execution_policy::{
    ChildAdmissionPolicy, ChildCeilingPolicy, ChildMemoryPolicy, DecompositionRuntimePolicy,
    DirectChildAllocationPolicy, ExactRatio, ExecutionRuntimePolicy, PerAgentModelIdentity,
    PerAgentToolProfileIdentity, RoleSpecificModelMapIdentity, RouteTopology, WallSplitPolicy,
    WorkflowAggregatePolicy, WriterFanTurnPolicy,
};
use iteron_protocol::{Capability, Effort, capability_set::CapabilitySet};
use iteron_tunables::{ResolutionValue, RuntimeGetterId};
use std::collections::BTreeMap;

#[cfg(test)]
pub(crate) fn decode(
    view: &EffectiveTunablesView,
) -> Result<ExecutionRuntimePolicy, EffectiveExecutionError> {
    decode_with_effort_policy(
        view,
        &super::effective_core::EffortRuntimePolicy::compiled(),
    )
}

pub(crate) fn decode_with_effort_policy(
    view: &EffectiveTunablesView,
    effort_policy: &super::effective_core::EffortRuntimePolicy,
) -> Result<ExecutionRuntimePolicy, EffectiveExecutionError> {
    view.with_getter(RuntimeGetterId::EffectiveExecution, || {
        decode_inner(view, effort_policy)
    })
}

fn decode_inner(
    view: &EffectiveTunablesView,
    effort_policy: &super::effective_core::EffortRuntimePolicy,
) -> Result<ExecutionRuntimePolicy, EffectiveExecutionError> {
    let route_topology = match view.enumeration("route_topology")? {
        "direct" => RouteTopology::Direct,
        "orchestrated" => RouteTopology::Orchestrated,
        value => {
            return Err(EffectiveExecutionError::UnknownEnum(
                "route_topology",
                value.into(),
            ));
        }
    };
    let admission = view.object("admission")?;
    let turn = view.object("writer_fan_turn_split")?;
    let wall = view.object("wall_split")?;
    let fan_token_share = decimal_ratio(view, "token_split")?;
    let direct = view.object("direct_child_allocation")?;
    let workflow = view.object("workflow_aggregate")?;
    let schema_retry = view.object("schema_retry_jitter")?;
    let sibling_cancellation = view.object("speculative_sibling_cancellation")?;
    let quorum = view.object("early_stop_quorum_policy")?;
    let task_retry = view.object("task_retry_reassignment_policy")?;
    let write_set = view.object("write_set_conflict_admission")?;
    decode_join_reduce_invariant(view)?;
    let decomposition = optional_object(view, "decomposition_profile")?
        .map(|fields| decode_decomposition(fields, effort_policy))
        .transpose()?;
    let fan_breadth = optional_integer(view, "fan_breadth")?
        .map(|value| usize::try_from(value).map_err(|_| range("fan_breadth", "$")))
        .transpose()?;
    let fan_concurrency = usize::try_from(view.integer("fan_concurrency")?)
        .map_err(|_| range("fan_concurrency", "$"))?;
    let workflow_max_concurrency = usize_field(workflow, "workflow_aggregate", "max_concurrency")?;
    if fan_concurrency != workflow_max_concurrency {
        return Err(EffectiveExecutionError::InvalidOwner(
            "fan concurrency differs from the immutable workflow aggregate",
        ));
    }
    let worker_min_turns = optional_integer(view, "worker_min_turns")?
        .map(|value| u32::try_from(value).map_err(|_| range("worker_min_turns", "$")))
        .transpose()?;
    let child_ceiling = optional_object(view, "child_ceiling")?
        .map(decode_child_ceiling)
        .transpose()?;
    let spawn_depth = optional_integer(view, "spawn_depth_control")?
        .map(|value| u8::try_from(value).map_err(|_| range("spawn_depth_control", "$")))
        .transpose()?;
    let task_priority = optional_object(view, "task_priority_scheduling")?
        .map(decode_task_priority)
        .transpose()?;
    let effort_label = view.enumeration("subagent_effort_inheritance")?;
    let subagent_effort = Effort::parse(effort_label).ok_or_else(|| {
        EffectiveExecutionError::UnknownEnum("subagent_effort_inheritance", effort_label.to_owned())
    })?;
    let per_agent_effort_label = view.enumeration("per_agent_effort_thinking")?;
    let per_agent_effort = Effort::parse(per_agent_effort_label).ok_or_else(|| {
        EffectiveExecutionError::UnknownEnum(
            "per_agent_effort_thinking",
            per_agent_effort_label.to_owned(),
        )
    })?;
    let per_agent_effort = match per_agent_effort {
        Effort::Ultracode => Effort::Max,
        other => other,
    };
    let per_agent_model = PerAgentModelIdentity::from_route(view.enumeration("per_agent_model")?)
        .map_err(EffectiveExecutionError::InvalidOwner)?;
    let per_agent_tool_profile = view
        .map("per_agent_tool_profile")?
        .iter()
        .map(|(tool, value)| match value {
            ResolutionValue::Enum { value } => Ok((tool.clone(), value.clone())),
            _ => Err(EffectiveExecutionError::WrongType(
                "per_agent_tool_profile",
                tool.clone(),
            )),
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let per_agent_tool_profile = PerAgentToolProfileIdentity::from_labels(&per_agent_tool_profile)
        .map_err(EffectiveExecutionError::InvalidOwner)?;
    let per_agent_memory = view.object("per_agent_memory_scope")?;
    let role_specific_models = view.map("role_specific_model_map")?;
    let role_specific_models = role_specific_models
        .iter()
        .map(|(role, value)| match value {
            ResolutionValue::Enum { value } => Ok((role.clone(), value.clone())),
            _ => Err(EffectiveExecutionError::WrongType(
                "role_specific_model_map",
                role.clone(),
            )),
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if enum_field(per_agent_memory, "per_agent_memory_scope", "mode")? != "isolated"
        || bool_field(per_agent_memory, "per_agent_memory_scope", "inherit_parent")?
        || per_agent_memory.contains_key("scope_id")
    {
        return Err(EffectiveExecutionError::InvalidOwner(
            "workflow children currently require isolated memory without a parent scope",
        ));
    }
    let policy = ExecutionRuntimePolicy {
        route_topology,
        admission: ChildAdmissionPolicy {
            minimum_remaining_turns: u32_field(admission, "admission", "minimum_remaining_turns")?,
            minimum_remaining_wall_seconds: u64_field(
                admission,
                "admission",
                "minimum_remaining_wall_seconds",
            )?,
            require_capability_subset: bool_field(
                admission,
                "admission",
                "require_capability_subset",
            )?,
        },
        writer_fan_turn_split: WriterFanTurnPolicy {
            writer_share: ratio(turn, "writer_fan_turn_split", "writer")?,
            minimum_writer_turns: u32_field(turn, "writer_fan_turn_split", "minimum_writer_turns")?,
            strictly_dominant: bool_field(turn, "writer_fan_turn_split", "strictly_dominant")?,
        },
        wall_split: WallSplitPolicy {
            fan_share: ratio(wall, "wall_split", "fan")?,
            minimum_fan_seconds: u64_field(wall, "wall_split", "minimum_fan_seconds")?,
        },
        fan_token_share,
        effecting_tool_admission: crate::runtime::EffectingToolAdmissionPolicy {
            max_concurrency: usize::try_from(view.integer("effecting_tool_concurrency")?)
                .map_err(|_| range("effecting_tool_concurrency", "$"))?,
            declared_set_required: bool_field(
                write_set,
                "write_set_conflict_admission",
                "declared_set_required",
            )?,
            overlap: match enum_field(write_set, "write_set_conflict_admission", "overlap")? {
                "reject" => "reject",
                "serialize" => "serialize",
                value => {
                    return Err(EffectiveExecutionError::UnknownEnum(
                        "write_set_conflict_admission",
                        value.into(),
                    ));
                }
            },
            unknown_set: match enum_field(write_set, "write_set_conflict_admission", "unknown_set")?
            {
                "reject" => "reject",
                "serialize" => "serialize",
                value => {
                    return Err(EffectiveExecutionError::UnknownEnum(
                        "write_set_conflict_admission",
                        value.into(),
                    ));
                }
            },
        },
        direct_child_allocation: DirectChildAllocationPolicy {
            writer_share: ratio(direct, "direct_child_allocation", "writer_turn")?,
            strictly_dominant_writer: bool_field(
                direct,
                "direct_child_allocation",
                "strictly_dominant_writer",
            )?,
            child_token_share: ratio(direct, "direct_child_allocation", "child_token")?,
            child_wall_share: ratio(direct, "direct_child_allocation", "child_wall")?,
            minimum_child_turns: u32_field(
                direct,
                "direct_child_allocation",
                "minimum_child_turns",
            )?,
            minimum_remaining_wall_seconds: u64_field(
                direct,
                "direct_child_allocation",
                "minimum_remaining_wall_seconds",
            )?,
        },
        subagent_effort,
        per_agent_effort,
        per_agent_model,
        per_agent_tool_profile,
        per_agent_memory: ChildMemoryPolicy::Isolated,
        role_specific_models: RoleSpecificModelMapIdentity::from_routes(&role_specific_models)
            .map_err(EffectiveExecutionError::InvalidOwner)?,
        report_budget_bytes: usize::try_from(view.integer("report_budget")?)
            .map_err(|_| EffectiveExecutionError::Range("report_budget", "$".into()))?,
        workflow: WorkflowAggregatePolicy {
            max_calls: usize_field(workflow, "workflow_aggregate", "max_calls")?,
            max_tokens: optional_u64_field(workflow, "workflow_aggregate", "max_tokens")?,
            max_wall_seconds: u64_field(workflow, "workflow_aggregate", "max_wall_seconds")?,
            max_concurrency: workflow_max_concurrency,
        },
        decomposition,
        fan_breadth,
        worker_min_turns,
        child_ceiling,
        spawn_depth,
        task_priority,
        early_stop_quorum: iteron_workflow::EarlyStopQuorumPolicy::new(
            usize_field(quorum, "early_stop_quorum_policy", "minimum_evidence")?,
            usize_field(quorum, "early_stop_quorum_policy", "required_roles")?,
            bool_field(quorum, "early_stop_quorum_policy", "strong_veto")?,
        )
        .map_err(EffectiveExecutionError::InvalidOwner)?,
        speculative_siblings: decode_speculative_siblings(view, sibling_cancellation)?,
        task_retry: iteron_workflow::TaskRetryPolicy::new(
            usize_field(task_retry, "task_retry_reassignment_policy", "max_attempts")?,
            match enum_field(task_retry, "task_retry_reassignment_policy", "on_failure")? {
                "stop" => iteron_workflow::TaskFailureAction::Stop,
                "retry_same" => iteron_workflow::TaskFailureAction::RetrySame,
                "reassign" => iteron_workflow::TaskFailureAction::Reassign,
                value => {
                    return Err(EffectiveExecutionError::UnknownEnum(
                        "task_retry_reassignment_policy",
                        value.to_owned(),
                    ));
                }
            },
            bool_field(
                task_retry,
                "task_retry_reassignment_policy",
                "preserve_evidence",
            )?,
        )
        .map_err(EffectiveExecutionError::InvalidOwner)?,
        schema_retry: iteron_workflow::SchemaRetryPolicy::new(
            u32_field(schema_retry, "schema_retry_jitter", "max_attempts")?,
            u64_field(schema_retry, "schema_retry_jitter", "base_milliseconds")?,
            u64_field(schema_retry, "schema_retry_jitter", "cap_milliseconds")?,
        )
        .map_err(EffectiveExecutionError::InvalidOwner)?,
    };
    policy
        .validate_with_effort_policy(effort_policy)
        .map_err(EffectiveExecutionError::InvalidOwner)
}

fn decimal_ratio(
    view: &EffectiveTunablesView,
    family: &'static str,
) -> Result<ExactRatio, EffectiveExecutionError> {
    let ResolutionValue::Decimal { value } = view.value(family)? else {
        return Err(EffectiveExecutionError::WrongType(family, "$".into()));
    };
    let numerator = u32::try_from(value.coefficient)
        .map_err(|_| EffectiveExecutionError::Range(family, "$".into()))?;
    let denominator = 10_u32
        .checked_pow(u32::from(value.scale))
        .ok_or_else(|| EffectiveExecutionError::Range(family, "$".into()))?;
    ExactRatio::new(numerator, denominator).map_err(EffectiveExecutionError::InvalidOwner)
}

fn decode_join_reduce_invariant(
    view: &EffectiveTunablesView,
) -> Result<(), EffectiveExecutionError> {
    let family = "join_reduce";
    let fields = view.object(family)?;
    if enum_field(fields, family, "join")? != "wait_all"
        || enum_field(fields, family, "order")? != "declaration"
        || bool_field(fields, family, "include_failed_evidence")?
    {
        return Err(EffectiveExecutionError::InvalidOwner(
            "join/reduce is pinned to complete declaration coverage, deterministic order, and non-evidence failure diagnostics",
        ));
    }
    Ok(())
}

fn decode_decomposition(
    fields: &BTreeMap<String, ResolutionValue>,
    effort_policy: &super::effective_core::EffortRuntimePolicy,
) -> Result<DecompositionRuntimePolicy, EffectiveExecutionError> {
    let family = "decomposition_profile";
    let effort = enum_field(fields, family, "effort")?;
    let effort = Effort::parse(effort)
        .ok_or_else(|| EffectiveExecutionError::UnknownEnum(family, effort.to_owned()))?;
    let policy = DecompositionRuntimePolicy {
        max_output_tokens: u64_field(fields, family, "max_output_tokens")?,
        effort,
        thinking_tokens: u32_field(fields, family, "thinking_tokens")?,
    };
    if policy.max_output_tokens == 0
        || policy.thinking_tokens > effort_policy.thinking_budget(policy.effort)
    {
        return Err(EffectiveExecutionError::InvalidOwner(
            "decomposition profile exceeds its physical effort envelope",
        ));
    }
    Ok(policy)
}

fn decode_child_ceiling(
    fields: &BTreeMap<String, ResolutionValue>,
) -> Result<ChildCeilingPolicy, EffectiveExecutionError> {
    let family = "child_ceiling";
    let capabilities = match fields.get("capabilities") {
        Some(ResolutionValue::List { items }) => items
            .iter()
            .map(|value| match value {
                ResolutionValue::Text { value } => match value.as_str() {
                    "read_only" => Ok(Capability::ReadOnly),
                    "reversible_local" => Ok(Capability::ReversibleLocal),
                    "code_executing" => Ok(Capability::CodeExecuting),
                    "trust_mutating" => Ok(Capability::TrustMutating),
                    "irreversible_external" => Ok(Capability::IrreversibleExternal),
                    other => Err(EffectiveExecutionError::UnknownEnum(
                        family,
                        other.to_owned(),
                    )),
                },
                _ => Err(EffectiveExecutionError::WrongType(
                    family,
                    "capabilities".into(),
                )),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(EffectiveExecutionError::WrongType(
                family,
                "capabilities".into(),
            ));
        }
        None => {
            return Err(EffectiveExecutionError::MissingField(
                family,
                "capabilities".into(),
            ));
        }
    };
    Ok(ChildCeilingPolicy {
        max_turns: u32_field(fields, family, "max_turns")?,
        max_wall_seconds: u64_field(fields, family, "max_wall_seconds")?,
        max_consecutive_errors: u32_field(fields, family, "max_consecutive_errors")?,
        capabilities: CapabilitySet::from_iter_capabilities(capabilities),
    })
}

fn decode_task_priority(
    fields: &BTreeMap<String, ResolutionValue>,
) -> Result<iteron_workflow::TaskPrioritySchedulingPolicy, EffectiveExecutionError> {
    let family = "task_priority_scheduling";
    let owner = iteron_workflow::TaskPrioritySchedulingPolicy::owner();
    if usize_field(fields, family, "priority_levels")? != owner.priority_levels()
        || enum_field(fields, family, "tie_break")? != owner.tie_break().label()
        || bool_field(fields, family, "dependency_ready_only")? != owner.dependency_ready_only()
    {
        return Err(EffectiveExecutionError::InvalidOwner(
            "task priority checkpoint differs from the physical ready-queue owner",
        ));
    }
    Ok(owner)
}

fn optional_object<'a>(
    view: &'a EffectiveTunablesView,
    family: &'static str,
) -> Result<Option<&'a BTreeMap<String, ResolutionValue>>, EffectiveExecutionError> {
    match view.optional_value(family) {
        Some(ResolutionValue::Object { fields }) => Ok(Some(fields)),
        Some(_) => Err(EffectiveExecutionError::WrongType(family, "$".into())),
        None => Ok(None),
    }
}

fn optional_integer(
    view: &EffectiveTunablesView,
    family: &'static str,
) -> Result<Option<i64>, EffectiveExecutionError> {
    match view.optional_value(family) {
        Some(ResolutionValue::Integer { value }) => Ok(Some(*value)),
        Some(_) => Err(EffectiveExecutionError::WrongType(family, "$".into())),
        None => Ok(None),
    }
}

fn range(family: &'static str, field: &str) -> EffectiveExecutionError {
    EffectiveExecutionError::Range(family, field.to_owned())
}

fn decode_speculative_siblings(
    view: &EffectiveTunablesView,
    cancellation: &BTreeMap<String, ResolutionValue>,
) -> Result<iteron_workflow::SpeculativeSiblingPolicy, EffectiveExecutionError> {
    let family = "speculative_sibling_cancellation";
    // The executable workflow owner currently accepts only verified winner evidence and requires
    // both cancellation and unknown-effect reconciliation.  The resolver's authority constraints
    // narrow the public schema to exactly this supported domain; a forged or stale checkpoint is
    // rejected instead of silently falling back to `Default`.
    if enum_field(cancellation, family, "winner_evidence")? != "first_verified"
        || !bool_field(cancellation, family, "cancel_losers")?
        || !bool_field(cancellation, family, "reconcile_unknown_effects")?
    {
        return Err(EffectiveExecutionError::InvalidOwner(
            "unsupported speculative sibling cancellation posture",
        ));
    }
    iteron_workflow::SpeculativeSiblingPolicy::new(
        usize::try_from(view.integer("speculative_sibling_count")?)
            .map_err(|_| EffectiveExecutionError::Range("speculative_sibling_count", "$".into()))?,
        std::time::Duration::from_secs(u64_field(cancellation, family, "cleanup_timeout_seconds")?),
    )
    .map_err(EffectiveExecutionError::InvalidOwner)
}

fn ratio(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    prefix: &'static str,
) -> Result<ExactRatio, EffectiveExecutionError> {
    let numerator = u32_field(fields, family, &format!("{prefix}_numerator"))?;
    let denominator = u32_field(fields, family, &format!("{prefix}_denominator"))?;
    ExactRatio::new(numerator, denominator).map_err(EffectiveExecutionError::InvalidOwner)
}

fn integer_field(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &str,
) -> Result<i64, EffectiveExecutionError> {
    match fields.get(field) {
        Some(ResolutionValue::Integer { value }) => Ok(*value),
        Some(_) => Err(EffectiveExecutionError::WrongType(family, field.into())),
        None => Err(EffectiveExecutionError::MissingField(family, field.into())),
    }
}

fn bool_field(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &str,
) -> Result<bool, EffectiveExecutionError> {
    match fields.get(field) {
        Some(ResolutionValue::Boolean { value }) => Ok(*value),
        Some(_) => Err(EffectiveExecutionError::WrongType(family, field.into())),
        None => Err(EffectiveExecutionError::MissingField(family, field.into())),
    }
}

fn enum_field<'a>(
    fields: &'a BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &str,
) -> Result<&'a str, EffectiveExecutionError> {
    match fields.get(field) {
        Some(ResolutionValue::Enum { value }) => Ok(value),
        Some(_) => Err(EffectiveExecutionError::WrongType(family, field.into())),
        None => Err(EffectiveExecutionError::MissingField(family, field.into())),
    }
}

fn u32_field(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &str,
) -> Result<u32, EffectiveExecutionError> {
    u32::try_from(integer_field(fields, family, field)?)
        .map_err(|_| EffectiveExecutionError::Range(family, field.into()))
}

fn u64_field(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &str,
) -> Result<u64, EffectiveExecutionError> {
    u64::try_from(integer_field(fields, family, field)?)
        .map_err(|_| EffectiveExecutionError::Range(family, field.into()))
}

fn usize_field(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &str,
) -> Result<usize, EffectiveExecutionError> {
    usize::try_from(integer_field(fields, family, field)?)
        .map_err(|_| EffectiveExecutionError::Range(family, field.into()))
}

fn optional_u64_field(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &str,
) -> Result<Option<u64>, EffectiveExecutionError> {
    fields
        .get(field)
        .map(|_| u64_field(fields, family, field))
        .transpose()
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EffectiveExecutionError {
    #[error(transparent)]
    View(#[from] EffectiveViewError),
    #[error("effective tunable `{0}` has unknown enum value `{1}`")]
    UnknownEnum(&'static str, String),
    #[error("effective tunable `{0}` is missing object field `{1}`")]
    MissingField(&'static str, String),
    #[error("effective tunable `{0}` object field `{1}` has the wrong type")]
    WrongType(&'static str, String),
    #[error("effective tunable `{0}` field `{1}` is outside the runtime type range")]
    Range(&'static str, String),
    #[error("effective execution policy violates its production owner: {0}")]
    InvalidOwner(&'static str),
}
