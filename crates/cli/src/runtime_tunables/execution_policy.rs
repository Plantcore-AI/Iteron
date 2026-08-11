//! Typed immutable owner for orchestration families whose values used to be catalog-only shapes.

use iteron_protocol::{Budget, Effort, capability_set::CapabilitySet};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteTopology {
    Direct,
    Orchestrated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExactRatio {
    pub numerator: u32,
    pub denominator: u32,
}

impl ExactRatio {
    pub(crate) fn new(numerator: u32, denominator: u32) -> Result<Self, &'static str> {
        if denominator == 0 || numerator > denominator {
            return Err("execution ratio must satisfy 0 <= numerator <= denominator");
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    pub(crate) fn floor_u32(self, value: u32) -> u32 {
        u32::try_from(
            u64::from(value).saturating_mul(u64::from(self.numerator))
                / u64::from(self.denominator),
        )
        .unwrap_or(u32::MAX)
    }

    pub(crate) fn floor_u64(self, value: u64) -> u64 {
        value.saturating_mul(u64::from(self.numerator)) / u64::from(self.denominator)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChildAdmissionPolicy {
    pub minimum_remaining_turns: u32,
    pub minimum_remaining_wall_seconds: u64,
    pub require_capability_subset: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WriterFanTurnPolicy {
    pub writer_share: ExactRatio,
    pub minimum_writer_turns: u32,
    pub strictly_dominant: bool,
}

impl WriterFanTurnPolicy {
    pub(crate) fn writer_reserve(self, remaining_turns: u32) -> u32 {
        let mut reserve = self.writer_share.floor_u32(remaining_turns);
        if self.strictly_dominant
            && u64::from(reserve).saturating_mul(2) <= u64::from(remaining_turns)
        {
            reserve = reserve.saturating_add(1);
        }
        reserve.max(self.minimum_writer_turns).min(remaining_turns)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WallSplitPolicy {
    pub fan_share: ExactRatio,
    pub minimum_fan_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectChildAllocationPolicy {
    pub writer_share: ExactRatio,
    pub strictly_dominant_writer: bool,
    pub child_token_share: ExactRatio,
    pub child_wall_share: ExactRatio,
    pub minimum_child_turns: u32,
    pub minimum_remaining_wall_seconds: u64,
}

impl DirectChildAllocationPolicy {
    pub(crate) fn allocate(
        self,
        remaining_turns: u32,
        remaining_wall_seconds: u64,
        remaining_tokens: Option<u64>,
        ceiling: &Budget,
    ) -> Option<Budget> {
        if remaining_wall_seconds < self.minimum_remaining_wall_seconds
            || remaining_tokens.is_some_and(|tokens| tokens < 2)
        {
            return None;
        }
        let mut writer = self.writer_share.floor_u32(remaining_turns);
        if self.strictly_dominant_writer
            && u64::from(writer).saturating_mul(2) <= u64::from(remaining_turns)
        {
            writer = writer.saturating_add(1);
        }
        let child_turns = remaining_turns
            .saturating_sub(writer.max(2).min(remaining_turns))
            .min(ceiling.max_turns);
        if child_turns < self.minimum_child_turns {
            return None;
        }
        Some(Budget {
            max_turns: child_turns,
            max_usd: ceiling.max_usd,
            max_tokens: match (remaining_tokens, ceiling.max_tokens) {
                (Some(tokens), Some(limit)) => {
                    Some(self.child_token_share.floor_u64(tokens).min(limit))
                }
                (Some(tokens), None) => Some(self.child_token_share.floor_u64(tokens)),
                (None, limit) => limit,
            },
            max_wall_secs: self
                .child_wall_share
                .floor_u64(remaining_wall_seconds)
                .clamp(1, ceiling.max_wall_secs),
            max_consecutive_tool_errors: ceiling.max_consecutive_tool_errors,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkflowAggregatePolicy {
    pub max_calls: usize,
    pub max_tokens: Option<u64>,
    pub max_wall_seconds: u64,
    pub max_concurrency: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecompositionRuntimePolicy {
    pub max_output_tokens: u64,
    pub effort: Effort,
    pub thinking_tokens: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChildCeilingPolicy {
    pub max_turns: u32,
    pub max_wall_seconds: u64,
    pub max_consecutive_errors: u32,
    pub capabilities: CapabilitySet,
}

impl ChildCeilingPolicy {
    pub(crate) fn narrow_budget(self, mut budget: Budget) -> Budget {
        budget.max_turns = budget.max_turns.min(self.max_turns);
        budget.max_wall_secs = budget.max_wall_secs.min(self.max_wall_seconds);
        budget.max_consecutive_tool_errors = budget
            .max_consecutive_tool_errors
            .min(self.max_consecutive_errors);
        budget
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildMemoryPolicy {
    /// A child receives no parent memory workspace or write handle.
    Isolated,
}

/// Content-free commitment to the default child route carried by family 133.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PerAgentModelIdentity([u8; 32]);

impl PerAgentModelIdentity {
    pub(crate) fn from_route(route: &str) -> Result<Self, &'static str> {
        if route.is_empty() || route.len() > 512 || !route.contains(':') {
            return Err("per-agent model route is not a bounded provider:model identity");
        }
        Ok(Self(digest_parts(
            b"core-per-agent-model-v1",
            [route.as_bytes()],
        )))
    }

    fn empty() -> Self {
        Self(digest_parts(b"core-per-agent-model-v1", [b"".as_slice()]))
    }

    pub(crate) fn validate_owner(
        self,
        provider_id: &str,
        model_id: &str,
    ) -> Result<(), &'static str> {
        let route = format!("{provider_id}:{model_id}");
        if self == Self::from_route(&route)? {
            Ok(())
        } else {
            Err("pinned per-agent model differs from the executable child route")
        }
    }
}

/// Content-free commitment to the exact parent tool-rule profile carried by family 135.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PerAgentToolProfileIdentity {
    digest: [u8; 32],
    entries: u16,
}

impl PerAgentToolProfileIdentity {
    pub(crate) fn from_labels(profile: &BTreeMap<String, String>) -> Result<Self, &'static str> {
        let entries = u16::try_from(profile.len())
            .map_err(|_| "per-agent tool profile exceeds the runtime entry bound")?;
        if profile.len() > 256
            || profile.iter().any(|(tool, disposition)| {
                tool.is_empty()
                    || tool.len() > 96
                    || !matches!(disposition.as_str(), "allow" | "ask" | "deny")
            })
        {
            return Err("per-agent tool profile is outside the executable owner domain");
        }
        let mut digest = Sha256::new();
        digest.update(b"core-per-agent-tool-profile-v1");
        for (tool, disposition) in profile {
            for part in [tool.as_bytes(), disposition.as_bytes()] {
                digest.update((part.len() as u64).to_be_bytes());
                digest.update(part);
            }
        }
        Ok(Self {
            digest: digest.finalize().into(),
            entries,
        })
    }

    fn empty() -> Self {
        Self::from_labels(&BTreeMap::new()).expect("empty tool profile is bounded")
    }

    pub(crate) fn validate_owner(
        self,
        rules: &iteron_protocol::PermissionRules,
    ) -> Result<(), &'static str> {
        let profile = rules
            .tool_rules()
            .map(|(tool, verdict)| {
                let disposition = match verdict {
                    iteron_protocol::Verdict::Auto => "allow",
                    iteron_protocol::Verdict::Ask => "ask",
                    iteron_protocol::Verdict::Deny => "deny",
                };
                (tool.to_owned(), disposition.to_owned())
            })
            .collect::<BTreeMap<_, _>>();
        if self == Self::from_labels(&profile)? {
            Ok(())
        } else {
            Err("pinned per-agent tool profile differs from the executable permission owner")
        }
    }
}

fn digest_parts<'a>(domain: &[u8], parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

/// Content-free getter for the exact role-specific model overrides admitted by this run.
///
/// Inherited roles are intentionally absent: `None` on an `AgentDef` means the already-bound
/// parent model. An explicit override is admitted only when it names that same resolved model;
/// the current spawner owns one provider instance and therefore has no evidence for any other
/// route. Unsupported overrides remain in the catalog for diagnostics but fail closed at spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoleSpecificModelMapIdentity {
    digest_sha256: [u8; 32],
    entry_count: u16,
}

impl RoleSpecificModelMapIdentity {
    const DOMAIN: &'static [u8] = b"core-role-specific-model-map-v1";
    const MAX_ENTRIES: usize = 256;

    pub(crate) fn from_routes(routes: &BTreeMap<String, String>) -> Result<Self, &'static str> {
        let entry_count = u16::try_from(routes.len())
            .map_err(|_| "role-specific model map exceeds its runtime entry range")?;
        if routes.len() > Self::MAX_ENTRIES {
            return Err("role-specific model map exceeds the 256-entry owner envelope");
        }
        let mut digest = Sha256::new();
        digest.update(Self::DOMAIN);
        for (role, route) in routes {
            digest.update((role.len() as u64).to_be_bytes());
            digest.update(role.as_bytes());
            digest.update((route.len() as u64).to_be_bytes());
            digest.update(route.as_bytes());
        }
        Ok(Self {
            digest_sha256: digest.finalize().into(),
            entry_count,
        })
    }

    pub(crate) fn validate_owner(
        self,
        catalog: &iteron_agents::AgentCatalog,
        provider_id: &str,
        model_id: &str,
    ) -> Result<BTreeMap<String, String>, &'static str> {
        let routes = admitted_role_model_routes(catalog, provider_id, model_id)?;
        if self != Self::from_routes(&routes)? {
            return Err("pinned role-specific model map differs from the executable agent catalog");
        }
        Ok(routes)
    }
}

pub(crate) fn admitted_role_model_routes(
    catalog: &iteron_agents::AgentCatalog,
    provider_id: &str,
    model_id: &str,
) -> Result<BTreeMap<String, String>, &'static str> {
    let mut routes = BTreeMap::new();
    for definition in catalog.defs() {
        let Some(requested_model) = definition.model.as_deref() else {
            continue;
        };
        // A definition may name an unavailable model. It remains diagnosable in the exact catalog,
        // but it is not an admitted role route until composition owns a matching provider instance.
        if requested_model != model_id {
            continue;
        }
        if routes
            .insert(
                definition.name.clone(),
                format!("{provider_id}:{requested_model}"),
            )
            .is_some()
        {
            return Err("agent catalog contains duplicate role names");
        }
    }
    if routes.len() > RoleSpecificModelMapIdentity::MAX_ENTRIES {
        return Err("role-specific model map exceeds the 256-entry owner envelope");
    }
    Ok(routes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecutionRuntimePolicy {
    pub route_topology: RouteTopology,
    pub admission: ChildAdmissionPolicy,
    pub writer_fan_turn_split: WriterFanTurnPolicy,
    pub wall_split: WallSplitPolicy,
    pub direct_child_allocation: DirectChildAllocationPolicy,
    pub subagent_effort: Effort,
    pub per_agent_effort: Effort,
    pub per_agent_model: PerAgentModelIdentity,
    pub per_agent_tool_profile: PerAgentToolProfileIdentity,
    pub per_agent_memory: ChildMemoryPolicy,
    pub role_specific_models: RoleSpecificModelMapIdentity,
    pub report_budget_bytes: usize,
    pub workflow: WorkflowAggregatePolicy,
    pub decomposition: Option<DecompositionRuntimePolicy>,
    pub fan_breadth: Option<usize>,
    pub worker_min_turns: Option<u32>,
    pub child_ceiling: Option<ChildCeilingPolicy>,
    pub spawn_depth: Option<u8>,
    pub task_priority: Option<iteron_workflow::TaskPrioritySchedulingPolicy>,
    /// Host-owned workflow controls decoded from the same immutable run snapshot.  Keeping these
    /// beside the aggregate limits prevents `RunSpec::default` from becoming a second effective
    /// truth on fresh, resumed, or child-launched workflows.
    pub early_stop_quorum: iteron_workflow::EarlyStopQuorumPolicy,
    pub speculative_siblings: iteron_workflow::SpeculativeSiblingPolicy,
    pub task_retry: iteron_workflow::TaskRetryPolicy,
    pub schema_retry: iteron_workflow::SchemaRetryPolicy,
}

impl ExecutionRuntimePolicy {
    /// Canonical production owner sampled by composition before resolution.
    pub(crate) fn owner(
        effort: Effort,
        budget: &Budget,
        run_limits: iteron_workflow::RunLimits,
    ) -> Self {
        let decomposition = iteron_agents::DecompositionProfile::owner();
        let child = iteron_agents::subagent_budget_ceiling();
        Self {
            route_topology: if effort == Effort::Ultracode {
                RouteTopology::Orchestrated
            } else {
                RouteTopology::Direct
            },
            admission: ChildAdmissionPolicy {
                minimum_remaining_turns: 4,
                minimum_remaining_wall_seconds: 3,
                require_capability_subset: true,
            },
            writer_fan_turn_split: WriterFanTurnPolicy {
                writer_share: ExactRatio {
                    numerator: 1,
                    denominator: 2,
                },
                minimum_writer_turns: 4,
                strictly_dominant: true,
            },
            wall_split: WallSplitPolicy {
                fan_share: ExactRatio {
                    numerator: 1,
                    denominator: 3,
                },
                minimum_fan_seconds: 1,
            },
            direct_child_allocation: DirectChildAllocationPolicy {
                writer_share: ExactRatio {
                    numerator: 1,
                    denominator: 2,
                },
                strictly_dominant_writer: true,
                child_token_share: ExactRatio {
                    numerator: 1,
                    denominator: 2,
                },
                child_wall_share: ExactRatio {
                    numerator: 1,
                    denominator: 3,
                },
                minimum_child_turns: 2,
                minimum_remaining_wall_seconds: 3,
            },
            subagent_effort: match effort {
                Effort::Ultracode => Effort::Max,
                other => other,
            },
            per_agent_effort: match effort {
                Effort::Ultracode => Effort::Max,
                other => other,
            },
            per_agent_model: PerAgentModelIdentity::empty(),
            per_agent_tool_profile: PerAgentToolProfileIdentity::empty(),
            per_agent_memory: ChildMemoryPolicy::Isolated,
            role_specific_models: RoleSpecificModelMapIdentity::from_routes(&BTreeMap::new())
                .expect("empty role-specific model map is valid"),
            report_budget_bytes: 16 * 1024,
            workflow: WorkflowAggregatePolicy {
                max_calls: run_limits.max_agent_calls(),
                max_tokens: budget.max_tokens,
                max_wall_seconds: budget.max_wall_secs,
                max_concurrency: run_limits.max_concurrency(),
            },
            decomposition: Some(DecompositionRuntimePolicy {
                max_output_tokens: decomposition
                    .max_output_tokens
                    .min(budget.max_tokens.unwrap_or(65_536)),
                effort: decomposition.effort,
                thinking_tokens: decomposition.thinking_tokens,
            }),
            fan_breadth: Some(iteron_agents::FAN_CAP.min(run_limits.max_agent_calls())),
            worker_min_turns: Some(iteron_agents::MIN_SUBAGENT_TURNS.min(budget.max_turns)),
            child_ceiling: Some(ChildCeilingPolicy {
                max_turns: child.max_turns.min(budget.max_turns),
                max_wall_seconds: child.max_wall_secs.min(budget.max_wall_secs),
                max_consecutive_errors: child.max_consecutive_tool_errors,
                capabilities: CapabilitySet::only(iteron_protocol::Capability::ReadOnly),
            }),
            spawn_depth: Some(
                u8::try_from(
                    iteron_workflow::SpawnDepthControl::owner()
                        .max_depth()
                        .min(budget.max_turns.min(64)),
                )
                .expect("spawn-depth owner and schema fit u8"),
            ),
            task_priority: Some(iteron_workflow::TaskPrioritySchedulingPolicy::owner()),
            early_stop_quorum: iteron_workflow::EarlyStopQuorumPolicy::default(),
            speculative_siblings: iteron_workflow::SpeculativeSiblingPolicy::default(),
            task_retry: iteron_workflow::TaskRetryPolicy::default(),
            schema_retry: iteron_workflow::SchemaRetryPolicy::default(),
        }
    }

    /// Safe state for the narrow unpinned constructor used by kernel tests. It cannot fan or admit
    /// children; production constructors replace it from the immutable checkpoint before return.
    pub(crate) fn fail_closed() -> Self {
        let mut policy = Self::owner(
            Effort::Medium,
            &Budget {
                max_turns: 1,
                max_usd: None,
                max_tokens: Some(1),
                max_wall_secs: 1,
                max_consecutive_tool_errors: 1,
            },
            iteron_workflow::RunLimits::new(1, 1).expect("fixed fail-closed limits"),
        );
        policy.admission.minimum_remaining_turns = u32::MAX;
        policy.admission.minimum_remaining_wall_seconds = u64::MAX;
        policy.decomposition = None;
        policy.fan_breadth = None;
        policy.worker_min_turns = None;
        policy.child_ceiling = None;
        policy.spawn_depth = None;
        policy.task_priority = None;
        policy.schema_retry = iteron_workflow::SchemaRetryPolicy::new(0, 0, 0)
            .expect("fixed fail-closed schema policy");
        policy
    }

    pub(crate) fn validate(self) -> Result<Self, &'static str> {
        ExactRatio::new(
            self.writer_fan_turn_split.writer_share.numerator,
            self.writer_fan_turn_split.writer_share.denominator,
        )?;
        ExactRatio::new(
            self.wall_split.fan_share.numerator,
            self.wall_split.fan_share.denominator,
        )?;
        for ratio in [
            self.direct_child_allocation.writer_share,
            self.direct_child_allocation.child_token_share,
            self.direct_child_allocation.child_wall_share,
        ] {
            ExactRatio::new(ratio.numerator, ratio.denominator)?;
        }
        if !self.admission.require_capability_subset
            || self.admission.minimum_remaining_turns == 0
            || self.admission.minimum_remaining_wall_seconds == 0
            || self.writer_fan_turn_split.minimum_writer_turns == 0
            || self.wall_split.minimum_fan_seconds == 0
            || self.direct_child_allocation.minimum_child_turns == 0
            || self.direct_child_allocation.minimum_remaining_wall_seconds == 0
            || self.report_budget_bytes == 0
            || self.report_budget_bytes > 16 * 1024 * 1024
            || self.workflow.max_calls == 0
            || self.workflow.max_calls > 1_000
            || self.workflow.max_concurrency == 0
            || self.workflow.max_concurrency > 1_024
            || self.workflow.max_wall_seconds == 0
            || self.decomposition.is_some_and(|policy| {
                policy.max_output_tokens == 0
                    || policy.thinking_tokens > policy.effort.thinking_budget()
            })
            || self.fan_breadth == Some(0)
            || self.worker_min_turns == Some(0)
            || self.child_ceiling.is_some_and(|policy| {
                policy.max_turns == 0
                    || policy.max_wall_seconds == 0
                    || policy.max_consecutive_errors == 0
                    || policy.capabilities.is_empty()
            })
            || self.spawn_depth == Some(0)
            || self.task_priority.is_some_and(|policy| {
                policy != iteron_workflow::TaskPrioritySchedulingPolicy::owner()
            })
        {
            return Err("execution runtime policy is outside its bounded owner envelope");
        }
        Ok(self)
    }

    /// Admit a model-requested leaf effort only when it narrows the immutable per-agent ceiling.
    /// `Ultracode` is a parent topology, never a leaf mode, and therefore normalizes to `Max`.
    pub(crate) fn admit_child_effort(
        self,
        requested: Option<Effort>,
    ) -> Result<Effort, &'static str> {
        let requested = match requested.unwrap_or(self.per_agent_effort) {
            Effort::Ultracode => Effort::Max,
            other => other,
        };
        if requested.thinking_budget() > self.per_agent_effort.thinking_budget() {
            return Err("requested child effort exceeds the pinned per-agent ceiling");
        }
        Ok(requested)
    }
}
