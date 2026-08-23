//! Provider-independent optimization search and objective contracts.
//!
//! The runtime registries already know every learnable family, parameter, model-visible artifact,
//! and replaceable module.  Repeating those identities in an optimizer creates a second, stale
//! list and encourages model/provider-specific branches.  This module projects the live registries
//! into one bounded search plan and exposes the closed metric vocabulary consumed by the built-in
//! offline tuner.

use crate::trainer_bridge::{RewardDirection, RewardObjective};
use crate::tuner::{TrialResult, TunerCandidate};
use iteron_tunables::{
    ModuleId, ModuleKind, OptimizationClass, ParamClass, ParamDisposition, ParamType, SearchPhase,
    ValueKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const UNIVERSAL_SEARCH_PLAN_SCHEMA_VERSION: u16 = 1;

/// The production address space in which a search dimension is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchDimensionKind {
    Family,
    Parameter,
    ModelVisibleArtifact,
    Implementation,
}

/// Method class, derived from value shape rather than from a provider or model identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchMethod {
    BooleanBandit,
    NumericTpe,
    CategoricalTpe,
    StructuredMutation,
    TextEvolution,
    ImplementationSelection,
}

/// Coarse scheduling tier. Safety and replay invariants never enter this enum because they are not
/// search dimensions in the first place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchTier {
    First,
    Second,
    Conditional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchDimension {
    /// Stable candidate feature address: `family/...`, `param/...`, `artifact/...`, or
    /// `implementation/...`.
    pub address: String,
    pub module: ModuleId,
    pub kind: SearchDimensionKind,
    pub method: SearchMethod,
    pub tier: SearchTier,
    /// Schema/type identity needed by an external candidate producer to construct values without
    /// guessing their shape.
    pub value_domain: String,
    /// Implementation choices are supplied by an admitted catalog and therefore are discoverable
    /// slots, not embedded implementation names.
    pub catalog_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSearchPlan {
    pub module: ModuleId,
    pub kind: ModuleKind,
    pub dimensions: Vec<SearchDimension>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPlanCounts {
    pub modules: usize,
    pub dimensions: usize,
    pub families: usize,
    pub parameters: usize,
    pub model_visible_artifacts: usize,
    pub implementation_slots: usize,
}

/// Complete search space for the current compiled runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UniversalSearchPlan {
    pub schema_version: u16,
    pub registry_revision: u16,
    pub registry_digest: String,
    pub param_registry_digest: String,
    pub tool_text_registry_digest: String,
    pub counts: SearchPlanCounts,
    pub modules: Vec<ModuleSearchPlan>,
}

/// How much of one module a concrete candidate pool can actually learn about. Merely carrying a
/// dimension is distinct from varying it: a constant field provides no experimental contrast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleCandidateCoverage {
    pub module: ModuleId,
    pub searchable_dimensions: usize,
    pub represented_dimensions: usize,
    pub varying_dimensions: usize,
    pub implementation_slot_represented: bool,
    pub implementation_slot_varies: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePoolCoverage {
    pub candidate_count: usize,
    pub modules_total: usize,
    pub modules_represented: usize,
    pub modules_varying: usize,
    pub dimensions_total: usize,
    pub dimensions_represented: usize,
    pub dimensions_varying: usize,
    pub modules: Vec<ModuleCandidateCoverage>,
}

/// Compare an actual candidate pool with the live universal plan. The result is diagnostic only:
/// small ablations may intentionally explore one module, while a claimed universal campaign can
/// fail on the explicit missing/varying counts instead of relying on a hand-maintained checklist.
pub fn candidate_pool_coverage(candidates: &[TunerCandidate]) -> CandidatePoolCoverage {
    let plan = universal_search_plan();
    let features = candidates
        .iter()
        .map(crate::tuner::tuning_candidate_features)
        .collect::<Vec<_>>();
    let mut modules = Vec::with_capacity(plan.modules.len());
    for module in &plan.modules {
        let mut represented = 0_usize;
        let mut varying = 0_usize;
        let mut implementation_slot_represented = false;
        let mut implementation_slot_varies = false;
        for dimension in &module.dimensions {
            let values = features
                .iter()
                .map(|candidate| candidate.get(&dimension.address))
                .collect::<Vec<_>>();
            let is_represented = values.iter().any(|value| value.is_some());
            // `None` is the compiled/default value of a sparse candidate and therefore is a real
            // contrast against an explicit override.
            let variants = values
                .iter()
                .map(|value| value.map(String::as_str))
                .collect::<BTreeSet<_>>();
            let does_vary = candidates.len() > 1 && variants.len() > 1;
            represented += usize::from(is_represented);
            varying += usize::from(does_vary);
            if dimension.kind == SearchDimensionKind::Implementation {
                implementation_slot_represented = is_represented;
                implementation_slot_varies = does_vary;
            }
        }
        modules.push(ModuleCandidateCoverage {
            module: module.module,
            searchable_dimensions: module.dimensions.len(),
            represented_dimensions: represented,
            varying_dimensions: varying,
            implementation_slot_represented,
            implementation_slot_varies,
        });
    }
    CandidatePoolCoverage {
        candidate_count: candidates.len(),
        modules_total: modules.len(),
        modules_represented: modules
            .iter()
            .filter(|module| module.represented_dimensions > 0)
            .count(),
        modules_varying: modules
            .iter()
            .filter(|module| module.varying_dimensions > 0)
            .count(),
        dimensions_total: modules
            .iter()
            .map(|module| module.searchable_dimensions)
            .sum(),
        dimensions_represented: modules
            .iter()
            .map(|module| module.represented_dimensions)
            .sum(),
        dimensions_varying: modules.iter().map(|module| module.varying_dimensions).sum(),
        modules,
    }
}

impl UniversalSearchPlan {
    pub fn validate(&self) -> Result<(), SearchPlanError> {
        if self.schema_version != UNIVERSAL_SEARCH_PLAN_SCHEMA_VERSION
            || self.registry_revision != iteron_tunables::REGISTRY_REVISION
            || self.registry_digest != iteron_tunables::REGISTRY_DIGEST_SHA256
            || self.param_registry_digest != iteron_tunables::param_registry_digest_sha256()
            || self.tool_text_registry_digest != iteron_tunables::tool_text_registry_digest_sha256()
            || self.modules.len() != ModuleId::ALL.len()
        {
            return Err(SearchPlanError::Identity);
        }
        let mut addresses = BTreeSet::new();
        let mut families = 0_usize;
        let mut parameters = 0_usize;
        let mut artifacts = 0_usize;
        let mut implementations = 0_usize;
        for (expected, module) in ModuleId::ALL.into_iter().zip(&self.modules) {
            if module.module != expected
                || module.kind != expected.kind()
                || module.dimensions.is_empty()
                || module.dimensions.iter().any(|dimension| {
                    dimension.module != expected
                        || dimension.address.is_empty()
                        || dimension.value_domain.is_empty()
                        || !method_matches_kind(dimension)
                        || !addresses.insert(dimension.address.clone())
                })
            {
                return Err(SearchPlanError::Shape);
            }
            for dimension in &module.dimensions {
                match dimension.kind {
                    SearchDimensionKind::Family => families += 1,
                    SearchDimensionKind::Parameter => parameters += 1,
                    SearchDimensionKind::ModelVisibleArtifact => artifacts += 1,
                    SearchDimensionKind::Implementation => implementations += 1,
                }
            }
        }
        let counts = SearchPlanCounts {
            modules: self.modules.len(),
            dimensions: addresses.len(),
            families,
            parameters,
            model_visible_artifacts: artifacts,
            implementation_slots: implementations,
        };
        if counts != self.counts || implementations != ModuleId::ALL.len() {
            return Err(SearchPlanError::Counts);
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> Result<String, SearchPlanError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| SearchPlanError::Encode)?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    pub fn dimensions(&self) -> impl Iterator<Item = &SearchDimension> {
        self.modules
            .iter()
            .flat_map(|module| module.dimensions.iter())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SearchPlanError {
    #[error("optimization search plan registry identity is stale")]
    Identity,
    #[error("optimization search plan module or dimension shape is invalid")]
    Shape,
    #[error("optimization search plan counts do not match its dimensions")]
    Counts,
    #[error("optimization search plan could not be encoded")]
    Encode,
}

/// Derive the entire legal search plan from the compiled registries. There are intentionally no
/// provider/model inputs to this function.
pub fn universal_search_plan() -> UniversalSearchPlan {
    let mut modules = ModuleId::ALL
        .into_iter()
        .map(|module| ModuleSearchPlan {
            module,
            kind: module.kind(),
            dimensions: Vec::new(),
        })
        .collect::<Vec<_>>();

    for family in iteron_tunables::families().iter().filter(|family| {
        family.is_profile_addressable() && family.optimization.class != OptimizationClass::Pin
    }) {
        push_dimension(
            &mut modules,
            SearchDimension {
                address: format!("family/{}", family.id),
                module: iteron_tunables::family_module(family.ordinal),
                kind: SearchDimensionKind::Family,
                method: family_method(family.value_schema.kind),
                tier: family_tier(family.optimization.search_phase)
                    .expect("pinned families were excluded from the learnable search plan"),
                value_domain: family.value_schema.schema_id.into(),
                catalog_bound: matches!(family.value_schema.kind, ValueKind::Catalog),
            },
        );
    }

    for parameter in iteron_tunables::params().iter().filter(|parameter| {
        parameter.applied
            && parameter.disposition == ParamDisposition::RuntimeSettable
            && matches!(
                parameter.class,
                ParamClass::Searchable | ParamClass::Bounded
            )
    }) {
        push_dimension(
            &mut modules,
            SearchDimension {
                address: format!("param/{}", parameter.id),
                module: parameter.module,
                kind: SearchDimensionKind::Parameter,
                method: parameter_method(parameter.ty),
                tier: SearchTier::Second,
                value_domain: parameter.ty.as_str().into(),
                catalog_bound: false,
            },
        );
    }

    for artifact in iteron_tunables::PROMPT_ARTIFACTS
        .iter()
        .filter(|artifact| artifact.overridable)
    {
        push_artifact(&mut modules, artifact.id, artifact.module);
    }
    for artifact in iteron_tunables::TOOL_TEXT_ARTIFACTS
        .iter()
        .filter(|artifact| artifact.overridable)
    {
        push_artifact(&mut modules, artifact.id, artifact.module);
    }

    // Every module has one catalog-backed implementation slot. The plan never embeds an
    // implementation/provider name; candidate admission binds the selected catalog artifact.
    for module in ModuleId::ALL {
        push_dimension(
            &mut modules,
            SearchDimension {
                address: format!("implementation/{}", module.as_str()),
                module,
                kind: SearchDimensionKind::Implementation,
                method: SearchMethod::ImplementationSelection,
                tier: SearchTier::Conditional,
                value_domain: crate::tuner::IMPLEMENTATION_PROTOCOL.into(),
                catalog_bound: true,
            },
        );
    }

    for module in &mut modules {
        module
            .dimensions
            .sort_by(|left, right| left.address.cmp(&right.address));
    }
    let counts = count_plan(&modules);
    let plan = UniversalSearchPlan {
        schema_version: UNIVERSAL_SEARCH_PLAN_SCHEMA_VERSION,
        registry_revision: iteron_tunables::REGISTRY_REVISION,
        registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
        param_registry_digest: iteron_tunables::param_registry_digest_sha256(),
        tool_text_registry_digest: iteron_tunables::tool_text_registry_digest_sha256(),
        counts,
        modules,
    };
    debug_assert!(plan.validate().is_ok());
    plan
}

fn push_artifact(modules: &mut [ModuleSearchPlan], id: &str, module: ModuleId) {
    push_dimension(
        modules,
        SearchDimension {
            address: format!("artifact/{id}"),
            module,
            kind: SearchDimensionKind::ModelVisibleArtifact,
            method: SearchMethod::TextEvolution,
            tier: SearchTier::Conditional,
            value_domain: "utf8_text".into(),
            catalog_bound: false,
        },
    );
}

fn push_dimension(modules: &mut [ModuleSearchPlan], dimension: SearchDimension) {
    modules
        .iter_mut()
        .find(|module| module.module == dimension.module)
        .expect("ModuleId::ALL contains every registry module")
        .dimensions
        .push(dimension);
}

fn count_plan(modules: &[ModuleSearchPlan]) -> SearchPlanCounts {
    let dimensions = modules.iter().flat_map(|module| &module.dimensions);
    let mut counts = SearchPlanCounts {
        modules: modules.len(),
        dimensions: 0,
        families: 0,
        parameters: 0,
        model_visible_artifacts: 0,
        implementation_slots: 0,
    };
    for dimension in dimensions {
        counts.dimensions += 1;
        match dimension.kind {
            SearchDimensionKind::Family => counts.families += 1,
            SearchDimensionKind::Parameter => counts.parameters += 1,
            SearchDimensionKind::ModelVisibleArtifact => counts.model_visible_artifacts += 1,
            SearchDimensionKind::Implementation => counts.implementation_slots += 1,
        }
    }
    counts
}

const fn family_method(kind: ValueKind) -> SearchMethod {
    match kind {
        ValueKind::Bool => SearchMethod::BooleanBandit,
        ValueKind::Count
        | ValueKind::Duration
        | ValueKind::Bytes
        | ValueKind::Ratio
        | ValueKind::Decimal => SearchMethod::NumericTpe,
        ValueKind::Enum | ValueKind::Catalog => SearchMethod::CategoricalTpe,
        ValueKind::String => SearchMethod::TextEvolution,
        ValueKind::List | ValueKind::Map | ValueKind::Policy => SearchMethod::StructuredMutation,
    }
}

const fn parameter_method(kind: ParamType) -> SearchMethod {
    match kind {
        ParamType::Boolean => SearchMethod::BooleanBandit,
        ParamType::Integer | ParamType::Float | ParamType::Duration => SearchMethod::NumericTpe,
        ParamType::Enum => SearchMethod::CategoricalTpe,
        ParamType::Text => SearchMethod::TextEvolution,
        ParamType::Array | ParamType::Map | ParamType::Object => SearchMethod::StructuredMutation,
    }
}

const fn family_tier(phase: SearchPhase) -> Option<SearchTier> {
    match phase {
        SearchPhase::P1 => Some(SearchTier::First),
        SearchPhase::P2 => Some(SearchTier::Second),
        SearchPhase::Conditional => Some(SearchTier::Conditional),
        SearchPhase::Pinned => None,
    }
}

fn method_matches_kind(dimension: &SearchDimension) -> bool {
    match dimension.kind {
        SearchDimensionKind::ModelVisibleArtifact => {
            dimension.method == SearchMethod::TextEvolution
        }
        SearchDimensionKind::Implementation => {
            dimension.method == SearchMethod::ImplementationSelection && dimension.catalog_bound
        }
        SearchDimensionKind::Family | SearchDimensionKind::Parameter => {
            dimension.method != SearchMethod::ImplementationSelection
        }
    }
}

/// Closed, provider-independent metric vocabulary implemented by [`crate::tuner::OfflineTuner`].
/// External trainers may implement other reward contracts; the built-in tuner fails closed rather
/// than silently ignoring an objective it cannot observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuningMetric {
    ResolvedRate,
    TurnsPerRun,
    TotalTokens,
    AgentLatencyMs,
    TotalLatencyMs,
    CostUsd,
    ToolCalls,
    ToolErrorRate,
    PeakToolConcurrency,
    ContextTokensPerTurn,
    PeakContextTokens,
    TranscriptTokensReclaimed,
    TranscriptShrinkEventsPerRun,
    StablePrefixTokensPerTurn,
    InstructionTokensPerTurn,
    TaskContextTokensPerTurn,
    MemoryTokensPerTurn,
    TranscriptTokensPerTurn,
    AttachmentTokensPerTurn,
    ToolSchemaTokensPerTurn,
    ToolResultTokensPerTurn,
    LspResultTokensPerTurn,
}

impl TuningMetric {
    pub const ALL: [Self; 22] = [
        Self::ResolvedRate,
        Self::TurnsPerRun,
        Self::TotalTokens,
        Self::AgentLatencyMs,
        Self::TotalLatencyMs,
        Self::CostUsd,
        Self::ToolCalls,
        Self::ToolErrorRate,
        Self::PeakToolConcurrency,
        Self::ContextTokensPerTurn,
        Self::PeakContextTokens,
        Self::TranscriptTokensReclaimed,
        Self::TranscriptShrinkEventsPerRun,
        Self::StablePrefixTokensPerTurn,
        Self::InstructionTokensPerTurn,
        Self::TaskContextTokensPerTurn,
        Self::MemoryTokensPerTurn,
        Self::TranscriptTokensPerTurn,
        Self::AttachmentTokensPerTurn,
        Self::ToolSchemaTokensPerTurn,
        Self::ToolResultTokensPerTurn,
        Self::LspResultTokensPerTurn,
    ];

    pub fn parse(metric: &str) -> Option<Self> {
        match metric {
            "resolved_rate" | "functional_acceptance" | "quality" => Some(Self::ResolvedRate),
            "turns_per_run" | "average_turns" | "turns" => Some(Self::TurnsPerRun),
            "total_tokens" | "average_tokens" | "tokens" => Some(Self::TotalTokens),
            "agent_latency_ms" | "speed" => Some(Self::AgentLatencyMs),
            "total_latency_ms" | "latency_ms" => Some(Self::TotalLatencyMs),
            "cost_usd" | "average_cost_usd" => Some(Self::CostUsd),
            "tool_calls" | "average_tool_calls" => Some(Self::ToolCalls),
            "tool_error_rate" | "average_tool_error_rate" => Some(Self::ToolErrorRate),
            "peak_tool_concurrency" | "average_peak_tool_concurrency" => {
                Some(Self::PeakToolConcurrency)
            }
            "context_tokens_per_turn" | "average_context_tokens_per_turn" => {
                Some(Self::ContextTokensPerTurn)
            }
            "peak_context_tokens" | "average_peak_context_tokens" => Some(Self::PeakContextTokens),
            "transcript_tokens_reclaimed" | "average_transcript_tokens_reclaimed" => {
                Some(Self::TranscriptTokensReclaimed)
            }
            "transcript_shrink_events_per_run" | "average_transcript_shrink_events" => {
                Some(Self::TranscriptShrinkEventsPerRun)
            }
            "stable_prefix_tokens_per_turn" | "average_stable_prefix_tokens_per_turn" => {
                Some(Self::StablePrefixTokensPerTurn)
            }
            "instruction_tokens_per_turn" | "average_instruction_tokens_per_turn" => {
                Some(Self::InstructionTokensPerTurn)
            }
            "task_context_tokens_per_turn" | "average_task_context_tokens_per_turn" => {
                Some(Self::TaskContextTokensPerTurn)
            }
            "memory_tokens_per_turn" | "average_memory_tokens_per_turn" => {
                Some(Self::MemoryTokensPerTurn)
            }
            "transcript_tokens_per_turn" | "average_transcript_tokens_per_turn" => {
                Some(Self::TranscriptTokensPerTurn)
            }
            "attachment_tokens_per_turn" | "average_attachment_tokens_per_turn" => {
                Some(Self::AttachmentTokensPerTurn)
            }
            "tool_schema_tokens_per_turn" | "average_tool_schema_tokens_per_turn" => {
                Some(Self::ToolSchemaTokensPerTurn)
            }
            "tool_result_tokens_per_turn" | "average_tool_result_tokens_per_turn" => {
                Some(Self::ToolResultTokensPerTurn)
            }
            "lsp_result_tokens_per_turn" | "average_lsp_result_tokens_per_turn" => {
                Some(Self::LspResultTokensPerTurn)
            }
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResolvedRate => "resolved_rate",
            Self::TurnsPerRun => "turns_per_run",
            Self::TotalTokens => "total_tokens",
            Self::AgentLatencyMs => "agent_latency_ms",
            Self::TotalLatencyMs => "total_latency_ms",
            Self::CostUsd => "cost_usd",
            Self::ToolCalls => "tool_calls",
            Self::ToolErrorRate => "tool_error_rate",
            Self::PeakToolConcurrency => "peak_tool_concurrency",
            Self::ContextTokensPerTurn => "context_tokens_per_turn",
            Self::PeakContextTokens => "peak_context_tokens",
            Self::TranscriptTokensReclaimed => "transcript_tokens_reclaimed",
            Self::TranscriptShrinkEventsPerRun => "transcript_shrink_events_per_run",
            Self::StablePrefixTokensPerTurn => "stable_prefix_tokens_per_turn",
            Self::InstructionTokensPerTurn => "instruction_tokens_per_turn",
            Self::TaskContextTokensPerTurn => "task_context_tokens_per_turn",
            Self::MemoryTokensPerTurn => "memory_tokens_per_turn",
            Self::TranscriptTokensPerTurn => "transcript_tokens_per_turn",
            Self::AttachmentTokensPerTurn => "attachment_tokens_per_turn",
            Self::ToolSchemaTokensPerTurn => "tool_schema_tokens_per_turn",
            Self::ToolResultTokensPerTurn => "tool_result_tokens_per_turn",
            Self::LspResultTokensPerTurn => "lsp_result_tokens_per_turn",
        }
    }

    pub fn value(self, result: &TrialResult) -> Option<f64> {
        match self {
            Self::ResolvedRate => Some(result.resolved_rate),
            Self::TurnsPerRun => result.optimization.and_then(|value| value.average_turns),
            Self::TotalTokens => result.average_tokens,
            Self::AgentLatencyMs => result.average_agent_latency_ms,
            Self::TotalLatencyMs => Some(result.average_latency_ms),
            Self::CostUsd => result.average_cost_usd,
            Self::ToolCalls => result.optimization.map(|value| value.average_tool_calls),
            Self::ToolErrorRate => result
                .optimization
                .map(|value| value.average_tool_error_rate),
            Self::PeakToolConcurrency => result
                .optimization
                .map(|value| value.average_peak_tool_concurrency),
            Self::ContextTokensPerTurn => result
                .optimization
                .map(|value| value.average_context_tokens_per_turn),
            Self::PeakContextTokens => result
                .optimization
                .map(|value| value.average_peak_context_tokens),
            Self::TranscriptTokensReclaimed => result
                .optimization
                .map(|value| value.average_transcript_tokens_reclaimed),
            Self::TranscriptShrinkEventsPerRun => result
                .optimization
                .and_then(|value| value.average_transcript_shrink_events),
            Self::StablePrefixTokensPerTurn => component_value(result, |value| value.stable_prefix),
            Self::InstructionTokensPerTurn => component_value(result, |value| value.instructions),
            Self::TaskContextTokensPerTurn => component_value(result, |value| value.task_context),
            Self::MemoryTokensPerTurn => component_value(result, |value| value.memory),
            Self::TranscriptTokensPerTurn => component_value(result, |value| value.transcript),
            Self::AttachmentTokensPerTurn => component_value(result, |value| value.attachments),
            Self::ToolSchemaTokensPerTurn => component_value(result, |value| value.tool_schemas),
            Self::ToolResultTokensPerTurn => component_value(result, |value| value.tool_results),
            Self::LspResultTokensPerTurn => component_value(result, |value| value.lsp_results),
        }
    }
}

fn component_value(
    result: &TrialResult,
    project: impl FnOnce(crate::tuner::TrialContextComponentAverages) -> f64,
) -> Option<f64> {
    result
        .optimization?
        .average_context_components_per_turn
        .map(project)
}

pub(crate) fn validate_objectives(objectives: &[RewardObjective]) -> bool {
    objectives
        .iter()
        .all(|objective| TuningMetric::parse(&objective.metric).is_some())
}

pub(crate) fn objective_penalties(
    results: &[&TrialResult],
    objectives: &[RewardObjective],
) -> Vec<(String, u128)> {
    let mut penalties = results
        .iter()
        .map(|result| (result.candidate_id.clone(), 0_u128))
        .collect::<Vec<_>>();
    for objective in objectives {
        let Some(metric) = TuningMetric::parse(&objective.metric) else {
            continue;
        };
        // Completion is a hard first-order gate in the built-in tuner. Including it in the reward
        // contract remains useful to external trainers, but does not double-count it here.
        if metric == TuningMetric::ResolvedRate {
            continue;
        }
        let mut ranked = results.to_vec();
        ranked.sort_by(|left, right| {
            metric_order(metric, objective.direction, left, right)
                .then_with(|| left.candidate_id.cmp(&right.candidate_id))
        });
        let mut prior_value: Option<Option<f64>> = None;
        let mut rank = 0_u128;
        for (position, result) in ranked.into_iter().enumerate() {
            let value = metric.value(result);
            if prior_value.is_some_and(|prior| prior != value) {
                rank = position as u128;
            }
            prior_value = Some(value);
            let penalty = rank.saturating_mul(u128::from(objective.weight_micros));
            if let Some((_, total)) = penalties
                .iter_mut()
                .find(|(candidate, _)| candidate == &result.candidate_id)
            {
                *total = total.saturating_add(penalty);
            }
        }
    }
    penalties
}

fn metric_order(
    metric: TuningMetric,
    direction: RewardDirection,
    left: &TrialResult,
    right: &TrialResult,
) -> std::cmp::Ordering {
    let present_order = match (metric.value(left), metric.value(right)) {
        (Some(left), Some(right)) => left
            .partial_cmp(&right)
            .unwrap_or(std::cmp::Ordering::Equal),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    };
    match direction {
        // Missing evidence remains last under either direction; reverse only a comparison between
        // two present values.
        RewardDirection::Maximize
            if metric.value(left).is_some() && metric.value(right).is_some() =>
        {
            present_order.reverse()
        }
        RewardDirection::Maximize | RewardDirection::Minimize => present_order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_plan_is_registry_derived_and_covers_every_module() {
        let plan = universal_search_plan();
        plan.validate().unwrap();
        assert_eq!(plan.modules.len(), ModuleId::ALL.len());
        assert_eq!(plan.counts.implementation_slots, ModuleId::ALL.len());
        assert_eq!(
            plan.counts.parameters,
            iteron_tunables::params()
                .iter()
                .filter(|parameter| parameter.applied
                    && parameter.disposition == ParamDisposition::RuntimeSettable
                    && matches!(
                        parameter.class,
                        ParamClass::Searchable | ParamClass::Bounded
                    ))
                .count()
        );
        assert!(
            plan.modules
                .iter()
                .all(|module| !module.dimensions.is_empty())
        );

        let method = |address: &str| {
            plan.dimensions()
                .find(|dimension| dimension.address == address)
                .map(|dimension| dimension.method)
        };
        assert_eq!(
            method("param/ctx.compact.default_trigger_tokens"),
            Some(SearchMethod::NumericTpe)
        );
        assert_eq!(
            method("param/ctx.memory.header"),
            Some(SearchMethod::TextEvolution)
        );
        assert_eq!(
            method("artifact/tool/tool_search/description@v1"),
            Some(SearchMethod::TextEvolution)
        );
    }

    #[test]
    fn metric_vocabulary_has_no_provider_or_model_identity_axis() {
        let names = TuningMetric::ALL.map(TuningMetric::as_str);
        assert!(names.iter().all(|name| {
            !name.contains("provider") && !name.contains("model") && !name.contains("route")
        }));
        assert!(TuningMetric::parse("provider_id").is_none());
        assert!(TuningMetric::parse("model_name").is_none());
        assert_eq!(
            TuningMetric::parse("memory_tokens_per_turn"),
            Some(TuningMetric::MemoryTokensPerTurn)
        );
        assert_eq!(
            TuningMetric::parse("tool_result_tokens_per_turn"),
            Some(TuningMetric::ToolResultTokensPerTurn)
        );
        assert_eq!(
            TuningMetric::parse("turns_per_run"),
            Some(TuningMetric::TurnsPerRun)
        );
        assert_eq!(
            TuningMetric::parse("transcript_shrink_events_per_run"),
            Some(TuningMetric::TranscriptShrinkEventsPerRun)
        );
    }
}
