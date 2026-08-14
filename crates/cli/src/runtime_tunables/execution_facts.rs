//! Production-owner facts for tunable families 35 through 85.
//!
//! The adapter is deliberately conservative. It reads live owner objects and public owner query
//! APIs; it never reuses a registry candidate as the observation or authority that approves that
//! candidate. Where an owner cannot expose a complete value, or the registry schema cannot encode
//! the owner's policy, the result contains a typed [`ExecutionFactGap`] instead of guessed bytes.

#[path = "execution_facts/constraints.rs"]
mod constraints;
#[path = "execution_facts/values.rs"]
mod values;

pub(crate) use values::live_fixed_authority_samples;

use crate::config::McpServerConfig;
use crate::providers::{ModelCapabilities, ProviderDirectory};
use iteron_agents::AgentCatalog;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{Budget, DurableEnvironmentContext, Effort};
use iteron_tools::Registry;
use iteron_tunables::{ProductionOwnerSymbolId, RuntimeResolutionBuilder, RuntimeResolutionError};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Registry/schema blockers already identified by the H01 audit. Keep this typed list even at
/// zero so a future unrepresentable owner must be made explicit rather than disappearing into a
/// comment or status label.
pub(crate) const KNOWN_SCHEMA_BLOCKERS: [&str; 0] = [];

/// Exact composition-root inputs, all sampled before the immutable checkpoint is resolved.
pub(crate) struct ExecutionFactsInput<'a> {
    /// Exact selected/admitted route used by activation and external ceilings. Fixed owner
    /// attestations use the same capability set so an inactive family is never falsely sampled.
    pub route: &'a iteron_tunables::RouteCapabilities,
    pub registry: &'a Registry,
    pub agent_catalog: &'a AgentCatalog,
    pub budget: &'a Budget,
    pub run_limits: iteron_workflow::RunLimits,
    pub effort: Effort,
    pub hooks_catalog: Option<crate::runtime::hooks::HookCatalogIdentity>,
    pub model_capabilities: &'a ModelCapabilities,
    pub directory: &'a ProviderDirectory,
    pub configured_mcp: &'a [McpServerConfig],
    /// The task authority after every operator/project narrowing has been applied. This is kept
    /// separate from tool registration: presence of a tool never proves authority to invoke it.
    pub authority_ceiling: CapabilitySet,
    /// Durable frontend observation, if already resolved. Its opaque text cannot be parsed back
    /// into the family-84 map without inventing keys; it is retained for content-free inventory.
    pub environment: Option<&'a DurableEnvironmentContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(
    dead_code,
    reason = "the typed stage vocabulary keeps future activation gaps distinct from defaults"
)]
pub(crate) enum FactStage {
    Activation,
    Default,
    Constraint,
    Inventory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(
    dead_code,
    reason = "closed fail-closed owner-gap reasons are retained for audit classification"
)]
pub(crate) enum GapReason {
    OwnerQueryUnavailable,
    OwnerProjectionNotVisible,
    OwnerValueDiffersFromLiteral,
    SchemaCannotExpressOwner,
    ConstraintUnitMismatch,
    ConstraintAuthorityUnavailable,
    ProviderCapabilityIncomplete,
    DynamicPolicyNotRepresentable,
    GovernedCatalogNotAdmissible,
    CatalogResolverValueShapeMismatch,
    OpaqueEnvironmentNotAMap,
    CredentialFreeWebInventoryUnavailable,
    ValueExceedsAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExecutionFactGap {
    pub family: &'static str,
    pub stage: FactStage,
    pub reason: GapReason,
    pub known_schema_blocker: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AppliedFact {
    pub family: &'static str,
    pub stage: FactStage,
}

/// Secret-free, bounded inventory proving which concrete owners were sampled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionInventory {
    pub tool_count: usize,
    pub pure_tool_count: usize,
    pub tool_registry_digest_sha256: String,
    pub provider_count: usize,
    pub provider_inventory_digest_sha256: String,
    pub agent_count: usize,
    pub agent_catalog_digest_sha256: String,
    pub configured_mcp_count: usize,
    pub live_mcp_count: usize,
    pub hooks_configured: bool,
    pub environment_digest_sha256: Option<String>,
    pub web_fetch_registered: bool,
    pub web_search_registered: bool,
}

#[derive(Debug)]
pub(crate) struct ExecutionFactsReport {
    pub applied: Vec<AppliedFact>,
    pub gaps: Vec<ExecutionFactGap>,
    #[allow(
        dead_code,
        reason = "content-free sampled-owner inventory is retained with the atomic fact report"
    )]
    pub inventory: ExecutionInventory,
}

impl ExecutionFactsReport {
    fn new(input: &ExecutionFactsInput<'_>) -> Result<Self, ExecutionFactError> {
        Ok(Self {
            applied: Vec::new(),
            gaps: Vec::new(),
            inventory: collect_inventory(input)?,
        })
    }

    pub(crate) fn mark(&mut self, family: &'static str, stage: FactStage) {
        self.applied.push(AppliedFact { family, stage });
    }

    pub(crate) fn gap(&mut self, family: &'static str, stage: FactStage, reason: GapReason) {
        self.gaps.push(ExecutionFactGap {
            family,
            stage,
            reason,
            known_schema_blocker: KNOWN_SCHEMA_BLOCKERS.contains(&family),
        });
    }

    fn finish(&mut self) {
        for family in KNOWN_SCHEMA_BLOCKERS {
            if !self.gaps.iter().any(|gap| gap.family == family) {
                self.gap(
                    family,
                    FactStage::Default,
                    GapReason::SchemaCannotExpressOwner,
                );
            }
        }
        self.applied.sort_unstable();
        self.applied.dedup();
        self.gaps.sort_unstable();
        self.gaps.dedup();
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExecutionFactError {
    #[error("runtime owner value for `{0}` exceeds the tunables integer representation")]
    IntegerOverflow(&'static str),
    #[error("execution-owner evidence could not be encoded")]
    EvidenceEncoding,
    #[error("the child-allocation owner exposed no admissible minimum")]
    ChildAllocationUnavailable,
    #[error(transparent)]
    Resolution(#[from] RuntimeResolutionError),
}

/// Add every fact that can be traced to a production owner for families 35..=85.
pub(crate) fn apply_execution_facts(
    builder: &mut RuntimeResolutionBuilder,
    input: ExecutionFactsInput<'_>,
) -> Result<ExecutionFactsReport, ExecutionFactError> {
    let mut report = ExecutionFactsReport::new(&input)?;
    values::apply(builder, &input, &mut report)?;
    constraints::apply(builder, &input, &mut report)?;
    values::record_catalog_and_owner_gaps(&input, &mut report);
    submit_owner_symbols(builder)?;
    report.finish();
    Ok(report)
}

fn submit_owner_symbols(builder: &mut RuntimeResolutionBuilder) -> Result<(), ExecutionFactError> {
    use ProductionOwnerSymbolId as Owner;
    for (owner, families) in [
        (
            Owner::ObservationToolPolicy,
            &[
                "shell_timeout_output",
                "read_file_limits",
                "list_dir_limits",
                "glob_limits",
                "grep_limits",
                "repo_map",
                "git_limits",
                "web_fetch_limits",
            ][..],
        ),
        (Owner::VerificationPolicy, &["verifier_feedback_tails"][..]),
        (
            Owner::WorkflowExecutionPolicy,
            &[
                "direct_child_allocation",
                "workflow_aggregate",
                "schema_retry_jitter",
            ][..],
        ),
        (
            Owner::MultimodalAdmissionPolicy,
            &["multimodal_input_admission_decode_envelope"][..],
        ),
        (
            Owner::AppServerQueuePolicy,
            &["app_server_sq_eq_backpressure"][..],
        ),
        (Owner::AgentCatalog, &["agent_catalog"][..]),
        (Owner::HookCatalog, &["hooks_map"][..]),
        (Owner::WorkflowGraph, &["workflow_graph"][..]),
    ] {
        builder.submit_owner_symbol(owner, families)?;
    }
    Ok(())
}

pub(super) fn owner_digest(
    label: &'static str,
    value: &impl Serialize,
) -> Result<String, ExecutionFactError> {
    let bytes =
        serde_json::to_vec(&(label, value)).map_err(|_| ExecutionFactError::EvidenceEncoding)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(super) fn i64u(value: usize, family: &'static str) -> Result<i64, ExecutionFactError> {
    i64::try_from(value).map_err(|_| ExecutionFactError::IntegerOverflow(family))
}

pub(super) fn i64v(value: u64, family: &'static str) -> Result<i64, ExecutionFactError> {
    i64::try_from(value).map_err(|_| ExecutionFactError::IntegerOverflow(family))
}

fn collect_inventory(
    input: &ExecutionFactsInput<'_>,
) -> Result<ExecutionInventory, ExecutionFactError> {
    let mut specs = input.registry.specs();
    specs.sort_by(|left, right| left.name.cmp(&right.name));
    let names = specs
        .iter()
        .map(|spec| spec.name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let pure_tool_count = specs
        .iter()
        .filter(|spec| spec.purity == iteron_protocol::Purity::Pure)
        .count();
    let providers = input
        .directory
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.id(),
                entry.catalog_provenance_label(),
                entry
                    .catalog
                    .as_ref()
                    .map_or(0, |catalog| catalog.models.len()),
            )
        })
        .collect::<Vec<_>>();
    let live_mcp_count = input
        .configured_mcp
        .iter()
        .filter(|server| {
            let prefix = format!("{}__", server.name);
            names.iter().any(|name| name.starts_with(&prefix))
        })
        .count();
    Ok(ExecutionInventory {
        tool_count: specs.len(),
        pure_tool_count,
        tool_registry_digest_sha256: owner_digest("tool_registry", &specs)?,
        provider_count: providers.len(),
        provider_inventory_digest_sha256: owner_digest("provider_inventory", &providers)?,
        agent_count: input.agent_catalog.defs().len(),
        agent_catalog_digest_sha256: input.agent_catalog.execution_digest(),
        configured_mcp_count: input.configured_mcp.len(),
        live_mcp_count,
        hooks_configured: input.hooks_catalog.is_some(),
        environment_digest_sha256: input
            .environment
            .map(|environment| owner_digest("environment", environment))
            .transpose()?,
        web_fetch_registered: names.contains("web_fetch"),
        web_search_registered: names.contains("web_search"),
    })
}
