//! Source-form-complete production optimization census and honesty gate.
//!
//! The Tier-2 catalog remains the compatibility surface for const/static parameters. This module
//! adds syntax-aware discovery for a closed list of production source forms, then emits one exact
//! generated artifact covering those inventories. It deliberately claims completeness only for
//! those declared forms, never for the mathematical set of every possible optimization input.

mod discovery;

use crate::tunables_params::{
    CandidateKind, Disposition, InvariantReason, OwnerRow, ParamRow, UseSiteRow,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use discovery::{DiscoveryReport, scan_production_sources, source_form_invariant_matches};
#[cfg(test)]
use discovery::{discover_source, source_form_observation_counts, unclassified_source_form_count};

const EXCLUDED_CRATES: &[&str] = &["xtask"];

/// Source-specific overrides for existing quality-sounding read-only rows. Keeping these as exact
/// ids is intentional: a newly discovered marker/threshold/policy/tool/routing candidate cannot
/// inherit an invariant disposition from a name heuristic; it stops generation until its owner
/// supplies an explicit disposition. The generated `review_evidence` is mechanical and makes no
/// claim that a human performed the review.
const QUALITY_INVARIANT_OVERRIDES: &[&str] = &[
    "agents.catalog.vendor_markers",
    "agents.decompose.router_slot_version",
    "agents.def.isolated_writer_tools",
    "agents.def.read_only_tools",
    "agents.policy.recognised_policies",
    "cli.output.max_pending_stream_token_bytes",
    "cli.providers.setup_effect.policy_canonical",
    "cli.providers.setup_effect.policy_id",
    "cli.runtime.failed_action_cache.marker",
    "cli.runtime.interrupted_stream_marker",
    "cli.runtime.policy_evidence.collaboration_slot",
    "cli.runtime.policy_evidence.context_slot",
    "cli.runtime.policy_evidence.memory_slot",
    "cli.runtime.policy_evidence.model_router_slot",
    "cli.runtime.policy_evidence.scheduler_slot",
    "cli.runtime.policy_evidence.tool_policy_slot",
    "cli.runtime.policy_evidence.verifier_slot",
    "cli.runtime.policy_evidence_recorder.digest.opportunity_id_domain",
    "cli.runtime.policy_evidence_recorder.next_recorder_id",
    "cli.runtime.policy_evidence_recorder.types.frozen_policy_slot_count",
    "cli.runtime.policy_evidence_recorder.types.frozen_policy_slot_names",
    "cli.runtime.route_state.model_route_feature_schema",
    "cli.runtime.tool_output_spill.store.sha256_bytes",
    "cli.runtime.tool_output_spill.store.spill_sequence_base",
    "cli.runtime_tunables.catalogs.model_routes",
    "cli.runtime_tunables.catalogs.tool_registry_owner",
    "cli.runtime_tunables.execution_policy.domain",
    "cli.runtime_tunables.provider_process_facts.defaults.catalog_id",
    "cli.runtime_tunables.route.route_attestation_canonicalization",
    "cli.tui.terminal_input.prefix",
    "cli.tui.transcript_viewer.projection.marker",
    "cli.workflow.policy_checkpoint.policy_checkpoint_file",
    "ctx.compact.compaction_marker_close",
    "ctx.compact.compaction_marker_open",
    "ctx.context_port.skill_cache",
    "ctx.context_materialization.marker",
    "ctx.skills_metadata.skill_refused_tools",
    "ctx.token_estimator.observed_usage_estimator_policy_id",
    "eval.iteron_harness_main.max_evaluation_manifest_bytes",
    "eval.runner.process_output_limit",
    "evolve.conformance.runtime_activation_markers",
    "evolve.policy_evidence_projection.policy_evidence_run_schema_version",
    "kernel.ports.tool_port_version",
    "kernel.ports.toolport.version",
    "mcp.result_policy.default_mcp_spill_result_bytes",
    "mcp.result_policy.hex",
    "mcp.result_policy.sha256_bytes",
    "mcp.result_policy.store_seq",
    "mcp.supervisor.catalog.summary_marker",
    "mcp.tool_catalog.default_input_schema_bytes",
    "mcp.tool_catalog.mcp_tool_capability",
    "mcp.tool_catalog.protocol_head_marker",
    "mcp.tool_catalog.truncated_marker",
    "mcp.tool_filter.max_mcp_bare_tool_name_bytes",
    "obs.otel.catalog.tool_families",
    "protocol.event.providerrouteattemptaccounting.route_id_bytes",
    "protocol.event.providerrouteattemptidentity.route_id_bytes",
    "protocol.policy_bundle_checkpoint.run_genesis_policy_bundle_canonicalization",
    "protocol.policy_bundle_checkpoint.run_genesis_policy_bundle_slot_count",
    "protocol.policy_evidence.actions",
    "protocol.policy_evidence.codes",
    "protocol.policy_evidence.hex",
    "protocol.policy_evidence.ordered_harness_errors_domain",
    "protocol.policy_evidence.ordered_opportunities_domain",
    "protocol.policy_evidence.policy_action_vocabulary_version",
    "protocol.policy_evidence.policy_decision_evidence_schema_version",
    "protocol.policy_evidence.policy_outcome_evidence_schema_version",
    "protocol.tunables_snapshot.max_extension_server_name_bytes",
    "provider.catalog.model_router_slot_version",
    "record.content_store.model.marker_prefix",
    "record.policy_bundle.slot_names",
    "record.redact.prefix",
    "record.redact.suffix",
    "sandbox.bubblewrap.toolchain_home_read_subpaths",
    "sandbox.lib.id",
    "tools.fs_tools.utf8_bom",
    "tools.git_filters.filter_cache",
    "tools.git_harness.git_executable_cache",
    "tools.git_harness.null_device.cfg_cfg_not_windows",
    "tools.git_harness.null_device.cfg_cfg_windows",
    "tools.lib.dispatch_agent",
    "tools.process.supervisor.exhausted_job_sequence",
    "tools.schema.supported_types",
    "tools.tool_policy.tool_policy_slot_version",
    "tools.web.fetch_client.client",
    "tools.web.search_client.client",
    "tools.web.block_tags",
    "tools.web.truncated_close_tag_is_boundary",
    "tools.write_file.max_write_bytes",
    "tools.write_file.next_temp_id",
    "tunables.requirements.agent_tool",
    "tunables.requirements.budget",
    "tunables.requirements.tool_cache",
    "tunables.requirements.tool_context",
    "tunables.requirements.tooling",
    "tunables.tool_text.tool_text_artifacts",
    "tunables.tool_text.tool_text_registry_id",
    "tunables.tool_text.tool_text_schema_version",
    "verify.runtime_policy.all_ids",
    "verify.runtime_policy.id",
    // Threshold/default/budget-shaped invariant rows are also exact-id gated. These are source
    // dispositions awaiting owning-human review, not a name-based exemption for future rows.
    "cli.config.mcpserverbindingid.max_server_bytes",
    "cli.config.pluginmcpbindingid.max_server_bytes",
    "cli.config.retry.env_cap_ms",
    "cli.config.retry.env_max_attempts",
    "cli.plugin_runtime.candidate.max_candidate_path_bytes",
    "cli.main.default_allow_code",
    "cli.output.exit_budget",
    "cli.paste_input.max_pasted_text_bytes",
    "cli.paste_input.max_total_pasted_text_bytes",
    "cli.pricing.max_rate_cards",
    "cli.providers.max_catalog_cache_entries",
    "cli.providers.max_probe_cache_entries",
    "cli.providers.eager_discovery_budget",
    "cli.providers.last_success_route_version",
    "cli.runtime.deferred_tools.bash_write_domain",
    "cli.session_view.max_agent_definition_tag_bytes",
    "cli.tui.headless.auth.max_bearer_token_input_bytes",
    "eval.adapter_registry.max_executable_bytes",
    "eval.runner.hermetic.max_hermetic_manifest_bytes",
    "eval.terminal_bench.max_evidence_bytes",
    "eval.terminal_bench.max_memory_bytes",
    "eval.terminal_bench.max_output_bytes",
    "eval.terminal_bench.max_request_bytes",
    "eval.terminal_bench.max_result_bytes",
    "eval.terminal_bench.max_task_prompt_bytes",
    "eval.terminal_bench.max_text_bytes",
    "eval.terminal_bench.max_turns",
    "eval.terminal_bench.max_wall_secs",
    "eval.research_protocol.max_evidence_bytes",
    "eval.research_protocol.max_id_bytes",
    "eval.research_protocol.max_memory_bytes",
    "eval.research_protocol.max_output_bytes",
    "eval.research_protocol.max_path_bytes",
    "eval.research_protocol.max_prompt_bytes",
    "eval.research_protocol.max_protocol_request_bytes",
    "eval.research_protocol.max_protocol_response_bytes",
    "eval.research_protocol.max_native_materialization_bytes",
    "eval.research_protocol.max_native_receipt_bytes",
    "eval.research_protocol.max_turns",
    "eval.research_protocol.max_wall_secs",
    "eval.research_execution.process.max_group_processes",
    "eval.research_execution.process.proc_pgrp_only",
    "eval.research_execution.implementation.max_receipt_bytes",
    "eval.research_execution.response_validation.max_argument",
    "eval.research_execution.response_validation.max_output",
    "eval.research_execution.response_validation.max_path",
    "eval.trainer_bridge.max_distributed_workers",
    "eval.trainer_bridge.max_batch_suggestions",
    "eval.trainer_bridge.max_id_bytes",
    "eval.trainer_bridge.max_resource_bytes",
    "eval.trainer_bridge.max_reward_objectives",
    "eval.trainer_bridge.max_schema_id_bytes",
    "eval.trainer_bridge.max_trainer_bridge_message_bytes",
    "eval.tuner.max_families_per_candidate",
    "eval.tuner.max_universal_candidate_dimensions",
    "eval.tuner.candidate_graph.max_address_text_bytes",
    "eval.tuner.candidate_graph.max_candidate_topology_edges",
    "eval.tuner.candidate_graph.max_native_value_bytes",
    "eval.tuner.candidate_graph.max_value_depth",
    "eval.tuner.candidate_graph.max_value_nodes",
    "evolve.dataset.max_governed_dataset_bytes",
    "evolve.held_out.max_held_out_report_tasks",
    "evolve.registry.max_trajectory_lineage_policies",
    "evolve.registry.max_trajectory_registry_envelope_bytes",
    "lsp.lib.max_jsonrpc_numeric_id",
    "lsp.lib.max_lsp_position",
    "mcp.supervisor.config.max_mcp_deadline_ms",
    "mcp.supervisor.config.max_mcp_operation_deadline_ms",
    "marketplace.implementation.max_implementation_arg_bytes",
    "marketplace.implementation.max_implementation_argv",
    "marketplace.implementation.max_implementation_argv_bytes",
    "marketplace.implementation.max_implementation_cancellation_ms",
    "marketplace.implementation.max_implementation_catalog_bytes",
    "marketplace.implementation.max_implementation_dependencies",
    "marketplace.implementation.max_implementation_evidence_bytes",
    "marketplace.implementation.max_implementation_id_bytes",
    "marketplace.implementation.max_implementation_observations",
    "marketplace.implementation.max_implementation_path_bytes",
    "marketplace.implementation.max_implementation_runtime_ms",
    "marketplace.implementation_activation.max_implementation_activation_bytes",
    "marketplace.implementation_activation.max_implementation_activation_sources",
    "marketplace.implementation_activation.strict_json.duplicate_marker",
    "marketplace.implementation_runtime.max_implementation_stdin_bytes",
    "marketplace.implementation_runtime.max_implementation_state_evidence",
    "marketplace.implementation.max_implementations",
    "marketplace.implementation_protocol.max_failure_message_bytes",
    "marketplace.implementation_protocol.duplicate_key_marker",
    "marketplace.implementation_protocol.max_implementation_message_bytes",
    "marketplace.implementation_protocol.max_implementation_payload_bytes",
    "marketplace.implementation_protocol.max_implementation_state_bytes",
    "marketplace.implementation_protocol.max_implementation_state_deadline_ms",
    "marketplace.implementation_protocol.max_protocol_id_bytes",
    "marketplace.hotswap.max_hotswap_deadline_ms",
    "marketplace.hotswap.max_hotswap_id_bytes",
    "marketplace.hotswap.max_hotswap_ledger_bytes",
    "marketplace.hotswap.max_hotswap_reason_bytes",
    "marketplace.hotswap.max_hotswap_record_bytes",
    "protocol.input.max_input_images",
    "protocol.input.max_input_segments",
    "protocol.input.max_total_image_base64_bytes",
    "protocol.message.max_stop_reason_code_bytes",
    "protocol.tunables_snapshot.max_run_genesis_tunable_entries",
    "provider.anthropic.default_api_root",
    "provider.lib.rate_limit_headers",
    "provider.openai.default_chat_api_root",
    "provider.responses.default_root",
    "record.cache_io.max_session_meta_bytes",
    "record.content_store.model.max_content_json_bytes",
    "record.lib.max_erasure_receipts",
    "record.lib.max_private_content_bytes",
    "record.lib.max_private_content_preview_bytes",
    "tunables.capability_graph.max_capability_seam_graph_bytes",
    "tunables.capability_graph.max_capability_seams",
    "tunables.capability_graph.max_contract_id_bytes",
    "tunables.service_graph.max_runtime_service_graph_bytes",
    "tunables.capability_graph.max_seam_dependencies",
    "tunables.requirements.rate_limit_inference",
    "tunables.resolution_metadata.appendix.defaults",
    "tunables.resolution_metadata.current.defaults",
    "tunables.resolution_explain.max_explain_entries",
    "tunables.resolution_types.max_profile_values",
];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum CensusCandidateKind {
    Const,
    Static,
    AssociatedConst,
    SerdeDefault,
    ClapDefault,
    PolicyDefaultConstructor,
    PolicyFallbackCall,
    BuilderQualityDefault,
    IncludeStrAsset,
    IncludeBytesAsset,
    DynamicImplementationManifest,
    DynamicPluginManifest,
}

impl CensusCandidateKind {
    fn all() -> [Self; 12] {
        [
            Self::Const,
            Self::Static,
            Self::AssociatedConst,
            Self::SerdeDefault,
            Self::ClapDefault,
            Self::PolicyDefaultConstructor,
            Self::PolicyFallbackCall,
            Self::BuilderQualityDefault,
            Self::IncludeStrAsset,
            Self::IncludeBytesAsset,
            Self::DynamicImplementationManifest,
            Self::DynamicPluginManifest,
        ]
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum CensusDisposition {
    RuntimeSettable,
    InvariantReadOnly,
    BindingRequired,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum ExternalAddressKind {
    UnifiedProfile,
    DirectConfig,
    CallerInput,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum AddressSelectorKind {
    Key,
    Path,
    Argument,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum AddressOwnerKind {
    Schema,
    Protocol,
}

/// A writable address is a concrete external input, not merely a claim that a value is
/// "addressable". `selector` is interpreted according to `selector_kind`; `owner` prevents two
/// independent schemas/protocols which happen to use the same spelling from colliding.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct ExternalAddress {
    kind: ExternalAddressKind,
    selector_kind: AddressSelectorKind,
    selector: String,
    owner_kind: AddressOwnerKind,
    owner: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum CallerInputProofKind {
    PublicFunction,
    PublicMethod,
    PublicTraitMethod,
    SerdeEnvelope,
    ClapEnvelope,
    ProtocolEnvelope,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct CallerInputProof {
    pub(super) kind: CallerInputProofKind,
    pub(super) path: String,
    pub(super) symbol: String,
    pub(super) evidence: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum InvariantKind {
    Identity,
    WireCompatibility,
    Authority,
    Security,
    Durability,
    Replay,
    HardBudget,
    EffectLedger,
    NonValueStructural,
}

/// Source inspection can prove a mechanical disposition but cannot prove that the accountable
/// owning human approved it. Every invariant remains explicitly pending that governance step.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum OwningHumanReviewStatus {
    RequiredNotSourceProven,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct CensusRow {
    pub(super) id: String,
    pub(super) candidate_kind: CensusCandidateKind,
    pub(super) rust_type: String,
    pub(super) value: String,
    pub(super) owner: OwnerRow,
    pub(super) use_sites: Vec<UseSiteRow>,
    pub(super) disposition: CensusDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_address: Option<ExternalAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) caller_input_proof: Option<CallerInputProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) binding_requirement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) invariant_kind: Option<InvariantKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) review_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) owning_human_review: Option<OwningHumanReviewStatus>,
    pub(super) explicit_invariant_override: bool,
    pub(super) applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) behavior_oracle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) tier2_id: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct SourceCoverage {
    completeness_claim: &'static str,
    production_rust_files_scanned: usize,
    /// Observed syntax forms, including constructors/use sites which are coverage evidence but
    /// are not themselves independent optimization candidates.
    source_form_counts: BTreeMap<CensusCandidateKind, usize>,
    /// Emitted independent candidate rows. This deliberately does not have to equal the source
    /// observation counts: one builder declaration can expose several real parameters, while
    /// many constructor calls expose no new parameter at all.
    candidate_row_counts: BTreeMap<CensusCandidateKind, usize>,
    unclassified_source_forms: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct CensusDocument {
    schema_version: u16,
    total: usize,
    runtime_settable: usize,
    invariant_read_only: usize,
    binding_required: usize,
    advertised_runtime_settable: usize,
    runtime_applied: usize,
    externally_addressed_runtime_settable: usize,
    unaddressed_runtime_settable: usize,
    mechanical_invariant_dispositions: usize,
    owning_human_review_required: usize,
    explicit_invariant_overrides: usize,
    address_kind_counts: BTreeMap<ExternalAddressKind, usize>,
    invariant_kind_counts: BTreeMap<InvariantKind, usize>,
    source_coverage: SourceCoverage,
    candidates: Vec<CensusRow>,
}

pub(crate) fn run(root: &Path, write: bool) -> Result<()> {
    let (document, rendered) = current_document_and_render(root)?;
    let path = root.join("governance/optimization-census.json");
    if write {
        std::fs::write(&path, &rendered).with_context(|| format!("writing {}", path.display()))?;
        println!(
            "wrote governance/optimization-census.json ({} profile, {} direct config, {} proven caller input, {} binding required, {} invariant / {} owning-human review required)",
            document.address_kind_counts[&ExternalAddressKind::UnifiedProfile],
            document.address_kind_counts[&ExternalAddressKind::DirectConfig],
            document.address_kind_counts[&ExternalAddressKind::CallerInput],
            document.binding_required,
            document.invariant_read_only,
            document.owning_human_review_required,
        );
        return Ok(());
    }
    let committed =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    if committed != rendered {
        bail!(
            "governance/optimization-census.json is stale; run `cargo run --locked -p \
             iteron-xtask -- tunables generate-optimization-census`"
        );
    }
    if document.binding_required != 0 {
        bail!(
            "optimization census has {} binding_required candidate(s); bind each to a public protocol or classify it as a reviewed invariant before claiming external completeness",
            document.binding_required
        );
    }
    println!(
        "optimization census matches all declared production source forms: {} candidates, {} runtime-settable/applied/addressed ({} unified-profile), {} invariant awaiting owning-human review; {} Rust files scanned, 0 unclassified forms",
        document.total,
        document.runtime_applied,
        document.address_kind_counts[&ExternalAddressKind::UnifiedProfile],
        document.owning_human_review_required,
        document.source_coverage.production_rust_files_scanned,
    );
    Ok(())
}

/// Render the census implied by the current Rust sources without mutating the committed artifact.
/// Review tooling uses this to bind human decisions to source-current evidence rather than trusting
/// a possibly stale generated file.
pub(crate) fn render_current(root: &Path) -> Result<String> {
    Ok(current_document_and_render(root)?.1)
}

fn current_document_and_render(root: &Path) -> Result<(CensusDocument, String)> {
    let document = scan(root)?;
    validate(&document.candidates)?;
    validate_source_coverage(&document.source_coverage, document.total)?;
    validate_override_registry(&document.candidates)?;
    let mut rendered = serde_json::to_string_pretty(&document)?;
    rendered.push('\n');
    Ok((document, rendered))
}

fn validate_source_coverage(coverage: &SourceCoverage, total: usize) -> Result<()> {
    if coverage.production_rust_files_scanned == 0 {
        bail!("optimization census scanned no production Rust files");
    }
    if coverage.unclassified_source_forms != 0 {
        bail!(
            "optimization census found {} unclassified declared source form(s); extend the closed candidate_kind vocabulary before generation",
            coverage.unclassified_source_forms
        );
    }
    let expected = CensusCandidateKind::all()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual = coverage
        .source_form_counts
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    let candidate_kinds = coverage
        .candidate_row_counts
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    if actual != expected || candidate_kinds != expected {
        bail!("optimization census source-form coverage summary is not exhaustive");
    }
    if coverage.candidate_row_counts.values().sum::<usize>() != total {
        bail!("optimization census source-form coverage summary is not exhaustive");
    }
    Ok(())
}

fn validate_override_registry(rows: &[CensusRow]) -> Result<()> {
    let invariant_ids: BTreeSet<&str> = rows
        .iter()
        .filter(|row| matches!(row.disposition, CensusDisposition::InvariantReadOnly))
        .map(|row| row.id.as_str())
        .collect();
    let mut registered = BTreeSet::new();
    for id in QUALITY_INVARIANT_OVERRIDES {
        if !registered.insert(*id) {
            bail!("duplicate quality-invariant override `{id}`");
        }
        if !invariant_ids.contains(id) {
            bail!(
                "stale quality-invariant override `{id}`; remove it or restore a source-proven invariant candidate"
            );
        }
    }
    Ok(())
}

fn scan(root: &Path) -> Result<CensusDocument> {
    let params = crate::tunables_params::scan(root)?;
    crate::tunables_params::validate_rows(&params)?;
    let mut rows: Vec<CensusRow> = params.iter().map(CensusRow::from_param).collect();
    let DiscoveryReport {
        rows: discovered,
        production_rust_files_scanned,
        source_form_counts: discovered_source_form_counts,
        unclassified_source_forms,
    } = scan_production_sources(root, EXCLUDED_CRATES)?;
    rows.extend(discovered);
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let runtime_settable = rows
        .iter()
        .filter(|row| matches!(row.disposition, CensusDisposition::RuntimeSettable))
        .count();
    let invariant_read_only = rows
        .iter()
        .filter(|row| matches!(row.disposition, CensusDisposition::InvariantReadOnly))
        .count();
    let binding_required = rows
        .iter()
        .filter(|row| matches!(row.disposition, CensusDisposition::BindingRequired))
        .count();
    let runtime_applied = rows
        .iter()
        .filter(|row| matches!(row.disposition, CensusDisposition::RuntimeSettable) && row.applied)
        .count();
    let address_kind_counts = address_kind_counts(&rows);
    let invariant_kind_counts = invariant_kind_counts(&rows);
    let externally_addressed_runtime_settable: usize = address_kind_counts.values().sum();
    let unaddressed_runtime_settable =
        runtime_settable.saturating_sub(externally_addressed_runtime_settable);
    let mechanical_invariant_dispositions = rows
        .iter()
        .filter(|row| {
            matches!(row.disposition, CensusDisposition::InvariantReadOnly)
                && row.review_evidence.is_some()
        })
        .count();
    let owning_human_review_required = rows
        .iter()
        .filter(|row| row.owning_human_review.is_some())
        .count();
    let explicit_invariant_overrides = rows
        .iter()
        .filter(|row| row.explicit_invariant_override)
        .count();
    let mut source_form_counts = CensusCandidateKind::all()
        .into_iter()
        .map(|kind| (kind, 0usize))
        .collect::<BTreeMap<_, _>>();
    for row in params.iter() {
        let kind = match row.candidate_kind {
            CandidateKind::Const => CensusCandidateKind::Const,
            CandidateKind::Static => CensusCandidateKind::Static,
            CandidateKind::AssociatedConst => CensusCandidateKind::AssociatedConst,
        };
        *source_form_counts.entry(kind).or_default() += 1;
    }
    for (kind, count) in discovered_source_form_counts {
        *source_form_counts.entry(kind).or_default() += count;
    }
    let mut candidate_row_counts = BTreeMap::new();
    for kind in CensusCandidateKind::all() {
        candidate_row_counts.insert(kind, 0usize);
    }
    for row in &rows {
        *candidate_row_counts.entry(row.candidate_kind).or_default() += 1;
    }
    Ok(CensusDocument {
        schema_version: 4,
        total: rows.len(),
        runtime_settable,
        invariant_read_only,
        binding_required,
        advertised_runtime_settable: runtime_settable,
        runtime_applied,
        externally_addressed_runtime_settable,
        unaddressed_runtime_settable,
        mechanical_invariant_dispositions,
        owning_human_review_required,
        explicit_invariant_overrides,
        address_kind_counts,
        invariant_kind_counts,
        source_coverage: SourceCoverage {
            completeness_claim: "complete_for_declared_production_source_forms_not_mathematical_universe",
            production_rust_files_scanned,
            source_form_counts,
            candidate_row_counts,
            unclassified_source_forms,
        },
        candidates: rows,
    })
}

fn address_kind_counts(rows: &[CensusRow]) -> BTreeMap<ExternalAddressKind, usize> {
    let mut counts = BTreeMap::from([
        (ExternalAddressKind::UnifiedProfile, 0),
        (ExternalAddressKind::DirectConfig, 0),
        (ExternalAddressKind::CallerInput, 0),
    ]);
    for address in rows.iter().filter_map(|row| row.external_address.as_ref()) {
        *counts.entry(address.kind).or_default() += 1;
    }
    counts
}

fn invariant_kind_counts(rows: &[CensusRow]) -> BTreeMap<InvariantKind, usize> {
    let mut counts = BTreeMap::from([
        (InvariantKind::Identity, 0),
        (InvariantKind::WireCompatibility, 0),
        (InvariantKind::Authority, 0),
        (InvariantKind::Security, 0),
        (InvariantKind::Durability, 0),
        (InvariantKind::Replay, 0),
        (InvariantKind::HardBudget, 0),
        (InvariantKind::EffectLedger, 0),
        (InvariantKind::NonValueStructural, 0),
    ]);
    for kind in rows.iter().filter_map(|row| row.invariant_kind) {
        *counts.entry(kind).or_default() += 1;
    }
    counts
}

impl CensusRow {
    fn from_param(param: &ParamRow) -> Self {
        let candidate_kind = match param.candidate_kind {
            CandidateKind::Const => CensusCandidateKind::Const,
            CandidateKind::Static => CensusCandidateKind::Static,
            CandidateKind::AssociatedConst => CensusCandidateKind::AssociatedConst,
        };
        let (invariant_kind, review_evidence, explicit_invariant_override) = if matches!(
            param.disposition,
            Disposition::InvariantReadOnly
        ) {
            let kind = invariant_kind(param);
            let explicit = QUALITY_INVARIANT_OVERRIDES.contains(&param.id.as_str());
            let qualifier = if explicit {
                "explicit census disposition override"
            } else {
                "closed Tier-2 disposition rule"
            };
            let evidence_site = param
                .use_sites
                .first()
                .map(|site| format!("{}:{} ({})", site.path, site.line, site.evidence))
                .unwrap_or_else(|| "no production use-site evidence".to_owned());
            (
                Some(kind),
                Some(format!(
                    "{qualifier}: `{}` at {} — {}; observed at {evidence_site}; mechanical source evidence only, not a claim of human review",
                    param.owner.symbol,
                    param.owner.path,
                    invariant_review_evidence(kind)
                )),
                explicit,
            )
        } else {
            (None, None, false)
        };
        Self {
            id: param.id.clone(),
            candidate_kind,
            rust_type: param.rust_type.clone(),
            value: param.default.clone(),
            owner: param.owner.clone(),
            use_sites: param.use_sites.clone(),
            disposition: match param.disposition {
                Disposition::RuntimeSettable => CensusDisposition::RuntimeSettable,
                Disposition::InvariantReadOnly => CensusDisposition::InvariantReadOnly,
            },
            external_address: if matches!(param.disposition, Disposition::RuntimeSettable) {
                Some(ExternalAddress {
                    kind: ExternalAddressKind::UnifiedProfile,
                    selector_kind: AddressSelectorKind::Key,
                    selector: param.id.clone(),
                    owner_kind: AddressOwnerKind::Schema,
                    owner: "iteron_tunables::Param/ResolutionValue".to_owned(),
                })
            } else {
                None
            },
            caller_input_proof: None,
            binding_requirement: None,
            invariant_kind,
            review_evidence,
            owning_human_review: if matches!(param.disposition, Disposition::InvariantReadOnly) {
                Some(OwningHumanReviewStatus::RequiredNotSourceProven)
            } else {
                None
            },
            explicit_invariant_override,
            applied: param.applied,
            behavior_oracle: param.behavior_oracle.clone(),
            tier2_id: Some(param.id.clone()),
        }
    }
}

fn invariant_review_evidence(kind: InvariantKind) -> &'static str {
    match kind {
        InvariantKind::Identity => "the value participates in stable identity/canonical naming",
        InvariantKind::WireCompatibility => {
            "the value fixes serialized, decoded, or cross-process wire compatibility"
        }
        InvariantKind::Authority => "the value defines a capability/permission authority boundary",
        InvariantKind::Security => {
            "the value fixes authentication, cryptographic, or secret-handling shape"
        }
        InvariantKind::Durability => "the value fixes durable storage or checkpoint interpretation",
        InvariantKind::Replay => "the value fixes deterministic replay interpretation",
        InvariantKind::HardBudget => {
            "the value is classified as a hard ceiling rather than a quality preference"
        }
        InvariantKind::EffectLedger => {
            "the value participates in effect admission/accounting ledger integrity"
        }
        InvariantKind::NonValueStructural => {
            "the declaration is structural state/type/alias evidence, not an independent runtime value"
        }
    }
}

fn invariant_kind(param: &ParamRow) -> InvariantKind {
    let id = param.id.to_ascii_lowercase();
    match param
        .invariant_reason
        .expect("invariant ParamRow has a closed reason")
    {
        InvariantReason::Identity => InvariantKind::Identity,
        InvariantReason::WireCompatibility => InvariantKind::WireCompatibility,
        InvariantReason::CapabilityAuthority => InvariantKind::Authority,
        InvariantReason::Security => InvariantKind::Security,
        InvariantReason::DurabilityReplay => {
            if id.contains("replay") {
                InvariantKind::Replay
            } else {
                InvariantKind::Durability
            }
        }
        InvariantReason::HardBudgetEffectLedger => {
            if id.contains("effect") || id.contains("ledger") || id.contains("admission") {
                InvariantKind::EffectLedger
            } else {
                InvariantKind::HardBudget
            }
        }
        InvariantReason::RuntimeStateNotAValue => {
            if id.contains("schema")
                || id.contains("version")
                || id.contains("digest")
                || id.contains("domain")
                || id.contains("marker")
                || id.contains("canonical")
            {
                InvariantKind::Identity
            } else {
                InvariantKind::NonValueStructural
            }
        }
    }
}

fn validate(rows: &[CensusRow]) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut advertised = 0usize;
    let mut applied = 0usize;
    let mut missing_quality_overrides = Vec::new();
    for row in rows {
        if row.id.is_empty() || !ids.insert(&row.id) {
            bail!(
                "optimization candidate id is empty or duplicated: `{}`",
                row.id
            );
        }
        if row.rust_type.trim().is_empty() || row.value.trim().is_empty() {
            bail!("{} has no Rust type/value evidence", row.id);
        }
        if row.owner.krate.is_empty() || row.owner.path.is_empty() || row.owner.symbol.is_empty() {
            bail!("{} has incomplete ownership", row.id);
        }
        match row.disposition {
            CensusDisposition::RuntimeSettable => {
                advertised += 1;
                let address = row.external_address.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("{} is runtime_settable without an external address", row.id)
                })?;
                if address.selector.trim().is_empty() || address.owner.trim().is_empty() {
                    bail!(
                        "{} has an empty external selector or schema/protocol owner",
                        row.id
                    );
                }
                if matches!(address.kind, ExternalAddressKind::CallerInput) {
                    let proof = row.caller_input_proof.as_ref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "{} claims caller_input without a public protocol proof",
                            row.id
                        )
                    })?;
                    if proof.path != row.owner.path
                        || proof.symbol.trim().is_empty()
                        || proof.evidence.trim().is_empty()
                    {
                        bail!("{} has an inexact caller_input protocol proof", row.id);
                    }
                } else if row.caller_input_proof.is_some() {
                    bail!(
                        "{} carries caller_input proof for a non-caller address",
                        row.id
                    );
                }
                if row.binding_requirement.is_some() {
                    bail!(
                        "{} is runtime_settable but still marked binding_required",
                        row.id
                    );
                }
                let address_identity = format!(
                    "{:?}\0{:?}\0{}\0{:?}\0{}",
                    address.kind,
                    address.selector_kind,
                    address.selector,
                    address.owner_kind,
                    address.owner
                );
                if !addresses.insert(address_identity) {
                    bail!(
                        "{} collides with another external address; qualify the selector by its schema/protocol owner",
                        row.id
                    );
                }
                if !row.applied {
                    bail!("{} is advertised runtime_settable but not applied", row.id);
                }
                applied += 1;
                if row.use_sites.is_empty() {
                    bail!(
                        "{} is runtime_settable without production use-site evidence",
                        row.id
                    );
                }
                if row.behavior_oracle.as_deref().is_none_or(str::is_empty) {
                    bail!("{} is runtime_settable without a behavior oracle", row.id);
                }
                if row.invariant_kind.is_some()
                    || row.review_evidence.is_some()
                    || row.owning_human_review.is_some()
                    || row.explicit_invariant_override
                {
                    bail!(
                        "{} is settable but carries invariant disposition evidence",
                        row.id
                    );
                }
            }
            CensusDisposition::InvariantReadOnly => {
                if row.external_address.is_some() {
                    bail!("{} is invariant but carries a settable address", row.id);
                }
                if row.caller_input_proof.is_some() || row.binding_requirement.is_some() {
                    bail!("{} invariant carries caller-binding metadata", row.id);
                }
                if row.invariant_kind.is_none() {
                    bail!("{} is read-only without a closed invariant kind", row.id);
                }
                let evidence = row.review_evidence.as_deref().unwrap_or_default();
                if evidence.is_empty() {
                    bail!("{} is read-only without mechanical review evidence", row.id);
                }
                if !evidence.contains(&row.owner.path)
                    || !evidence.contains(&row.owner.symbol)
                    || !evidence.contains("mechanical source evidence only")
                    || !evidence.contains("not a claim of human review")
                    || evidence.contains("no production use-site evidence")
                {
                    bail!(
                        "{} invariant evidence must identify its source/use and explicitly disclaim human approval",
                        row.id
                    );
                }
                if !matches!(
                    row.owning_human_review,
                    Some(OwningHumanReviewStatus::RequiredNotSourceProven)
                ) {
                    bail!(
                        "{} must record that owning-human review is required and not source-proven",
                        row.id
                    );
                }
                if row.explicit_invariant_override
                    && !QUALITY_INVARIANT_OVERRIDES.contains(&row.id.as_str())
                {
                    bail!("{} carries an unregistered invariant override", row.id);
                }
                let exact_source_invariant = source_form_invariant_matches(row);
                if exact_source_invariant && !evidence.contains("closed source-form invariant rule")
                {
                    bail!("{} has incomplete source-form invariant evidence", row.id);
                }
                if quality_affecting_candidate(row)
                    && !row.explicit_invariant_override
                    && !exact_source_invariant
                {
                    missing_quality_overrides.push(row.id.as_str());
                }
                if row.applied {
                    bail!("{} is invariant_read_only but marked applied", row.id);
                }
                if row.behavior_oracle.is_some() {
                    bail!(
                        "{} is invariant_read_only but carries a writable behavior oracle",
                        row.id
                    );
                }
            }
            CensusDisposition::BindingRequired => {
                if row.external_address.is_some() || row.caller_input_proof.is_some() {
                    bail!(
                        "{} is binding_required but claims a concrete/proven external address",
                        row.id
                    );
                }
                if row.binding_requirement.as_deref().is_none_or(str::is_empty) {
                    bail!(
                        "{} is binding_required without an exact missing proof",
                        row.id
                    );
                }
                if row.use_sites.is_empty()
                    || !row.applied
                    || row.behavior_oracle.as_deref().is_none_or(str::is_empty)
                {
                    bail!(
                        "{} binding_required row must retain its applied use site and behavior oracle",
                        row.id
                    );
                }
                if row.invariant_kind.is_some()
                    || row.review_evidence.is_some()
                    || row.owning_human_review.is_some()
                    || row.explicit_invariant_override
                {
                    bail!("{} binding_required row carries invariant evidence", row.id);
                }
            }
        }
    }
    if !missing_quality_overrides.is_empty() {
        bail!(
            "{} quality-affecting invariant candidate(s) have no explicit override; classify them settable or add source-specific dispositions:\n  {}",
            missing_quality_overrides.len(),
            missing_quality_overrides.join("\n  ")
        );
    }
    if advertised != applied {
        bail!(
            "advertised/applied mismatch: {advertised} runtime-settable rows but {applied} applied rows"
        );
    }
    Ok(())
}

fn quality_affecting_candidate(row: &CensusRow) -> bool {
    let identity = format!("{} {}", row.id, row.owner.symbol).to_ascii_lowercase();
    let semantic_marker = [
        "marker",
        "threshold",
        "default",
        "policy",
        "tool",
        "routing",
        "route",
    ]
    .iter()
    .any(|marker| identity.contains(marker));
    let threshold_token = identity
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token| {
            matches!(
                token,
                "max" | "min" | "limit" | "cap" | "ceiling" | "budget"
            )
        });
    semantic_marker || threshold_token
}

#[cfg(test)]
mod tests;
