//! Covered-class production optimization census and honesty gate.
//!
//! The Tier-2 catalog remains the compatibility surface for const/static parameters. This module
//! adds syntax-aware discovery of defaults expressed through serde/clap and named runtime policy
//! constructors, then emits one exact generated artifact covering those inventories. It does not
//! claim that these syntax classes exhaust every optimization input in the repository.

use crate::tunables_params::{
    CandidateKind, Disposition, InvariantReason, OwnerRow, ParamRow, UseSiteRow,
};
use anyhow::{Context, Result, bail};
use quote::ToTokens as _;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};

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
    "cli.providers.setup_effect.policy_canonical",
    "cli.providers.setup_effect.policy_id",
    "cli.runtime.failed_action_cache.marker",
    "cli.runtime.interrupted_stream_marker",
    "cli.runtime.policy_evidence.collaboration_slot",
    "cli.runtime.policy_evidence.context_slot",
    "cli.runtime.policy_evidence.memory_slot",
    "cli.runtime.policy_evidence.model_router_slot",
    "cli.runtime.policy_evidence.planner_slot",
    "cli.runtime.policy_evidence.router_slot",
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
    "ctx.context_materialization.marker",
    "ctx.memory.footer",
    "ctx.memory.header",
    "ctx.skills_metadata.skill_refused_tools",
    "ctx.token_estimator.route_aware_estimator_policy_id",
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
    "provider.catalog.model_router_slot_version",
    "record.content_store.model.marker_prefix",
    "record.policy_bundle.slot_names",
    "record.redact.prefix",
    "record.redact.suffix",
    "sandbox.bubblewrap.toolchain_home_read_subpaths",
    "sandbox.lib.id",
    "tools.fs_tools.utf8_bom",
    "tools.git_harness.null_device.cfg_cfg_not_windows",
    "tools.git_harness.null_device.cfg_cfg_windows",
    "tools.lib.dispatch_agent",
    "tools.process.supervisor.exhausted_job_sequence",
    "tools.schema.supported_types",
    "tools.tool_policy.tool_policy_slot_version",
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
    "cli.output.max_pending_stream_token_bytes",
    "cli.paste_input.max_pasted_text_bytes",
    "cli.paste_input.max_total_pasted_text_bytes",
    "cli.pricing.max_rate_cards",
    "cli.providers.max_catalog_cache_entries",
    "cli.providers.max_probe_cache_entries",
    "cli.session_view.max_agent_definition_tag_bytes",
    "cli.tui.headless.auth.max_bearer_token_input_bytes",
    "eval.adapter_registry.max_executable_bytes",
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
    "eval.research_protocol.max_turns",
    "eval.research_protocol.max_wall_secs",
    "eval.research_execution.process.max_group_processes",
    "eval.research_execution.process.proc_pgrp_only",
    "eval.research_execution.implementation.max_receipt_bytes",
    "eval.research_execution.response_validation.max_argument",
    "eval.research_execution.response_validation.max_output",
    "eval.research_execution.response_validation.max_path",
    "eval.trainer_bridge.max_distributed_workers",
    "eval.trainer_bridge.max_id_bytes",
    "eval.trainer_bridge.max_resource_bytes",
    "eval.trainer_bridge.max_reward_objectives",
    "eval.trainer_bridge.max_schema_id_bytes",
    "eval.trainer_bridge.max_trainer_bridge_message_bytes",
    "eval.tuner.max_families_per_candidate",
    "eval.tuner.max_universal_candidate_dimensions",
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
    "marketplace.implementation.max_implementations",
    "marketplace.implementation_protocol.max_failure_message_bytes",
    "marketplace.implementation_protocol.max_implementation_message_bytes",
    "marketplace.implementation_protocol.max_implementation_payload_bytes",
    "marketplace.implementation_protocol.max_protocol_id_bytes",
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
    "tunables.capability_graph.max_seam_dependencies",
    "tunables.requirements.rate_limit_inference",
    "tunables.resolution_metadata.appendix.defaults",
    "tunables.resolution_metadata.current.defaults",
    "tunables.resolution_explain.max_explain_entries",
    "tunables.resolution_types.max_profile_values",
];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CensusCandidateKind {
    Const,
    Static,
    AssociatedConst,
    SerdeDefault,
    ClapDefault,
    PolicyDefaultConstructor,
    PolicyFallbackCall,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum ExternalAddressKind {
    UnifiedProfile,
    DirectConfig,
    CallerInput,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AddressSelectorKind {
    Key,
    Path,
    Argument,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AddressOwnerKind {
    Schema,
    Protocol,
}

/// A writable address is a concrete external input, not merely a claim that a value is
/// "addressable". `selector` is interpreted according to `selector_kind`; `owner` prevents two
/// independent schemas/protocols which happen to use the same spelling from colliding.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ExternalAddress {
    kind: ExternalAddressKind,
    selector_kind: AddressSelectorKind,
    selector: String,
    owner_kind: AddressOwnerKind,
    owner: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum InvariantKind {
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
enum OwningHumanReviewStatus {
    RequiredNotSourceProven,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CensusRow {
    id: String,
    candidate_kind: CensusCandidateKind,
    rust_type: String,
    value: String,
    owner: OwnerRow,
    use_sites: Vec<UseSiteRow>,
    disposition: Disposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_address: Option<ExternalAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invariant_kind: Option<InvariantKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    review_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owning_human_review: Option<OwningHumanReviewStatus>,
    explicit_invariant_override: bool,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    behavior_oracle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier2_id: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct CensusDocument {
    schema_version: u16,
    total: usize,
    runtime_settable: usize,
    invariant_read_only: usize,
    advertised_runtime_settable: usize,
    runtime_applied: usize,
    externally_addressed_runtime_settable: usize,
    unaddressed_runtime_settable: usize,
    mechanical_invariant_dispositions: usize,
    owning_human_review_required: usize,
    explicit_invariant_overrides: usize,
    address_kind_counts: BTreeMap<ExternalAddressKind, usize>,
    invariant_kind_counts: BTreeMap<InvariantKind, usize>,
    candidates: Vec<CensusRow>,
}

pub(crate) fn run(root: &Path, write: bool) -> Result<()> {
    let (document, rendered) = current_document_and_render(root)?;
    let path = root.join("governance/optimization-census.json");
    if write {
        std::fs::write(&path, &rendered).with_context(|| format!("writing {}", path.display()))?;
        println!(
            "wrote governance/optimization-census.json ({} profile, {} direct config, {} caller input, {} unaddressed, {} invariant / {} owning-human review required)",
            document.address_kind_counts[&ExternalAddressKind::UnifiedProfile],
            document.address_kind_counts[&ExternalAddressKind::DirectConfig],
            document.address_kind_counts[&ExternalAddressKind::CallerInput],
            document.unaddressed_runtime_settable,
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
    println!(
        "optimization census matches covered source classes: {} candidates, {} runtime-settable/applied/addressed ({} unified-profile), {} invariant awaiting owning-human review",
        document.total,
        document.runtime_applied,
        document.address_kind_counts[&ExternalAddressKind::UnifiedProfile],
        document.owning_human_review_required,
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
    validate_override_registry(&document.candidates)?;
    let mut rendered = serde_json::to_string_pretty(&document)?;
    rendered.push('\n');
    Ok((document, rendered))
}

fn validate_override_registry(rows: &[CensusRow]) -> Result<()> {
    let invariant_ids: BTreeSet<&str> = rows
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::InvariantReadOnly))
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

    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files)?;
    files.sort();
    for file in files {
        let relative = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_path(&relative) {
            continue;
        }
        let Some(krate) = crate_of(&relative) else {
            continue;
        };
        if EXCLUDED_CRATES.contains(&krate) {
            continue;
        }
        let source = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        rows.extend(discover_source(krate, &relative, &source)?);
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let runtime_settable = rows
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::RuntimeSettable))
        .count();
    let invariant_read_only = rows.len() - runtime_settable;
    let runtime_applied = rows
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::RuntimeSettable) && row.applied)
        .count();
    let address_kind_counts = address_kind_counts(&rows);
    let invariant_kind_counts = invariant_kind_counts(&rows);
    let externally_addressed_runtime_settable: usize = address_kind_counts.values().sum();
    let unaddressed_runtime_settable =
        runtime_settable.saturating_sub(externally_addressed_runtime_settable);
    let mechanical_invariant_dispositions = rows
        .iter()
        .filter(|row| {
            matches!(row.disposition, Disposition::InvariantReadOnly)
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
    Ok(CensusDocument {
        schema_version: 3,
        total: rows.len(),
        runtime_settable,
        invariant_read_only,
        advertised_runtime_settable: runtime_settable,
        runtime_applied,
        externally_addressed_runtime_settable,
        unaddressed_runtime_settable,
        mechanical_invariant_dispositions,
        owning_human_review_required,
        explicit_invariant_overrides,
        address_kind_counts,
        invariant_kind_counts,
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
            disposition: param.disposition,
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

fn discover_source(krate: &str, relative: &str, source: &str) -> Result<Vec<CensusRow>> {
    let syntax = syn::parse_file(source)
        .with_context(|| format!("parsing {relative} for optimization candidates"))?;
    let mut visitor = CensusVisitor {
        krate,
        relative,
        modules: Vec::new(),
        owner: Vec::new(),
        serde_rename_all: Vec::new(),
        ordinals: BTreeMap::new(),
        found: Vec::new(),
    };
    visitor.visit_file(&syntax);
    Ok(visitor.found)
}

struct CensusVisitor<'a> {
    krate: &'a str,
    relative: &'a str,
    modules: Vec<String>,
    owner: Vec<String>,
    serde_rename_all: Vec<Option<String>>,
    ordinals: BTreeMap<String, usize>,
    found: Vec<CensusRow>,
}

impl CensusVisitor<'_> {
    fn current_owner(&self) -> String {
        self.modules
            .iter()
            .chain(self.owner.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("::")
    }

    fn field_default(
        &mut self,
        field: &syn::Field,
        field_index: usize,
        kind: CensusCandidateKind,
        value: String,
        attribute: &str,
    ) {
        let field_name = field
            .ident
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("unnamed_{field_index}"));
        let owner = self.current_owner();
        let serialized_field_name = serde_field_name(
            field,
            &field_name,
            self.serde_rename_all.last().and_then(Option::as_deref),
        );
        let clap_argument = clap_argument(field, &field_name);
        let flavor = match kind {
            CensusCandidateKind::SerdeDefault => "serde_default",
            CensusCandidateKind::ClapDefault => "clap_default",
            _ => unreachable!("field defaults use serde or clap"),
        };
        self.found.push(CensusRow {
            id: stable_id(
                self.krate,
                self.relative,
                &format!("{owner}.{field_name}.{flavor}"),
            ),
            candidate_kind: kind,
            rust_type: field.ty.to_token_stream().to_string(),
            value,
            owner: OwnerRow {
                krate: self.krate.to_owned(),
                path: self.relative.to_owned(),
                symbol: format!("{owner}::{field_name}"),
            },
            use_sites: vec![UseSiteRow {
                path: self.relative.to_owned(),
                line: field.span().start().line,
                evidence: format!("{attribute} production parser/deserializer default"),
            }],
            disposition: Disposition::RuntimeSettable,
            external_address: Some(match kind {
                CensusCandidateKind::ClapDefault => ExternalAddress {
                    kind: ExternalAddressKind::DirectConfig,
                    selector_kind: if clap_argument.is_some() {
                        AddressSelectorKind::Argument
                    } else {
                        AddressSelectorKind::Path
                    },
                    selector: clap_argument.unwrap_or_else(|| format!("{owner}.{field_name}")),
                    owner_kind: AddressOwnerKind::Schema,
                    owner: format!("clap::{owner}"),
                },
                CensusCandidateKind::SerdeDefault => ExternalAddress {
                    kind: ExternalAddressKind::DirectConfig,
                    selector_kind: AddressSelectorKind::Path,
                    selector: format!("{owner}.{serialized_field_name}"),
                    owner_kind: AddressOwnerKind::Schema,
                    owner: format!("serde::{owner}"),
                },
                _ => unreachable!("field defaults use serde or clap"),
            }),
            invariant_kind: None,
            review_evidence: None,
            owning_human_review: None,
            explicit_invariant_override: false,
            applied: true,
            behavior_oracle: Some(format!(
                "explicit input for {owner}::{field_name} replaces the declared {attribute} default"
            )),
            tier2_id: None,
        });
    }

    fn inspect_fields<'a>(&mut self, fields: impl Iterator<Item = &'a syn::Field>) {
        for (field_index, field) in fields.enumerate() {
            if has_cfg_test(&field.attrs) {
                continue;
            }
            for attr in &field.attrs {
                let path = attr.path();
                let rendered = attr.meta.to_token_stream().to_string();
                if path.is_ident("serde") && attribute_option(&rendered, "default") {
                    self.field_default(
                        field,
                        field_index,
                        CensusCandidateKind::SerdeDefault,
                        attribute_value(&rendered, "default")
                            .unwrap_or_else(|| "Default::default()".to_owned()),
                        "serde(default)",
                    );
                }
                if (path.is_ident("arg") || path.is_ident("clap"))
                    && (attribute_option(&rendered, "default_value")
                        || attribute_option(&rendered, "default_value_t"))
                {
                    self.field_default(
                        field,
                        field_index,
                        CensusCandidateKind::ClapDefault,
                        attribute_value(&rendered, "default_value_t")
                            .or_else(|| attribute_value(&rendered, "default_value"))
                            .unwrap_or_else(|| "Default::default()".to_owned()),
                        "clap(default_value)",
                    );
                }
            }
        }
    }

    fn inspect_container_default(
        &mut self,
        ident: &syn::Ident,
        attrs: &[syn::Attribute],
        span: proc_macro2::Span,
    ) {
        for attr in attrs {
            let rendered = attr.meta.to_token_stream().to_string();
            if !attr.path().is_ident("serde") || !attribute_option(&rendered, "default") {
                continue;
            }
            let owner = self.current_owner();
            self.found.push(CensusRow {
                id: stable_id(self.krate, self.relative, &format!("{owner}.serde_default")),
                candidate_kind: CensusCandidateKind::SerdeDefault,
                rust_type: ident.to_string(),
                value: attribute_value(&rendered, "default")
                    .unwrap_or_else(|| "Default::default()".to_owned()),
                owner: OwnerRow {
                    krate: self.krate.to_owned(),
                    path: self.relative.to_owned(),
                    symbol: owner.clone(),
                },
                use_sites: vec![UseSiteRow {
                    path: self.relative.to_owned(),
                    line: span.start().line,
                    evidence: "serde(default) production container deserializer".to_owned(),
                }],
                disposition: Disposition::RuntimeSettable,
                external_address: Some(ExternalAddress {
                    kind: ExternalAddressKind::DirectConfig,
                    selector_kind: AddressSelectorKind::Path,
                    selector: owner.clone(),
                    owner_kind: AddressOwnerKind::Schema,
                    owner: format!("serde::{owner}"),
                }),
                invariant_kind: None,
                review_evidence: None,
                owning_human_review: None,
                explicit_invariant_override: false,
                applied: true,
                behavior_oracle: Some(format!(
                    "explicit input fields for {owner} replace its serde container defaults"
                )),
                tier2_id: None,
            });
        }
    }

    fn policy_call(&mut self, node: &syn::ExprCall, callee: &syn::Path) {
        let rendered = callee.to_token_stream().to_string().replace(' ', "");
        let leaf = callee
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let context = format!("{}::{rendered}", self.current_owner()).to_ascii_lowercase();
        let named_default = leaf == "default" || leaf.starts_with("default_");
        let named_fallback = leaf.contains("fallback");
        if !(named_default || named_fallback) || !is_policy_context(&context) {
            return;
        }
        let key = format!("{}::{rendered}", self.current_owner());
        let ordinal = {
            let entry = self.ordinals.entry(key).or_default();
            *entry += 1;
            *entry
        };
        let kind = if named_fallback {
            CensusCandidateKind::PolicyFallbackCall
        } else {
            CensusCandidateKind::PolicyDefaultConstructor
        };
        let owner = self.current_owner();
        let address_owner = owner.clone();
        self.found.push(CensusRow {
            id: stable_id(
                self.krate,
                self.relative,
                &format!("{owner}.{rendered}.{ordinal}"),
            ),
            candidate_kind: kind,
            rust_type: "_ (inferred by rustc)".to_owned(),
            value: node.to_token_stream().to_string(),
            owner: OwnerRow {
                krate: self.krate.to_owned(),
                path: self.relative.to_owned(),
                symbol: owner,
            },
            use_sites: vec![UseSiteRow {
                path: self.relative.to_owned(),
                line: node.span().start().line,
                evidence: "production policy constructor call".to_owned(),
            }],
            disposition: Disposition::RuntimeSettable,
            external_address: Some(ExternalAddress {
                kind: ExternalAddressKind::CallerInput,
                selector_kind: AddressSelectorKind::Argument,
                selector: format!("{address_owner}::{rendered}#{ordinal}"),
                owner_kind: AddressOwnerKind::Protocol,
                owner: format!("rust-call::{}::{address_owner}", self.relative),
            }),
            invariant_kind: None,
            review_evidence: None,
            owning_human_review: None,
            explicit_invariant_override: false,
            applied: true,
            behavior_oracle: Some(
                "caller-provided policy/configuration replaces this constructor fallback"
                    .to_owned(),
            ),
            tier2_id: None,
        });
    }
}

impl<'ast> Visit<'ast> for CensusVisitor<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.modules.push(item.ident.to_string());
        if let Some((_, items)) = &item.content {
            for item in items {
                self.visit_item(item);
            }
        }
        self.modules.pop();
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.ident.to_string());
        self.serde_rename_all
            .push(serde_container_rename(&item.attrs, "rename_all"));
        self.inspect_container_default(&item.ident, &item.attrs, item.span());
        self.inspect_fields(item.fields.iter());
        self.serde_rename_all.pop();
        self.owner.pop();
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.ident.to_string());
        self.serde_rename_all
            .push(serde_container_rename(&item.attrs, "rename_all_fields"));
        self.inspect_container_default(&item.ident, &item.attrs, item.span());
        for variant in &item.variants {
            if has_cfg_test(&variant.attrs) {
                continue;
            }
            self.owner.push(variant.ident.to_string());
            self.inspect_fields(variant.fields.iter());
            self.owner.pop();
        }
        self.serde_rename_all.pop();
        self.owner.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.sig.ident.to_string());
        visit::visit_item_fn(self, item);
        self.owner.pop();
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner
            .push(item.self_ty.to_token_stream().to_string().replace(' ', ""));
        visit::visit_item_impl(self, item);
        self.owner.pop();
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.ident.to_string());
        visit::visit_item_trait(self, item);
        self.owner.pop();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.sig.ident.to_string());
        visit::visit_trait_item_fn(self, item);
        self.owner.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.sig.ident.to_string());
        visit::visit_impl_item_fn(self, item);
        self.owner.pop();
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = node.func.as_ref() {
            self.policy_call(node, &function.path);
        }
        visit::visit_expr_call(self, node);
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
            Disposition::RuntimeSettable => {
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
            Disposition::InvariantReadOnly => {
                if row.external_address.is_some() {
                    bail!("{} is invariant but carries a settable address", row.id);
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
                if quality_affecting_candidate(row) && !row.explicit_invariant_override {
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

fn stable_id(krate: &str, relative: &str, symbol: &str) -> String {
    let module = relative
        .rsplit_once("/src/")
        .map(|(_, tail)| tail)
        .unwrap_or(relative)
        .trim_end_matches(".rs");
    format!("{krate}.{module}.{symbol}")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect::<String>()
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn is_policy_context(context: &str) -> bool {
    [
        "policy",
        "config",
        "options",
        "limits",
        "budget",
        "retry",
        "timeout",
        "cache",
        "routing",
        "router",
        "model",
        "provider",
        "workflow",
        "verifier",
        "context",
        "memory",
        "compact",
        "prompt",
        "tool",
        "sandbox",
        "admission",
        "sampling",
        "reasoning",
        "queue",
        "concurrency",
        "turnstate",
    ]
    .iter()
    .any(|marker| context.contains(marker))
}

fn attribute_option(rendered: &str, name: &str) -> bool {
    rendered
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| token == name)
}

fn attribute_value(rendered: &str, name: &str) -> Option<String> {
    let (_, tail) = rendered.split_once(name)?;
    let value = tail.trim_start().strip_prefix('=')?.trim_start();
    Some(
        value
            .split(',')
            .next()
            .unwrap_or(value)
            .trim()
            .trim_end_matches(')')
            .trim()
            .to_owned(),
    )
}

fn serde_container_rename(attrs: &[syn::Attribute], key: &str) -> Option<String> {
    attrs.iter().find_map(|attr| {
        attr.path()
            .is_ident("serde")
            .then(|| attribute_value(&attr.meta.to_token_stream().to_string(), key))
            .flatten()
            .map(|value| value.trim_matches('"').to_owned())
    })
}

fn serde_field_name(field: &syn::Field, rust_name: &str, rename_all: Option<&str>) -> String {
    if let Some(explicit) = field.attrs.iter().find_map(|attr| {
        attr.path()
            .is_ident("serde")
            .then(|| attribute_value(&attr.meta.to_token_stream().to_string(), "rename"))
            .flatten()
    }) {
        return explicit.trim_matches('"').to_owned();
    }
    let rust_name = rust_name.strip_prefix("r#").unwrap_or(rust_name);
    match rename_all {
        Some("camelCase") => camel_case(rust_name, false),
        Some("PascalCase") => camel_case(rust_name, true),
        Some("kebab-case") => rust_name.replace('_', "-"),
        Some("SCREAMING_SNAKE_CASE") => rust_name.to_ascii_uppercase(),
        Some("SCREAMING-KEBAB-CASE") => rust_name.replace('_', "-").to_ascii_uppercase(),
        Some("UPPERCASE") => rust_name.to_ascii_uppercase(),
        Some("lowercase") => rust_name.to_ascii_lowercase(),
        Some("snake_case") | None => rust_name.to_owned(),
        Some(_) => rust_name.to_owned(),
    }
}

fn camel_case(name: &str, upper_first: bool) -> String {
    let mut parts = name.split('_').filter(|part| !part.is_empty());
    let Some(first) = parts.next() else {
        return String::new();
    };
    let mut rendered = if upper_first {
        capitalize(first)
    } else {
        first.to_ascii_lowercase()
    };
    for part in parts {
        rendered.push_str(&capitalize(part));
    }
    rendered
}

fn capitalize(part: &str) -> String {
    let mut chars = part.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    first.to_uppercase().chain(chars).collect()
}

fn clap_argument(field: &syn::Field, rust_name: &str) -> Option<String> {
    for attr in &field.attrs {
        if !(attr.path().is_ident("arg") || attr.path().is_ident("clap")) {
            continue;
        }
        let rendered = attr.meta.to_token_stream().to_string();
        if let Some(explicit) = attribute_value(&rendered, "long") {
            return Some(format!("--{}", explicit.trim_matches('"')));
        }
        if attribute_option(&rendered, "long") {
            return Some(format!(
                "--{}",
                rust_name
                    .strip_prefix("r#")
                    .unwrap_or(rust_name)
                    .replace('_', "-")
            ));
        }
    }
    None
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg") && attr.meta.to_token_stream().to_string().contains("test")
    })
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rust_files(&path, out)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn is_test_path(relative: &str) -> bool {
    relative.contains("/tests/")
        || relative.ends_with("_tests.rs")
        || relative.ends_with("/tests.rs")
        || relative.contains("/benches/")
}

fn crate_of(relative: &str) -> Option<&str> {
    relative
        .strip_prefix("crates/")
        .and_then(|rest| rest.split('/').next())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_serde_clap_and_policy_defaults_but_excludes_tests() {
        let source = r#"
            struct RuntimePolicy {
                #[serde(default = "default_timeout")]
                timeout: u64,
                #[arg(default_value_t = 4)]
                workers: usize,
            }
            fn build_policy() { let _ = RuntimePolicy::default(); }
            #[cfg(test)]
            mod tests {
                struct Hidden { #[serde(default)] field: bool }
                fn policy_test() { let _ = RuntimePolicy::default(); }
            }
        "#;
        let rows = discover_source("demo", "crates/demo/src/lib.rs", source).unwrap();
        assert!(
            rows.iter()
                .any(|row| matches!(row.candidate_kind, CensusCandidateKind::SerdeDefault))
        );
        assert!(
            rows.iter()
                .any(|row| matches!(row.candidate_kind, CensusCandidateKind::ClapDefault))
        );
        assert!(rows.iter().any(|row| matches!(
            row.candidate_kind,
            CensusCandidateKind::PolicyDefaultConstructor
        )));
        assert_eq!(
            rows.iter()
                .filter(|row| row.owner.symbol.contains("Hidden"))
                .count(),
            0
        );
    }

    #[test]
    fn honesty_gate_rejects_settable_without_evidence() {
        let mut rows = discover_source(
            "demo",
            "crates/demo/src/lib.rs",
            "struct Config { #[serde(default)] value: usize }",
        )
        .unwrap();
        rows[0].use_sites.clear();
        assert!(
            validate(&rows)
                .unwrap_err()
                .to_string()
                .contains("without production use-site")
        );
        rows[0].use_sites.push(UseSiteRow {
            path: "crates/demo/src/lib.rs".to_owned(),
            line: 1,
            evidence: "serde".to_owned(),
        });
        rows[0].behavior_oracle = None;
        assert!(
            validate(&rows)
                .unwrap_err()
                .to_string()
                .contains("without a behavior oracle")
        );
    }

    #[test]
    fn addressability_distinguishes_profile_config_and_injection() {
        let source = r#"
            #[serde(rename_all = "camelCase")]
            struct RuntimePolicy {
                #[serde(default)]
                feature_enabled: bool,
                #[arg(long, default_value_t = 4)]
                workers: usize,
            }
            fn build_policy() { let _ = RuntimePolicy::default(); }
        "#;
        let rows = discover_source("demo", "crates/demo/src/lib.rs", source).unwrap();
        let counts = address_kind_counts(&rows);
        assert_eq!(counts[&ExternalAddressKind::DirectConfig], 2);
        assert_eq!(counts[&ExternalAddressKind::CallerInput], 1);
        assert_eq!(counts[&ExternalAddressKind::UnifiedProfile], 0);
        let clap = rows
            .iter()
            .find(|row| matches!(row.candidate_kind, CensusCandidateKind::ClapDefault))
            .unwrap()
            .external_address
            .as_ref()
            .unwrap();
        assert_eq!(clap.selector_kind, AddressSelectorKind::Argument);
        assert_eq!(clap.selector, "--workers");
        let serde = rows
            .iter()
            .find(|row| matches!(row.candidate_kind, CensusCandidateKind::SerdeDefault))
            .unwrap()
            .external_address
            .as_ref()
            .unwrap();
        assert_eq!(serde.selector, "RuntimePolicy.featureEnabled");
    }

    #[test]
    fn invariant_kind_vocabulary_is_closed_and_specific() {
        let kinds = [
            InvariantKind::Identity,
            InvariantKind::WireCompatibility,
            InvariantKind::Authority,
            InvariantKind::Security,
            InvariantKind::Durability,
            InvariantKind::Replay,
            InvariantKind::HardBudget,
            InvariantKind::EffectLedger,
            InvariantKind::NonValueStructural,
        ];
        let json = serde_json::to_string(&kinds).unwrap();
        assert!(!json.contains("other"));
        assert!(!json.contains("generic"));
    }

    #[test]
    fn quality_affecting_invariant_requires_an_explicit_override() {
        let mut row = discover_source(
            "demo",
            "crates/demo/src/lib.rs",
            "struct Policy { #[serde(default)] threshold: usize }",
        )
        .unwrap()
        .remove(0);
        row.disposition = Disposition::InvariantReadOnly;
        row.external_address = None;
        row.invariant_kind = Some(InvariantKind::NonValueStructural);
        row.id = "tools.web.block_tags".to_owned();
        row.review_evidence = Some(format!(
            "closed Tier-2 disposition rule: `{}` at {} — mechanical test; observed at {}:1; mechanical source evidence only, not a claim of human review",
            row.owner.symbol, row.owner.path, row.owner.path
        ));
        row.owning_human_review = Some(OwningHumanReviewStatus::RequiredNotSourceProven);
        row.applied = false;
        row.behavior_oracle = None;
        assert!(
            validate(std::slice::from_ref(&row))
                .unwrap_err()
                .to_string()
                .contains("have no explicit override")
        );
        row.explicit_invariant_override = true;
        validate(std::slice::from_ref(&row)).unwrap();
    }

    #[test]
    fn invariant_cannot_retain_a_writable_address_or_claim_human_approval() {
        let mut row = discover_source(
            "demo",
            "crates/demo/src/lib.rs",
            "struct Policy { #[serde(default)] threshold: usize }",
        )
        .unwrap()
        .remove(0);
        row.disposition = Disposition::InvariantReadOnly;
        row.id = "tools.web.default_search_result_count".to_owned();
        row.invariant_kind = Some(InvariantKind::NonValueStructural);
        row.review_evidence = Some(format!(
            "explicit census disposition override: `{}` at {} — mechanical test; observed at {}:1; mechanical source evidence only, not a claim of human review",
            row.owner.symbol, row.owner.path, row.owner.path
        ));
        row.owning_human_review = Some(OwningHumanReviewStatus::RequiredNotSourceProven);
        row.explicit_invariant_override = true;
        row.applied = false;
        row.behavior_oracle = None;
        assert!(
            validate(std::slice::from_ref(&row))
                .unwrap_err()
                .to_string()
                .contains("carries a settable address")
        );
        row.external_address = None;
        row.owning_human_review = None;
        assert!(
            validate(std::slice::from_ref(&row))
                .unwrap_err()
                .to_string()
                .contains("owning-human review is required")
        );
    }

    #[test]
    fn every_discovered_runtime_row_has_one_concrete_external_address() {
        let rows = discover_source(
            "demo",
            "crates/demo/src/lib.rs",
            r#"
                struct RuntimePolicy {
                    #[serde(default)] enabled: bool,
                    #[arg(long, default_value_t = 4)] workers: usize,
                }
                fn build_policy() { let _ = RuntimePolicy::default(); }
            "#,
        )
        .unwrap();
        validate(&rows).unwrap();
        assert!(rows.iter().all(|row| {
            matches!(row.disposition, Disposition::RuntimeSettable)
                && row.external_address.as_ref().is_some_and(|address| {
                    !address.selector.is_empty() && !address.owner.is_empty()
                })
        }));
        assert_eq!(
            address_kind_counts(&rows).values().sum::<usize>(),
            rows.len()
        );
    }

    #[test]
    fn duplicate_external_addresses_require_owner_qualification() {
        let mut rows = discover_source(
            "demo",
            "crates/demo/src/lib.rs",
            "struct Config { #[serde(default)] value: usize }",
        )
        .unwrap();
        let mut duplicate = rows[0].clone();
        duplicate.id.push_str(".duplicate");
        rows.push(duplicate);
        assert!(
            validate(&rows)
                .unwrap_err()
                .to_string()
                .contains("collides with another external address")
        );
        rows[1].external_address.as_mut().unwrap().owner = "serde::OtherConfig".to_owned();
        validate(&rows).unwrap();
    }
}
