//! Small source-shape bridge for schemas whose serialized outer fields are Rust-private.
//!
//! Protocol payload changes are already covered by the global protocol-version gate. These outer
//! structs are checked directly so a field cannot be added to code while the compatibility
//! manifest and fixtures remain unchanged.

#[path = "schema_compat_rust_authority.rs"]
mod authority;
#[path = "schema_compat_rust_cli.rs"]
mod cli;
#[path = "schema_compat_rust_cli_diff.rs"]
mod cli_diff;
#[path = "schema_compat_rust_cli_effort.rs"]
mod cli_effort;
#[path = "schema_compat_rust_cli_exact.rs"]
mod cli_exact;
#[path = "schema_compat_rust_cli_main.rs"]
mod cli_main;
#[path = "schema_compat_rust_cli_parse.rs"]
mod cli_parse;
#[path = "schema_compat_rust_cli_parse_scan.rs"]
mod cli_parse_scan;
#[cfg(test)]
#[path = "schema_compat_rust_cli_parse_tests.rs"]
mod cli_parse_tests;
#[path = "schema_compat_rust_cli_parse_tokens.rs"]
mod cli_parse_tokens;
#[path = "schema_compat_rust_cli_writer.rs"]
mod cli_writer;
#[path = "schema_compat_rust_cli_writer_ast.rs"]
mod cli_writer_ast;
#[path = "schema_compat_rust_json.rs"]
mod json;
#[path = "schema_compat_rust_kernel.rs"]
mod kernel;
#[path = "schema_compat_rust_parse.rs"]
mod parse;
#[path = "schema_compat_rust_record.rs"]
mod record;
#[path = "schema_compat_rust_record_resolve.rs"]
mod record_resolve;
#[path = "schema_compat_rust_record_types.rs"]
mod record_types;
#[path = "schema_compat_rust_runtime.rs"]
mod runtime;
#[path = "schema_compat_rust_semantics.rs"]
mod semantics;
#[path = "schema_compat_rust_surfaces.rs"]
mod surfaces;

use self::parse::{named_struct_fields, tagged_enum_fields};
use self::record::{validate_named_record_inventory, validate_record_tagged_family};
use super::manifest::{Contract, read_bounded};
use crate::rust_source::{SerdeAuthority, require_serde_authority};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const CLI_MACHINE_OUTPUT_SOURCE: &str = "crates/cli/src/output.rs";
const OP_SOURCE: &str = "crates/protocol/src/lib.rs";
const OP_SIGNATURE: &str = "pub enum Op {";
const OP_SURFACE_PREFIX: &str = "protocol.op.";
const EVENT_SOURCE: &str = "crates/protocol/src/event.rs";
const EVENT_KIND_SIGNATURE: &str = "pub enum EventKind {";
const EVENT_KIND_SURFACE_PREFIX: &str = "record.event-kind.";
const BLOCK_SOURCE: &str = "crates/protocol/src/message.rs";
const BLOCK_SIGNATURE: &str = "pub enum Block {";
const BLOCK_SURFACE_PREFIX: &str = "record.block.";
const WORKFLOW_EVENT_SIGNATURE: &str = "pub enum WorkflowEvent {";
const WORKFLOW_EVENT_SURFACE_PREFIX: &str = "record.workflow-event.";
const COST_ATTRIBUTION_SOURCE: &str = "crates/protocol/src/pricing.rs";
const COST_ATTRIBUTION_SIGNATURE: &str = "pub enum CostAttribution {";
const COST_ATTRIBUTION_SURFACE_PREFIX: &str = "record.cost-attribution.";
const NAMED_RECORD_SURFACE_PREFIX: &str = "record.named.";
const KERNEL_DIAGNOSTIC_SOURCE: &str = "crates/kernel/src/diagnostics.rs";

const NAMED_RECORD_SHAPES: &[(&str, &str, &str)] = &[
    (
        "record.named.message",
        "crates/protocol/src/message.rs",
        "pub struct Message {",
    ),
    (
        "record.named.provider-state",
        "crates/protocol/src/message.rs",
        "pub struct ProviderState {",
    ),
    (
        "record.named.tool-use",
        "crates/protocol/src/tool.rs",
        "pub struct ToolUse {",
    ),
    (
        "record.named.tool-result",
        "crates/protocol/src/tool.rs",
        "pub struct ToolResult {",
    ),
    (
        "record.named.usage",
        "crates/protocol/src/message.rs",
        "pub struct Usage {",
    ),
    (
        "record.named.durable-environment-context",
        EVENT_SOURCE,
        "pub struct DurableEnvironmentContext {",
    ),
    (
        "record.named.durable-instruction-context",
        EVENT_SOURCE,
        "pub struct DurableInstructionContext {",
    ),
    (
        "record.named.workflow-task-evidence",
        EVENT_SOURCE,
        "pub struct WorkflowTaskEvidence {",
    ),
    (
        "record.named.workflow-metrics",
        EVENT_SOURCE,
        "pub struct WorkflowMetrics {",
    ),
    (
        "record.named.workflow-cost-evidence",
        EVENT_SOURCE,
        "pub struct WorkflowCostEvidence {",
    ),
    (
        "record.named.budget",
        "crates/protocol/src/lib.rs",
        "pub struct Budget {",
    ),
    (
        "record.named.permission-rules",
        "crates/protocol/src/permission.rs",
        "pub struct PermissionRules {",
    ),
    (
        "record.named.pricing-route",
        COST_ATTRIBUTION_SOURCE,
        "pub struct PricingRoute {",
    ),
    (
        "record.named.token-rate-card",
        COST_ATTRIBUTION_SOURCE,
        "pub struct TokenRateCard {",
    ),
    (
        "record.named.rate-card",
        COST_ATTRIBUTION_SOURCE,
        "pub struct RateCard {",
    ),
    (
        "record.named.signed-rate-card",
        COST_ATTRIBUTION_SOURCE,
        "pub struct SignedRateCard {",
    ),
    (
        "record.named.cost-projection-identity",
        COST_ATTRIBUTION_SOURCE,
        "pub struct CostProjectionIdentity {",
    ),
    (
        "record.named.cost-projection",
        COST_ATTRIBUTION_SOURCE,
        "pub struct CostProjection {",
    ),
];

pub(super) fn compare(
    root: &Path,
    base: &str,
    previous: &Contract,
    candidate: &Contract,
) -> Result<()> {
    semantics::compare(root, base, previous, candidate)
}

pub(super) fn validate(root: &Path, contract: &Contract) -> Result<()> {
    // Focused contract-unit fixtures intentionally contain no Rust workspace. Real repository
    // validation always executes from the workspace that built xtask and therefore has Cargo.toml.
    if root.join("Cargo.toml").is_file() {
        authority::validate(root)?;
        runtime::validate(root)?;
    }
    validate_protocol_op_shapes(root, contract)?;
    validate_record_event_shapes(root, contract)?;
    validate_record_payload_shapes(root, contract)?;
    validate_named_record_inventory(root, contract)?;
    kernel::validate(root, contract)?;
    surfaces::validate(root, contract)
}

fn validate_protocol_op_shapes(root: &Path, contract: &Contract) -> Result<()> {
    let declared_surfaces = contract
        .surfaces
        .iter()
        .filter(|surface| surface.id.starts_with(OP_SURFACE_PREFIX))
        .collect::<Vec<_>>();
    if declared_surfaces.is_empty() && !root.join(OP_SOURCE).is_file() {
        return Ok(());
    }
    if !contract
        .surfaces
        .iter()
        .any(|surface| surface.id == "protocol.sq-envelope")
    {
        bail!("protocol Op surfaces require protocol.sq-envelope");
    }

    let source = read_bounded(root, OP_SOURCE, MAX_SOURCE_BYTES)?;
    let source_text = std::str::from_utf8(&source)
        .with_context(|| format!("schema source `{OP_SOURCE}` is not UTF-8"))?;
    require_serde_authority(source_text, OP_SIGNATURE, SerdeAuthority::Both)?;
    let emitted = tagged_enum_fields(&source, OP_SIGNATURE, "op", 1, &BTreeMap::new())?;
    let mut declared = BTreeMap::new();
    for surface in declared_surfaces {
        let id_tag = surface
            .id
            .strip_prefix(OP_SURFACE_PREFIX)
            .expect("filtered Op surface has its prefix");
        let selector = surface
            .selector
            .as_ref()
            .with_context(|| format!("protocol Op surface `{}` lacks a selector", surface.id))?;
        let expected_id_tag = selector.value.replace('_', "-");
        if selector.field != "op" || id_tag != expected_id_tag {
            bail!(
                "protocol Op surface `{}` must use its `op={}` wire selector",
                surface.id,
                selector.value
            );
        }
        let fields = surface
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect::<BTreeSet<_>>();
        if declared.insert(selector.value.clone(), fields).is_some() {
            bail!("protocol Op compatibility surfaces repeat a wire tag");
        }
    }
    if emitted != declared {
        bail!(
            "protocol Op Rust shapes differ from compatibility surfaces: emitted {emitted:?}, declared {declared:?}"
        );
    }
    Ok(())
}

fn validate_record_payload_shapes(root: &Path, contract: &Contract) -> Result<()> {
    let has_payload_surfaces = contract.surfaces.iter().any(|surface| {
        surface.id.starts_with(BLOCK_SURFACE_PREFIX)
            || surface.id.starts_with(WORKFLOW_EVENT_SURFACE_PREFIX)
            || surface.id.starts_with(COST_ATTRIBUTION_SURFACE_PREFIX)
    });
    if !has_payload_surfaces && !root.join(BLOCK_SOURCE).is_file() {
        return Ok(());
    }
    if !contract
        .surfaces
        .iter()
        .any(|surface| surface.id == "record.event-envelope")
    {
        bail!("record payload surfaces require record.event-envelope");
    }

    let block_source = read_bounded(root, BLOCK_SOURCE, MAX_SOURCE_BYTES)?;
    let block_text = std::str::from_utf8(&block_source)
        .with_context(|| format!("schema source `{BLOCK_SOURCE}` is not UTF-8"))?;
    let tool_source_path = "crates/protocol/src/tool.rs";
    let tool_source = read_bounded(root, tool_source_path, MAX_SOURCE_BYTES)?;
    let tool_text = std::str::from_utf8(&tool_source)
        .with_context(|| format!("schema source `{tool_source_path}` is not UTF-8"))?;
    for (source, signature) in [
        (block_text, "pub struct ProviderState {"),
        (tool_text, "pub struct ToolUse {"),
        (tool_text, "pub struct ToolResult {"),
    ] {
        require_serde_authority(source, signature, SerdeAuthority::Both)?;
    }
    require_serde_authority(block_text, BLOCK_SIGNATURE, SerdeAuthority::Both)?;
    let block_newtypes = BTreeMap::from([
        (
            "ProviderState".to_owned(),
            named_struct_fields(block_text, "pub struct ProviderState {")?,
        ),
        (
            "ToolUse".to_owned(),
            named_struct_fields(tool_text, "pub struct ToolUse {")?,
        ),
        (
            "ToolResult".to_owned(),
            named_struct_fields(tool_text, "pub struct ToolResult {")?,
        ),
    ]);
    let blocks = tagged_enum_fields(&block_source, BLOCK_SIGNATURE, "type", 0, &block_newtypes)?;
    validate_record_tagged_family(contract, BLOCK_SURFACE_PREFIX, "type", "Block", blocks)?;

    let event_source = read_bounded(root, EVENT_SOURCE, MAX_SOURCE_BYTES)?;
    let event_text = std::str::from_utf8(&event_source)
        .with_context(|| format!("schema source `{EVENT_SOURCE}` is not UTF-8"))?;
    require_serde_authority(event_text, WORKFLOW_EVENT_SIGNATURE, SerdeAuthority::Both)?;
    let workflow_events = tagged_enum_fields(
        &event_source,
        WORKFLOW_EVENT_SIGNATURE,
        "event",
        0,
        &BTreeMap::new(),
    )?;
    validate_record_tagged_family(
        contract,
        WORKFLOW_EVENT_SURFACE_PREFIX,
        "event",
        "WorkflowEvent",
        workflow_events,
    )?;

    let pricing_source = read_bounded(root, COST_ATTRIBUTION_SOURCE, MAX_SOURCE_BYTES)?;
    let pricing_text = std::str::from_utf8(&pricing_source)
        .with_context(|| format!("schema source `{COST_ATTRIBUTION_SOURCE}` is not UTF-8"))?;
    require_serde_authority(
        pricing_text,
        COST_ATTRIBUTION_SIGNATURE,
        SerdeAuthority::Both,
    )?;
    let cost_attributions = tagged_enum_fields(
        &pricing_source,
        COST_ATTRIBUTION_SIGNATURE,
        "kind",
        0,
        &BTreeMap::new(),
    )?;
    validate_record_tagged_family(
        contract,
        COST_ATTRIBUTION_SURFACE_PREFIX,
        "kind",
        "CostAttribution",
        cost_attributions,
    )
}

fn validate_record_event_shapes(root: &Path, contract: &Contract) -> Result<()> {
    let declared_surfaces = contract
        .surfaces
        .iter()
        .filter(|surface| surface.id.starts_with(EVENT_KIND_SURFACE_PREFIX))
        .collect::<Vec<_>>();
    if declared_surfaces.is_empty() && !root.join(EVENT_SOURCE).is_file() {
        return Ok(());
    }
    if !contract
        .surfaces
        .iter()
        .any(|surface| surface.id == "record.event-envelope")
    {
        bail!("record EventKind surfaces require record.event-envelope");
    }

    let source = read_bounded(root, EVENT_SOURCE, MAX_SOURCE_BYTES)?;
    let source_text = std::str::from_utf8(&source)
        .with_context(|| format!("schema source `{EVENT_SOURCE}` is not UTF-8"))?;
    require_serde_authority(source_text, EVENT_KIND_SIGNATURE, SerdeAuthority::Both)?;
    let emitted = tagged_enum_fields(&source, EVENT_KIND_SIGNATURE, "kind", 1, &BTreeMap::new())?;
    let mut declared = BTreeMap::new();
    for surface in declared_surfaces {
        let tag = surface
            .id
            .strip_prefix(EVENT_KIND_SURFACE_PREFIX)
            .expect("filtered EventKind surface has its prefix");
        let selector = surface.selector.as_ref().with_context(|| {
            format!(
                "record event-kind surface `{}` lacks a selector",
                surface.id
            )
        })?;
        if selector.field != "kind" || selector.value != tag {
            bail!(
                "record event-kind surface `{}` must select `kind={tag}`",
                surface.id
            );
        }
        let fields = surface
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect::<BTreeSet<_>>();
        if declared.insert(tag.to_owned(), fields).is_some() {
            bail!("record EventKind compatibility surfaces repeat a wire tag");
        }
    }
    if emitted != declared {
        bail!(
            "durable EventKind Rust shapes differ from compatibility surfaces: emitted {emitted:?}, declared {declared:?}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d13_14_contract_versions_must_track_the_live_producer_versions() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        let mut contract = super::super::manifest::load_candidate(root).unwrap();
        let sq = contract
            .surfaces
            .iter_mut()
            .find(|surface| surface.id == "protocol.sq-envelope")
            .unwrap();
        sq.current_version = sq.current_version.saturating_add(1);
        assert!(validate(root, &contract).is_err());

        let mut contract = super::super::manifest::load_candidate(root).unwrap();
        let op = contract
            .surfaces
            .iter_mut()
            .find(|surface| surface.id.starts_with(OP_SURFACE_PREFIX))
            .unwrap();
        op.current_version = op.current_version.saturating_add(1);
        assert!(validate(root, &contract).is_err());

        let mut contract = super::super::manifest::load_candidate(root).unwrap();
        let diagnostics = contract
            .surfaces
            .iter_mut()
            .find(|surface| surface.id == "kernel.diagnostic")
            .unwrap();
        diagnostics.current_version = diagnostics.current_version.saturating_add(1);
        assert!(validate(root, &contract).is_err());

        let mut contract = super::super::manifest::load_candidate(root).unwrap();
        let machine_result = contract
            .surfaces
            .iter_mut()
            .find(|surface| surface.id == "cli.machine-result")
            .unwrap();
        machine_result.current_version = machine_result.current_version.saturating_add(1);
        assert!(validate(root, &contract).is_err());

        let mut contract = super::super::manifest::load_candidate(root).unwrap();
        let stream = contract
            .surfaces
            .iter_mut()
            .find(|surface| surface.id.starts_with("cli.machine-stream."))
            .unwrap();
        stream.current_version = stream.current_version.saturating_add(1);
        assert!(validate(root, &contract).is_err());
    }
}
