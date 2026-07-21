use super::super::manifest::{Contract, read_bounded};
use super::cli_diff::{golden_nested_shapes, validate_diff_bindings};
use super::cli_effort::cli_effort_output_shapes;
use super::cli_parse::cli_nested_literal_fields;
use super::cli_writer::validate_cli_writer_dataflow;
use super::parse::{decimal_constant, named_struct_fields, serde_snake_case, tagged_enum_fields};
use super::{BLOCK_SOURCE, MAX_SOURCE_BYTES};
use crate::rust_source::{
    SerdeAuthority, enum_variant_names, require_serde_authority, require_serde_container_flag,
};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const PROVIDER_SOURCE: &str = "crates/provider/src/lib.rs";
const EFFORT_APPLICATION_SIGNATURE: &str = "pub enum EffortApplication {";
const EVAL_CONTRACT_SOURCE: &str = "crates/eval/src/contract.rs";
const CLI_EFFORT_APPLICATION_SIGNATURE: &str = "enum CliEffortApplication {";
const KERNEL_SOURCE: &str = "crates/kernel/src/lib.rs";

fn decimal_slice_constant(source: &[u8], name: &str, ty: &str) -> Result<Vec<u32>> {
    crate::rust_source::public_decimal_slice_const(source, name, ty)
}

pub(super) fn require_strict_deserialize(source: &str, signature: &str) -> Result<()> {
    require_serde_authority(source, signature, SerdeAuthority::Deserialize)?;
    require_serde_container_flag(source, signature, "deny_unknown_fields")?;
    Ok(())
}

fn cli_manifest_fixture_versions(
    contract: &Contract,
    current_version: u32,
    current_golden_path: &str,
) -> Result<BTreeSet<u32>> {
    let mut versions = BTreeSet::new();
    let mut stream_surfaces = 0usize;
    let mut current_all_goldens = BTreeSet::new();
    for surface in &contract.surfaces {
        let id = surface.id.as_str();
        if id != "cli.machine-result" && !id.starts_with("cli.machine-stream.") {
            continue;
        }
        let mut declares_current_golden = false;
        for fixture in &surface.fixtures {
            versions.insert(fixture.schema_version);
            if fixture.path == current_golden_path {
                declares_current_golden = true;
            }
            if fixture.schema_version == current_version
                && fixture.path.contains("/machine_stream_all_v")
                && fixture.path.ends_with(".jsonl")
            {
                current_all_goldens.insert(fixture.path.clone());
            }
        }
        if id.starts_with("cli.machine-stream.") {
            stream_surfaces = stream_surfaces.saturating_add(1);
            if !declares_current_golden {
                bail!("current CLI stream surface '{id}' does not declare '{current_golden_path}'");
            }
        }
    }
    if stream_surfaces == 0
        || current_all_goldens != BTreeSet::from([current_golden_path.to_owned()])
    {
        bail!(
            "CLI manifest must declare one derived current all-events golden '{current_golden_path}'"
        );
    }
    Ok(versions)
}

fn cli_manifest_fixture_type_versions(contract: &Contract) -> Result<BTreeSet<(String, u32)>> {
    let mut pairs = BTreeSet::new();
    let mut surfaces = 0usize;
    for surface in &contract.surfaces {
        if surface.id != "cli.machine-result" && !surface.id.starts_with("cli.machine-stream.") {
            continue;
        }
        surfaces = surfaces.saturating_add(1);
        let selector = surface
            .selector
            .as_ref()
            .with_context(|| format!("CLI machine surface '{}' lacks a selector", surface.id))?;
        if selector.field != "type" || surface.fixtures.is_empty() {
            bail!(
                "CLI machine surface '{}' lacks exact type fixtures",
                surface.id
            );
        }
        for fixture in &surface.fixtures {
            pairs.insert((selector.value.clone(), fixture.schema_version));
        }
    }
    if surfaces == 0 || pairs.is_empty() {
        bail!("compatibility manifest has no CLI machine type/version fixture matrix");
    }
    Ok(pairs)
}

pub(super) fn validate_cli_source_bindings(
    root: &Path,
    contract: &Contract,
    cli_source: &[u8],
    producer_shapes: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    validate_cli_writer_dataflow(root, cli_source)?;
    let cli_version = decimal_constant(cli_source, "SCHEMA_VERSION", "u32")?;
    let current_golden_path =
        format!("crates/cli/tests/golden/machine_stream_all_v{cli_version}.jsonl");
    let manifest_versions =
        cli_manifest_fixture_versions(contract, cli_version, &current_golden_path)?;

    let eval_source = read_bounded(root, EVAL_CONTRACT_SOURCE, MAX_SOURCE_BYTES)?;
    let eval_text = std::str::from_utf8(&eval_source)
        .with_context(|| format!("schema source '{EVAL_CONTRACT_SOURCE}' is not UTF-8"))?;
    let eval_current = decimal_constant(&eval_source, "CORE_CLI_SCHEMA_VERSION", "u32")?;
    if eval_current != cli_version {
        bail!(
            "eval CORE_CLI_SCHEMA_VERSION {eval_current} differs from CLI SCHEMA_VERSION {cli_version}"
        );
    }
    let supported =
        decimal_slice_constant(&eval_source, "SUPPORTED_CORE_CLI_SCHEMA_VERSIONS", "u32")?;
    let supported_set = supported.iter().copied().collect::<BTreeSet<_>>();
    if supported_set != manifest_versions || supported.last() != Some(&cli_version) {
        bail!(
            "eval supported CLI versions {supported:?} differ from manifest fixture versions {manifest_versions:?} or do not end at current {cli_version}"
        );
    }
    let supported_type_versions = crate::rust_source::public_string_u32_tuple_slice_const(
        &eval_source,
        "SUPPORTED_CORE_CLI_TYPE_VERSIONS",
    )?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let manifest_type_versions = cli_manifest_fixture_type_versions(contract)?;
    if supported_type_versions != manifest_type_versions {
        bail!(
            "eval supported CLI type/version matrix {supported_type_versions:?} differs from manifest fixture matrix {manifest_type_versions:?}"
        );
    }

    require_strict_deserialize(eval_text, "enum CliStreamEvent {")?;
    let eval_stream = tagged_enum_fields(
        &eval_source,
        "enum CliStreamEvent {",
        "type",
        0,
        &BTreeMap::new(),
    )?;
    let mut producer_stream = producer_shapes.clone();
    let producer_result = producer_stream
        .remove("result")
        .context("CLI producer shapes lack the final result object")?;
    if producer_stream != eval_stream {
        bail!(
            "CLI stream producer shapes differ from strict eval consumer: producer {producer_stream:?}, eval {eval_stream:?}"
        );
    }
    require_strict_deserialize(eval_text, "pub struct CliFinalResult {")?;
    let eval_result = named_struct_fields(eval_text, "pub struct CliFinalResult {")?;
    if producer_result != eval_result {
        bail!(
            "CLI final-result producer shape differs from strict eval consumer: producer {producer_result:?}, eval {eval_result:?}"
        );
    }

    let provider_source = read_bounded(root, PROVIDER_SOURCE, MAX_SOURCE_BYTES)?;
    let provider_source_text = std::str::from_utf8(&provider_source)
        .with_context(|| format!("schema source '{PROVIDER_SOURCE}' is not UTF-8"))?;
    let provider = enum_variant_names(provider_source_text, EFFORT_APPLICATION_SIGNATURE)?
        .into_iter()
        .map(|variant| serde_snake_case(&variant))
        .collect::<BTreeSet<_>>();

    let output_effort = cli_effort_output_shapes(cli_source)?;
    require_strict_deserialize(eval_text, CLI_EFFORT_APPLICATION_SIGNATURE)?;
    let eval_effort = tagged_enum_fields(
        &eval_source,
        CLI_EFFORT_APPLICATION_SIGNATURE,
        "enforcement",
        0,
        &BTreeMap::new(),
    )?;

    let golden_source = read_bounded(root, &current_golden_path, MAX_SOURCE_BYTES)?;
    validate_diff_bindings(root, eval_text, &golden_source)?;
    let golden = golden_nested_shapes(&golden_source)?;
    let output_tags = output_effort.keys().cloned().collect::<BTreeSet<_>>();
    if provider != output_tags || output_effort != eval_effort || output_effort != golden.effort {
        bail!(
            "EffortApplication bindings differ: provider tags {provider:?}, output {output_effort:?}, eval {eval_effort:?}, current golden {:?}",
            golden.effort
        );
    }

    let protocol_usage_source = read_bounded(root, BLOCK_SOURCE, MAX_SOURCE_BYTES)?;
    let protocol_usage_text = std::str::from_utf8(&protocol_usage_source)
        .with_context(|| format!("schema source '{BLOCK_SOURCE}' is not UTF-8"))?;
    require_serde_authority(
        protocol_usage_text,
        "pub struct Usage {",
        SerdeAuthority::Both,
    )?;
    let protocol_usage = named_struct_fields(protocol_usage_text, "pub struct Usage {")?;
    require_strict_deserialize(eval_text, "struct CliUsage {")?;
    let eval_usage = named_struct_fields(eval_text, "struct CliUsage {")?;
    if protocol_usage != eval_usage || protocol_usage != golden.usage {
        bail!(
            "CLI turn_end usage shapes differ: protocol {protocol_usage:?}, eval {eval_usage:?}, current golden {:?}",
            golden.usage
        );
    }

    let producer_context = cli_nested_literal_fields(cli_source, "turn_end", "context")?;
    require_strict_deserialize(eval_text, "struct CliContextEstimate {")?;
    let eval_context = named_struct_fields(eval_text, "struct CliContextEstimate {")?;
    if producer_context != eval_context || producer_context != golden.context {
        bail!(
            "CLI turn_end context shapes differ: producer {producer_context:?}, eval {eval_context:?}, current golden {:?}",
            golden.context
        );
    }

    let producer_budget = cli_nested_literal_fields(cli_source, "workflow_plan", "budget")?;
    require_strict_deserialize(eval_text, "struct CliWorkflowBudget {")?;
    let eval_budget = named_struct_fields(eval_text, "struct CliWorkflowBudget {")?;
    if producer_budget != eval_budget || producer_budget != golden.budget {
        bail!(
            "CLI workflow_plan budget shapes differ: producer {producer_budget:?}, eval {eval_budget:?}, current golden {:?}",
            golden.budget
        );
    }

    let kernel_source = read_bounded(root, KERNEL_SOURCE, MAX_SOURCE_BYTES)?;
    let kernel_text = std::str::from_utf8(&kernel_source)
        .with_context(|| format!("schema source '{KERNEL_SOURCE}' is not UTF-8"))?;
    require_serde_authority(
        kernel_text,
        "pub struct WorkflowTaskUi {",
        SerdeAuthority::Serialize,
    )?;
    let producer_task = named_struct_fields(kernel_text, "pub struct WorkflowTaskUi {")?;
    require_strict_deserialize(eval_text, "struct CliWorkflowTask {")?;
    let eval_task = named_struct_fields(eval_text, "struct CliWorkflowTask {")?;
    if producer_task != eval_task || producer_task != golden.task {
        bail!(
            "CLI workflow_plan task shapes differ: producer {producer_task:?}, eval {eval_task:?}, current golden {:?}",
            golden.task
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::super::manifest::{load_candidate, read_bounded};
    use super::super::CLI_MACHINE_OUTPUT_SOURCE;
    use super::super::cli_effort::{cli_effort_enforcements, cli_effort_output_shapes};
    use super::super::cli_parse::cli_machine_record_shapes;
    use super::*;
    use std::collections::BTreeSet;
    use std::path::Path;

    #[test]
    fn d13_14_effort_application_is_bound_across_all_four_sources() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        let source = read_bounded(root, CLI_MACHINE_OUTPUT_SOURCE, MAX_SOURCE_BYTES).unwrap();
        let producer_shapes = cli_machine_record_shapes(&source).unwrap();
        let contract = load_candidate(root).unwrap();
        validate_cli_source_bindings(root, &contract, &source, &producer_shapes).unwrap();
        assert_eq!(
            cli_effort_enforcements(&source).unwrap(),
            BTreeSet::from([
                "budget_based".to_owned(),
                "exact".to_owned(),
                "mapped".to_owned(),
                "toggle_only".to_owned(),
                "unsupported".to_owned(),
            ])
        );
        assert_eq!(
            cli_effort_output_shapes(&source).unwrap()["exact"],
            BTreeSet::from([
                "capability_proven_by_catalog".to_owned(),
                "enforcement".to_owned(),
                "meaning".to_owned(),
                "requested".to_owned(),
                "sent".to_owned(),
            ])
        );
        assert!(decimal_slice_constant(b"pub const V: &[u32] = &[4, 3];", "V", "u32").is_err());
        assert!(decimal_slice_constant(b"pub const V: &[u32] = &[3, 3];", "V", "u32").is_err());
    }
}
