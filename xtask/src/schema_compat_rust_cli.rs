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
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const PROVIDER_SOURCE: &str = "crates/provider/src/lib.rs";
const OBS_SOURCE: &str = "crates/obs/src/lib.rs";
const OBS_KERNEL_TAX_SIGNATURE: &str = "pub struct KernelTax {";
const EFFORT_APPLICATION_SIGNATURE: &str = "pub enum EffortApplication {";
const EVAL_CONTRACT_SOURCE: &str = "crates/eval/src/contract.rs";
const EVAL_KERNEL_TAX_SIGNATURE: &str = "pub struct CliKernelTax {";
const CLI_EFFORT_APPLICATION_SIGNATURE: &str = "enum CliEffortApplication {";
const RUNTIME_SOURCE: &str = "crates/cli/src/runtime.rs";

#[derive(Debug, PartialEq, Eq)]
struct KernelTaxRustShape {
    fields: BTreeMap<String, String>,
}

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
    const INPUT_ATTACHMENT_SURFACE: &str = "cli.machine-stream.input-attachment";
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
            if !declares_current_golden && id != INPUT_ATTACHMENT_SURFACE {
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

fn kernel_tax_rust_shape(
    source: &str,
    signature: &str,
    struct_name: &str,
    authority: SerdeAuthority,
) -> Result<KernelTaxRustShape> {
    require_serde_authority(source, signature, authority)?;
    require_serde_container_flag(source, signature, "deny_unknown_fields")?;
    let wire_fields = named_struct_fields(source, signature)?;
    let file =
        syn::parse_file(source).context("kernel-tax schema source does not parse as Rust")?;
    let mut structs = file.items.iter().filter_map(|item| match item {
        syn::Item::Struct(item) if item.ident == struct_name => Some(item),
        _ => None,
    });
    let item = structs
        .next()
        .with_context(|| format!("kernel-tax schema source lacks `{struct_name}`"))?;
    if structs.next().is_some() {
        bail!("kernel-tax schema source repeats `{struct_name}`");
    }

    let mut deny_unknown_fields = 0usize;
    for attribute in item
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("serde"))
    {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("deny_unknown_fields") && meta.input.is_empty() {
                deny_unknown_fields = deny_unknown_fields.saturating_add(1);
                Ok(())
            } else {
                Err(meta.error("kernel-tax container allows only `deny_unknown_fields`"))
            }
        })?;
    }
    if deny_unknown_fields != 1 {
        bail!("kernel-tax schema `{struct_name}` must have exactly one `deny_unknown_fields` flag");
    }

    let syn::Fields::Named(named) = &item.fields else {
        bail!("kernel-tax schema `{struct_name}` must remain a named struct");
    };
    let mut fields = BTreeMap::new();
    for field in &named.named {
        if !matches!(field.vis, syn::Visibility::Public(_)) {
            bail!("kernel-tax schema `{struct_name}` fields must remain public");
        }
        if field
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("serde"))
        {
            bail!("kernel-tax schema `{struct_name}` fields cannot transform serde semantics");
        }
        let name = field
            .ident
            .as_ref()
            .context("kernel-tax named struct contains an unnamed field")?
            .to_string();
        if fields
            .insert(name.clone(), field.ty.to_token_stream().to_string())
            .is_some()
        {
            bail!("kernel-tax schema `{struct_name}` repeats field `{name}`");
        }
    }
    if fields.keys().cloned().collect::<BTreeSet<_>>() != wire_fields {
        bail!("kernel-tax schema `{struct_name}` Rust and serde field names differ");
    }
    Ok(KernelTaxRustShape { fields })
}

fn validate_kernel_tax_bindings(
    obs_text: &str,
    eval_text: &str,
    golden_fields: Option<&BTreeSet<String>>,
) -> Result<()> {
    let producer = kernel_tax_rust_shape(
        obs_text,
        OBS_KERNEL_TAX_SIGNATURE,
        "KernelTax",
        SerdeAuthority::Both,
    )?;
    let consumer = kernel_tax_rust_shape(
        eval_text,
        EVAL_KERNEL_TAX_SIGNATURE,
        "CliKernelTax",
        SerdeAuthority::Deserialize,
    )?;
    if producer != consumer {
        bail!(
            "kernel-tax Rust fields/types differ between core_obs producer {:?} and strict eval consumer {:?}",
            producer.fields,
            consumer.fields
        );
    }
    for (field, ty) in &producer.fields {
        if ty != "u64" {
            bail!("kernel-tax producer/consumer field `{field}` must remain u64, found `{ty}`");
        }
    }
    if let Some(golden_fields) = golden_fields
        && producer.fields.keys().cloned().collect::<BTreeSet<_>>() != *golden_fields
    {
        bail!(
            "kernel-tax Rust fields differ from canonical current result fixtures: Rust {:?}, fixtures {golden_fields:?}",
            producer.fields.keys().collect::<BTreeSet<_>>()
        );
    }
    Ok(())
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
    let obs_source = read_bounded(root, OBS_SOURCE, MAX_SOURCE_BYTES)?;
    let obs_text = std::str::from_utf8(&obs_source)
        .with_context(|| format!("schema source '{OBS_SOURCE}' is not UTF-8"))?;
    let golden_kernel_tax = super::super::current_cli_result_kernel_tax_fields(root, contract)?;
    validate_kernel_tax_bindings(obs_text, eval_text, golden_kernel_tax.as_ref())?;

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

    let runtime_source = read_bounded(root, RUNTIME_SOURCE, MAX_SOURCE_BYTES)?;
    let runtime_text = std::str::from_utf8(&runtime_source)
        .with_context(|| format!("schema source '{RUNTIME_SOURCE}' is not UTF-8"))?;
    require_serde_authority(
        runtime_text,
        "pub struct WorkflowTaskUi {",
        SerdeAuthority::Serialize,
    )?;
    let producer_task = named_struct_fields(runtime_text, "pub struct WorkflowTaskUi {")?;
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
    fn current_cli_machine_result_manifest_field_rename_fails_canonical_source_bound_gate() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        let contract = load_candidate(root).unwrap();
        let current_results =
            super::super::super::current_cli_result_values(root, &contract).unwrap();
        let canonical_result = &current_results
            .first()
            .expect("canonical manifest has current result fixtures")
            .1;
        let snapshot = crate::schema_compat::validate_current(root).unwrap();
        snapshot.validate(canonical_result).unwrap();

        let mut open_kernel_tax = canonical_result.clone();
        open_kernel_tax["kernel_tax"]["unexpected"] = serde_json::Value::from(0);
        assert!(
            snapshot.validate(&open_kernel_tax).is_err(),
            "the canonical result validator must reject an open nested kernel_tax shape"
        );

        let mut renamed_contract = contract;
        let result = renamed_contract
            .surfaces
            .iter_mut()
            .find(|surface| surface.id == "cli.machine-result")
            .expect("canonical manifest declares cli.machine-result");
        let field = result
            .fields
            .iter_mut()
            .find(|field| field.name == "assistant_text")
            .expect("current result shape contains assistant_text");
        field.name = "assistant_message".into();

        let error = super::super::validate(root, &renamed_contract)
            .expect_err("renaming a canonical result field must fail the Rust/source-bound gate")
            .to_string();
        assert!(
            error.contains("CLI machine record shapes differ from the compatibility surfaces"),
            "unexpected schema-gate error: {error}"
        );
    }

    #[test]
    fn kernel_tax_producer_u64_to_i64_drift_fails_canonical_schema_gate() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        let contract = load_candidate(root).unwrap();
        let golden =
            super::super::super::current_cli_result_kernel_tax_fields(root, &contract).unwrap();
        let obs_source = read_bounded(root, OBS_SOURCE, MAX_SOURCE_BYTES).unwrap();
        let obs_text = std::str::from_utf8(&obs_source).unwrap();
        let eval_source = read_bounded(root, EVAL_CONTRACT_SOURCE, MAX_SOURCE_BYTES).unwrap();
        let eval_text = std::str::from_utf8(&eval_source).unwrap();
        validate_kernel_tax_bindings(obs_text, eval_text, golden.as_ref()).unwrap();

        let drifted = obs_text.replacen(
            "pub admission_latency_us: u64",
            "pub admission_latency_us: i64",
            1,
        );
        assert_ne!(drifted, obs_text, "the planted producer drift must apply");
        let error = validate_kernel_tax_bindings(&drifted, eval_text, golden.as_ref())
            .expect_err("u64-to-i64 producer drift must fail the canonical schema gate")
            .to_string();
        assert!(
            error.contains("fields/types differ"),
            "unexpected kernel-tax schema-gate error: {error}"
        );
    }

    #[test]
    fn current_cli_result_top_level_allows_only_declared_optional_omissions() {
        let allowed = BTreeSet::from([
            "kind".to_owned(),
            "optional".to_owned(),
            "version".to_owned(),
        ]);
        let required = BTreeSet::from(["kind".to_owned(), "version".to_owned()]);
        let authority = super::super::super::CliResultTopLevelAuthority {
            allowed_fields: &allowed,
            required_fields: &required,
            selector_field: "kind",
            selector_value: "result",
            version_field: "version",
            current_version: 7,
        };
        let without_optional = serde_json::json!({"kind": "result", "version": 7});
        super::super::super::validate_cli_result_top_level(
            &without_optional,
            "synthetic result",
            &authority,
        )
        .unwrap();

        let optional_kernel_tax_snapshot = crate::schema_compat::CurrentCliResultSnapshot {
            available: true,
            selector_field: "kind".to_owned(),
            selector_value: "result".to_owned(),
            version_field: "version".to_owned(),
            current_version: 7,
            allowed_fields: BTreeSet::from([
                "kernel_tax".to_owned(),
                "kind".to_owned(),
                "version".to_owned(),
            ]),
            required_fields: required.clone(),
            kernel_tax_fields: None,
        };
        optional_kernel_tax_snapshot
            .validate(&without_optional)
            .expect("an absent optional kernel_tax needs no nested shape");
        assert!(
            optional_kernel_tax_snapshot
                .validate(&serde_json::json!({
                    "kind": "result",
                    "version": 7,
                    "kernel_tax": {}
                }))
                .is_err(),
            "a present kernel_tax cannot claim an ungrounded nested shape"
        );

        let with_unknown = serde_json::json!({"kind": "result", "version": 7, "unknown": true});
        assert!(
            super::super::super::validate_cli_result_top_level(
                &with_unknown,
                "synthetic result",
                &authority,
            )
            .is_err()
        );
        let missing_required = serde_json::json!({"kind": "result"});
        assert!(
            super::super::super::validate_cli_result_top_level(
                &missing_required,
                "synthetic result",
                &authority,
            )
            .is_err()
        );
    }

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
