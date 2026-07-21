use super::super::manifest::read_bounded;
use super::MAX_SOURCE_BYTES;
use super::cli::require_strict_deserialize;
use super::json::parse_json_no_duplicates;
use super::parse::{named_struct_fields, validate_wire_identifier};
use crate::rust_source::{
    SerdeAuthority, require_serde_authority, require_serde_container_flag, unit_enum_variant_names,
};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const DIFF_SOURCE: &str = "crates/protocol/src/diff.rs";

pub(super) fn validate_diff_bindings(
    root: &Path,
    eval_text: &str,
    golden_source: &[u8],
) -> Result<()> {
    let protocol_source = read_bounded(root, DIFF_SOURCE, MAX_SOURCE_BYTES)?;
    let protocol_text = std::str::from_utf8(&protocol_source)
        .with_context(|| format!("schema source '{DIFF_SOURCE}' is not UTF-8"))?;
    let pairs = [
        ("pub struct FileDiff {", "struct CliFileDiff {"),
        ("pub struct Hunk {", "struct CliDiffHunk {"),
        ("pub struct DiffLine {", "struct CliDiffLine {"),
    ];
    let mut protocol_shapes = Vec::new();
    for (producer, consumer) in pairs {
        require_serde_authority(protocol_text, producer, SerdeAuthority::Both)?;
        require_serde_container_flag(protocol_text, producer, "deny_unknown_fields")?;
        require_strict_deserialize(eval_text, consumer)?;
        let producer_fields = named_struct_fields(protocol_text, producer)?;
        let consumer_fields = named_struct_fields(eval_text, consumer)?;
        if producer_fields != consumer_fields {
            bail!("structured diff producer '{producer}' differs from eval consumer '{consumer}'");
        }
        protocol_shapes.push(producer_fields);
    }
    require_serde_authority(protocol_text, "pub enum DiffTag {", SerdeAuthority::Both)?;
    require_serde_authority(eval_text, "enum CliDiffTag {", SerdeAuthority::Deserialize)?;
    let protocol_tags = unit_enum_variant_names(protocol_text, "pub enum DiffTag {")?;
    let eval_tags = unit_enum_variant_names(eval_text, "enum CliDiffTag {")?;
    if protocol_tags != eval_tags {
        bail!("structured diff tags differ between protocol producer and eval consumer");
    }
    validate_diff_golden(
        golden_source,
        &protocol_shapes[0],
        &protocol_shapes[1],
        &protocol_shapes[2],
        &protocol_tags,
    )
}

fn validate_diff_golden(
    source: &[u8],
    file_fields: &BTreeSet<String>,
    hunk_fields: &BTreeSet<String>,
    line_fields: &BTreeSet<String>,
    tags: &BTreeSet<String>,
) -> Result<()> {
    let source = std::str::from_utf8(source).context("CLI all-events golden is not UTF-8")?;
    let mut observed = 0usize;
    let mut observed_tags = BTreeSet::new();
    for (index, line) in source.lines().enumerate() {
        let value = parse_json_no_duplicates(line)
            .with_context(|| format!("CLI all-events golden line {} is invalid JSON", index + 1))?;
        let Some(object) = value.as_object() else {
            bail!("CLI all-events golden line {} is not an object", index + 1);
        };
        if object.get("type").and_then(serde_json::Value::as_str) != Some("tool_end") {
            continue;
        }
        observed = observed.saturating_add(1);
        let diff = object
            .get("diff")
            .and_then(serde_json::Value::as_object)
            .context("current tool_end golden must carry a non-null typed FileDiff")?;
        if &json_object_fields(diff) != file_fields {
            bail!("current tool_end golden FileDiff fields differ from protocol source");
        }
        let hunks = diff
            .get("hunks")
            .and_then(serde_json::Value::as_array)
            .context("current tool_end golden FileDiff lacks hunks")?;
        if hunks.is_empty() {
            bail!("current tool_end golden FileDiff hunks cannot be empty");
        }
        for hunk in hunks {
            let hunk = hunk
                .as_object()
                .context("current tool_end golden contains a non-object hunk")?;
            if &json_object_fields(hunk) != hunk_fields {
                bail!("current tool_end golden Hunk fields differ from protocol source");
            }
            let lines = hunk
                .get("lines")
                .and_then(serde_json::Value::as_array)
                .context("current tool_end golden Hunk lacks lines")?;
            if lines.is_empty() {
                bail!("current tool_end golden Hunk lines cannot be empty");
            }
            for line in lines {
                let line = line
                    .as_object()
                    .context("current tool_end golden contains a non-object diff line")?;
                if &json_object_fields(line) != line_fields {
                    bail!("current tool_end golden DiffLine fields differ from protocol source");
                }
                let tag = line
                    .get("tag")
                    .and_then(serde_json::Value::as_str)
                    .context("current tool_end golden DiffLine lacks a literal tag")?;
                observed_tags.insert(tag.to_owned());
            }
        }
    }
    if observed != 1 || &observed_tags != tags {
        bail!("current all-events golden must contain one typed tool_end covering every DiffTag");
    }
    Ok(())
}

pub(super) struct CliGoldenNestedShapes {
    pub(super) usage: BTreeSet<String>,
    pub(super) context: BTreeSet<String>,
    pub(super) budget: BTreeSet<String>,
    pub(super) task: BTreeSet<String>,
    pub(super) effort: BTreeMap<String, BTreeSet<String>>,
}

pub(super) fn golden_nested_shapes(source: &[u8]) -> Result<CliGoldenNestedShapes> {
    let source = std::str::from_utf8(source).context("CLI all-events golden is not UTF-8")?;
    let mut usage = None;
    let mut context = None;
    let mut budget = None;
    let mut task = None;
    let mut effort = BTreeMap::new();
    for (index, line) in source.lines().enumerate() {
        if line.is_empty() {
            bail!("CLI all-events golden contains a blank JSONL record");
        }
        let value = parse_json_no_duplicates(line)
            .with_context(|| format!("CLI all-events golden line {} is invalid JSON", index + 1))?;
        let object = value.as_object().with_context(|| {
            format!("CLI all-events golden line {} is not an object", index + 1)
        })?;
        let record_type = object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .with_context(|| {
                format!(
                    "CLI all-events golden line {} lacks a literal type",
                    index + 1
                )
            })?;
        if record_type == "turn_end" {
            let usage_object = object
                .get("usage")
                .and_then(serde_json::Value::as_object)
                .with_context(|| {
                    format!(
                        "CLI all-events golden turn_end line {} lacks usage",
                        index + 1
                    )
                })?;
            observe_golden_shape(
                &mut usage,
                json_object_fields(usage_object),
                "turn_end.usage",
            )?;
            let context_object = object
                .get("context")
                .and_then(serde_json::Value::as_object)
                .with_context(|| {
                    format!(
                        "CLI all-events golden turn_end line {} lacks context",
                        index + 1
                    )
                })?;
            observe_golden_shape(
                &mut context,
                json_object_fields(context_object),
                "turn_end.context",
            )?;
            let effort_object = object
                .get("effort")
                .and_then(serde_json::Value::as_object)
                .with_context(|| {
                    format!(
                        "CLI all-events golden turn_end line {} lacks effort",
                        index + 1
                    )
                })?;
            let enforcement = effort_object
                .get("enforcement")
                .and_then(serde_json::Value::as_str)
                .with_context(|| {
                    format!(
                        "CLI all-events golden turn_end line {} lacks effort.enforcement",
                        index + 1
                    )
                })?;
            validate_wire_identifier("golden effort enforcement", enforcement)?;
            let fields = json_object_fields(effort_object);
            if let Some(previous) = effort.insert(enforcement.to_owned(), fields.clone())
                && previous != fields
            {
                bail!("CLI all-events golden observes divergent effort shapes for '{enforcement}'");
            }
        } else if record_type == "workflow_plan" {
            let budget_object = object
                .get("budget")
                .and_then(serde_json::Value::as_object)
                .with_context(|| {
                    format!(
                        "CLI all-events golden workflow_plan line {} lacks budget",
                        index + 1
                    )
                })?;
            observe_golden_shape(
                &mut budget,
                json_object_fields(budget_object),
                "workflow_plan.budget",
            )?;
            let tasks = object
                .get("tasks")
                .and_then(serde_json::Value::as_array)
                .with_context(|| {
                    format!(
                        "CLI all-events golden workflow_plan line {} lacks tasks",
                        index + 1
                    )
                })?;
            if tasks.is_empty() {
                bail!("CLI all-events golden workflow_plan tasks cannot be empty");
            }
            for value in tasks {
                let task_object = value
                    .as_object()
                    .context("CLI all-events golden workflow_plan task is not an object")?;
                observe_golden_shape(
                    &mut task,
                    json_object_fields(task_object),
                    "workflow_plan.tasks[]",
                )?;
            }
        }
    }
    Ok(CliGoldenNestedShapes {
        usage: usage.context("CLI all-events golden has no turn_end usage shape")?,
        context: context.context("CLI all-events golden has no turn_end context shape")?,
        budget: budget.context("CLI all-events golden has no workflow_plan budget shape")?,
        task: task.context("CLI all-events golden has no workflow_plan task shape")?,
        effort,
    })
}

fn observe_golden_shape(
    observed: &mut Option<BTreeSet<String>>,
    shape: BTreeSet<String>,
    label: &str,
) -> Result<()> {
    if let Some(previous) = observed {
        if *previous != shape {
            bail!("CLI all-events golden observes divergent '{label}' shapes");
        }
    } else {
        *observed = Some(shape);
    }
    Ok(())
}

fn json_object_fields(object: &serde_json::Map<String, serde_json::Value>) -> BTreeSet<String> {
    object.keys().cloned().collect()
}
