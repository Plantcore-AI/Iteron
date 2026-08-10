use super::*;

use core_protocol::input::{
    MAX_IMAGE_BASE64_BYTES, MAX_INPUT_IMAGES, MAX_TOTAL_IMAGE_BASE64_BYTES,
};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    let specs = input.registry.specs();
    let names = specs
        .iter()
        .map(|spec| spec.name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let registry_digest = owner_digest("runtime_tool_registry", &specs)?;
    for (family, seam, tool) in [
        ("shell_timeout_output", "crates/tools/src/shell.rs", "bash"),
        (
            "read_file_limits",
            "crates/tools/src/fs_tools.rs",
            "read_file",
        ),
        (
            "list_dir_limits",
            "crates/tools/src/fs_tools.rs",
            "list_dir",
        ),
        ("glob_limits", "crates/tools/src/fs_tools.rs", "glob"),
        ("grep_limits", "crates/tools/src/grep_tool.rs", "grep"),
        ("repo_map", "crates/tools/src/fs_tools.rs", "repo_map"),
        ("git_limits", "crates/tools/src/git.rs", "git_diff"),
        ("web_fetch_limits", "crates/tools/src/web.rs", "web_fetch"),
    ] {
        builder.activate(family, seam, names.contains(tool), registry_digest.clone())?;
        report.mark(family, FactStage::Activation);
    }

    builder.activate(
        "verifier_feedback_tails",
        "crates/verify/src/lib.rs",
        input.verify_command.is_some(),
        owner_digest("verifier_plan", &input.verify_command)?,
    )?;
    report.mark("verifier_feedback_tails", FactStage::Activation);

    builder.activate(
        "direct_child_allocation",
        "crates/cli/src/runtime.rs",
        names.contains(core_tools::DISPATCH_AGENT),
        registry_digest.clone(),
    )?;
    report.mark("direct_child_allocation", FactStage::Activation);

    let workflow_active = names.contains(core_tools::WORKFLOW_TOOL);
    builder.activate(
        "workflow_aggregate",
        "crates/workflow/src/lib.rs",
        workflow_active,
        registry_digest.clone(),
    )?;
    report.mark("workflow_aggregate", FactStage::Activation);
    builder.activate(
        "schema_retry_jitter",
        "crates/cli/src/runtime.rs",
        workflow_active,
        registry_digest,
    )?;
    report.mark("schema_retry_jitter", FactStage::Activation);

    let image_owner = (
        MAX_INPUT_IMAGES,
        MAX_IMAGE_BASE64_BYTES,
        MAX_TOTAL_IMAGE_BASE64_BYTES,
        crate::image_input::MAX_IMAGE_FILE_BYTES,
        crate::image_input::MAX_TOTAL_IMAGE_FILE_BYTES,
    );
    builder.activate(
        "multimodal_input_admission_decode_envelope",
        "crates/cli/src/image_input.rs",
        true,
        owner_digest("image_input", &image_owner)?,
    )?;
    report.mark(
        "multimodal_input_admission_decode_envelope",
        FactStage::Activation,
    );

    let app_server_owner = (
        crate::app_server::SQ_CAPACITY,
        crate::app_server::SQ_BYTE_CAPACITY,
        crate::app_server::EQ_CAPACITY,
    );
    builder.activate(
        "app_server_sq_eq_backpressure",
        "crates/cli/src/app_server.rs",
        input.app_server_active,
        owner_digest("app_server", &app_server_owner)?,
    )?;
    report.mark("app_server_sq_eq_backpressure", FactStage::Activation);

    let provider_inventory = input
        .directory
        .entries()
        .iter()
        .map(|entry| (entry.id(), entry.catalog_provenance_label()))
        .collect::<Vec<_>>();
    builder.activate(
        "provider_discovery_account_probe_cache_policy",
        "crates/cli/src/providers.rs",
        true,
        owner_digest("provider_directory", &provider_inventory)?,
    )?;
    report.mark(
        "provider_discovery_account_probe_cache_policy",
        FactStage::Activation,
    );

    builder.activate(
        "agent_catalog",
        "crates/agents/src/catalog.rs",
        true,
        input
            .agent_catalog
            .execution_digest()
            .trim_start_matches("sha256:"),
    )?;
    report.mark("agent_catalog", FactStage::Activation);
    Ok(())
}
