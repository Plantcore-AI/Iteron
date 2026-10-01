//! Executable direction and responsibility guards for the live state owners.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use quote::ToTokens;
use syn::parse::Parser;
use syn::visit::Visit;

const MAX_SOURCE_BYTES: u64 = 2 * 1_024 * 1_024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1_024;
const MAX_PACKAGES: usize = 128;
const MAX_PRODUCTION_LINES: usize = 1_200;

const SCHEDULER_MODULES: &[&str] = &[
    "crates/workflow/src/live_scheduler/mod.rs",
    "crates/workflow/src/live_scheduler/types.rs",
    "crates/workflow/src/live_scheduler/ports.rs",
    "crates/workflow/src/live_scheduler/owner.rs",
    "crates/workflow/src/live_scheduler/validation.rs",
    "crates/workflow/src/live_scheduler/file_journal.rs",
];

pub(crate) fn validate(root: &Path) -> Result<()> {
    validate_dependency_graph(root)?;
    validate_ticket_profile(root)?;
    validate_script_profile(root)?;
    validate_legacy_profile(root)?;
    validate_extracted_owners(root)?;
    if root.join("crates/cli/src/queue_policy.rs").is_file() {
        validate_runtime_direction(root)?;
    }
    if root.join("crates/cli/src/machine_projection.rs").is_file() {
        validate_frontend_projection_direction(root)?;
    }
    // The direct public module declaration activates this new contract for historical trusted
    // base comparisons too; old bases remain readable without pretending they contain it.
    let workflow = read(root, "crates/workflow/src/lib.rs", MAX_SOURCE_BYTES)?;
    if workflow
        .lines()
        .any(|line| line.trim() == "pub mod live_scheduler;")
    {
        for relative in SCHEDULER_MODULES {
            let source = read(root, relative, MAX_SOURCE_BYTES)?;
            validate_production_module(relative, &source)?;
            if !relative.ends_with("file_journal.rs") {
                validate_domain_source(relative, &source)?;
            }
        }
    }
    Ok(())
}

fn validate_ticket_profile(root: &Path) -> Result<()> {
    let manifest: toml::Value =
        toml::from_str(&read(root, "crates/cli/Cargo.toml", MAX_MANIFEST_BYTES)?)?;
    let Some(features) = manifest.get("features").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    if !features.contains_key("ticket-investigation") {
        return Ok(());
    }
    let default = features
        .get("default")
        .and_then(toml::Value::as_array)
        .context("optional strategy needs an explicit default feature list")?;
    // Conservative: defaults stay empty so a renamed transitive alias cannot re-enable ticket
    // initialization. A future default feature needs an explicit reviewed profile graph.
    if !default.is_empty() {
        bail!("ordinary production must not enable optional ticket features");
    }
    let runtime = read(root, "crates/cli/src/runtime.rs", MAX_SOURCE_BYTES)?;
    validate_ticket_declaration(&runtime)
}

fn validate_ticket_declaration(source: &str) -> Result<()> {
    let parsed = syn::parse_file(source)?;
    let mut found = false;
    for item in parsed.items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let path = module
            .attrs
            .iter()
            .find(|a| a.path().is_ident("path"))
            .and_then(|a| match &a.meta {
                syn::Meta::NameValue(v) => match &v.value {
                    syn::Expr::Lit(lit) => match &lit.lit {
                        syn::Lit::Str(value) => Some(value.value()),
                        _ => None,
                    },
                    _ => None,
                },
                _ => None,
            });
        let original = path
            .as_ref()
            .is_some_and(|p| p.ends_with("investigation_convergence.rs"))
            || (path.is_none() && module.ident == "investigation_convergence");
        if !original {
            continue;
        }
        if module.content.is_some() {
            bail!("ticket strategy must be an independently compiled module");
        }
        let cfgs = module
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("cfg"))
            .map(|attribute| attribute.parse_args::<syn::Meta>())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for platform in [false, true] {
            let disabled = cfgs
                .iter()
                .map(|cfg| eval_cfg(cfg, false, false, platform))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .all(|enabled| enabled);
            if disabled {
                bail!("ticket investigation module is compiled into ordinary production");
            }
        }
        let enabled = cfgs
            .iter()
            .map(|cfg| eval_cfg(cfg, true, false, true))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .all(|enabled| enabled);
        if !enabled {
            bail!("ticket-investigation profile does not enable its strategy module");
        }
        found = true;
    }
    if !found {
        bail!("ticket-investigation feature has no independently gated strategy module");
    }
    Ok(())
}

fn eval_cfg(meta: &syn::Meta, ticket: bool, test: bool, unix: bool) -> Result<bool> {
    eval_feature_cfg(meta, "ticket-investigation", ticket, test, unix)
}

fn eval_feature_cfg(
    meta: &syn::Meta,
    feature_name: &str,
    enabled: bool,
    test: bool,
    unix: bool,
) -> Result<bool> {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => Ok(test),
        syn::Meta::Path(path) if path.is_ident("unix") => Ok(unix),
        syn::Meta::Path(path) if path.is_ident("windows") => Ok(!unix),
        syn::Meta::NameValue(value) if value.path.is_ident("feature") => match &value.value {
            syn::Expr::Lit(lit) => match &lit.lit {
                syn::Lit::Str(feature) if feature.value() == feature_name => Ok(enabled),
                syn::Lit::Str(_) => Ok(false),
                _ => bail!("feature cfg needs string literal"),
            },
            _ => bail!("feature cfg needs literal value"),
        },
        syn::Meta::List(list) => {
            let items = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                .parse2(list.tokens.clone())?;
            let values = items
                .iter()
                .map(|item| eval_feature_cfg(item, feature_name, enabled, test, unix))
                .collect::<Result<Vec<_>>>()?;
            if list.path.is_ident("any") {
                Ok(values.into_iter().any(|v| v))
            } else if list.path.is_ident("all") {
                Ok(values.into_iter().all(|v| v))
            } else if list.path.is_ident("not") && values.len() == 1 {
                Ok(!values[0])
            } else {
                bail!("unsupported ticket compile cfg expression")
            }
        }
        _ => bail!("ticket profile cfg must explicitly express feature/test/platform conditions"),
    }
}

fn validate_script_profile(root: &Path) -> Result<()> {
    let workflow: toml::Value = toml::from_str(&read(
        root,
        "crates/workflow/Cargo.toml",
        MAX_MANIFEST_BYTES,
    )?)?;
    let Some(features) = workflow.get("features").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    if !features.contains_key("script-workflows") {
        return Ok(());
    }
    if !features
        .get("default")
        .and_then(toml::Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        bail!("default workflow profile must not compile the script engine");
    }
    if workflow
        .get("dependencies")
        .and_then(|d| d.get("rquickjs"))
        .and_then(|d| d.get("optional"))
        .and_then(toml::Value::as_bool)
        != Some(true)
    {
        bail!("QuickJS dependency must be optional");
    }
    let source = read(root, "crates/workflow/src/lib.rs", MAX_SOURCE_BYTES)?;
    for name in ["bindings", "executor", "host", "meta"] {
        validate_feature_module(&source, name, "script-workflows")?;
    }
    let ledger = read(
        root,
        "crates/workflow/src/task_dag/mod.rs",
        MAX_SOURCE_BYTES,
    )?;
    validate_feature_module(&ledger, "runtime", "script-workflows")?;
    let tools: toml::Value =
        toml::from_str(&read(root, "crates/tools/Cargo.toml", MAX_MANIFEST_BYTES)?)?;
    if tools
        .get("features")
        .and_then(|f| f.get("script-workflows"))
        .is_none()
    {
        bail!("script profile must control the writer schema catalog too");
    }
    validate_feature_module(
        &read(root, "crates/tools/src/lib.rs", MAX_SOURCE_BYTES)?,
        "workflow_tool",
        "script-workflows",
    )?;
    let cli: toml::Value =
        toml::from_str(&read(root, "crates/cli/Cargo.toml", MAX_MANIFEST_BYTES)?)?;
    let forwarded = cli
        .get("features")
        .and_then(|f| f.get("script-workflows"))
        .and_then(toml::Value::as_array)
        .context("CLI must explicitly forward its optional script feature")?;
    for edge in [
        "iteron-workflow/script-workflows",
        "iteron-tools/script-workflows",
    ] {
        if !forwarded.iter().any(|v| v.as_str() == Some(edge)) {
            bail!("CLI script profile does not forward {edge}");
        }
    }
    Ok(())
}

fn validate_feature_module(source: &str, name: &str, feature: &str) -> Result<()> {
    let parsed = syn::parse_file(source)?;
    let mut found = false;
    for item in parsed.items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if module.ident != name {
            continue;
        }
        let cfgs = module
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("cfg"))
            .map(|a| a.parse_args::<syn::Meta>())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for unix in [false, true] {
            let default = cfgs
                .iter()
                .map(|m| eval_feature_cfg(m, feature, false, false, unix))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .all(|v| v);
            if default {
                bail!("optional module {name} is compiled into default production");
            }
        }
        let selected = cfgs
            .iter()
            .map(|m| eval_feature_cfg(m, feature, true, false, true))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .all(|v| v);
        if !selected {
            bail!("feature {feature} does not select its module {name}");
        }
        found = true;
    }
    if !found {
        bail!("feature {feature} has no module {name}");
    }
    Ok(())
}

fn validate_legacy_profile(root: &Path) -> Result<()> {
    let manifest: toml::Value =
        toml::from_str(&read(root, "crates/cli/Cargo.toml", MAX_MANIFEST_BYTES)?)?;
    let Some(features) = manifest.get("features").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    if !features.contains_key("legacy-plantcore") {
        return Ok(());
    }
    if !features
        .get("default")
        .and_then(toml::Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        bail!("standalone default must not enable legacy project integrations");
    }
    for (file, name) in [
        ("crates/cli/src/runtime.rs", "plantcore"),
        ("crates/cli/src/main.rs", "recording_provider"),
        ("crates/cli/src/app_server.rs", "plantcore"),
        ("crates/cli/src/app_server.rs", "recording_fault"),
        ("crates/cli/src/tui/headless.rs", "commands"),
    ] {
        validate_legacy_declaration(&read(root, file, MAX_SOURCE_BYTES)?, name)?;
    }
    Ok(())
}

fn validate_legacy_declaration(source: &str, name: &str) -> Result<()> {
    let mut original = false;
    let mut disabled = false;
    for item in syn::parse_file(source)?.items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if module.ident != name {
            continue;
        }
        if module.content.is_some() {
            bail!("legacy integration must live in a separate compiled module");
        }
        let shim = module.attrs.iter().any(|attribute| {
            matches!(&attribute.meta, syn::Meta::NameValue(value)
                if value.path.is_ident("path")
                    && matches!(&value.value, syn::Expr::Lit(literal)
                        if matches!(&literal.lit, syn::Lit::Str(path)
                            if path.value().ends_with("_disabled.rs"))))
        });
        let cfgs = module
            .attrs
            .iter()
            .filter(|attribute| attribute.path().is_ident("cfg"))
            .map(|attribute| attribute.parse_args::<syn::Meta>())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for enabled in [false, true] {
            for test in [false, true] {
                for unix in [false, true] {
                    let selected = cfgs
                        .iter()
                        .map(|cfg| eval_feature_cfg(cfg, "legacy-plantcore", enabled, test, unix))
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .all(|value| value);
                    if selected != (enabled != shim) {
                        bail!(
                            "{name} legacy/default declarations do not isolate every platform/profile"
                        );
                    }
                }
            }
        }
        if shim {
            if disabled {
                bail!("duplicate standalone compatibility shim for {name}");
            }
            disabled = true;
        } else {
            if original {
                bail!("duplicate legacy integration declaration for {name}");
            }
            original = true;
        }
    }
    if !original || !disabled {
        bail!("{name} needs separately gated legacy and standalone modules");
    }
    Ok(())
}

fn validate_extracted_owners(root: &Path) -> Result<()> {
    let facade = read(root, "crates/cli/src/workflow.rs", MAX_SOURCE_BYTES)?;
    if !facade.lines().any(|l| l.trim() == "mod supervisor;") {
        return Ok(());
    }
    for path in [
        "crates/cli/src/workflow/launch.rs",
        "crates/cli/src/workflow/progress.rs",
        "crates/cli/src/workflow/run_store.rs",
        "crates/cli/src/workflow/summary.rs",
        "crates/cli/src/workflow/supervisor.rs",
        "crates/cli/src/workflow/live_session/mod.rs",
        "crates/cli/src/workflow/live_session/types.rs",
        "crates/cli/src/workflow/live_session/registry.rs",
        "crates/cli/src/workflow/live_session/pump.rs",
        "crates/cli/src/workflow/live_session/store.rs",
        "crates/cli/src/runtime/frontend_events.rs",
        "crates/cli/src/runtime/tool_presentation.rs",
        "crates/cli/src/runtime/stream_progress.rs",
        "crates/cli/src/runtime/deferred_batch_executor.rs",
        "crates/cli/src/runtime/deferred_tool_batch.rs",
        "crates/cli/src/runtime/ordered_tool_call.rs",
        "crates/cli/src/runtime/optional_tool_round.rs",
        "crates/cli/src/runtime/request_preparation.rs",
        "crates/cli/src/runtime/request_accounting.rs",
        "crates/cli/src/runtime/provider_dispatch.rs",
        "crates/cli/src/runtime/control_ingress.rs",
        "crates/cli/src/runtime/permission_transaction.rs",
        "crates/cli/src/runtime/tool_declaration_admission.rs",
        "crates/cli/src/runtime/model_response.rs",
        "crates/cli/src/runtime/approval_wait.rs",
        "crates/cli/src/runtime/control_terminal.rs",
        "crates/cli/src/runtime/run_finalization.rs",
        "crates/cli/src/runtime/terminal_runtime.rs",
        "crates/cli/src/runtime/ordinary_extensions.rs",
        "crates/cli/src/runtime/ordinary_extension_runtime.rs",
        "crates/cli/src/providers/discovery.rs",
        "crates/cli/src/machine_projection.rs",
        "crates/cli/src/tui/input_lanes.rs",
        "crates/cli/src/tui/completion_owner.rs",
        "crates/cli/src/tui/attachment_owner.rs",
        "crates/cli/src/tui/picker_owner.rs",
        "crates/cli/src/tui/ordinary_extensions.rs",
        "crates/cli/src/queue_policy.rs",
        "crates/cli/src/tui/headless/commands.rs",
        "crates/cli/src/tui/headless/connection.rs",
        "crates/cli/src/runtime/deferred_tools.rs",
        "crates/cli/src/runtime/early_tool_gate.rs",
        "crates/cli/src/runtime/early_tool_executor.rs",
        "crates/cli/src/runtime/early_tool_collection.rs",
        "crates/cli/src/runtime/tool_execution_journal.rs",
        "crates/cli/src/runtime/terminal_record.rs",
        "crates/cli/src/runtime/turn_publication.rs",
        "crates/cli/src/runtime/workspace_checkpoint.rs",
        "crates/cli/src/runtime/provider_stream_observer.rs",
        "crates/cli/src/runtime/provider_round.rs",
        "crates/cli/src/runtime/provider_stream_attempt.rs",
        "crates/cli/src/runtime/provider_transport_attempt.rs",
        "crates/cli/src/runtime/provider_output_request.rs",
        "crates/cli/src/runtime/provider_charge_evidence.rs",
        "crates/cli/src/runtime/provider_financial_context.rs",
        "crates/cli/src/runtime/provider_attempt_journal.rs",
        "crates/cli/src/runtime/provider_attempt_pump.rs",
        "crates/cli/src/runtime/provider_route_admission.rs",
        "crates/cli/src/runtime/provider_route_journal.rs",
        "crates/cli/src/runtime/provider_selection.rs",
        "crates/cli/src/runtime/provider_selection_journal.rs",
        "crates/cli/src/runtime/provider_route_turn.rs",
        "crates/cli/src/runtime/provider_route_events.rs",
        "crates/cli/src/runtime/tool_turn.rs",
        "crates/cli/src/runtime/kernel_effect_bridge.rs",
        "crates/cli/src/runtime/effect_descriptor.rs",
        "crates/cli/src/runtime/effect_journal_owner.rs",
        "crates/cli/src/runtime/stream_tool_admission.rs",
        "crates/cli/src/runtime/stream_tool_journal.rs",
        "crates/cli/src/runtime/stream_tool_events.rs",
        "crates/cli/src/runtime/stream_tools.rs",
        "crates/cli/src/runtime/hook_execution.rs",
        "crates/cli/src/runtime/session_control.rs",
        "crates/cli/src/runtime/session_inbox.rs",
        "crates/cli/src/runtime/submitted_turn_state.rs",
        "crates/cli/src/runtime/provider_turn_evidence.rs",
        "crates/cli/src/runtime/request_context_evidence.rs",
        "crates/workflow/src/bindings.rs",
        "crates/workflow/src/bindings/run_state.rs",
        "crates/workflow/src/bindings/attempt_executor.rs",
        "crates/tools/src/desktop/mod.rs",
        "crates/tools/src/desktop/driver.rs",
        "crates/tools/src/desktop/types.rs",
        "crates/cli/src/providers.rs",
        "crates/cli/src/providers/directory.rs",
        "crates/cli/src/providers/catalog_cache.rs",
        "crates/cli/src/providers/probe_cache.rs",
        "crates/cli/src/providers/cache_storage.rs",
        "crates/cli/src/providers/cache_writeback.rs",
        "crates/cli/src/providers/instance_factory.rs",
        "crates/cli/src/providers/selection_identity.rs",
        "crates/cli/src/runtime/provider_execution_scope.rs",
        "crates/cli/src/runtime/provider_followup.rs",
        "crates/cli/src/runtime/tool_response.rs",
        "crates/cli/src/runtime/tool_round_driver.rs",
        "crates/cli/src/runtime/tool_round_execution.rs",
        "crates/cli/src/runtime/tool_execution_session.rs",
        "crates/cli/src/runtime/provider_response_commit.rs",
        "crates/cli/src/runtime/provider_usage_journal.rs",
        "crates/cli/src/runtime/context_usage_reconciliation.rs",
        "crates/cli/src/runtime/request_cycle.rs",
        "crates/cli/src/runtime/provider_turn_entry.rs",
        "crates/cli/src/runtime/coding_run_driver.rs",
        "crates/cli/src/runtime/coding_provider_execution.rs",
        "crates/cli/src/runtime/tool_image_projection.rs",
        "crates/cli/src/runtime/kernel_dispatch_control.rs",
        "crates/cli/src/runtime/kernel_dispatch_journal.rs",
        "crates/cli/src/runtime/kernel_special_execution.rs",
        "crates/cli/src/runtime/kernel_child_accounting.rs",
        "crates/cli/src/runtime/invocation_funding.rs",
        "crates/cli/src/runtime/invocation_funding_assembly.rs",
        "crates/cli/src/runtime/invocation_admission.rs",
        "crates/cli/src/runtime/invocation_admission_assembly.rs",
        "crates/cli/src/runtime/invocation_cleanup.rs",
        "crates/cli/src/runtime/persistent_writer_settlement.rs",
        "crates/cli/src/runtime/workflow_spawner/writer_settlement.rs",
        "crates/cli/src/runtime/workflow_spawner/worktree/evidence.rs",
        "crates/tools/src/contained_source.rs",
        "crates/support/src/durable_windows_state/contained_read.rs",
        "crates/support/src/durable_windows_state/workspace_publication.rs",
        "crates/cli/src/client_effects/export_macos.rs",
        "crates/cli/src/client_effects/export_windows.rs",
        "crates/sandbox/src/owned_process_cleanup.rs",
        "crates/cli/src/runtime/direct_child_execution.rs",
        "crates/cli/src/runtime/workflow_execution.rs",
        "crates/cli/src/runtime/workflow_preparation.rs",
        "crates/cli/src/client_effects.rs",
        "crates/cli/src/client_effects/export.rs",
        "crates/cli/src/client_effects/payload.rs",
        "crates/cli/src/client_effects/process.rs",
        "crates/cli/src/client_effects/worker.rs",
        "crates/cli/src/app_server/client_export.rs",
        "crates/cli/src/runtime/session_transcript.rs",
        "crates/cli/src/runtime/provider_usage_reservation.rs",
        "crates/cli/src/runtime/persistent_agents/prepared_mailbox.rs",
        "crates/cli/src/tui/session_navigation.rs",
        "crates/cli/src/main.rs",
        "crates/cli/src/runtime.rs",
        "crates/cli/src/app_server.rs",
        "crates/cli/src/tui.rs",
        "crates/provider/src/usage_bounds.rs",
    ] {
        let source = read(root, path, MAX_SOURCE_BYTES)?;
        validate_production_module(path, &source)?;
        let parsed = syn::parse_file(&source)?;
        let mut guard = ExplicitImports { violation: false };
        guard.visit_file(&parsed);
        if guard.violation {
            bail!("{path}: wildcard imports or include source fragments hide ownership");
        }
    }
    Ok(())
}

/// Runtime source depends on shared contracts. A frontend adapter may depend on the runtime;
/// the reverse import would make replacement of a transport or presentation require core edits.
fn validate_runtime_direction(root: &Path) -> Result<()> {
    let mut paths = vec![
        "crates/cli/src/runtime.rs".to_owned(),
        "crates/cli/src/queue_policy.rs".to_owned(),
    ];
    let mut directories = vec![
        "crates/cli/src/runtime".to_owned(),
        "crates/cli/src/runtime_tunables".to_owned(),
    ];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(root.join(&directory))? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let relative = format!("{directory}/{}", entry.file_name().to_string_lossy());
            if kind.is_dir() {
                directories.push(relative);
            } else if kind.is_file()
                && relative.ends_with(".rs")
                && !relative.ends_with("/tests.rs")
                && !relative.ends_with("_tests.rs")
                && !relative.contains("/tests/")
            {
                paths.push(relative);
            }
            if paths.len() + directories.len() > 4_096 {
                bail!("runtime source inventory exceeds its bounded direction review");
            }
        }
    }
    for path in paths {
        validate_runtime_source_direction(&path, &read(root, &path, MAX_SOURCE_BYTES)?)?;
    }
    Ok(())
}

fn validate_runtime_source_direction(relative: &str, source: &str) -> Result<()> {
    let parsed = syn::parse_file(source)?;
    let mut guard = FrontendDependencyGuard {
        violation: false,
        forbidden: &[
            "app_server",
            "tui",
            "headless",
            "ratatui",
            "crossterm",
            "output",
        ],
    };
    guard.visit_file(&parsed);
    if guard.violation {
        bail!("{relative}: runtime cannot depend on App Server, TUI or headless adapters");
    }
    Ok(())
}

/// Server and frontend adapters consume the same pure machine owner. Production imports must
/// not route through another frontend's physical emitter, options or mutable presentation state.
fn validate_frontend_projection_direction(root: &Path) -> Result<()> {
    for (parent, tree, forbidden) in [
        (
            "crates/cli/src/app_server.rs",
            "crates/cli/src/app_server",
            &["output", "options", "tui"][..],
        ),
        (
            "crates/cli/src/machine_projection.rs",
            "crates/cli/src/machine_projection",
            &["app_server", "tui", "cli_entry", "output", "options"][..],
        ),
    ] {
        let mut paths = vec![parent.to_owned()];
        let mut directories = vec![tree.to_owned()];
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(root.join(&directory))? {
                let entry = entry?;
                let kind = entry.file_type()?;
                let relative = format!("{directory}/{}", entry.file_name().to_string_lossy());
                if kind.is_dir() && !relative.ends_with("/tests") {
                    directories.push(relative);
                } else if kind.is_file()
                    && relative.ends_with(".rs")
                    && !relative.ends_with("/tests.rs")
                    && !relative.ends_with("_tests.rs")
                {
                    paths.push(relative);
                }
                if paths.len() + directories.len() > 4_096 {
                    bail!("frontend source inventory exceeds its bounded direction review");
                }
            }
        }
        for path in paths {
            validate_frontend_source(&path, &read(root, &path, MAX_SOURCE_BYTES)?, forbidden)?;
        }
    }
    Ok(())
}
fn validate_frontend_source(relative: &str, source: &str, forbidden: &[&str]) -> Result<()> {
    let parsed = syn::parse_file(source)?;
    let mut guard = FrontendDependencyGuard {
        violation: false,
        forbidden,
    };
    guard.visit_file(&parsed);
    if guard.violation {
        bail!("{relative}: frontend contract imports a forbidden physical adapter");
    }
    Ok(())
}
struct FrontendDependencyGuard<'a> {
    violation: bool,
    forbidden: &'a [&'a str],
}
impl FrontendDependencyGuard<'_> {
    fn forbids(&self, name: &syn::Ident) -> bool {
        self.forbidden.contains(&name.to_string().as_str())
    }
}
impl<'ast> Visit<'ast> for FrontendDependencyGuard<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if node.attrs.iter().any(|attribute| {
            attribute.path().is_ident("cfg")
                && attribute.parse_args::<syn::Meta>().is_ok_and(
                    |meta| matches!(meta, syn::Meta::Path(path) if path.is_ident("test")),
                )
        }) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.violation |= path
            .segments
            .iter()
            .any(|segment| self.forbids(&segment.ident));
        syn::visit::visit_path(self, path);
    }
    fn visit_use_tree(&mut self, tree: &'ast syn::UseTree) {
        self.violation |= match tree {
            syn::UseTree::Path(path) => self.forbids(&path.ident),
            syn::UseTree::Name(name) => self.forbids(&name.ident),
            syn::UseTree::Rename(rename) => self.forbids(&rename.ident),
            _ => false,
        };
        syn::visit::visit_use_tree(self, tree);
    }
}

struct ExplicitImports {
    violation: bool,
}
impl<'ast> Visit<'ast> for ExplicitImports {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if super::architecture_inventory::test_only_item(item) {
            return;
        }
        syn::visit::visit_item(self, item);
    }
    fn visit_use_tree(&mut self, tree: &'ast syn::UseTree) {
        self.violation |= matches!(tree, syn::UseTree::Glob(_));
        syn::visit::visit_use_tree(self, tree);
    }
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.violation |= node.path.is_ident("include");
        syn::visit::visit_macro(self, node);
    }
}

fn validate_dependency_graph(root: &Path) -> Result<()> {
    let workspace: toml::Value = toml::from_str(&read(root, "Cargo.toml", MAX_MANIFEST_BYTES)?)?;
    let members = workspace
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .context("workspace members must be an explicit array")?;
    if members.len() > MAX_PACKAGES {
        bail!("architecture package capacity exceeded");
    }
    let mut graph = BTreeMap::new();
    for member in members {
        let relative = member
            .as_str()
            .context("workspace member must be a string")?;
        if relative.is_empty()
            || relative.starts_with('/')
            || relative.split('/').any(|p| p == "..")
        {
            bail!("workspace member escapes the repository");
        }
        let manifest: toml::Value = toml::from_str(&read(
            root,
            &format!("{relative}/Cargo.toml"),
            MAX_MANIFEST_BYTES,
        )?)?;
        let name = manifest
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
            .context("package needs explicit name")?;
        let mut dependencies = BTreeSet::new();
        collect_normal_dependencies(&manifest, &mut dependencies);
        if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
            for target in targets.values() {
                collect_normal_dependencies(target, &mut dependencies);
            }
        }
        if graph.insert(name.to_string(), dependencies).is_some() {
            bail!("duplicate workspace package identity");
        }
    }
    validate_graph(&graph)
}

fn collect_normal_dependencies(manifest: &toml::Value, dependencies: &mut BTreeSet<String>) {
    if let Some(table) = manifest.get("dependencies").and_then(toml::Value::as_table) {
        for (key, value) in table {
            let name = value
                .get("package")
                .and_then(toml::Value::as_str)
                .unwrap_or(key);
            dependencies.insert(name.to_string());
        }
    }
}

fn validate_graph(graph: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    let mut indegree = graph
        .keys()
        .map(|name| (name, 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut dependents = BTreeMap::<&String, Vec<&String>>::new();
    for (name, dependencies) in graph {
        for dependency in dependencies {
            if graph.contains_key(dependency) {
                *indegree.get_mut(name).context("package missing in graph")? += 1;
                dependents.entry(dependency).or_default().push(name);
            }
        }
        // The assembly crate is the only frontend entry; it cannot be a domain dependency.
        if name != "iteron-cli" && dependencies.contains("iteron-cli") {
            bail!("domain package {name} cannot depend on frontend/composition iteron-cli");
        }
        if matches!(
            name.as_str(),
            "iteron-agents" | "iteron-kernel" | "iteron-protocol" | "iteron-ctx"
        ) {
            for forbidden in [
                "ratatui",
                "crossterm",
                "reqwest",
                "iteron-provider",
                "iteron-workflow",
            ] {
                if dependencies.contains(forbidden) {
                    bail!(
                        "state-owner package {name} cannot depend on concrete/frontend {forbidden}"
                    );
                }
            }
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(name, degree)| (*degree == 0).then_some(*name))
        .collect::<Vec<_>>();
    let mut count = 0usize;
    while let Some(name) = ready.pop() {
        count += 1;
        if let Some(users) = dependents.get(name) {
            for user in users {
                let degree = indegree.get_mut(user).context("dependency user missing")?;
                *degree -= 1;
                if *degree == 0 {
                    ready.push(user);
                }
            }
        }
    }
    if count != graph.len() {
        bail!("workspace normal dependency cycle");
    }
    Ok(())
}

fn validate_production_module(relative: &str, source: &str) -> Result<()> {
    // Exclude only syntactically test-only items, using the same rule as the maintained inventory.
    // Product include fragments remain forbidden by ExplicitImports, including optional profiles.
    if super::architecture_inventory::production_lines(source)? > MAX_PRODUCTION_LINES {
        bail!("{relative} exceeds the 1200-line production owner limit");
    }
    Ok(())
}

struct DomainGuard {
    violations: BTreeSet<&'static str>,
}

impl<'ast> Visit<'ast> for DomainGuard {
    fn visit_use_tree(&mut self, tree: &'ast syn::UseTree) {
        if matches!(tree, syn::UseTree::Glob(_)) {
            self.violations
                .insert("wildcard import hides state ownership");
        }
        if let syn::UseTree::Name(name) = tree
            && matches!(name.ident.to_string().as_str(), "fs" | "process" | "net")
        {
            self.violations
                .insert("concrete I/O must stay behind an adapter port");
        }
        if matches!(tree, syn::UseTree::Path(path) if matches!(path.ident.to_string().as_str(), "fs" | "process" | "net"))
            || matches!(tree, syn::UseTree::Rename(rename) if matches!(rename.ident.to_string().as_str(), "fs" | "process" | "net"))
        {
            self.violations
                .insert("concrete I/O aliases must stay behind an adapter port");
        }
        syn::visit::visit_use_tree(self, tree);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments = path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>();
        if segments.iter().any(|s| {
            matches!(
                s.as_str(),
                "iteron_agents"
                    | "iteron_provider"
                    | "iteron_sched"
                    | "reqwest"
                    | "ratatui"
                    | "crossterm"
            )
        }) {
            self.violations
                .insert("domain core cannot depend on concrete controller/provider/frontend");
        }
        if segments.windows(2).any(|s| {
            (s[0] == "std" || s[0] == "tokio") && matches!(s[1].as_str(), "fs" | "process" | "net")
        }) {
            self.violations
                .insert("concrete I/O must stay behind an adapter port");
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.is_ident("include") {
            self.violations
                .insert("include source slicing is not domain separation");
        }
        syn::visit::visit_macro(self, node);
    }
}

fn validate_domain_source(relative: &str, source: &str) -> Result<()> {
    let parsed =
        syn::parse_file(source).with_context(|| format!("parse architecture module {relative}"))?;
    let mut guard = DomainGuard {
        violations: BTreeSet::new(),
    };
    guard.visit_file(&parsed);
    // Imported module names in grouped use trees need recursive inspection too. This token check
    // catches the concrete dependency regardless of whether it is renamed after import.
    let tokens = parsed.to_token_stream().to_string();
    for dependency in [
        "iteron_agents",
        "iteron_provider",
        "iteron_sched",
        "reqwest",
        "ratatui",
        "crossterm",
    ] {
        if tokens
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|token| token == dependency)
        {
            guard
                .violations
                .insert("concrete dependency hidden in module tokens");
        }
    }
    if !guard.violations.is_empty() {
        bail!(
            "{relative}: {}",
            guard.violations.into_iter().collect::<Vec<_>>().join("; ")
        );
    }
    Ok(())
}

fn read(root: &Path, relative: &str, max: u64) -> Result<String> {
    let mut result = String::new();
    std::fs::File::open(root.join(relative))?
        .take(max + 1)
        .read_to_string(&mut result)?;
    if result.len() as u64 > max {
        bail!("architecture input {relative} exceeds byte ceiling");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn illegal_dependency_directions_and_cycles_are_rejected() {
        let graph = BTreeMap::from([
            (
                "iteron-agents".into(),
                BTreeSet::from(["iteron-provider".into()]),
            ),
            ("iteron-provider".into(), BTreeSet::new()),
        ]);
        assert!(validate_graph(&graph).is_err());
        let graph = BTreeMap::from([
            ("a".into(), BTreeSet::from(["b".into()])),
            ("b".into(), BTreeSet::from(["a".into()])),
        ]);
        assert!(validate_graph(&graph).is_err());
        let graph = BTreeMap::from([
            (
                "iteron-workflow".into(),
                BTreeSet::from(["iteron-cli".into()]),
            ),
            ("iteron-cli".into(), BTreeSet::new()),
        ]);
        assert!(validate_graph(&graph).is_err());
    }

    #[test]
    fn runtime_frontend_imports_are_rejected_while_shared_contracts_are_allowed() {
        for source in [
            "use crate::app_server::QueuePolicy;",
            "use crate::{app_server as transport};",
            "fn f() { crate::tui::run(); }",
            "type Socket = crate::headless::Connection;",
        ] {
            assert!(
                validate_runtime_source_direction("runtime.rs", source).is_err(),
                "{source}"
            );
        }
        assert!(validate_runtime_source_direction("runtime.rs", "use crate::queue_policy::FrontendQueuePolicy; #[cfg(test)] mod tests { use crate::app_server::AppServer; }").is_ok());
    }

    #[test]
    fn server_and_common_projection_cannot_alias_cli_or_tui_adapters() {
        for source in [
            "use crate::output::event_json;",
            "use crate::{tui as view};",
            "fn f() { crate::options::parse(); }",
        ] {
            assert!(
                validate_frontend_source("server.rs", source, &["output", "options", "tui"])
                    .is_err()
            );
        }
        assert!(
            validate_frontend_source(
                "server.rs",
                "use crate::machine_projection::event_json;",
                &["output", "options", "tui"]
            )
            .is_ok()
        );
        assert!(
            validate_frontend_source(
                "common.rs",
                "use crate::{app_server as adapter};",
                &["app_server", "tui", "cli_entry", "output"]
            )
            .is_err()
        );
    }

    #[test]
    fn concrete_io_aliases_wildcards_and_fake_module_splits_are_rejected() {
        for source in [
            "use super::*;",
            "use std::{fs, process};",
            "use std::fs as disk;",
            "use iteron_agents as owner;",
            "fn spawn() { tokio::process::Command::new(\"sh\"); }",
            "include!(\"giant-owner.rs\");",
        ] {
            assert!(
                validate_domain_source("owner.rs", source).is_err(),
                "{source}"
            );
        }
        assert!(
            validate_domain_source(
                "owner.rs",
                "use super::ports::Controller; struct Owner { revision: u64 }"
            )
            .is_ok()
        );
        assert!(
            validate_production_module("owner.rs", &"\n".repeat(MAX_PRODUCTION_LINES + 1)).is_err()
        );
    }

    #[test]
    fn actual_workspace_and_scheduler_keep_the_direction_contract() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        validate(root).unwrap();
    }

    #[test]
    fn optional_strategy_is_physically_absent_from_default_production() {
        assert!(validate_feature_module("mod host;", "host", "script-workflows").is_err());
        assert!(
            validate_feature_module(
                "#[cfg(any(unix, feature = \"script-workflows\"))] mod host;",
                "host",
                "script-workflows"
            )
            .is_err()
        );
        assert!(
            validate_feature_module(
                "#[cfg(feature = \"script-workflows\")] mod host;",
                "host",
                "script-workflows"
            )
            .is_ok()
        );
        assert!(validate_ticket_declaration("mod investigation_convergence;").is_err());
        assert!(
            validate_ticket_declaration(
                "#[cfg(not(feature = \"ticket-investigation\"))] mod investigation_convergence;"
            )
            .is_err()
        );
        assert!(
            validate_ticket_declaration(
                "#[cfg(feature = \"ticket-investigation\")] mod investigation_convergence;"
            )
            .is_ok()
        );
        assert!(validate_ticket_declaration("#[cfg(any(test, feature = \"ticket-investigation\"))] mod investigation_convergence; #[cfg(not(any(test, feature = \"ticket-investigation\")))] #[path = \"runtime/general_turn_strategy.rs\"] mod investigation_convergence;").is_ok());
        assert!(validate_ticket_declaration("#[cfg(any(unix, feature = \"ticket-investigation\"))] mod investigation_convergence;").is_err());
    }

    #[test]
    fn legacy_modules_are_absent_from_default_even_when_unit_tests_compile() {
        let isolated = r#"
            #[cfg(feature = "legacy-plantcore")]
            mod plantcore;
            #[cfg(not(feature = "legacy-plantcore"))]
            #[path = "runtime/plantcore_disabled.rs"]
            mod plantcore;
        "#;
        assert!(validate_legacy_declaration(isolated, "plantcore").is_ok());
        assert!(
            validate_legacy_declaration(
                &isolated.replace(
                    "cfg(feature = \"legacy-plantcore\")",
                    "cfg(any(test, feature = \"legacy-plantcore\"))"
                ),
                "plantcore"
            )
            .is_err()
        );
        assert!(
            validate_legacy_declaration(
                &isolated.replace("#[cfg(feature = \"legacy-plantcore\")]", ""),
                "plantcore"
            )
            .is_err()
        );
        assert!(
            validate_legacy_declaration(&format!("{isolated}\nmod plantcore;"), "plantcore")
                .is_err()
        );
    }
}
