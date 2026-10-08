//! CLI composition ports. Each child owns one launch or presentation responsibility.
//! Explicit value inputs keep runtime session state out of these owners.

mod options;
pub(crate) use options::{AuthAction, Cli, ConfigAction, LocalCommand};
mod prompts;
#[cfg(test)]
pub(crate) use prompts::SYSTEM_PROMPT;
pub(crate) use prompts::{SystemPromptAssembly, assemble_system_prompt, compaction_summary_prompt};
mod tunables;
pub(crate) use tunables::tunables_surface_view;
mod build_identity;
pub(crate) use build_identity::{BUILD_COMMIT, BUILD_DATE, warn_if_stale};
#[cfg(test)]
pub(crate) use build_identity::{
    BUILD_STALE_AFTER_DAYS, build_date_days, long_version, staleness_note,
};
mod permissions;
#[cfg(test)]
pub(crate) use permissions::confined_execution;
pub(crate) use permissions::{
    admitted_execution_posture, dangerous_bypass_notice, default_permission_mode,
    fresh_permission_bypass, initial_permission_rules, requested_permission_bypass,
    trusted_allow_code,
};
mod records;
pub(crate) use records::{
    erasure_now_unix_ms, print_timeline, resolve_runs_dir, run_prune_command, run_record_command,
};
mod diagnostics;
pub(crate) use diagnostics::StderrDiagnosticDrain;
mod catalog;
pub(crate) use catalog::{
    agent_catalog_snapshot_path, agent_discovery_activity, discover_agent_catalog,
    report_agent_catalog_scan, safe_agent_diagnostic, scan_agent_catalog,
};
mod workflow_command;
pub(crate) use workflow_command::run_workflow_command;
mod pricing_command;
pub(crate) use pricing_command::run_pricing_command;
mod one_shot;
#[cfg(test)]
pub(crate) use one_shot::build_one_shot_submission;
pub(crate) use one_shot::submit_one_shot;

pub(crate) mod preflight;

pub(crate) mod frontend;
pub(crate) mod local_commands;
pub(crate) mod tool_bootstrap;

pub(crate) mod provider_bootstrap;
#[cfg(test)]
pub(crate) use provider_bootstrap::BUILTIN_DEFAULT_PROVIDER;
pub(crate) use provider_bootstrap::CLI_OVERRIDE_PROVIDER_ID;
#[cfg(all(test, feature = "legacy-plantcore"))]
pub(crate) use provider_bootstrap::validate_plantcore_provider_credentials;
pub(crate) mod run_options;
#[cfg(test)]
pub(crate) use run_options::validate_serve_listen;

pub(crate) mod continuation;
pub(crate) use tool_bootstrap::load_project_config;

pub(crate) mod admitted_view;

mod clocks;
pub(crate) use clocks::{RUN_ID_NANOS_WITHOUT_FRESH_CLOCK, UNIX_SECS_ON_UNUSABLE_CLOCK};

pub(crate) mod route_launch;
