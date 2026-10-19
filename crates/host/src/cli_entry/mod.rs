//! CLI composition ports. Each child owns one launch or presentation responsibility.
//! Explicit value inputs keep runtime session state out of these owners.

pub mod options;
pub use options::{AuthAction, Cli, ConfigAction, LocalCommand};
pub mod prompts;
#[cfg(test)]
pub use prompts::SYSTEM_PROMPT;
pub use prompts::{SystemPromptAssembly, assemble_system_prompt, compaction_summary_prompt};
pub mod tunables;
pub use tunables::tunables_surface_view;
pub mod build_identity;
pub use build_identity::{BUILD_COMMIT, BUILD_DATE, warn_if_stale};
#[cfg(test)]
pub use build_identity::{BUILD_STALE_AFTER_DAYS, build_date_days, long_version, staleness_note};
pub mod permissions;
#[cfg(test)]
pub use permissions::confined_execution;
pub use permissions::{
    admitted_execution_posture, dangerous_bypass_notice, default_permission_mode,
    fresh_permission_bypass, initial_permission_rules, requested_permission_bypass,
    trusted_allow_code,
};
pub mod records;
pub use records::{
    erasure_now_unix_ms, print_timeline, resolve_runs_dir, run_prune_command, run_record_command,
};
pub mod diagnostics;
pub use diagnostics::StderrDiagnosticDrain;
pub mod catalog;
pub use catalog::{
    agent_catalog_snapshot_path, agent_discovery_activity, discover_agent_catalog,
    report_agent_catalog_scan, safe_agent_diagnostic, scan_agent_catalog,
};
pub mod pricing_command;
pub use pricing_command::run_pricing_command;
pub mod one_shot;
#[cfg(test)]
pub use one_shot::build_one_shot_submission;
pub use one_shot::submit_one_shot;

pub mod preflight;

pub mod tool_bootstrap;

pub mod provider_bootstrap;
#[cfg(test)]
pub use provider_bootstrap::BUILTIN_DEFAULT_PROVIDER;
pub use provider_bootstrap::CLI_OVERRIDE_PROVIDER_ID;
#[cfg(all(test, feature = "legacy-plantcore"))]
pub use provider_bootstrap::validate_plantcore_provider_credentials;
pub mod run_options;
#[cfg(test)]
pub use run_options::validate_serve_listen;

pub mod continuation;
pub use tool_bootstrap::load_project_config;

pub mod admitted_view;

pub mod clocks;
pub use clocks::{RUN_ID_NANOS_WITHOUT_FRESH_CLOCK, UNIX_SECS_ON_UNUSABLE_CLOCK};

pub mod route_launch;
