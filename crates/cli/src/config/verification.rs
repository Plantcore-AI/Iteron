//! Trusted operator configuration for the runtime-effective verification policy.
//!
//! Repository configuration is never passed to this resolver. The workspace completion command
//! remains owned by `--verify`; trusted user configuration may add bounded narrower feedback
//! commands, but those commands can never replace or bypass the final workspace command.

use iteron_verify::{
    FlakyQuarantinePolicy, VerificationCheckpointPolicy, VerificationQuorumPolicy,
    VerificationRestorePolicy, VerificationRollbackMode, VerificationRuntimePolicy,
    VerificationSelectionMode, VerifierPlan,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path};

const MAX_CONFIGURED_RESTORE_PATHS: usize = 1_024;
const MAX_RESTORE_PATH_BYTES: usize = 4_096;
const MAX_CONFIGURED_VERIFICATION_COMMANDS: usize = iteron_verify::MAX_VERIFICATION_COMMANDS - 1;
const MAX_VERIFICATION_COMMAND_BYTES: usize = 4_096;
// Keep the complete approval payload (paths plus exact digests) below the runtime's 16 KiB
// approval-evidence ceiling even at the 1,024-path count bound. The operator must see and durably
// approve the actual destructive scope, not only a truncated summary.
const MAX_AGGREGATE_RESTORE_PATH_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct VerificationConfig {
    pub selection: Option<VerificationSelectionConfig>,
    /// Optional trusted feedback commands. `--verify` is always appended as the final full
    /// workspace gate, so selecting one of these can add earlier feedback but can never turn a
    /// narrow pass into completion.
    pub commands: Vec<VerificationCommandConfig>,
    pub checkpoint: Option<VerificationCheckpointConfig>,
    pub quorum: Option<VerificationQuorumConfig>,
    pub rollback: Option<VerificationRollbackConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerificationCommandConfig {
    pub scope: VerificationCommandScopeConfig,
    pub command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerificationCommandScopeConfig {
    Incremental,
    Impacted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerificationSelectionConfig {
    Incremental,
    Impacted,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct VerificationCheckpointConfig {
    pub turn_boundary: bool,
    pub before_verification: bool,
    pub minimum_turn_interval: u32,
}

impl Default for VerificationCheckpointConfig {
    fn default() -> Self {
        let policy = VerificationCheckpointPolicy::default();
        Self {
            turn_boundary: policy.turn_boundary,
            before_verification: policy.before_verification,
            minimum_turn_interval: policy.minimum_turn_interval,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct VerificationQuorumConfig {
    pub verifiers: u8,
    pub required_agreement: u8,
    pub strong_veto: bool,
}

impl Default for VerificationQuorumConfig {
    fn default() -> Self {
        let policy = VerificationQuorumPolicy::default();
        Self {
            verifiers: policy.verifiers,
            required_agreement: policy.required_agreement,
            strong_veto: policy.strong_veto,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct VerificationRollbackConfig {
    pub mode: VerificationRollbackConfigMode,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerificationRollbackConfigMode {
    #[default]
    Off,
    SelectedPaths,
    Workspace,
}

impl VerificationConfig {
    pub(crate) fn resolve(
        &self,
        workspace: &Path,
        verify_command: Option<&str>,
        verifier_plan: Option<&VerifierPlan>,
    ) -> Result<VerificationRuntimePolicy, String> {
        // Absence is deliberately conservative: a lane-capable verifier is permission to run a
        // narrower loop, not evidence that the operator selected one. Only trusted user config
        // may move the effective mode away from full verification.
        let derived_selection = VerificationSelectionMode::Full;
        let selection = self
            .selection
            .map_or(derived_selection, |selection| match selection {
                VerificationSelectionConfig::Incremental => VerificationSelectionMode::Incremental,
                VerificationSelectionConfig::Impacted => VerificationSelectionMode::Impacted,
                VerificationSelectionConfig::Full => VerificationSelectionMode::Full,
            });
        validate_commands(&self.commands, verify_command)?;

        // A narrow command is advisory even though its oracle is physically strong. Completion
        // still requires the exact operator-owned `--verify` command at workspace scope. If the
        // requested scope has no trusted command, conservatively upgrade to full rather than
        // claiming an incremental/impacted run that never existed.
        let narrow_commands = self
            .commands
            .iter()
            .filter(|entry| {
                matches!(
                    (selection, entry.scope),
                    (
                        VerificationSelectionMode::Incremental,
                        VerificationCommandScopeConfig::Incremental
                    ) | (
                        VerificationSelectionMode::Impacted,
                        VerificationCommandScopeConfig::Impacted
                    )
                )
            })
            .map(|entry| entry.command.clone())
            .collect::<Vec<_>>();
        let selection =
            if selection != VerificationSelectionMode::Full && narrow_commands.is_empty() {
                VerificationSelectionMode::Full
            } else {
                selection
            };

        let checkpoint = self.checkpoint.as_ref().map_or_else(
            VerificationCheckpointPolicy::default,
            |configured| VerificationCheckpointPolicy {
                turn_boundary: configured.turn_boundary,
                before_verification: configured.before_verification,
                // Drain's durable checkpoint is a session safety invariant, not an operator knob.
                before_drain: true,
                minimum_turn_interval: configured.minimum_turn_interval,
            },
        );
        let quorum =
            self.quorum
                .as_ref()
                .map_or_else(VerificationQuorumPolicy::default, |configured| {
                    VerificationQuorumPolicy {
                        verifiers: configured.verifiers,
                        required_agreement: configured.required_agreement,
                        strong_veto: configured.strong_veto,
                    }
                });
        let restore = resolve_restore(workspace, self.rollback.as_ref())?;
        let flaky = verifier_plan.map_or_else(FlakyQuarantinePolicy::default, |plan| {
            FlakyQuarantinePolicy {
                repeat_count: u8::try_from(plan.attempts).unwrap_or(u8::MAX),
                minimum_disagreements: 1,
                quarantine_seconds: 0,
                report_disagreement: plan.report_flake,
            }
        });
        let mut required_commands = if selection == VerificationSelectionMode::Full {
            Vec::new()
        } else {
            narrow_commands
        };
        if let Some(command) = verify_command {
            required_commands.push(command.to_owned());
        }
        let max_commands = u16::try_from(required_commands.len().max(1))
            .map_err(|_| "verification command count exceeds its bounded ceiling".to_owned())?;
        let policy = VerificationRuntimePolicy {
            selection,
            required_commands,
            max_commands,
            flaky,
            quorum,
            checkpoint,
            restore,
            ..VerificationRuntimePolicy::default()
        };
        policy
            .validate()
            .map_err(|error| format!("invalid trusted verification policy: {error}"))?;
        Ok(policy)
    }
}

fn validate_commands(
    commands: &[VerificationCommandConfig],
    full_command: Option<&str>,
) -> Result<(), String> {
    if commands.len()
        > iteron_tunables::param_integer(
            "cli.config.verification.max_configured_verification_commands",
            MAX_CONFIGURED_VERIFICATION_COMMANDS,
        )
    {
        return Err(format!(
            "trusted verification commands exceed their {}-command ceiling",
            iteron_tunables::param_integer(
                "cli.config.verification.max_configured_verification_commands",
                MAX_CONFIGURED_VERIFICATION_COMMANDS
            )
        ));
    }
    if !commands.is_empty() && full_command.is_none() {
        return Err(
            "trusted narrow verification commands require `--verify` as the full workspace gate"
                .into(),
        );
    }
    let mut seen = BTreeSet::new();
    for entry in commands {
        if entry.command.is_empty()
            || entry.command.len()
                > iteron_tunables::param_integer(
                    "cli.config.verification.max_verification_command_bytes",
                    MAX_VERIFICATION_COMMAND_BYTES,
                )
            || entry.command.contains('\0')
        {
            return Err("trusted verification command is outside its byte bound".into());
        }
        if full_command == Some(entry.command.as_str()) {
            return Err(
                "a narrow verification command must differ from the full workspace gate".into(),
            );
        }
        if !seen.insert(entry.command.as_str()) {
            return Err("trusted verification commands must be unique".into());
        }
    }
    Ok(())
}

fn resolve_restore(
    workspace: &Path,
    configured: Option<&VerificationRollbackConfig>,
) -> Result<VerificationRestorePolicy, String> {
    let Some(configured) = configured else {
        return Ok(VerificationRestorePolicy::default());
    };
    let mode = match configured.mode {
        VerificationRollbackConfigMode::Off => VerificationRollbackMode::Off,
        VerificationRollbackConfigMode::SelectedPaths => VerificationRollbackMode::SelectedPaths,
        VerificationRollbackConfigMode::Workspace => VerificationRollbackMode::Workspace,
    };
    if mode != VerificationRollbackMode::SelectedPaths && !configured.paths.is_empty() {
        return Err("verification rollback paths require mode `selected_paths`".into());
    }
    if mode == VerificationRollbackMode::SelectedPaths
        && (configured.paths.is_empty()
            || configured.paths.len()
                > iteron_tunables::param_integer(
                    "cli.config.verification.max_configured_restore_paths",
                    MAX_CONFIGURED_RESTORE_PATHS,
                ))
    {
        return Err(format!(
            "selected verification rollback requires 1..={MAX_CONFIGURED_RESTORE_PATHS} paths"
        ));
    }
    let mut seen = BTreeSet::new();
    let mut aggregate_bytes = 0usize;
    let mut paths = Vec::with_capacity(configured.paths.len());
    for path in &configured.paths {
        let path = normalize_restore_path(workspace, path)?;
        aggregate_bytes = aggregate_bytes
            .checked_add(path.len())
            .ok_or_else(|| "verification rollback path bytes overflowed".to_owned())?;
        if aggregate_bytes
            > iteron_tunables::param_integer(
                "cli.config.verification.max_aggregate_restore_path_bytes",
                MAX_AGGREGATE_RESTORE_PATH_BYTES,
            )
        {
            return Err("verification rollback paths exceed their aggregate byte ceiling".into());
        }
        if !seen.insert(path.clone()) {
            return Err(format!("duplicate verification rollback path `{path}`"));
        }
        paths.push(path);
    }
    paths.sort();
    Ok(VerificationRestorePolicy {
        mode,
        paths,
        // This field is intentionally absent from every serde config shape. A live exact approval
        // receipt is required immediately before the restore effect.
        require_operator_confirmation: true,
    })
}

fn normalize_restore_path(workspace: &Path, value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len()
            > iteron_tunables::param_integer(
                "cli.config.verification.max_restore_path_bytes",
                MAX_RESTORE_PATH_BYTES,
            )
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err("verification rollback path is outside its byte/character bound".into());
    }
    let mut components = Vec::new();
    for component in Path::new(value).components() {
        match component {
            Component::Normal(component) => components.push(component.to_owned()),
            Component::CurDir if components.is_empty() => {}
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("verification rollback path must remain repository-relative".into());
            }
        }
    }
    if components.is_empty()
        || components.first().is_some_and(|component| {
            component == std::ffi::OsStr::new(".git")
                || component == std::ffi::OsStr::new(iteron_protocol::home::HOME_DIR)
        })
    {
        return Err("verification rollback path targets protected runtime metadata".into());
    }
    let normalized = components.iter().collect::<std::path::PathBuf>();
    let normalized = normalized
        .to_str()
        .ok_or_else(|| "verification rollback path must be UTF-8".to_owned())?
        .replace(std::path::MAIN_SEPARATOR, "/");

    // Refuse a currently symlinked ancestor. The record restore owner repeats this check at the
    // mutation boundary, closing the time-of-check/time-of-use window.
    let mut parent = workspace.to_path_buf();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        parent.push(component);
        match std::fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("verification rollback path traverses a symbolic link".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(format!(
                    "verification rollback path is unavailable: {error}"
                ));
            }
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_config_cannot_serialize_or_deserialize_confirmation_bypass() {
        let rejected = serde_json::from_str::<VerificationConfig>(
            r#"{"rollback":{"mode":"workspace","require_operator_confirmation":false}}"#,
        );
        assert!(rejected.is_err());
        let encoded = serde_json::to_string(&VerificationConfig::default()).unwrap();
        assert!(!encoded.contains("require_operator_confirmation"));
    }

    #[test]
    fn selected_restore_paths_are_normalized_bounded_and_runtime_private_paths_are_refused() {
        let workspace = std::env::temp_dir();
        let configured: VerificationConfig = serde_json::from_str(
            r#"{"rollback":{"mode":"selected_paths","paths":["src/./lib.rs"]}}"#,
        )
        .unwrap();
        let policy = configured.resolve(&workspace, Some("check"), None).unwrap();
        assert_eq!(policy.restore.paths, ["src/lib.rs"]);
        for path in ["../outside", "/absolute", ".git/config", ".iteron/runs/x"] {
            let configured: VerificationConfig = serde_json::from_value(serde_json::json!({
                "rollback": {"mode": "selected_paths", "paths": [path]}
            }))
            .unwrap();
            assert!(configured.resolve(&workspace, Some("check"), None).is_err());
        }
    }

    #[test]
    fn repository_verification_policy_never_becomes_the_trusted_owner() {
        let user = crate::config::FileConfig::default();
        let project = crate::config::FileConfig::parse(
            r#"{"schema_version":2,"verification":{"quorum":{"verifiers":9}}}"#,
        )
        .unwrap();
        assert!(crate::config::trusted_verification_config(&user, &project).is_none());
    }

    #[test]
    fn trusted_commands_materialize_distinct_scopes_with_a_mandatory_full_gate() {
        let workspace = std::env::temp_dir();
        let base = serde_json::json!({
            "commands": [
                {"scope": "incremental", "command": "trusted-incremental"},
                {"scope": "impacted", "command": "trusted-impacted"}
            ]
        });
        for (selection, expected_mode, expected_commands) in [
            (
                "incremental",
                VerificationSelectionMode::Incremental,
                vec!["trusted-incremental", "trusted-full"],
            ),
            (
                "impacted",
                VerificationSelectionMode::Impacted,
                vec!["trusted-impacted", "trusted-full"],
            ),
            (
                "full",
                VerificationSelectionMode::Full,
                vec!["trusted-full"],
            ),
        ] {
            let mut value = base.clone();
            value["selection"] = serde_json::Value::String(selection.into());
            let configured: VerificationConfig = serde_json::from_value(value).unwrap();
            let policy = configured
                .resolve(&workspace, Some("trusted-full"), None)
                .unwrap();
            assert_eq!(policy.selection, expected_mode);
            assert_eq!(
                policy.required_commands,
                expected_commands
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            );
            assert_eq!(policy.selected_commands(), policy.required_commands);
        }
    }

    #[test]
    fn unsupported_narrow_scope_upgrades_to_full_and_narrow_commands_need_a_full_gate() {
        let workspace = std::env::temp_dir();
        let configured: VerificationConfig = serde_json::from_value(serde_json::json!({
            "selection": "impacted",
            "commands": [
                {"scope": "incremental", "command": "trusted-incremental"}
            ]
        }))
        .unwrap();
        let policy = configured
            .resolve(&workspace, Some("trusted-full"), None)
            .unwrap();
        assert_eq!(policy.selection, VerificationSelectionMode::Full);
        assert_eq!(policy.required_commands, ["trusted-full"]);
        assert!(configured.resolve(&workspace, None, None).is_err());
    }
}
