//! Version-neutral decoder and installer for process/LSP session ownership.

use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use iteron_tools::{
    ChildProcessEnvironmentPolicy, EgressAllowPolicy, InteractiveStdinWaitPolicy, LspLanguageRoute,
    LspRecoveryPolicy, LspRuntimePolicy, PersistentBackendSelection, ProcessCwdPolicy,
    ProcessCwdScope, ProcessLaunchPolicy, ProcessRuntimePolicy, Registry,
};
use iteron_tunables::{ResolutionValue, RuntimeGetterId};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub(crate) struct EffectiveToolingSettings {
    pub egress_allow: Option<EgressAllowPolicy>,
    pub observation: iteron_tools::ObservationToolPolicy,
    pub process: ProcessRuntimePolicy,
    pub process_launch: ProcessLaunchPolicy,
    pub lsp: Option<LspRuntimePolicy>,
    pub tool_output_spill: crate::runtime::tool_output_spill::ToolOutputSpillPolicy,
    pub tool_result_cache_ttl_seconds: u64,
}

impl EffectiveToolingSettings {
    pub(crate) fn decode(view: &EffectiveTunablesView) -> Result<Self, EffectiveToolingError> {
        view.with_getter(RuntimeGetterId::EffectiveTooling, || {
            Self::decode_inner(view)
        })
    }

    fn decode_inner(view: &EffectiveTunablesView) -> Result<Self, EffectiveToolingError> {
        let egress_allow = view
            .optional_value("egress_allow")
            .map(decode_egress_allow)
            .transpose()?;
        let observation = super::effective_observation_tools::decode(view)
            .map_err(|error| EffectiveToolingError::InvalidOwner(error.to_string()))?;
        let backend = match view.enumeration("persistent_pty_backend")? {
            "disabled" => PersistentBackendSelection::Disabled,
            "one_shot" => PersistentBackendSelection::OneShot,
            "persistent" => PersistentBackendSelection::Persistent,
            value => return Err(unknown("persistent_pty_backend", value)),
        };
        let stdin = view.object("interactive_stdin_wait_policy")?;
        let process = ProcessRuntimePolicy::new(
            backend,
            usizev(
                view.integer("concurrent_background_job_cap")?,
                "concurrent_background_job_cap",
            )?,
            u64v(
                view.integer("job_idle_stall_timeout")?,
                "job_idle_stall_timeout",
            )?,
            InteractiveStdinWaitPolicy {
                poll_milliseconds: object_u64(
                    stdin,
                    "interactive_stdin_wait_policy",
                    "poll_milliseconds",
                )?,
                idle_timeout_milliseconds: object_u64(
                    stdin,
                    "interactive_stdin_wait_policy",
                    "idle_timeout_milliseconds",
                )?,
                operator_prompt: object_bool(
                    stdin,
                    "interactive_stdin_wait_policy",
                    "operator_prompt",
                )?,
            },
        )
        .map_err(|error| EffectiveToolingError::InvalidOwner(error.to_string()))?;
        let cwd = view.object("process_cwd_continuity")?;
        let scope = match object_enum(cwd, "process_cwd_continuity", "scope")? {
            "job" => ProcessCwdScope::Job,
            value => return Err(unknown("process_cwd_continuity", value)),
        };
        let environment = view.object("child_process_environment_reuse")?;
        let process_launch = ProcessLaunchPolicy::new(
            ProcessCwdPolicy {
                scope,
                initial_cwd: PathBuf::from(object_text(
                    cwd,
                    "process_cwd_continuity",
                    "initial_cwd",
                )?),
                preserve_changes: object_bool(cwd, "process_cwd_continuity", "preserve_changes")?,
            },
            ChildProcessEnvironmentPolicy {
                reuse: object_bool(environment, "child_process_environment_reuse", "reuse")?,
                max_entries: usizev(
                    object_i64(
                        environment,
                        "child_process_environment_reuse",
                        "max_entries",
                    )?,
                    "child_process_environment_reuse",
                )?,
                max_bytes: usizev(
                    object_i64(environment, "child_process_environment_reuse", "max_bytes")?,
                    "child_process_environment_reuse",
                )?,
                blocked_names: object_text_list(
                    environment,
                    "child_process_environment_reuse",
                    "blocked_names",
                )?,
            },
        )
        .map_err(|error| EffectiveToolingError::InvalidOwner(error.to_string()))?;

        let routes = view.optional_value("lsp_server_language_selection");
        let recovery = view.optional_value("lsp_timeout_restart_policy");
        let lsp = match (routes, recovery) {
            (None, None) => None,
            (Some(routes), Some(ResolutionValue::Object { fields })) => Some(
                LspRuntimePolicy::new(decode_routes(routes)?, decode_recovery(fields)?)
                    .map_err(|error| EffectiveToolingError::InvalidOwner(error.to_string()))?,
            ),
            _ => return Err(EffectiveToolingError::IncompleteLspPolicy),
        };
        let tool_output_spill = decode_tool_output_spill_policy(view)?;
        let tool_result_cache_ttl_seconds = u64v(
            view.integer("tool_result_cache_ttl")?,
            "tool_result_cache_ttl",
        )?;
        Ok(Self {
            egress_allow,
            observation,
            process,
            process_launch,
            lsp,
            tool_output_spill,
            tool_result_cache_ttl_seconds,
        })
    }

    pub(crate) fn install(&self, registry: &Registry) -> Result<(), EffectiveToolingError> {
        registry
            .install_observation_tool_policy(self.observation)
            .map_err(|error| EffectiveToolingError::Install(error.to_string()))?;
        registry
            .install_egress_allow_policy(self.egress_allow.clone())
            .map_err(|error| EffectiveToolingError::Install(error.to_string()))?;
        registry
            .install_tool_result_cache_ttl(self.tool_result_cache_ttl_seconds)
            .map_err(|error| EffectiveToolingError::Install(error.to_string()))?;
        registry
            .install_process_launch_policy(self.process_launch.clone())
            .map_err(|error| EffectiveToolingError::Install(error.to_string()))?;
        if let Some(control) = registry.process_control() {
            control
                .configure_policy(self.process)
                .map_err(|error| EffectiveToolingError::Install(error.message))?;
        }
        match (registry.lsp_control(), &self.lsp) {
            (Some(control), Some(policy)) => control
                .configure_policy(policy.clone())
                .map_err(|error| EffectiveToolingError::Install(error.message))?,
            (Some(_), None) => return Err(EffectiveToolingError::IncompleteLspPolicy),
            (None, _) => {}
        }
        Ok(())
    }

    /// Adoption cannot reinstall process-scoped owners. It must prove that the historical pin is
    /// byte-for-byte compatible with the already-live registry before swapping journals.
    pub(crate) fn verify_installed(
        &self,
        registry: &Registry,
    ) -> Result<(), EffectiveToolingError> {
        if registry.installed_observation_tool_policy() != Some(self.observation)
            || registry.installed_egress_allow_policy() != Some(self.egress_allow.clone())
            || registry.tool_result_cache_ttl_seconds() != self.tool_result_cache_ttl_seconds
            || registry.installed_process_launch_policy() != Some(self.process_launch.clone())
            || registry
                .process_control()
                .is_some_and(|control| control.policy() != self.process)
            || match (registry.lsp_control(), &self.lsp) {
                (Some(control), Some(policy)) => control.policy() != *policy,
                (Some(_), None) => true,
                (None, _) => false,
            }
        {
            return Err(EffectiveToolingError::Install(
                "adopted tooling checkpoint differs from the live process owner".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn decode_tool_output_spill_policy(
    view: &EffectiveTunablesView,
) -> Result<crate::runtime::tool_output_spill::ToolOutputSpillPolicy, EffectiveToolingError> {
    use crate::runtime::tool_output_spill::{ToolOutputSpillCleanup, ToolOutputSpillPolicy};

    let family = "tool_output_spill_to_disk_policy";
    let fields = view.object(family)?;
    if !object_bool(fields, family, "private_storage")? {
        return Err(EffectiveToolingError::InvalidOwner(
            "ordinary tool overflow storage cannot be made public".into(),
        ));
    }
    let cleanup = match object_enum(fields, family, "cleanup")? {
        "tool_end" => ToolOutputSpillCleanup::ToolEnd,
        "turn_end" => ToolOutputSpillCleanup::TurnEnd,
        "run_end" => ToolOutputSpillCleanup::RunEnd,
        value => return Err(unknown(family, value)),
    };
    ToolOutputSpillPolicy::new(
        usizev(
            object_i64(fields, family, "memory_threshold_bytes")?,
            family,
        )?,
        usizev(object_i64(fields, family, "spill_max_bytes")?, family)?,
        cleanup,
    )
    .map_err(|error| EffectiveToolingError::InvalidOwner(error.to_string()))
}

fn decode_egress_allow(
    value: &ResolutionValue,
) -> Result<EgressAllowPolicy, EffectiveToolingError> {
    let ResolutionValue::List { items } = value else {
        return Err(wrong("egress_allow", "list"));
    };
    let destinations = items
        .iter()
        .map(|item| match item {
            ResolutionValue::Text { value } => Ok(value.clone()),
            _ => Err(wrong("egress_allow", "text-list member")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    EgressAllowPolicy::new(destinations)
        .map_err(|error| EffectiveToolingError::InvalidOwner(error.to_string()))
}

fn decode_routes(value: &ResolutionValue) -> Result<Vec<LspLanguageRoute>, EffectiveToolingError> {
    let ResolutionValue::List { items } = value else {
        return Err(wrong("lsp_server_language_selection", "list"));
    };
    items
        .iter()
        .map(|item| {
            let ResolutionValue::Object { fields } = item else {
                return Err(wrong("lsp_server_language_selection", "object entries"));
            };
            Ok(LspLanguageRoute {
                language_id: object_text(fields, "lsp_server_language_selection", "language_id")?
                    .to_owned(),
                server_id: object_text(fields, "lsp_server_language_selection", "server_id")?
                    .to_owned(),
                executable: object_text(fields, "lsp_server_language_selection", "executable")?
                    .to_owned(),
                arguments: object_text_list(fields, "lsp_server_language_selection", "arguments")?,
                workspace_markers: object_text_list(
                    fields,
                    "lsp_server_language_selection",
                    "workspace_markers",
                )?,
            })
        })
        .collect()
}

fn decode_recovery(
    fields: &BTreeMap<String, ResolutionValue>,
) -> Result<LspRecoveryPolicy, EffectiveToolingError> {
    LspRecoveryPolicy {
        request_timeout_milliseconds: object_u64(
            fields,
            "lsp_timeout_restart_policy",
            "request_timeout_milliseconds",
        )?,
        max_restarts: u32::try_from(object_u64(
            fields,
            "lsp_timeout_restart_policy",
            "max_restarts",
        )?)
        .map_err(|_| range("lsp_timeout_restart_policy"))?,
        backoff_base_milliseconds: object_u64(
            fields,
            "lsp_timeout_restart_policy",
            "backoff_base_milliseconds",
        )?,
        backoff_cap_milliseconds: object_u64(
            fields,
            "lsp_timeout_restart_policy",
            "backoff_cap_milliseconds",
        )?,
    }
    .validate()
    .map_err(|error| EffectiveToolingError::InvalidOwner(error.to_string()))
}

fn object_u64(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<u64, EffectiveToolingError> {
    match fields.get(field) {
        Some(ResolutionValue::Integer { value }) => u64v(*value, family),
        Some(_) => Err(wrong(family, "integer object field")),
        None => Err(EffectiveToolingError::MissingField { family, field }),
    }
}

fn object_i64(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<i64, EffectiveToolingError> {
    match fields.get(field) {
        Some(ResolutionValue::Integer { value }) => Ok(*value),
        Some(_) => Err(wrong(family, "integer object field")),
        None => Err(EffectiveToolingError::MissingField { family, field }),
    }
}

fn object_bool(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<bool, EffectiveToolingError> {
    match fields.get(field) {
        Some(ResolutionValue::Boolean { value }) => Ok(*value),
        Some(_) => Err(wrong(family, "boolean object field")),
        None => Err(EffectiveToolingError::MissingField { family, field }),
    }
}

fn object_text<'a>(
    fields: &'a BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<&'a str, EffectiveToolingError> {
    match fields.get(field) {
        Some(ResolutionValue::Text { value }) => Ok(value),
        Some(_) => Err(wrong(family, "text object field")),
        None => Err(EffectiveToolingError::MissingField { family, field }),
    }
}

fn object_enum<'a>(
    fields: &'a BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<&'a str, EffectiveToolingError> {
    match fields.get(field) {
        Some(ResolutionValue::Enum { value }) => Ok(value),
        Some(_) => Err(wrong(family, "enum object field")),
        None => Err(EffectiveToolingError::MissingField { family, field }),
    }
}

fn object_text_list(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<Vec<String>, EffectiveToolingError> {
    let Some(value) = fields.get(field) else {
        // `arguments` was added after the first V2 snapshots. Absence is the exact empty argv.
        return if field == "arguments" {
            Ok(Vec::new())
        } else {
            Err(EffectiveToolingError::MissingField { family, field })
        };
    };
    let ResolutionValue::List { items } = value else {
        return Err(wrong(family, "text-list object field"));
    };
    items
        .iter()
        .map(|item| match item {
            ResolutionValue::Text { value } => Ok(value.clone()),
            _ => Err(wrong(family, "text-list member")),
        })
        .collect()
}

fn u64v(value: i64, family: &'static str) -> Result<u64, EffectiveToolingError> {
    u64::try_from(value).map_err(|_| range(family))
}

fn usizev(value: i64, family: &'static str) -> Result<usize, EffectiveToolingError> {
    usize::try_from(value).map_err(|_| range(family))
}

fn wrong(family: &'static str, expected: &'static str) -> EffectiveToolingError {
    EffectiveToolingError::WrongType { family, expected }
}

fn range(family: &'static str) -> EffectiveToolingError {
    EffectiveToolingError::Range { family }
}

fn unknown(family: &'static str, value: &str) -> EffectiveToolingError {
    EffectiveToolingError::UnknownValue {
        family,
        value: value.to_owned(),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EffectiveToolingError {
    #[error(transparent)]
    View(#[from] EffectiveViewError),
    #[error("effective tunable `{family}` has the wrong type; expected {expected}")]
    WrongType {
        family: &'static str,
        expected: &'static str,
    },
    #[error("effective tunable `{family}` is outside the runtime type range")]
    Range { family: &'static str },
    #[error("effective tunable `{family}` is missing object field `{field}`")]
    MissingField {
        family: &'static str,
        field: &'static str,
    },
    #[error("effective tunable `{family}` contains unknown value `{value}`")]
    UnknownValue { family: &'static str, value: String },
    #[error("effective LSP route/recovery policy is only partially present")]
    IncompleteLspPolicy,
    #[error("resolved tooling policy violates its production owner: {0}")]
    InvalidOwner(String),
    #[error("resolved tooling policy could not be installed before activation: {0}")]
    Install(String),
}
