//! Version-neutral decoder for the MCP lifecycle families owned by the session runtime.
//!
//! Fresh and resumed sessions both arrive here through [`EffectiveTunablesView`]. No MCP
//! connection is allowed to start until this projection succeeds, which prevents reconnect,
//! deadline, and result-spill behavior from falling back to process-local defaults on resume.

use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use iteron_mcp::{
    McpDeadlinePolicy, McpResultPolicy, McpSpillCleanup, McpTransportDeadlines,
    reconnect::ReconnectPolicy,
};
use iteron_tunables::ResolutionValue;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EffectiveMcpSettings {
    pub reconnect: ReconnectPolicy,
    pub deadlines: McpDeadlinePolicy,
    pub result: McpResultPolicy,
}

impl EffectiveMcpSettings {
    pub(crate) fn decode(view: &EffectiveTunablesView) -> Result<Self, EffectiveMcpError> {
        let reconnect = view.object("mcp_reconnect_backoff")?;
        let reconnect = ReconnectPolicy::new(
            u32v(
                field(reconnect, "mcp_reconnect_backoff", "max_attempts")?,
                "mcp_reconnect_backoff",
            )?,
            u64v(
                field(reconnect, "mcp_reconnect_backoff", "base_milliseconds")?,
                "mcp_reconnect_backoff",
            )?,
            u64v(
                field(reconnect, "mcp_reconnect_backoff", "cap_milliseconds")?,
                "mcp_reconnect_backoff",
            )?,
        )
        .map_err(|error| invalid("mcp_reconnect_backoff", error))?;

        let startup = view.object("per_server_startup_deadline")?;
        let tool = view.object("per_tool_mcp_deadline")?;
        let stdio = McpTransportDeadlines::new(
            u64v(
                field(startup, "per_server_startup_deadline", "stdio_milliseconds")?,
                "per_server_startup_deadline",
            )?,
            u64v(
                field(tool, "per_tool_mcp_deadline", "stdio_milliseconds")?,
                "per_tool_mcp_deadline",
            )?,
        )
        .map_err(|reason| EffectiveMcpError::InvalidOwner {
            family: "per_server_startup_deadline/per_tool_mcp_deadline",
            reason: reason.into(),
        })?;
        let http = McpTransportDeadlines::new(
            u64v(
                field(startup, "per_server_startup_deadline", "http_milliseconds")?,
                "per_server_startup_deadline",
            )?,
            u64v(
                field(tool, "per_tool_mcp_deadline", "http_milliseconds")?,
                "per_tool_mcp_deadline",
            )?,
        )
        .map_err(|reason| EffectiveMcpError::InvalidOwner {
            family: "per_server_startup_deadline/per_tool_mcp_deadline",
            reason: reason.into(),
        })?;

        let result = view.object("mcp_result_cap_spill_policy")?;
        if !bool_field(result, "mcp_result_cap_spill_policy", "private_storage")? {
            return Err(EffectiveMcpError::InvalidOwner {
                family: "mcp_result_cap_spill_policy",
                reason: "MCP overflow storage cannot be made public".into(),
            });
        }
        let cleanup = match text_field(result, "mcp_result_cap_spill_policy", "cleanup")? {
            "tool_end" => McpSpillCleanup::ToolEnd,
            "turn_end" => McpSpillCleanup::TurnEnd,
            "run_end" => McpSpillCleanup::RunEnd,
            "session_end" => McpSpillCleanup::SessionEnd,
            other => {
                return Err(EffectiveMcpError::UnsupportedCleanup(other.to_owned()));
            }
        };
        let result = McpResultPolicy::new(
            usizev(
                field(result, "mcp_result_cap_spill_policy", "visible_max_bytes")?,
                "mcp_result_cap_spill_policy",
            )?,
            usizev(
                field(result, "mcp_result_cap_spill_policy", "spill_max_bytes")?,
                "mcp_result_cap_spill_policy",
            )?,
            cleanup,
        )
        .map_err(|error| invalid("mcp_result_cap_spill_policy", error))?;

        Ok(Self {
            reconnect,
            deadlines: McpDeadlinePolicy::new(stdio, http),
            result,
        })
    }
}

fn field(
    values: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<i64, EffectiveMcpError> {
    match values.get(field) {
        Some(ResolutionValue::Integer { value }) => Ok(*value),
        Some(_) => Err(EffectiveMcpError::WrongFieldType { family, field }),
        None => Err(EffectiveMcpError::MissingField { family, field }),
    }
}

fn bool_field(
    values: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<bool, EffectiveMcpError> {
    match values.get(field) {
        Some(ResolutionValue::Boolean { value }) => Ok(*value),
        Some(_) => Err(EffectiveMcpError::WrongFieldType { family, field }),
        None => Err(EffectiveMcpError::MissingField { family, field }),
    }
}

fn text_field<'a>(
    values: &'a BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<&'a str, EffectiveMcpError> {
    match values.get(field) {
        Some(ResolutionValue::Enum { value } | ResolutionValue::Text { value }) => Ok(value),
        Some(_) => Err(EffectiveMcpError::WrongFieldType { family, field }),
        None => Err(EffectiveMcpError::MissingField { family, field }),
    }
}

fn u64v(value: i64, family: &'static str) -> Result<u64, EffectiveMcpError> {
    u64::try_from(value).map_err(|_| EffectiveMcpError::Range { family })
}

fn u32v(value: i64, family: &'static str) -> Result<u32, EffectiveMcpError> {
    u32::try_from(value).map_err(|_| EffectiveMcpError::Range { family })
}

fn usizev(value: i64, family: &'static str) -> Result<usize, EffectiveMcpError> {
    usize::try_from(value).map_err(|_| EffectiveMcpError::Range { family })
}

fn invalid(family: &'static str, error: iteron_mcp::McpError) -> EffectiveMcpError {
    EffectiveMcpError::InvalidOwner {
        family,
        reason: error.public_summary(),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EffectiveMcpError {
    #[error(transparent)]
    View(#[from] EffectiveViewError),
    #[error("effective MCP tunable `{family}` is outside the runtime type range")]
    Range { family: &'static str },
    #[error("effective MCP tunable `{family}` is missing object field `{field}`")]
    MissingField {
        family: &'static str,
        field: &'static str,
    },
    #[error("effective MCP tunable `{family}` object field `{field}` has the wrong type")]
    WrongFieldType {
        family: &'static str,
        field: &'static str,
    },
    #[error("effective MCP tunable `{family}` violates its production owner: {reason}")]
    InvalidOwner {
        family: &'static str,
        reason: String,
    },
    #[error("MCP spill cleanup `{0}` is not implementable by the current session-owned store")]
    UnsupportedCleanup(String),
}
