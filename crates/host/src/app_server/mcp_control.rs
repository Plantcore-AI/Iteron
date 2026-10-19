//! Immediate operator controls for the session-owned MCP supervisors.

use super::{ControlReply, McpControl, McpControlReply};

pub(super) async fn apply_mcp_control(
    runtime: Option<&crate::mcp::McpRuntimeControl>,
    control: McpControl,
) -> ControlReply {
    let Some(runtime) = runtime else {
        return match control {
            McpControl::Status => ControlReply::Mcp(Box::new(McpControlReply {
                servers: Vec::new(),
                notice: None,
            })),
            McpControl::Cancel { .. } | McpControl::Restart { .. } | McpControl::Stop { .. } => {
                ControlReply::Refused("this session has no configured MCP servers".into())
            }
        };
    };

    let notice = match control {
        McpControl::Status => None,
        McpControl::Cancel { server } => {
            if !runtime.cancel(&server) {
                return ControlReply::Refused(format!("unknown MCP server `{server}`"));
            }
            Some(format!("cancellation requested for MCP server `{server}`"))
        }
        McpControl::Restart { server } => match runtime.restart(&server).await {
            Ok(()) => Some(format!(
                "MCP server `{server}` reset; its next request reconnects lazily"
            )),
            Err(reason) => {
                return ControlReply::Refused(format!(
                    "could not restart MCP server `{server}`: {reason}"
                ));
            }
        },
        McpControl::Stop { server } => match runtime.stop(&server).await {
            Ok(()) => Some(format!("MCP server `{server}` stopped")),
            Err(reason) => {
                return ControlReply::Refused(format!(
                    "could not stop MCP server `{server}`: {reason}"
                ));
            }
        },
    };

    ControlReply::Mcp(Box::new(McpControlReply {
        servers: runtime.health(),
        notice,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn absent_runtime_reports_empty_status_but_refuses_mutation() {
        let ControlReply::Mcp(status) = apply_mcp_control(None, McpControl::Status).await else {
            panic!("status must remain queryable without configured servers");
        };
        assert!(status.servers.is_empty());

        let reply = apply_mcp_control(
            None,
            McpControl::Stop {
                server: "missing".into(),
            },
        )
        .await;
        assert!(matches!(reply, ControlReply::Refused(_)));
    }
}
