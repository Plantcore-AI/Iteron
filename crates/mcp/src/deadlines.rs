//! Transport-specific MCP deadline ownership.
//!
//! A single scalar cannot describe stdio process handshakes and remote HTTP exchanges: they have
//! different failure domains and intentionally different bounds. This immutable policy is sampled
//! by both production clients and by the runtime tunables evidence adapter.

use std::time::Duration;

pub const MAX_MCP_DEADLINE_MILLISECONDS: u64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct McpTransportDeadlines {
    startup_milliseconds: u64,
    tool_call_milliseconds: u64,
}

impl McpTransportDeadlines {
    pub const fn new(
        startup_milliseconds: u64,
        tool_call_milliseconds: u64,
    ) -> Result<Self, &'static str> {
        if startup_milliseconds == 0 || startup_milliseconds > MAX_MCP_DEADLINE_MILLISECONDS {
            return Err("MCP startup deadline is outside 1..=86400000 milliseconds");
        }
        if tool_call_milliseconds == 0 || tool_call_milliseconds > MAX_MCP_DEADLINE_MILLISECONDS {
            return Err("MCP tool deadline is outside 1..=86400000 milliseconds");
        }
        Ok(Self {
            startup_milliseconds,
            tool_call_milliseconds,
        })
    }

    pub const fn startup_milliseconds(self) -> u64 {
        self.startup_milliseconds
    }

    pub const fn tool_call_milliseconds(self) -> u64 {
        self.tool_call_milliseconds
    }

    pub fn startup(self) -> Duration {
        Duration::from_millis(self.startup_milliseconds)
    }

    pub fn tool_call(self) -> Duration {
        Duration::from_millis(self.tool_call_milliseconds)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct McpDeadlinePolicy {
    stdio: McpTransportDeadlines,
    http: McpTransportDeadlines,
}

impl McpDeadlinePolicy {
    pub const fn new(stdio: McpTransportDeadlines, http: McpTransportDeadlines) -> Self {
        Self { stdio, http }
    }

    pub const fn stdio(self) -> McpTransportDeadlines {
        self.stdio
    }

    pub const fn http(self) -> McpTransportDeadlines {
        self.http
    }

    pub const fn for_transport(self, transport: crate::McpTransportKind) -> McpTransportDeadlines {
        match transport {
            crate::McpTransportKind::Stdio => self.stdio,
            crate::McpTransportKind::Http => self.http,
        }
    }
}

impl Default for McpDeadlinePolicy {
    fn default() -> Self {
        Self {
            stdio: McpTransportDeadlines {
                startup_milliseconds: 15_000,
                tool_call_milliseconds: 60_000,
            },
            http: McpTransportDeadlines {
                startup_milliseconds: 10_000,
                tool_call_milliseconds: 120_000,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_keep_transport_deadlines_distinct() {
        let policy = McpDeadlinePolicy::default();
        assert_eq!(policy.stdio().startup_milliseconds(), 15_000);
        assert_eq!(policy.stdio().tool_call_milliseconds(), 60_000);
        assert_eq!(policy.http().startup_milliseconds(), 10_000);
        assert_eq!(policy.http().tool_call_milliseconds(), 120_000);
        assert_ne!(policy.stdio(), policy.http());
    }

    #[test]
    fn zero_and_over_day_deadlines_are_refused() {
        assert!(McpTransportDeadlines::new(0, 1).is_err());
        assert!(McpTransportDeadlines::new(1, MAX_MCP_DEADLINE_MILLISECONDS + 1).is_err());
    }
}
