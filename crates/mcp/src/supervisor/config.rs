use crate::{McpError, tool_filter::validate_server_name};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::watch;

pub const MAX_MCP_COMMAND_BYTES: usize = 4096;
pub const MAX_MCP_LAUNCH_ARGS: usize = 128;
pub const MAX_MCP_LAUNCH_ARG_BYTES: usize = 16 * 1024;
pub const MAX_MCP_LAUNCH_BYTES: usize = 64 * 1024;
pub const MAX_MCP_SENSITIVE_ENV_NAMES: usize = 256;
pub const MAX_MCP_ENV_NAME_BYTES: usize = 256;
pub const MAX_MCP_DEADLINE_MS: u64 = crate::MAX_MCP_DEADLINE_MILLISECONDS;
pub const DEFAULT_MCP_OPERATION_DEADLINE_MS: u64 = 120_000;
pub const MAX_MCP_OPERATION_DEADLINE_MS: u64 = crate::MAX_MCP_DEADLINE_MILLISECONDS;

/// Immutable, bounded process binding. It intentionally has no `Debug` implementation because
/// command arguments are operator configuration and may contain private paths or opaque values.
pub struct McpLaunchConfig {
    command: String,
    args: Vec<String>,
    server_name: String,
    sensitive_env_names: Vec<String>,
    binding: Arc<[u8]>,
}

impl McpLaunchConfig {
    pub fn new(command: String, args: Vec<String>, server_name: String) -> Result<Self, McpError> {
        validate_server_name(&server_name)?;
        if command.is_empty()
            || command.len() > MAX_MCP_COMMAND_BYTES
            || command.contains('\0')
            || !std::path::Path::new(&command).is_absolute()
        {
            return Err(McpError::InvalidLaunchConfiguration {
                field: "absolute_command",
                limit: MAX_MCP_COMMAND_BYTES,
            });
        }
        if args.len() > MAX_MCP_LAUNCH_ARGS {
            return Err(McpError::InvalidLaunchConfiguration {
                field: "args",
                limit: MAX_MCP_LAUNCH_ARGS,
            });
        }
        let mut aggregate = command.len();
        for arg in &args {
            if arg.len() > MAX_MCP_LAUNCH_ARG_BYTES || arg.contains('\0') {
                return Err(McpError::InvalidLaunchConfiguration {
                    field: "arg",
                    limit: MAX_MCP_LAUNCH_ARG_BYTES,
                });
            }
            aggregate =
                aggregate
                    .checked_add(arg.len())
                    .ok_or(McpError::InvalidLaunchConfiguration {
                        field: "launch_bytes",
                        limit: MAX_MCP_LAUNCH_BYTES,
                    })?;
        }
        if aggregate > MAX_MCP_LAUNCH_BYTES {
            return Err(McpError::InvalidLaunchConfiguration {
                field: "launch_bytes",
                limit: MAX_MCP_LAUNCH_BYTES,
            });
        }
        let mut config = Self {
            command,
            args,
            server_name,
            sensitive_env_names: Vec::new(),
            binding: Arc::from([]),
        };
        config.binding = config.compute_binding();
        Ok(config)
    }

    /// Remove additional exact environment names before process spawn. Names, counts, and total
    /// bytes are bounded; values are never accepted or retained by this type.
    pub fn with_sensitive_env_names(mut self, names: Vec<String>) -> Result<Self, McpError> {
        if names.len() > MAX_MCP_SENSITIVE_ENV_NAMES {
            return Err(McpError::InvalidLaunchConfiguration {
                field: "sensitive_env_names",
                limit: MAX_MCP_SENSITIVE_ENV_NAMES,
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for name in &names {
            if name.is_empty()
                || name.len() > MAX_MCP_ENV_NAME_BYTES
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || !seen.insert(name.as_str())
            {
                return Err(McpError::InvalidLaunchConfiguration {
                    field: "sensitive_env_name",
                    limit: MAX_MCP_ENV_NAME_BYTES,
                });
            }
        }
        self.sensitive_env_names = names;
        self.binding = self.compute_binding();
        Ok(self)
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub(super) fn command(&self) -> &str {
        &self.command
    }

    pub(super) fn args(&self) -> &[String] {
        &self.args
    }

    pub(super) fn sensitive_env_names(&self) -> &[String] {
        &self.sensitive_env_names
    }

    pub(super) fn binding(&self) -> Arc<[u8]> {
        self.binding.clone()
    }

    fn compute_binding(&self) -> Arc<[u8]> {
        let mut binding = b"core-mcp-server-binding-v1\0".to_vec();
        append_field(&mut binding, self.server_name.as_bytes());
        append_field(&mut binding, self.command.as_bytes());
        append_fields(&mut binding, &self.args);
        append_fields(&mut binding, &self.sensitive_env_names);
        binding.into()
    }
}

fn append_fields(binding: &mut Vec<u8>, fields: &[String]) {
    binding.extend_from_slice(&(fields.len() as u64).to_be_bytes());
    for field in fields {
        append_field(binding, field.as_bytes());
    }
}

fn append_field(binding: &mut Vec<u8>, field: &[u8]) {
    binding.extend_from_slice(&(field.len() as u64).to_be_bytes());
    binding.extend_from_slice(field);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpTimeouts {
    handshake: Duration,
    discovery: Duration,
    request: Duration,
    startup_operation: Duration,
    tool_operation: Duration,
}

impl Default for McpTimeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(15),
            discovery: Duration::from_secs(60),
            request: Duration::from_secs(60),
            startup_operation: Duration::from_millis(DEFAULT_MCP_OPERATION_DEADLINE_MS),
            tool_operation: Duration::from_millis(DEFAULT_MCP_OPERATION_DEADLINE_MS),
        }
    }
}

impl McpTimeouts {
    pub fn new(
        handshake: Duration,
        discovery: Duration,
        request: Duration,
    ) -> Result<Self, McpError> {
        validate_deadline("handshake_deadline", handshake, MAX_MCP_DEADLINE_MS)?;
        validate_deadline("discovery_deadline", discovery, MAX_MCP_DEADLINE_MS)?;
        validate_deadline("request_deadline", request, MAX_MCP_DEADLINE_MS)?;
        Ok(Self {
            handshake,
            discovery,
            request,
            startup_operation: Duration::from_millis(DEFAULT_MCP_OPERATION_DEADLINE_MS),
            tool_operation: Duration::from_millis(DEFAULT_MCP_OPERATION_DEADLINE_MS),
        })
    }

    /// Bound one complete public operation, including every reconnect backoff, handshake, and
    /// discovery attempt. This budget is intentionally much smaller than the sum of phase maxima.
    pub fn with_operation_deadline(mut self, operation: Duration) -> Result<Self, McpError> {
        validate_deadline(
            "operation_deadline",
            operation,
            MAX_MCP_OPERATION_DEADLINE_MS,
        )?;
        self.startup_operation = operation;
        self.tool_operation = operation;
        Ok(self)
    }

    /// Install distinct aggregate budgets for lazy startup/discovery and effecting calls.
    pub fn with_operation_deadlines(
        mut self,
        startup: Duration,
        tool: Duration,
    ) -> Result<Self, McpError> {
        validate_deadline(
            "startup_operation_deadline",
            startup,
            MAX_MCP_OPERATION_DEADLINE_MS,
        )?;
        validate_deadline(
            "tool_operation_deadline",
            tool,
            MAX_MCP_OPERATION_DEADLINE_MS,
        )?;
        self.startup_operation = startup;
        self.tool_operation = tool;
        Ok(self)
    }

    pub fn handshake(self) -> Duration {
        self.handshake
    }

    pub fn discovery(self) -> Duration {
        self.discovery
    }

    pub fn request(self) -> Duration {
        self.request
    }

    pub fn startup_operation(self) -> Duration {
        self.startup_operation
    }

    pub fn tool_operation(self) -> Duration {
        self.tool_operation
    }
}

fn validate_deadline(
    field: &'static str,
    deadline: Duration,
    maximum_ms: u64,
) -> Result<(), McpError> {
    if deadline < Duration::from_millis(1) || deadline > Duration::from_millis(maximum_ms) {
        return Err(McpError::InvalidLaunchConfiguration {
            field,
            limit: maximum_ms as usize,
        });
    }
    Ok(())
}

/// Cloneable one-way cancellation latch. Cancellation is sticky and cannot be reset or missed.
#[derive(Clone)]
pub struct McpCancellation {
    sender: watch::Sender<bool>,
    cancelled: Arc<AtomicBool>,
}

impl Default for McpCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl McpCancellation {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self {
            sender,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns true exactly for the transition from live to cancelled.
    pub fn cancel(&self) -> bool {
        if self
            .cancelled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.sender.send_replace(true);
            true
        } else {
            false
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        if *receiver.borrow_and_update() {
            return;
        }
        while receiver.changed().await.is_ok() {
            if *receiver.borrow_and_update() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_binding_is_stable_and_changes_with_immutable_configuration() {
        let first =
            McpLaunchConfig::new("/bin/server".into(), vec!["a".into()], "files".into()).unwrap();
        let same =
            McpLaunchConfig::new("/bin/server".into(), vec!["a".into()], "files".into()).unwrap();
        let changed =
            McpLaunchConfig::new("/bin/server".into(), vec!["b".into()], "files".into()).unwrap();
        assert_eq!(first.binding(), same.binding());
        assert_ne!(first.binding(), changed.binding());
    }

    #[test]
    fn launch_configuration_and_deadlines_are_bounded() {
        assert!(McpLaunchConfig::new(String::new(), vec![], "files".into()).is_err());
        assert!(McpLaunchConfig::new("relative-server".into(), vec![], "files".into()).is_err());
        assert!(
            McpLaunchConfig::new("/bin/server".into(), vec![String::new()], "files".into()).is_ok()
        );
        assert!(
            McpLaunchConfig::new(
                "/bin/server".into(),
                vec!["x".repeat(MAX_MCP_LAUNCH_ARG_BYTES + 1)],
                "files".into()
            )
            .is_err()
        );
        let defaults = McpTimeouts::default();
        assert_eq!(
            defaults.startup_operation(),
            Duration::from_millis(DEFAULT_MCP_OPERATION_DEADLINE_MS)
        );
        assert_eq!(defaults.startup_operation(), defaults.tool_operation());
        assert!(defaults.with_operation_deadline(Duration::ZERO).is_err());
        assert!(
            defaults
                .with_operation_deadline(Duration::from_millis(MAX_MCP_OPERATION_DEADLINE_MS + 1))
                .is_err()
        );
        assert!(
            defaults
                .with_operation_deadline(
                    Duration::from_millis(MAX_MCP_OPERATION_DEADLINE_MS) + Duration::from_nanos(1)
                )
                .is_err()
        );
        assert!(
            McpTimeouts::new(
                Duration::ZERO,
                Duration::from_secs(1),
                Duration::from_secs(1)
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn cancellation_is_sticky_and_wakes_every_subscriber() {
        let cancellation = McpCancellation::new();
        let first = cancellation.clone();
        let second = cancellation.clone();
        let one = tokio::spawn(async move { first.cancelled().await });
        let two = tokio::spawn(async move { second.cancelled().await });
        assert!(cancellation.cancel());
        assert!(!cancellation.cancel());
        one.await.unwrap();
        two.await.unwrap();
        cancellation.cancelled().await;
    }

    #[tokio::test]
    async fn concurrent_cancellation_has_exactly_one_winner() {
        const CALLERS: usize = 32;
        let cancellation = McpCancellation::new();
        let barrier = Arc::new(tokio::sync::Barrier::new(CALLERS));
        let mut callers = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let cancellation = cancellation.clone();
            let barrier = barrier.clone();
            callers.push(tokio::spawn(async move {
                barrier.wait().await;
                cancellation.cancel()
            }));
        }
        let mut winners = 0;
        for caller in callers {
            winners += usize::from(caller.await.unwrap());
        }
        assert_eq!(winners, 1);
        assert!(cancellation.is_cancelled());
    }
}
