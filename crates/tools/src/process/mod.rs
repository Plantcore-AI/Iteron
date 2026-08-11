//! Bounded persistent-process tools.
//!
//! These tools expose a real, session-owned kernel PTY under Linux bubblewrap or macOS Seatbelt.
//! Job identity, terminal input, resize, lifecycle, and cleanup all use the same supervisor handle,
//! so model-facing calls and operator controls cannot drift into separate process tables.

mod actor;
mod output;
mod policy;
mod supervisor;
mod types;

#[cfg(test)]
mod tests;

use crate::{Registry, ToolError, ToolExecution, effectfut};
use iteron_protocol::{Capability, Purity, ToolResult, ToolSpec, Trust};
use serde::Serialize;
use std::sync::Arc;
use supervisor::Supervisor;
use types::ActionError;
pub use types::ProcessHealth;

pub use policy::{
    InteractiveStdinWaitPolicy, MAX_BACKGROUND_JOBS, MAX_IDLE_STALL_MILLISECONDS,
    MAX_STDIN_POLL_MILLISECONDS, PersistentBackendSelection, ProcessPolicyError,
    ProcessRuntimePolicy,
};

pub(super) const MAX_JOB_RECORDS: usize = 16;
pub(super) const MAX_COMMAND_BYTES: usize = 32 * 1024;
pub(super) const MAX_STDIN_BYTES: usize = 64 * 1024;
pub(super) const RETAINED_OUTPUT_BYTES_PER_STREAM: usize = 256 * 1024;
pub(super) const MAX_OBSERVED_OUTPUT_BYTES_PER_STREAM: u64 = 64 * 1024 * 1024;
pub(super) const POLL_OUTPUT_BYTES_PER_STREAM: usize = 32 * 1024;
pub(super) const MAX_JOB_RUNTIME_SECS: u64 = 10 * 60;
// One queued write plus the actor's one in-flight write keeps the worst-case response below the
// fixed controller deadline (2 * STDIN_WRITE_SECS < CONTROL_RESPONSE_SECS).
pub(super) const CONTROL_QUEUE_CAPACITY: usize = 1;
pub(super) const STOP_QUEUE_CAPACITY: usize = 1;
pub(super) const CONTROL_RESPONSE_SECS: u64 = 3;
pub(super) const STDIN_WRITE_SECS: u64 = 1;
pub(super) const OUTPUT_DRAIN_SECS: u64 = 1;
pub(super) const DEFAULT_PTY_ROWS: u16 = 24;
pub(super) const DEFAULT_PTY_COLS: u16 = 80;

const _: () = assert!(
    CONTROL_QUEUE_CAPACITY == 1 && 2 * STDIN_WRITE_SECS < CONTROL_RESPONSE_SECS,
    "queued and in-flight stdin writes must settle before the caller response deadline"
);

#[derive(Clone)]
pub struct ProcessControl {
    supervisor: Arc<Supervisor>,
}

/// Content-free terminal notification from the process owner itself.
///
/// Polling is a presentation concern, not a lifecycle authority.  The supervisor invokes this
/// observer exactly once when its actor commits a terminal state, including natural exits and
/// deadline/output-limit cleanup that no caller ever polls.  Keeping the callback typed prevents
/// the tools crate from depending on any frontend or telemetry vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLifecycleKind {
    Spawned,
    Exited,
    Stopped,
    TimedOut,
    IdleStalled,
    OutputLimitExceeded,
    IoFailed,
    CleanupUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLifecycleNotice {
    pub job_id: String,
    pub kind: ProcessLifecycleKind,
}

pub type ProcessLifecycleObserver = Arc<dyn Fn(ProcessLifecycleNotice) + Send + Sync>;

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct ProcessControlError {
    pub message: String,
    /// True when dispatch crossed an effect boundary but terminal reconciliation was not proven.
    pub unknown: bool,
}

impl ProcessControl {
    /// Bind the session-owned observation sink before the first process is admitted.
    /// Rebinding replaces only the observer; it never changes or recreates the job table.
    pub fn bind_lifecycle_observer(&self, observer: ProcessLifecycleObserver) {
        self.supervisor.bind_lifecycle_observer(observer);
    }

    /// Install the immutable resolved process policy before this session admits any job.
    pub fn configure_policy(
        &self,
        policy: ProcessRuntimePolicy,
    ) -> Result<(), ProcessControlError> {
        match self.supervisor.configure_policy(policy) {
            Ok(()) => Ok(()),
            Err(ActionError::Definite(message)) => Err(ProcessControlError {
                message,
                unknown: false,
            }),
            Err(ActionError::Unknown(message)) => Err(ProcessControlError {
                message,
                unknown: true,
            }),
        }
    }

    pub fn policy(&self) -> ProcessRuntimePolicy {
        self.supervisor.policy()
    }

    pub fn list(&self) -> Result<serde_json::Value, ProcessControlError> {
        encode_control(self.supervisor.list())
    }

    pub fn health(&self) -> ProcessHealth {
        self.supervisor.health()
    }

    pub async fn poll(
        &self,
        job_id: &str,
        stdout_cursor: u64,
        stderr_cursor: u64,
        wait_ms: u64,
    ) -> Result<serde_json::Value, ProcessControlError> {
        if wait_ms > MAX_STDIN_POLL_MILLISECONDS {
            return Err(ProcessControlError {
                message: format!(
                    "wait_ms exceeds the fixed {MAX_STDIN_POLL_MILLISECONDS}ms maximum"
                ),
                unknown: false,
            });
        }
        encode_action(
            self.supervisor
                .poll(job_id, stdout_cursor, stderr_cursor, wait_ms)
                .await,
        )
    }

    pub async fn write(
        &self,
        job_id: &str,
        input: String,
        eof: bool,
    ) -> Result<serde_json::Value, ProcessControlError> {
        if input.is_empty() && !eof {
            return Err(ProcessControlError {
                message: "input must be non-empty unless eof is true".into(),
                unknown: false,
            });
        }
        if input.len() > MAX_STDIN_BYTES {
            return Err(ProcessControlError {
                message: format!("input exceeds the fixed {MAX_STDIN_BYTES}-byte limit"),
                unknown: false,
            });
        }
        encode_action(self.supervisor.write(job_id, input.into_bytes(), eof).await)
    }

    pub async fn stop(&self, job_id: &str) -> Result<serde_json::Value, ProcessControlError> {
        encode_action(self.supervisor.stop(job_id).await)
    }

    pub fn resize(
        &self,
        job_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<serde_json::Value, ProcessControlError> {
        encode_action(self.supervisor.resize(job_id, rows, cols))
    }

    /// Stop all jobs owned by this session's one supervisor. This is deliberately separate from
    /// turn cancellation, session drain, and process exit.
    pub async fn clean(&self) -> Result<serde_json::Value, ProcessControlError> {
        encode_action(self.supervisor.clean().await)
    }
}

pub(crate) fn register(registry: &mut Registry) -> Result<ProcessControl, ToolError> {
    let supervisor = Arc::new(Supervisor::new().map_err(ToolError::Registration)?);
    register_start(registry, Arc::clone(&supervisor))?;
    register_list(registry, Arc::clone(&supervisor))?;
    register_poll(registry, Arc::clone(&supervisor))?;
    register_write(registry, Arc::clone(&supervisor))?;
    register_resize(registry, Arc::clone(&supervisor))?;
    register_stop(registry, Arc::clone(&supervisor))?;
    Ok(ProcessControl { supervisor })
}

fn register_start(registry: &mut Registry, supervisor: Arc<Supervisor>) -> Result<(), ToolError> {
    let sensitive_env_names = registry.sensitive_env_names_handle();
    registry.register_external_effect(
        ToolSpec {
            name: "process_start".into(),
            description: format!(
                "Start one confined background process on a real controlling PTY and return a stable \
                 job ID. Linux uses bubblewrap; macOS uses Seatbelt; unavailable confinement refuses \
                 before spawn. Session policy selects disabled, one-shot, or persistent lifetime and \
                 admits at most {MAX_BACKGROUND_JOBS} jobs; every job is stopped \
                 after {MAX_JOB_RUNTIME_SECS}s and retained output is bounded."
            ),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "command":{
                        "type":"string",
                        "description":"Shell command to run from the workspace root."
                    },
                    "rows":{"type":"integer","minimum":1},
                    "cols":{"type":"integer","minimum":1}
                },
                "required":["command"]
            }),
            purity: Purity::Effecting,
            capability: Capability::CodeExecuting,
        },
        move |call, root| {
            let supervisor = Arc::clone(&supervisor);
            let sensitive_env_names = Arc::clone(&sensitive_env_names);
            effectfut::box_it(async move {
                let Some(command) = required_string(&call.input, "command") else {
                    return definite_error(call.id, "command must be a non-empty string");
                };
                if command.is_empty() {
                    return definite_error(call.id, "command must be a non-empty string");
                }
                if command.len() > MAX_COMMAND_BYTES {
                    return definite_error(
                        call.id,
                        format!("command exceeds the fixed {MAX_COMMAND_BYTES}-byte limit"),
                    );
                }
                let rows = match optional_u16(&call.input, "rows", DEFAULT_PTY_ROWS) {
                    Ok(value) => value,
                    Err(error) => return definite_error(call.id, error),
                };
                let cols = match optional_u16(&call.input, "cols", DEFAULT_PTY_COLS) {
                    Ok(value) => value,
                    Err(error) => return definite_error(call.id, error),
                };
                let names = sensitive_env_names
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                action_result(
                    call.id,
                    supervisor.start(&root, command, rows, cols, names).await,
                )
            })
        },
    )
}

fn register_list(registry: &mut Registry, supervisor: Arc<Supervisor>) -> Result<(), ToolError> {
    registry.register_external_effect(
        ToolSpec {
            name: "process_list".into(),
            description: format!(
                "List at most {MAX_JOB_RECORDS} retained background jobs with lifecycle state, \
                 backend, bounded command, and output cursors. The response carries no output \
                 body; use process_poll to attach at a cursor."
            ),
            input_schema: serde_json::json!({"type":"object","properties":{}}),
            purity: Purity::Effecting,
            capability: Capability::ReadOnly,
        },
        move |call, _root| {
            let supervisor = Arc::clone(&supervisor);
            effectfut::box_it(async move { action_result(call.id, Ok(supervisor.list())) })
        },
    )
}

fn register_poll(registry: &mut Registry, supervisor: Arc<Supervisor>) -> Result<(), ToolError> {
    registry.register_external_effect(
        ToolSpec {
            name: "process_poll".into(),
            description: format!(
                "Read one bounded output page and the authoritative lifecycle state for a job. \
                 Pass the returned byte cursors to continue; each stream returns at most \
                 {POLL_OUTPUT_BYTES_PER_STREAM} bytes and explicitly reports retention gaps. \
                 Poll uses the session's interactive-stdin interval by default and never beyond \
                 {MAX_STDIN_POLL_MILLISECONDS}ms."
            ),
            input_schema: job_cursor_schema(),
            purity: Purity::Effecting,
            capability: Capability::ReadOnly,
        },
        move |call, _root| {
            let supervisor = Arc::clone(&supervisor);
            effectfut::box_it(async move {
                let parsed = parse_poll_input(&call.input, supervisor.policy());
                let result = match parsed {
                    Ok((job_id, stdout_cursor, stderr_cursor, wait_ms)) => {
                        supervisor
                            .poll(job_id, stdout_cursor, stderr_cursor, wait_ms)
                            .await
                    }
                    Err(error) => Err(ActionError::Definite(error)),
                };
                action_result(call.id, result)
            })
        },
    )
}

fn register_write(registry: &mut Registry, supervisor: Arc<Supervisor>) -> Result<(), ToolError> {
    registry.register_external_effect(
        ToolSpec {
            name: "process_write".into(),
            description: format!(
                "Write at most {MAX_STDIN_BYTES} UTF-8 bytes to a running job's stdin and \
                 optionally deliver canonical terminal EOF and retire this job's input capability. \
                 Raw-mode PTY programs may interpret EOF as input because a PTY has no independent \
                 write-half to close. Delivery failures after dispatch are reported as an unknown \
                 effect and terminate the job rather than risking an orphan."
            ),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "job_id":{"type":"string"},
                    "input":{"type":"string"},
                    "eof":{
                        "type":"boolean",
                        "description":"Deliver terminal VEOF and refuse later writes for this job."
                    }
                },
                "required":["job_id"]
            }),
            purity: Purity::Effecting,
            capability: Capability::CodeExecuting,
        },
        move |call, _root| {
            let supervisor = Arc::clone(&supervisor);
            effectfut::box_it(async move {
                let Some(job_id) = required_string(&call.input, "job_id") else {
                    return definite_error(call.id, "job_id must be a string");
                };
                let input = call
                    .input
                    .get("input")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let eof = call
                    .input
                    .get("eof")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                if input.is_empty() && !eof {
                    return definite_error(call.id, "input must be non-empty unless eof is true");
                }
                if input.len() > MAX_STDIN_BYTES {
                    return definite_error(
                        call.id,
                        format!("input exceeds the fixed {MAX_STDIN_BYTES}-byte limit"),
                    );
                }
                action_result(
                    call.id,
                    supervisor
                        .write(job_id, input.as_bytes().to_vec(), eof)
                        .await,
                )
            })
        },
    )
}

fn register_stop(registry: &mut Registry, supervisor: Arc<Supervisor>) -> Result<(), ToolError> {
    registry.register_external_effect(
        ToolSpec {
            name: "process_stop".into(),
            description:
                "Stop a job's entire process group, reap its direct child, and return the \
                          final lifecycle state. Calling stop on an already-terminal job is \
                          idempotent."
                    .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{"job_id":{"type":"string"}},
                "required":["job_id"]
            }),
            purity: Purity::Effecting,
            capability: Capability::CodeExecuting,
        },
        move |call, _root| {
            let supervisor = Arc::clone(&supervisor);
            effectfut::box_it(async move {
                let Some(job_id) = required_string(&call.input, "job_id") else {
                    return definite_error(call.id, "job_id must be a string");
                };
                action_result(call.id, supervisor.stop(job_id).await)
            })
        },
    )
}

fn register_resize(registry: &mut Registry, supervisor: Arc<Supervisor>) -> Result<(), ToolError> {
    registry.register_external_effect(
        ToolSpec {
            name: "process_resize".into(),
            description: "Resize a running job's kernel PTY and deliver SIGWINCH through the terminal foreground group.".into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "job_id":{"type":"string"},
                    "rows":{"type":"integer","minimum":1},
                    "cols":{"type":"integer","minimum":1}
                },
                "required":["job_id","rows","cols"]
            }),
            purity: Purity::Effecting,
            capability: Capability::CodeExecuting,
        },
        move |call, _root| {
            let supervisor = Arc::clone(&supervisor);
            effectfut::box_it(async move {
                let Some(job_id) = required_string(&call.input, "job_id") else {
                    return definite_error(call.id, "job_id must be a string");
                };
                let rows = match required_u16(&call.input, "rows") {
                    Ok(value) => value,
                    Err(error) => return definite_error(call.id, error),
                };
                let cols = match required_u16(&call.input, "cols") {
                    Ok(value) => value,
                    Err(error) => return definite_error(call.id, error),
                };
                action_result(call.id, supervisor.resize(job_id, rows, cols))
            })
        },
    )
}

fn job_cursor_schema() -> serde_json::Value {
    serde_json::json!({
        "type":"object",
        "properties":{
            "job_id":{"type":"string"},
            "stdout_cursor":{"type":"integer","minimum":0},
            "stderr_cursor":{"type":"integer","minimum":0},
            "wait_ms":{
                "type":"integer",
                "minimum":0,
                "description":format!("Long-poll ceiling in milliseconds; runtime-enforced maximum is {MAX_STDIN_POLL_MILLISECONDS}.")
            }
        },
        "required":["job_id"]
    })
}

fn parse_poll_input(
    input: &serde_json::Value,
    policy: ProcessRuntimePolicy,
) -> Result<(&str, u64, u64, u64), String> {
    let job_id =
        required_string(input, "job_id").ok_or_else(|| "job_id must be a string".to_owned())?;
    let stdout_cursor = optional_u64(input, "stdout_cursor")?;
    let stderr_cursor = optional_u64(input, "stderr_cursor")?;
    let wait_ms = match input.get("wait_ms") {
        None => policy.stdin_wait.poll_milliseconds,
        Some(_) => optional_u64(input, "wait_ms")?,
    };
    if wait_ms > MAX_STDIN_POLL_MILLISECONDS {
        return Err(format!(
            "wait_ms exceeds the fixed {MAX_STDIN_POLL_MILLISECONDS}ms maximum"
        ));
    }
    Ok((job_id, stdout_cursor, stderr_cursor, wait_ms))
}

fn required_string<'a>(input: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    input.get(name).and_then(serde_json::Value::as_str)
}

fn optional_u64(input: &serde_json::Value, name: &str) -> Result<u64, String> {
    match input.get(name) {
        None => Ok(0),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("{name} must be a non-negative integer")),
    }
}

fn optional_u16(input: &serde_json::Value, name: &str, default: u16) -> Result<u16, String> {
    match input.get(name) {
        None => Ok(default),
        Some(_) => required_u16(input, name),
    }
}

fn required_u16(input: &serde_json::Value, name: &str) -> Result<u16, String> {
    let value = input
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| format!("{name} must be an integer within 1..=4096"))?;
    iteron_sandbox::pty::WindowSize::new(
        if name == "rows" { value } else { 1 },
        if name == "cols" { value } else { 1 },
    )
    .map_err(|_| format!("{name} must be an integer within 1..=4096"))?;
    Ok(value)
}

fn action_result<T: Serialize>(
    tool_use_id: String,
    result: Result<T, ActionError>,
) -> ToolExecution {
    match result {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(content) => ToolExecution::Definite(tool_result(tool_use_id, content, false)),
            Err(error) => definite_error(tool_use_id, format!("serialize process result: {error}")),
        },
        Err(ActionError::Definite(error)) => definite_error(tool_use_id, error),
        Err(ActionError::Unknown(error)) => {
            ToolExecution::Unknown(tool_result(tool_use_id, error, true))
        }
    }
}

fn encode_action<T: Serialize>(
    result: Result<T, ActionError>,
) -> Result<serde_json::Value, ProcessControlError> {
    match result {
        Ok(value) => encode_control(value),
        Err(ActionError::Definite(message)) => Err(ProcessControlError {
            message,
            unknown: false,
        }),
        Err(ActionError::Unknown(message)) => Err(ProcessControlError {
            message,
            unknown: true,
        }),
    }
}

fn encode_control<T: Serialize>(value: T) -> Result<serde_json::Value, ProcessControlError> {
    serde_json::to_value(value).map_err(|error| ProcessControlError {
        message: format!("serialize process control result: {error}"),
        unknown: false,
    })
}

fn definite_error(tool_use_id: String, error: impl Into<String>) -> ToolExecution {
    ToolExecution::Definite(tool_result(tool_use_id, error.into(), true))
}

fn tool_result(tool_use_id: String, content: String, is_error: bool) -> ToolResult {
    ToolResult {
        tool_use_id,
        content,
        is_error,
        trust: Trust::Workspace,
        latency_ms: 0,
    }
}
