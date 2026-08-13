//! Bounded text clipboard output through fixed, direct-argv platform adapters.
//!
//! Clipboard writes are an explicit operator effect. No shell parses the payload or command, the
//! child receives a tiny allowlisted environment, and retained transcript defenses are repeated at
//! this boundary so a copied block cannot smuggle terminal controls or credential-shaped text.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use thiserror::Error;
use tokio::io::AsyncWriteExt as _;

use super::transcript_effect::{ProcessRegistry, ReapOutcome, RegisteredChild};

const MAX_CLIPBOARD_BYTES: usize = 64 * 1024;
const MAX_ENV_BYTES: usize = 4 * 1024;
const CLIPBOARD_TIMEOUT: Duration = Duration::from_secs(3);
const CLIPBOARD_REAP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum ClipboardError {
    #[error("no supported text clipboard adapter is installed")]
    Unavailable,
    #[error("clipboard text exceeds the 64 KiB limit")]
    TooLarge,
    #[error("clipboard adapter could not start")]
    Launch,
    #[error(
        "clipboard adapter {stage} failed after dispatch; clipboard outcome is unknown; child {cleanup}"
    )]
    DispatchedOutcomeUnknown {
        stage: PostSpawnStage,
        cleanup: CleanupState,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PostSpawnStage {
    MissingStdin,
    Write,
    Shutdown,
    Wait,
    Exit,
    Timeout,
}

impl fmt::Display for PostSpawnStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingStdin => "stdin setup",
            Self::Write => "write",
            Self::Shutdown => "stdin shutdown",
            Self::Wait => "wait",
            Self::Exit => "exit",
            Self::Timeout => "timeout",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupState {
    Reaped,
    AlreadyReaped,
    OutcomeUnknown,
}

impl fmt::Display for CleanupState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Reaped => "was explicitly killed and reaped",
            Self::AlreadyReaped => "had already been reaped",
            Self::OutcomeUnknown => "was killed but its reap outcome is unknown",
        })
    }
}

#[derive(Debug)]
struct RunReport {
    result: Result<(), ClipboardError>,
    #[cfg_attr(not(test), allow(dead_code))]
    cleanup: Option<CleanupState>,
}

#[cfg(not(test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectedFault {
    None,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectedFault {
    None,
    MissingStdin,
    Write,
    Shutdown,
    Wait,
}

#[derive(Debug, Clone)]
struct CommandSpec {
    program: PathBuf,
    args: Vec<OsString>,
}

impl CommandSpec {
    fn new(
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<OsString>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

pub(crate) async fn copy_text(
    text: &str,
    processes: &ProcessRegistry,
) -> Result<&'static str, ClipboardError> {
    let specs = platform_commands();
    copy_text_with_specs(text, &specs, processes).await
}

async fn copy_text_with_specs(
    text: &str,
    specs: &[CommandSpec],
    processes: &ProcessRegistry,
) -> Result<&'static str, ClipboardError> {
    let text = safe_text(text)?;
    if specs.is_empty() {
        return Err(ClipboardError::Unavailable);
    }

    let mut last_error = ClipboardError::Unavailable;
    for spec in specs {
        match run(
            spec,
            text.as_bytes(),
            iteron_tunables::param_duration(
                "cli.tui.clipboard.clipboard_timeout",
                CLIPBOARD_TIMEOUT,
            ),
            processes,
        )
        .await
        {
            Ok(()) => return Ok(adapter_name(&spec.program)),
            Err(ClipboardError::Launch) => last_error = ClipboardError::Launch,
            // Once a child starts, its clipboard side effect may have landed even if stdin, exit,
            // or timeout evidence fails. Never dispatch the payload to a second adapter.
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

async fn run(
    spec: &CommandSpec,
    bytes: &[u8],
    deadline: Duration,
    processes: &ProcessRegistry,
) -> Result<(), ClipboardError> {
    run_report(spec, bytes, deadline, InjectedFault::None, processes)
        .await
        .result
}

async fn run_report(
    spec: &CommandSpec,
    bytes: &[u8],
    deadline: Duration,
    fault: InjectedFault,
    processes: &ProcessRegistry,
) -> RunReport {
    #[cfg(not(test))]
    let _ = fault;
    let mut command = tokio::process::Command::new(&spec.program);
    command
        .args(&spec.args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (name, value) in clipboard_environment() {
        command.env(name, value);
    }
    let mut child = match processes.spawn(&mut command) {
        Ok(child) => child,
        Err(_) => {
            return RunReport {
                result: Err(ClipboardError::Launch),
                cleanup: None,
            };
        }
    };
    let stdin = child.take_stdin();
    #[cfg(test)]
    let stdin = (fault != InjectedFault::MissingStdin)
        .then_some(stdin)
        .flatten();
    let Some(mut stdin) = stdin else {
        return post_spawn_error(&mut child, PostSpawnStage::MissingStdin).await;
    };
    let deadline = tokio::time::Instant::now() + deadline;

    #[cfg(test)]
    if fault == InjectedFault::Write {
        drop(stdin);
        return post_spawn_error(&mut child, PostSpawnStage::Write).await;
    }
    match tokio::time::timeout_at(deadline, stdin.write_all(bytes)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            drop(stdin);
            return post_spawn_error(&mut child, PostSpawnStage::Write).await;
        }
        Err(_) => {
            drop(stdin);
            return post_spawn_error(&mut child, PostSpawnStage::Timeout).await;
        }
    }

    #[cfg(test)]
    if fault == InjectedFault::Shutdown {
        drop(stdin);
        return post_spawn_error(&mut child, PostSpawnStage::Shutdown).await;
    }
    match tokio::time::timeout_at(deadline, stdin.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            drop(stdin);
            return post_spawn_error(&mut child, PostSpawnStage::Shutdown).await;
        }
        Err(_) => {
            drop(stdin);
            return post_spawn_error(&mut child, PostSpawnStage::Timeout).await;
        }
    }
    drop(stdin);

    #[cfg(test)]
    if fault == InjectedFault::Wait {
        return post_spawn_error(&mut child, PostSpawnStage::Wait).await;
    }
    match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(Ok(status)) if status.success() => RunReport {
            result: Ok(()),
            cleanup: Some(CleanupState::AlreadyReaped),
        },
        Ok(Ok(_)) => RunReport {
            result: Err(ClipboardError::DispatchedOutcomeUnknown {
                stage: PostSpawnStage::Exit,
                cleanup: CleanupState::AlreadyReaped,
            }),
            cleanup: Some(CleanupState::AlreadyReaped),
        },
        Ok(Err(_)) => post_spawn_error(&mut child, PostSpawnStage::Wait).await,
        Err(_) => post_spawn_error(&mut child, PostSpawnStage::Timeout).await,
    }
}

async fn post_spawn_error(child: &mut RegisteredChild, stage: PostSpawnStage) -> RunReport {
    let cleanup = kill_and_reap(child).await;
    RunReport {
        result: Err(ClipboardError::DispatchedOutcomeUnknown { stage, cleanup }),
        cleanup: Some(cleanup),
    }
}

async fn kill_and_reap(child: &mut RegisteredChild) -> CleanupState {
    let _ = child.start_kill();
    match tokio::time::timeout(
        iteron_tunables::param_duration(
            "cli.tui.clipboard.clipboard_reap_timeout",
            CLIPBOARD_REAP_TIMEOUT,
        ),
        child.wait(),
    )
    .await
    {
        Ok(Ok(_)) => CleanupState::Reaped,
        Ok(Err(_)) | Err(_) => match child.reap_sync() {
            ReapOutcome::Reaped => CleanupState::Reaped,
            ReapOutcome::AlreadySettled => CleanupState::AlreadyReaped,
            ReapOutcome::OutcomeUnknown => CleanupState::OutcomeUnknown,
        },
    }
}

fn safe_text(text: &str) -> Result<String, ClipboardError> {
    if text.len()
        > iteron_tunables::param_integer(
            "cli.tui.clipboard.max_clipboard_bytes",
            MAX_CLIPBOARD_BYTES,
        )
    {
        return Err(ClipboardError::TooLarge);
    }
    let scrubbed = iteron_record::redact::scrub(text);
    let mut safe = String::with_capacity(scrubbed.len());
    for character in scrubbed.chars() {
        match character {
            '\n' | '\t' => safe.push(character),
            character if character.is_control() => safe.extend(character.escape_default()),
            character => safe.push(character),
        }
        if safe.len()
            > iteron_tunables::param_integer(
                "cli.tui.clipboard.max_clipboard_bytes",
                MAX_CLIPBOARD_BYTES,
            )
        {
            return Err(ClipboardError::TooLarge);
        }
    }
    Ok(safe)
}

fn bounded_environment(name: &'static str) -> Option<(&'static str, OsString)> {
    let value = std::env::var_os(name)?;
    let text = value.to_string_lossy();
    if text.is_empty()
        || text.len()
            > iteron_tunables::param_integer("cli.tui.clipboard.max_env_bytes", MAX_ENV_BYTES)
        || text.chars().any(char::is_control)
    {
        return None;
    }
    Some((name, value))
}

fn clipboard_environment() -> Vec<(&'static str, OsString)> {
    [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "XAUTHORITY",
    ]
    .into_iter()
    .filter_map(bounded_environment)
    .collect()
}

fn adapter_name(program: &Path) -> &'static str {
    match program.file_name().and_then(|name| name.to_str()) {
        Some("pbcopy") => "pbcopy",
        Some("wl-copy") => "wl-copy",
        Some("xclip") => "xclip",
        Some("clip.exe") => "clip.exe",
        _ => "direct clipboard adapter",
    }
}

#[cfg(target_os = "macos")]
fn platform_commands() -> Vec<CommandSpec> {
    installed([CommandSpec::new(
        "/usr/bin/pbcopy",
        std::iter::empty::<&str>(),
    )])
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_commands() -> Vec<CommandSpec> {
    installed([
        CommandSpec::new("/usr/bin/wl-copy", ["--type", "text/plain;charset=utf-8"]),
        CommandSpec::new("/usr/bin/xclip", ["-selection", "clipboard", "-in"]),
    ])
}

#[cfg(windows)]
fn platform_commands() -> Vec<CommandSpec> {
    let Some(root) = super::trusted_windows_directory().map(PathBuf::from) else {
        return Vec::new();
    };
    installed([CommandSpec::new(
        root.join("System32").join("clip.exe"),
        std::iter::empty::<&str>(),
    )])
}

#[cfg(not(any(unix, windows)))]
fn platform_commands() -> Vec<CommandSpec> {
    Vec::new()
}

fn installed<const N: usize>(specs: [CommandSpec; N]) -> Vec<CommandSpec> {
    specs
        .into_iter()
        .filter(|spec| trusted_adapter(&spec.program))
        .collect()
}

#[cfg(unix)]
fn trusted_adapter(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    metadata.file_type().is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
}

#[cfg(windows)]
fn trusted_adapter(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    metadata.file_type().is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
}

#[cfg(not(any(unix, windows)))]
fn trusted_adapter(_path: &Path) -> bool {
    false
}

#[cfg(test)]
#[path = "clipboard/tests.rs"]
mod tests;
