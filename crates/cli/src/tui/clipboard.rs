//! Bounded text clipboard output through fixed, direct-argv platform adapters.
//!
//! Clipboard writes are an explicit operator effect. No shell parses the payload or command, the
//! child receives a tiny allowlisted environment, and retained transcript defenses are repeated at
//! this boundary so a copied block cannot smuggle terminal controls or credential-shaped text.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use thiserror::Error;
use tokio::io::AsyncWriteExt as _;

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
    #[error("clipboard write failed after dispatch; clipboard outcome is unknown")]
    DispatchedWriteOutcomeUnknown,
    #[error("clipboard adapter failed after dispatch; clipboard outcome is unknown")]
    DispatchedExitOutcomeUnknown,
    #[error(
        "clipboard adapter timed out after dispatch and was reaped; clipboard outcome is unknown"
    )]
    DispatchedTimeoutOutcomeUnknown,
    #[error(
        "clipboard adapter timed out after dispatch and could not be reaped; clipboard outcome is unknown"
    )]
    DispatchedTimeoutUnreaped,
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

pub(crate) async fn copy_text(text: &str) -> Result<&'static str, ClipboardError> {
    let specs = platform_commands();
    copy_text_with_specs(text, &specs).await
}

async fn copy_text_with_specs(
    text: &str,
    specs: &[CommandSpec],
) -> Result<&'static str, ClipboardError> {
    let text = safe_text(text)?;
    if specs.is_empty() {
        return Err(ClipboardError::Unavailable);
    }

    let mut last_error = ClipboardError::Unavailable;
    for spec in specs {
        match run(spec, text.as_bytes(), CLIPBOARD_TIMEOUT).await {
            Ok(()) => return Ok(adapter_name(&spec.program)),
            Err(ClipboardError::Launch) => last_error = ClipboardError::Launch,
            // Once a child starts, its clipboard side effect may have landed even if stdin, exit,
            // or timeout evidence fails. Never dispatch the payload to a second adapter.
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

async fn run(spec: &CommandSpec, bytes: &[u8], deadline: Duration) -> Result<(), ClipboardError> {
    let mut command = tokio::process::Command::new(&spec.program);
    command
        .args(&spec.args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for (name, value) in clipboard_environment() {
        command.env(name, value);
    }
    let mut child = command.spawn().map_err(|_| ClipboardError::Launch)?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(CLIPBOARD_REAP_TIMEOUT, child.wait()).await;
        return Err(ClipboardError::DispatchedWriteOutcomeUnknown);
    };
    let completion = async {
        stdin
            .write_all(bytes)
            .await
            .map_err(|_| ClipboardError::DispatchedWriteOutcomeUnknown)?;
        stdin
            .shutdown()
            .await
            .map_err(|_| ClipboardError::DispatchedWriteOutcomeUnknown)?;
        drop(stdin);
        let status = child
            .wait()
            .await
            .map_err(|_| ClipboardError::DispatchedExitOutcomeUnknown)?;
        status
            .success()
            .then_some(())
            .ok_or(ClipboardError::DispatchedExitOutcomeUnknown)
    };
    match tokio::time::timeout(deadline, completion).await {
        Ok(result) => result,
        Err(_) => {
            // The timed future dropped ChildStdin. Explicitly kill and bounded-wait so timeout is
            // not represented as evidence that kill_on_drop eventually reaped the subprocess.
            let _ = child.start_kill();
            match tokio::time::timeout(CLIPBOARD_REAP_TIMEOUT, child.wait()).await {
                Ok(Ok(_)) => Err(ClipboardError::DispatchedTimeoutOutcomeUnknown),
                Ok(Err(_)) | Err(_) => Err(ClipboardError::DispatchedTimeoutUnreaped),
            }
        }
    }
}

fn safe_text(text: &str) -> Result<String, ClipboardError> {
    if text.len() > MAX_CLIPBOARD_BYTES {
        return Err(ClipboardError::TooLarge);
    }
    let scrubbed = core_record::redact::scrub(text);
    let mut safe = String::with_capacity(scrubbed.len());
    for character in scrubbed.chars() {
        match character {
            '\n' | '\t' => safe.push(character),
            character if character.is_control() => safe.extend(character.escape_default()),
            character => safe.push(character),
        }
        if safe.len() > MAX_CLIPBOARD_BYTES {
            return Err(ClipboardError::TooLarge);
        }
    }
    Ok(safe)
}

fn bounded_environment(name: &'static str) -> Option<(&'static str, OsString)> {
    let value = std::env::var_os(name)?;
    let text = value.to_string_lossy();
    if text.is_empty() || text.len() > MAX_ENV_BYTES || text.chars().any(char::is_control) {
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
mod tests {
    use super::*;

    #[test]
    fn copied_text_is_secret_and_terminal_control_safe_and_bounded() {
        let secret = format!("sk-{}", "a".repeat(48));
        let safe = safe_text(&format!("before {secret}\u{1b}]52;bad\u{7} after")).unwrap();
        assert!(!safe.contains(&secret));
        assert!(!safe.contains('\u{1b}'));
        assert!(!safe.contains('\u{7}'));
        assert_eq!(
            safe_text(&"x".repeat(MAX_CLIPBOARD_BYTES + 1)),
            Err(ClipboardError::TooLarge)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn direct_argv_adapter_reports_success_and_typed_failure() {
        let output = std::env::temp_dir().join(format!(
            "core-clipboard-{}-{:?}.txt",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&output);
        let success = [CommandSpec::new("/usr/bin/tee", [output.as_os_str()])];
        assert!(copy_text_with_specs("你好 😀", &success).await.is_ok());
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "你好 😀");
        let _ = std::fs::remove_file(output);

        let failure = [CommandSpec::new(
            "/usr/bin/false",
            std::iter::empty::<&str>(),
        )];
        assert!(matches!(
            copy_text_with_specs("text", &failure).await,
            Err(ClipboardError::DispatchedWriteOutcomeUnknown
                | ClipboardError::DispatchedExitOutcomeUnknown)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dispatched_failure_never_falls_through_to_a_second_adapter() {
        let output = std::env::temp_dir().join(format!(
            "core-clipboard-fallback-{}-{:?}.txt",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&output);
        let specs = [
            CommandSpec::new("/usr/bin/false", std::iter::empty::<&str>()),
            CommandSpec::new("/usr/bin/tee", [output.as_os_str()]),
        ];
        assert!(matches!(
            copy_text_with_specs("must run once", &specs).await,
            Err(ClipboardError::DispatchedWriteOutcomeUnknown
                | ClipboardError::DispatchedExitOutcomeUnknown)
        ));
        assert!(!output.exists(), "a dispatched failure retried the payload");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_explicitly_kills_and_reaps_with_unknown_outcome() {
        let spec = CommandSpec::new("/bin/sleep", ["10"]);
        let started = std::time::Instant::now();
        assert_eq!(
            run(&spec, b"", Duration::from_millis(25)).await,
            Err(ClipboardError::DispatchedTimeoutOutcomeUnknown)
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout did not complete its bounded kill/reap path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn adapter_admission_rejects_symlinks_and_non_root_writable_files() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = std::env::temp_dir().join(format!(
            "core-clipboard-trust-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let executable = root.join("adapter");
        std::fs::write(&executable, b"not executable code").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o777)).unwrap();
        let link = root.join("adapter-link");
        symlink("/usr/bin/true", &link).unwrap();

        assert!(!trusted_adapter(&executable));
        assert!(!trusted_adapter(&link));
        assert!(
            installed([
                CommandSpec::new(executable, std::iter::empty::<&str>()),
                CommandSpec::new(link, std::iter::empty::<&str>()),
            ])
            .is_empty()
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
