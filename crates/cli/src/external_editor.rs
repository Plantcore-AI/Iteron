//! Safe external-editor round trip for a text-only composer draft.
//!
//! The editor is an operator-configured argv, never a shell fragment. Drafts live in one private
//! bounded file below the Core home, provider credential variables are removed from the child,
//! and the original in-memory draft wins on every spawn/timeout/read/size failure.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const MAX_DRAFT_BYTES: usize = 64 * 1024;
const MAX_EDITOR_ARGS: usize = 16;
const MAX_ARG_BYTES: usize = 4096;
const MAX_TOTAL_ARG_BYTES: usize = 16 * 1024;
const MAX_TEMP_CREATE_ATTEMPTS: usize = 32;
const EDITOR_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(crate) fn validate_command(command: &[String]) -> Result<(), String> {
    if command.is_empty()
        || command.len()
            > iteron_tunables::param_integer("cli.external_editor.max_editor_args", MAX_EDITOR_ARGS)
    {
        return Err(format!(
            "external_editor must contain 1..={MAX_EDITOR_ARGS} argv entries"
        ));
    }
    let mut total = 0_usize;
    for (index, argument) in command.iter().enumerate() {
        if argument.is_empty()
            || argument.len()
                > iteron_tunables::param_integer("cli.external_editor.max_arg_bytes", MAX_ARG_BYTES)
            || argument.contains('\0')
            || argument
                .chars()
                .any(|character| character.is_control() && character != '\t' && character != '\n')
        {
            return Err(format!(
                "external_editor[{index}] must be non-empty, NUL-free, and at most {MAX_ARG_BYTES} bytes"
            ));
        }
        total = total
            .checked_add(argument.len())
            .ok_or_else(|| "external_editor argv size overflow".to_owned())?;
    }
    if total
        > iteron_tunables::param_integer(
            "cli.external_editor.max_total_arg_bytes",
            MAX_TOTAL_ARG_BYTES,
        )
    {
        return Err(format!(
            "external_editor argv exceeds {MAX_TOTAL_ARG_BYTES} total bytes"
        ));
    }
    Ok(())
}

/// Resolve the trusted user-config argv, or a single exact executable from VISUAL/EDITOR. An
/// environment value containing whitespace is not shell-split; the operator is directed to the
/// typed config array instead.
pub(crate) fn resolve_command(configured: Option<Vec<String>>) -> Result<Vec<String>, String> {
    if let Some(command) = configured {
        validate_command(&command)?;
        return Ok(command);
    }
    for name in ["VISUAL", "EDITOR"] {
        if let Some(value) = std::env::var_os(name) {
            let value = value
                .into_string()
                .map_err(|_| format!("{name} is not valid UTF-8; configure external_editor"))?;
            if value.split_whitespace().count() != 1 {
                return Err(format!(
                    "{name} contains arguments; configure external_editor as a JSON argv array"
                ));
            }
            let command = vec![value];
            validate_command(&command)?;
            return Ok(command);
        }
    }
    Err("no external editor configured; set external_editor, VISUAL, or EDITOR".into())
}

pub(crate) async fn edit(
    config_home: Option<PathBuf>,
    workspace: &Path,
    configured: Option<Vec<String>>,
    draft: &str,
    sensitive_env_names: &[String],
) -> Result<String, String> {
    if draft.len()
        > iteron_tunables::param_integer("cli.external_editor.max_draft_bytes", MAX_DRAFT_BYTES)
    {
        return Err(format!(
            "draft exceeds the external-editor limit of {MAX_DRAFT_BYTES} bytes"
        ));
    }
    let command = resolve_command(configured)?;
    let home = config_home.ok_or_else(|| {
        "no config root for a private draft; set HOME or ITERON_CONFIG_HOME".to_owned()
    })?;
    let temporary = TempDraft::create(&home, draft.as_bytes()).map_err(public_io)?;
    let mut process = tokio::process::Command::new(&command[0]);
    process
        .args(&command[1..])
        .arg(temporary.path())
        .current_dir(workspace)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    // Preserve the operator's editor/toolchain environment, but never hand it provider/pricing
    // names or ambient secret-shaped variables. The same shared classifier guards sandboxed code
    // and avoids a second, drifting notion of what looks credential-bearing.
    iteron_sandbox::confine_env_with_exact(&mut process, sensitive_env_names);
    let mut child = process
        .spawn()
        .map_err(|error| format!("external editor could not start: {error}"))?;
    let status = match tokio::time::timeout(
        iteron_tunables::param_duration("cli.external_editor.editor_timeout", EDITOR_TIMEOUT),
        child.wait(),
    )
    .await
    {
        Ok(result) => result.map_err(|error| format!("external editor wait failed: {error}"))?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err("external editor exceeded the 24-hour safety timeout".into());
        }
    };
    if !status.success() {
        return Err(format!(
            "external editor exited with {}",
            status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "a signal".into())
        ));
    }
    temporary.read().map_err(public_io)
}

fn public_io(error: std::io::Error) -> String {
    format!("external editor draft I/O failed: {error}")
}

struct TempDraft {
    path: PathBuf,
}

impl TempDraft {
    fn create(home: &Path, bytes: &[u8]) -> std::io::Result<Self> {
        let directory = iteron_protocol::home::path(home, "tmp");
        if let Ok(metadata) = fs::symlink_metadata(&directory)
            && metadata.file_type().is_symlink()
        {
            return Err(std::io::Error::other(
                "Iteron temporary directory cannot be a symlink",
            ));
        }
        fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        for _ in 0..iteron_tunables::param_integer(
            "cli.external_editor.max_temp_create_attempts",
            MAX_TEMP_CREATE_ATTEMPTS,
        ) {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!("prompt-edit-{}-{sequence}.md", std::process::id()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = match options.open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            };
            file.write_all(bytes)?;
            file.sync_all()?;
            return Ok(Self { path });
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("could not allocate a unique draft after {MAX_TEMP_CREATE_ATTEMPTS} attempts"),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> std::io::Result<String> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            // Open the reparse point itself so a replacement cannot redirect the read.
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options.open(&self.path)?;
        let metadata = file.metadata()?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(std::io::Error::other(
                "editor replaced the draft with a non-regular file",
            ));
        }
        if metadata.len()
            > iteron_tunables::param_integer("cli.external_editor.max_draft_bytes", MAX_DRAFT_BYTES)
                as u64
        {
            return Err(std::io::Error::other(format!(
                "edited draft exceeds {MAX_DRAFT_BYTES} bytes"
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(
            (iteron_tunables::param_integer("cli.external_editor.max_draft_bytes", MAX_DRAFT_BYTES)
                + 1) as u64,
        )
        .read_to_end(&mut bytes)?;
        if bytes.len()
            > iteron_tunables::param_integer("cli.external_editor.max_draft_bytes", MAX_DRAFT_BYTES)
        {
            return Err(std::io::Error::other(format!(
                "edited draft exceeds {MAX_DRAFT_BYTES} bytes"
            )));
        }
        String::from_utf8(bytes)
            .map_err(|_| std::io::Error::other("edited draft is not valid UTF-8"))
    }
}

impl Drop for TempDraft {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "core-external-editor-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn argv_validation_rejects_shellless_but_ambiguous_shapes() {
        assert!(validate_command(&[]).is_err());
        assert!(validate_command(&["editor".into(), "--wait".into()]).is_ok());
        assert!(validate_command(&["bad\0program".into()]).is_err());
        assert!(validate_command(&vec!["x".into(); MAX_EDITOR_ARGS + 1]).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn round_trip_is_exact_private_bounded_and_strips_provider_environment() {
        let home = scratch("home");
        let repo = scratch("repo");
        let env_name = "ITERON_EDITOR_TEST_PROVIDER_TOKEN".to_owned();
        let ambient_name = "ITERON_EDITOR_TEST_UNLISTED_SECRET";
        // The child receives the draft as $1; no shell ever interprets operator configuration.
        let command = vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf 'edited 写\\n%s/%s' \"${ITERON_EDITOR_TEST_PROVIDER_TOKEN-unset}\" \"${ITERON_EDITOR_TEST_UNLISTED_SECRET-unset}\" > \"$1\"".into(),
            "core-editor-test".into(),
        ];
        unsafe { std::env::set_var(&env_name, "must-not-cross") };
        unsafe { std::env::set_var(ambient_name, "must-not-cross-either") };
        let edited = edit(
            Some(home.clone()),
            &repo,
            Some(command),
            "original",
            std::slice::from_ref(&env_name),
        )
        .await
        .unwrap();
        unsafe { std::env::remove_var(&env_name) };
        unsafe { std::env::remove_var(ambient_name) };
        assert_eq!(edited, "edited 写\nunset/unset");
        let tmp = iteron_protocol::home::path(&home, "tmp");
        assert_eq!(fs::read_dir(tmp).unwrap().count(), 0, "draft is removed");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn editor_cannot_redirect_the_draft_read_through_a_symlink() {
        let home = scratch("symlink-home");
        let repo = scratch("symlink-repo");
        let command = vec![
            "/bin/sh".into(),
            "-c".into(),
            "rm -- \"$1\" && ln -s /etc/passwd \"$1\"".into(),
            "core-editor-symlink-test".into(),
        ];
        let error = edit(Some(home.clone()), &repo, Some(command), "original", &[])
            .await
            .unwrap_err();
        assert!(
            error.contains("draft I/O failed"),
            "refusal is public but must not include redirected file content: {error}"
        );
        let tmp = iteron_protocol::home::path(&home, "tmp");
        assert_eq!(fs::read_dir(tmp).unwrap().count(), 0, "symlink is removed");
    }
}
