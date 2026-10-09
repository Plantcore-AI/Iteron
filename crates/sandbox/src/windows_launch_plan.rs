//! One frozen Windows shell/environment/workspace preparation shared by pipe, terminal and
//! one-shot execution. It selects no fallback posture and grants no ambient HOME/PATH read tree.
use crate::{Confinement, SandboxError};
use iteron_support::durable_windows_state::WindowsWorkspaceReader;
use iteron_support::owned_windows_job::WindowsSandboxLaunch;
use iteron_support::windows_process_isolation::WindowsIsolationPolicy;
use std::ffi::OsString;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;
const MAX_ENVIRONMENT_ENTRIES: usize = 4096;
const MAX_ENVIRONMENT_BYTES: usize = 1024 * 1024;
const MAX_SHELL_PATH_ENTRIES: usize = 256;
const MAX_PREPARATIONS: usize = 16;
const PREPARATION_WAIT: Duration = Duration::from_secs(10);
static PREPARATIONS: OnceLock<Arc<Semaphore>> = OnceLock::new();

pub(crate) struct Plan {
    pub(crate) executable: PathBuf,
    pub(crate) arguments: Vec<OsString>,
    pub(crate) directory: PathBuf,
    pub(crate) environment: Vec<(OsString, OsString)>,
    scratch: PathBuf,
    allow_egress: bool,
    unconfined: bool,
    _workspace: Option<WindowsWorkspaceReader>,
    workspace_file: Option<File>,
}
impl Plan {
    pub(crate) async fn capture(
        command: &str,
        conf: &Confinement,
        workspace: Option<&File>,
        terminal: bool,
    ) -> Result<Self, SandboxError> {
        if command.encode_utf16().take(32768).count() > 32767
            || conf.workspace.as_os_str().encode_wide().take(32768).count() > 32767
            || (!conf.unconfined
                && conf.scratch.as_os_str().encode_wide().take(32768).count() > 32767)
        {
            return Err(profile(
                "Windows launch exceeds its physical path/command envelope",
            ));
        }
        let permit = PREPARATIONS
            .get_or_init(|| Arc::new(Semaphore::new(MAX_PREPARATIONS)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| profile("Windows launch preparation capacity unavailable"))?;
        let mut environment = environment(conf)?;
        let command = command.to_owned();
        let requested = conf.workspace.clone();
        let scratch = conf.scratch.clone();
        let workspace_file = workspace
            .map(File::try_clone)
            .transpose()
            .map_err(|_| profile("Windows workspace capability unavailable"))?;
        let allow_egress = conf.allow_egress;
        let unconfined = conf.unconfined;
        let work = tokio::task::spawn_blocking(move || {
            let _physical = permit;
            let requested = if requested.is_absolute() {
                requested
            } else {
                std::env::current_dir()
                    .map_err(|_| profile("Windows workspace unavailable"))?
                    .join(requested)
            };
            let binding = if !unconfined || workspace_file.is_some() {
                Some(
                    WindowsWorkspaceReader::open(&requested)
                        .map_err(|_| profile("Windows workspace namespace unavailable"))?,
                )
            } else {
                None
            };
            if let Some(actual) = &workspace_file {
                if !binding
                    .as_ref()
                    .expect("capability requires binding")
                    .matches_file(actual)
                    .map_err(|_| profile("Windows workspace capability unavailable"))?
                {
                    return Err(profile(
                        "Windows workspace differs from its admitted capability",
                    ));
                }
            }
            let directory = requested
                .canonicalize()
                .map_err(|_| profile("Windows workspace identity unavailable"))?;
            let executable = shell_from_snapshot(&environment).map_err(profile)?;
            for (name, value) in [
                ("TERM", if terminal { "xterm-256color" } else { "dumb" }),
                ("COLORTERM", "truecolor"),
                ("PAGER", "cat"),
                ("MANPAGER", "cat"),
                ("GIT_PAGER", "cat"),
                ("PIP_PROGRESS_BAR", "off"),
                ("TQDM_DISABLE", "1"),
            ] {
                set(&mut environment, name, value.into());
            }
            if !unconfined {
                // These are the exact private scratch bytes the OS lease grants, not ambient
                // directories or a model-authored environment override.
                for name in [
                    "TMPDIR",
                    "TEMP",
                    "TMP",
                    "HOME",
                    "USERPROFILE",
                    "APPDATA",
                    "LOCALAPPDATA",
                ] {
                    set(&mut environment, name, scratch.as_os_str().to_owned());
                }
            }
            Ok(Self {
                executable,
                arguments: vec!["-c".into(), command.into()],
                directory,
                environment,
                scratch,
                allow_egress,
                unconfined,
                _workspace: binding,
                workspace_file,
            })
        });
        tokio::time::timeout(PREPARATION_WAIT, work)
            .await
            .map_err(|_| profile("Windows launch preparation observation timed out"))?
            .map_err(|_| profile("Windows launch preparation worker unavailable"))?
    }
    pub(crate) async fn sandbox(&self) -> Result<Option<WindowsSandboxLaunch>, SandboxError> {
        if self.unconfined {
            return Ok(None);
        }
        let writes = vec![self.directory.clone()];
        WindowsSandboxLaunch::prepare(
            WindowsIsolationPolicy {
                workspace: &self.directory,
                scratch: &self.scratch,
                executable: &self.executable,
                environment: &self.environment,
                write_roots: &writes,
                read_only_roots: &[],
                allow_egress: self.allow_egress,
            },
            self.workspace_file.as_ref(),
        )
        .await
        .map(Some)
        .map_err(|error| SandboxError::WindowsLaunch(Box::new(error)))
    }
}
fn environment(conf: &Confinement) -> Result<Vec<(OsString, OsString)>, SandboxError> {
    let mut env = match &conf.child_environment {
        Some(env) => {
            let bytes = env.iter().try_fold(0usize, |size, (key, value)| {
                size.checked_add(key.as_encoded_bytes().len())?
                    .checked_add(value.as_encoded_bytes().len())?
                    .checked_add(1)
            });
            if env.len() > MAX_ENVIRONMENT_ENTRIES
                || bytes.is_none_or(|bytes| bytes > MAX_ENVIRONMENT_BYTES)
            {
                return Err(profile(
                    "Windows frozen environment exceeds its physical envelope",
                ));
            }
            env.clone()
        }
        None => crate::bounded_child_environment(
            true,
            MAX_ENVIRONMENT_ENTRIES,
            MAX_ENVIRONMENT_BYTES,
            &[],
            &conf.sensitive_env_names,
        )
        .map_err(profile)?,
    };
    env.retain(|(key, _)| {
        key.to_str().is_some_and(|key| {
            !crate::is_secret_env_key(key)
                && !crate::is_shell_startup_env_key(key)
                && !conf
                    .sensitive_env_names
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(key))
        })
    });
    Ok(env)
}
fn set(env: &mut Vec<(OsString, OsString)>, name: &str, value: OsString) {
    env.retain(|(key, _)| {
        !key.to_str()
            .is_some_and(|key| key.eq_ignore_ascii_case(name))
    });
    env.push((name.into(), value));
}
pub(crate) fn shell_from_snapshot(env: &[(OsString, OsString)]) -> Result<PathBuf, &'static str> {
    let path = env
        .iter()
        .find(|(key, _)| {
            key.to_str()
                .is_some_and(|key| key.eq_ignore_ascii_case("PATH"))
        })
        .map(|(_, value)| value)
        .ok_or("Windows shell requires Git Bash in its admitted PATH")?;
    for (index, directory) in std::env::split_paths(path).enumerate() {
        if index >= MAX_SHELL_PATH_ENTRIES {
            return Err("Windows shell search exceeds its physical envelope");
        }
        if !directory.is_absolute() {
            continue;
        }
        let executable = directory.join("bash.exe");
        if executable.is_file() {
            return executable
                .canonicalize()
                .map_err(|_| "Windows shell identity unavailable");
        }
    }
    Err("Windows shell requires Git Bash in its admitted absolute PATH")
}
fn profile(message: &'static str) -> SandboxError {
    SandboxError::Profile(message.into())
}
