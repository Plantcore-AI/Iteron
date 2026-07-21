//! Bounded subprocess collection for the evaluator itself.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(OsString, OsString)>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
}

impl ProcessOutput {
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == 0
    }

    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("cannot spawn `{program}`: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("spawned process `{0}` did not expose its {1} pipe")]
    MissingPipe(String, &'static str),
    #[error("cannot wait for `{program}`: {source}")]
    Wait {
        program: String,
        source: std::io::Error,
    },
    #[error("cannot collect `{program}` {stream}: {detail}")]
    Collect {
        program: String,
        stream: &'static str,
        detail: String,
    },
}

#[derive(Debug, Default)]
struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
}

async fn capture_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: usize,
) -> std::io::Result<Capture> {
    let mut capture = Capture {
        bytes: Vec::with_capacity(limit.min(8 * 1024)),
        truncated: false,
    };
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(capture);
        }
        let remaining = limit.saturating_sub(capture.bytes.len());
        let keep = remaining.min(read);
        capture.bytes.extend_from_slice(&chunk[..keep]);
        capture.truncated |= keep < read;
    }
}

pub async fn run_process(spec: &ProcessSpec) -> Result<ProcessOutput, ProcessError> {
    let label = spec.program.display().to_string();
    let mut command = tokio::process::Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    command.envs(spec.env.iter().cloned());
    core_sandbox::configure_process_group(&mut command);
    let mut child = command.spawn().map_err(|source| ProcessError::Spawn {
        program: label.clone(),
        source,
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProcessError::MissingPipe(label.clone(), "stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ProcessError::MissingPipe(label.clone(), "stderr"))?;
    let stdout_task = tokio::spawn(capture_bounded(stdout, spec.max_output_bytes));
    let stderr_task = tokio::spawn(capture_bounded(stderr, spec.max_output_bytes));

    let (timed_out, exit_code) = match tokio::time::timeout(spec.timeout, child.wait()).await {
        Ok(result) => {
            let status = result.map_err(|source| ProcessError::Wait {
                program: label.clone(),
                source,
            })?;
            (false, status.code().unwrap_or(-1))
        }
        Err(_) => {
            core_sandbox::terminate_process_group_and_reap(&mut child).await;
            (true, -1)
        }
    };

    // Once the child group is dead both pipes should close. Keep cleanup bounded in case a hostile
    // process escaped the group and retained an inherited descriptor.
    let collect_timeout = Duration::from_secs(2);
    let stdout = collect_capture(stdout_task, collect_timeout, &label, "stdout").await?;
    let stderr = collect_capture(stderr_task, collect_timeout, &label, "stderr").await?;
    Ok(ProcessOutput {
        exit_code,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        timed_out,
    })
}

async fn collect_capture(
    mut task: tokio::task::JoinHandle<std::io::Result<Capture>>,
    timeout: Duration,
    program: &str,
    stream: &'static str,
) -> Result<Capture, ProcessError> {
    match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(Ok(capture))) => Ok(capture),
        Ok(Ok(Err(error))) => Err(ProcessError::Collect {
            program: program.to_owned(),
            stream,
            detail: error.to_string(),
        }),
        Ok(Err(error)) => Err(ProcessError::Collect {
            program: program.to_owned(),
            stream,
            detail: error.to_string(),
        }),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(ProcessError::Collect {
                program: program.to_owned(),
                stream,
                detail: "pipe remained open after process-group termination".to_owned(),
            })
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FindCoreError {
    #[error("explicit core binary `{0}` is not a regular file")]
    InvalidExplicit(String),
    #[error(
        "cannot locate the Core CLI independent of cwd; pass --core-bin /absolute/path/to/core or run `cargo build -p core-cli`"
    )]
    NotFound,
    #[error("cannot canonicalize core binary `{path}`: {source}")]
    Canonicalize {
        path: String,
        source: std::io::Error,
    },
}

pub fn find_core(explicit: Option<&Path>) -> Result<PathBuf, FindCoreError> {
    if let Some(path) = explicit {
        if !path.is_file() {
            return Err(FindCoreError::InvalidExplicit(path.display().to_string()));
        }
        return canonicalize_core(path);
    }

    let executable_name = format!("core{}", std::env::consts::EXE_SUFFIX);
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        candidates.push(parent.join(&executable_name));
        if parent.file_name().is_some_and(|name| name == "deps")
            && let Some(profile_dir) = parent.parent()
        {
            candidates.push(profile_dir.join(&executable_name));
        }
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    candidates.push(workspace.join("target/debug").join(&executable_name));
    candidates.push(workspace.join("target/release").join(&executable_name));

    let mut seen = std::collections::HashSet::new();
    for candidate in candidates {
        if seen.insert(candidate.clone()) && candidate.is_file() {
            return canonicalize_core(&candidate);
        }
    }
    Err(FindCoreError::NotFound)
}

fn canonicalize_core(path: &Path) -> Result<PathBuf, FindCoreError> {
    std::fs::canonicalize(path).map_err(|source| FindCoreError::Canonicalize {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn process_timeout_is_typed_and_output_is_bounded() {
        let output = run_process(&ProcessSpec {
            program: PathBuf::from("sh"),
            args: vec!["-c".into(), "printf started; sleep 10".into()],
            cwd: None,
            env: Vec::new(),
            timeout: Duration::from_millis(100),
            max_output_bytes: 64,
        })
        .await
        .unwrap();
        assert!(output.timed_out);
        assert_eq!(output.stdout, b"started");

        let noisy = run_process(&ProcessSpec {
            program: PathBuf::from("sh"),
            args: vec!["-c".into(), "yes x | head -c 10000".into()],
            cwd: None,
            env: Vec::new(),
            timeout: Duration::from_secs(2),
            max_output_bytes: 32,
        })
        .await
        .unwrap();
        assert!(noisy.success());
        assert_eq!(noisy.stdout.len(), 32);
        assert!(noisy.stdout_truncated);
    }

    #[test]
    fn explicit_discovery_is_cwd_independent_and_missing_path_is_actionable() {
        let current = std::env::current_exe().unwrap();
        assert_eq!(
            find_core(Some(&current)).unwrap(),
            current.canonicalize().unwrap()
        );
        let missing = std::env::temp_dir().join("definitely-missing-core-eval-binary");
        let error = find_core(Some(&missing)).unwrap_err().to_string();
        assert!(error.contains("not a regular file"));
    }
}
