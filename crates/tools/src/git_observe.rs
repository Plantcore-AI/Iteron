//! Bounded `git_status` and `git_log` observations over the shared confined Git harness.

use crate::git_filters::discover_filter_drivers_bounded;
use crate::git_harness::{
    STDERR_LIMIT, hardened_args, hardened_git_command, resolve_git_executable,
    resolve_repository_layout, run_command_bounded,
};
use crate::{GitPolicy, Registry, ToolError, boxfut, err_result, ok_result};
use iteron_protocol::{Capability, Purity, ToolSpec};
use serde_json::Value;
use std::ffi::OsString;
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;

const DEFAULT_LOG_COUNT: usize = 20;
#[cfg(unix)]
const ENVIRONMENT_GIT_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(any(unix, test))]
const MAX_ENVIRONMENT_BRANCH_BYTES: usize = 512;
#[cfg(any(unix, test))]
const MAX_ENVIRONMENT_RENDERED_BYTES: usize = 1024;

#[derive(Default)]
struct Disclosure {
    escaped_fields: usize,
    non_utf8_fields: usize,
}

fn status_args(filter_drivers: &[String]) -> Vec<OsString> {
    hardened_args(
        filter_drivers,
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=normal",
            "--ignore-submodules=all",
            "--no-renames",
        ]
        .into_iter()
        .map(OsString::from),
    )
}

#[cfg(any(unix, test))]
fn environment_status_args(filter_drivers: &[String]) -> Vec<OsString> {
    hardened_args(
        filter_drivers,
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--branch",
            "--no-ahead-behind",
            "--untracked-files=normal",
            "--ignore-submodules=all",
            "--no-renames",
        ]
        .into_iter()
        .map(OsString::from),
    )
}

fn log_args(filter_drivers: &[String], max_count: usize) -> Vec<OsString> {
    hardened_args(
        filter_drivers,
        [
            OsString::from("log"),
            OsString::from("--no-show-signature"),
            OsString::from("--no-decorate"),
            OsString::from("--no-color"),
            OsString::from("--format=%H%x00%aI%x00%an%x00%s%x00"),
            OsString::from(format!("--max-count={max_count}")),
        ],
    )
}

async fn capture_observation_inner(
    root: &Path,
    args_for: impl FnOnce(&[String]) -> Vec<OsString>,
    label: &str,
    policy: GitPolicy,
) -> Result<Vec<u8>, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("workspace root: {error}"))?;
    let repository = resolve_repository_layout(&root)?;
    let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &root)
        .map_err(|error| format!("could not resolve trusted Git: {error}"))?;
    let timeout = Duration::from_secs(policy.timeout_seconds);
    let filter_drivers =
        discover_filter_drivers_bounded(&git, &repository, timeout, policy.output_max_bytes)
            .await?;
    let args = args_for(&filter_drivers);
    let mut command = hardened_git_command(&git, &repository, &args);
    let captured = run_command_bounded(
        &mut command,
        timeout,
        policy.output_max_bytes,
        policy.output_max_bytes.min(iteron_tunables::param_integer(
            "tools.git_harness.stderr_limit",
            STDERR_LIMIT,
        )),
    )
    .await
    .map_err(|error| format!("could not run bounded {label}: {error}"))?;

    if !captured.status.success() {
        return Err(format!(
            "{label} failed (exit {}): {}",
            captured.status.code().unwrap_or(-1),
            captured.stderr.render("Git stderr").trim()
        ));
    }
    if captured.stdout.truncated() {
        return Err(format!(
            "{label} output exceeded the {}-byte source limit; no partial \
             observation was returned",
            policy.output_max_bytes
        ));
    }
    Ok(captured.stdout.retained_bytes())
}

async fn capture_observation(
    root: &Path,
    args_for: impl FnOnce(&[String]) -> Vec<OsString>,
    label: &str,
    policy: GitPolicy,
) -> Result<Vec<u8>, String> {
    let timeout = Duration::from_secs(policy.timeout_seconds);
    tokio::time::timeout(
        timeout,
        capture_observation_inner(root, args_for, label, policy),
    )
    .await
    .map_err(|_| format!("{label} exceeded {} seconds", policy.timeout_seconds))?
}

fn is_suspicious_unicode(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{115f}'
                | '\u{1160}'
                | '\u{17b4}'
                | '\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff0}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{13455}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e00ff}'
                | '\u{e0100}'..='\u{e0fff}'
        )
}

fn render_field(bytes: &[u8], disclosure: &mut Disclosure) -> String {
    match std::str::from_utf8(bytes) {
        Ok(value) => {
            let mut rendered = String::with_capacity(value.len());
            let mut escaped = false;
            for ch in value.chars() {
                if ch == '\\' {
                    rendered.push_str("\\\\");
                    escaped = true;
                } else if is_suspicious_unicode(ch) {
                    use std::fmt::Write;
                    let _ = write!(rendered, "\\u{{{:x}}}", u32::from(ch));
                    escaped = true;
                } else {
                    rendered.push(ch);
                }
            }
            if escaped {
                disclosure.escaped_fields += 1;
            }
            rendered
        }
        Err(_) => {
            disclosure.escaped_fields += 1;
            disclosure.non_utf8_fields += 1;
            let mut rendered = String::with_capacity(bytes.len().saturating_mul(4));
            for byte in bytes {
                match byte {
                    b' '..=b'~' if *byte != b'\\' => rendered.push(char::from(*byte)),
                    b'\\' => rendered.push_str("\\\\"),
                    _ => {
                        use std::fmt::Write;
                        let _ = write!(rendered, "\\x{byte:02x}");
                    }
                }
            }
            rendered
        }
    }
}

fn push_bounded(
    output: &mut String,
    value: &str,
    label: &str,
    output_max_bytes: usize,
) -> Result<(), String> {
    let next = output
        .len()
        .checked_add(value.len())
        .ok_or_else(|| format!("{label} rendered output size overflowed"))?;
    if next > output_max_bytes {
        return Err(format!(
            "{label} rendered output exceeded the {output_max_bytes}-byte limit; no partial \
             observation was returned"
        ));
    }
    output.push_str(value);
    Ok(())
}

fn append_disclosure(
    output: &mut String,
    disclosure: &Disclosure,
    label: &str,
    output_max_bytes: usize,
) -> Result<(), String> {
    if disclosure.escaped_fields == 0 {
        return Ok(());
    }
    push_bounded(
        output,
        &format!(
            "[Git output safety: escaped {} field(s) containing control/invisible or invalid \
             UTF-8 data; {} field(s) were non-UTF-8]\n",
            disclosure.escaped_fields, disclosure.non_utf8_fields
        ),
        label,
        output_max_bytes,
    )
}

fn render_status_with_policy(bytes: &[u8], policy: GitPolicy) -> Result<String, String> {
    if bytes.is_empty() {
        return Ok("(working tree clean)".to_owned());
    }
    if bytes.last() != Some(&0) {
        return Err("Git status returned a malformed non-NUL-terminated record".to_owned());
    }

    let mut output = String::new();
    let mut disclosure = Disclosure::default();
    let mut records = 0_usize;
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        records += 1;
        if records > policy.status_max_entries {
            return Err(format!(
                "Git status exceeded the {}-record limit; no partial observation \
                 was returned",
                policy.status_max_entries
            ));
        }
        if record.len() < 4 || record[2] != b' ' || !record[..2].is_ascii() {
            return Err("Git status returned a malformed porcelain record".to_owned());
        }
        let path = render_field(&record[3..], &mut disclosure);
        push_bounded(
            &mut output,
            &format!(
                "{}{} {path}\n",
                char::from(record[0]),
                char::from(record[1])
            ),
            "Git status",
            policy.output_max_bytes,
        )?;
    }
    append_disclosure(
        &mut output,
        &disclosure,
        "Git status",
        policy.output_max_bytes,
    )?;
    if output.ends_with('\n') {
        output.pop();
    }
    Ok(output)
}

#[cfg(test)]
fn render_status(bytes: &[u8]) -> Result<String, String> {
    render_status_with_policy(bytes, crate::ObservationToolPolicy::default().git)
}

#[cfg(any(unix, test))]
fn split_once_bytes<'a>(value: &'a [u8], separator: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    value
        .windows(separator.len())
        .position(|window| window == separator)
        .map(|index| (&value[..index], &value[index + separator.len()..]))
}

#[cfg(any(unix, test))]
fn render_environment_branch(header: &[u8]) -> Result<(String, Disclosure), String> {
    let raw = header
        .strip_prefix(b"## ")
        .ok_or_else(|| "Git status omitted its porcelain branch header".to_owned())?;
    let (kind, branch) = if let Some(branch) = raw.strip_prefix(b"No commits yet on ") {
        ("unborn:", branch)
    } else if let Some(branch) = raw.strip_prefix(b"Initial commit on ") {
        ("unborn:", branch)
    } else if raw == b"HEAD (no branch)" || raw.starts_with(b"HEAD (detached") {
        ("", b"detached".as_slice())
    } else {
        (
            "",
            split_once_bytes(raw, b"...").map_or(raw, |(name, _)| name),
        )
    };
    if branch.is_empty() || branch.len() > MAX_ENVIRONMENT_BRANCH_BYTES {
        return Err(format!(
            "Git branch name is empty or exceeds the {MAX_ENVIRONMENT_BRANCH_BYTES}-byte bound"
        ));
    }
    let mut disclosure = Disclosure::default();
    let branch = render_field(branch, &mut disclosure);
    Ok((format!("{kind}{branch}"), disclosure))
}

#[cfg(any(unix, test))]
fn render_environment_status(bytes: &[u8]) -> Result<String, String> {
    if bytes.last() != Some(&0) {
        return Err("Git status returned a malformed non-NUL-terminated snapshot".to_owned());
    }
    let mut records = bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty());
    let header = records
        .next()
        .ok_or_else(|| "Git status omitted its porcelain branch header".to_owned())?;
    let (branch, disclosure) = render_environment_branch(header)?;
    let mut staged = 0usize;
    let mut modified = 0usize;
    let mut untracked = 0usize;
    let mut conflicts = 0usize;
    let mut count = 0usize;

    let max_records = crate::ObservationToolPolicy::default()
        .git
        .status_max_entries;
    for record in records {
        count = count.saturating_add(1);
        if count > max_records {
            return Err(format!(
                "Git status exceeded the {max_records}-record environment bound"
            ));
        }
        if record.len() < 4 || record[2] != b' ' || !record[..2].is_ascii() {
            return Err("Git status returned a malformed porcelain record".to_owned());
        }
        let x = record[0];
        let y = record[1];
        if x == b'?' && y == b'?' {
            untracked = untracked.saturating_add(1);
            continue;
        }
        if matches!(
            [x, y],
            [b'D', b'D']
                | [b'A', b'U']
                | [b'U', b'D']
                | [b'U', b'A']
                | [b'D', b'U']
                | [b'A', b'A']
                | [b'U', b'U']
        ) {
            conflicts = conflicts.saturating_add(1);
            continue;
        }
        if x != b' ' {
            staged = staged.saturating_add(1);
        }
        if y != b' ' {
            modified = modified.saturating_add(1);
        }
    }

    let status = if staged == 0 && modified == 0 && untracked == 0 && conflicts == 0 {
        "clean".to_owned()
    } else {
        format!("staged:{staged},modified:{modified},untracked:{untracked},conflicts:{conflicts}")
    };
    let encoding = if disclosure.escaped_fields == 0 {
        String::new()
    } else {
        format!(
            "; branch_encoding=escaped; branch_non_utf8={}",
            disclosure.non_utf8_fields
        )
    };
    let rendered = format!("branch={branch}; status={status}{encoding}");
    let max_rendered_bytes = iteron_tunables::param_usize(
        "tools.git_observe.max_environment_rendered_bytes",
        MAX_ENVIRONMENT_RENDERED_BYTES,
    );
    if rendered.len() > max_rendered_bytes {
        return Err(format!(
            "Git environment summary exceeded the {max_rendered_bytes}-byte rendered bound"
        ));
    }
    Ok(rendered)
}

fn valid_oid(bytes: &[u8]) -> bool {
    matches!(bytes.len(), 40 | 64) && bytes.iter().all(u8::is_ascii_hexdigit)
}

fn valid_iso_date(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || b"-T:+.Z".contains(byte))
}

fn render_log_with_policy(
    bytes: &[u8],
    max_count: usize,
    policy: GitPolicy,
) -> Result<String, String> {
    if bytes.is_empty() {
        return Ok("(no commits)".to_owned());
    }
    let mut fields = bytes.split(|byte| *byte == 0);
    let mut output = String::new();
    let mut disclosure = Disclosure::default();
    let mut records = 0_usize;

    while records < max_count {
        let Some(mut oid) = fields.next() else {
            break;
        };
        if oid.is_empty() || oid == b"\n" {
            break;
        }
        if records > 0 {
            oid = oid
                .strip_prefix(b"\n")
                .ok_or_else(|| "Git log returned a malformed record separator".to_owned())?;
        }
        let date = fields
            .next()
            .ok_or_else(|| "Git log omitted the author date field".to_owned())?;
        let author = fields
            .next()
            .ok_or_else(|| "Git log omitted the author field".to_owned())?;
        let subject = fields
            .next()
            .ok_or_else(|| "Git log omitted the subject field".to_owned())?;
        if !valid_oid(oid) || !valid_iso_date(date) {
            return Err("Git log returned malformed identity/date fields".to_owned());
        }
        let author = render_field(author, &mut disclosure);
        let subject = render_field(subject, &mut disclosure);
        push_bounded(
            &mut output,
            &format!(
                "{}\t{}\t{author}\t{subject}\n",
                String::from_utf8_lossy(oid),
                String::from_utf8_lossy(date)
            ),
            "Git log",
            policy.output_max_bytes,
        )?;
        records += 1;
    }

    if fields.any(|field| !field.is_empty() && field != b"\n") {
        return Err(format!(
            "Git log exceeded or violated the {max_count}-record contract; no partial observation \
             was returned"
        ));
    }
    append_disclosure(&mut output, &disclosure, "Git log", policy.output_max_bytes)?;
    if output.ends_with('\n') {
        output.pop();
    }
    Ok(output)
}

async fn run_git_status(root: &Path, policy: GitPolicy) -> Result<String, String> {
    let bytes = capture_observation(root, status_args, "Git status", policy).await?;
    render_status_with_policy(&bytes, policy)
}

async fn run_git_log(root: &Path, max_count: usize, policy: GitPolicy) -> Result<String, String> {
    let bytes = capture_observation(
        root,
        |drivers| log_args(drivers, max_count),
        "Git log",
        policy,
    )
    .await?;
    render_log_with_policy(&bytes, max_count, policy)
}

#[cfg(unix)]
pub(crate) async fn run_git_environment(root: &Path) -> Result<String, String> {
    let policy = crate::ObservationToolPolicy::default().git;
    let bytes = tokio::time::timeout(
        iteron_tunables::param_duration(
            "tools.git_observe.environment_git_timeout",
            ENVIRONMENT_GIT_TIMEOUT,
        ),
        capture_observation_inner(
            root,
            environment_status_args,
            "Git environment status",
            policy,
        ),
    )
    .await
    .map_err(|_| {
        format!(
            "Git environment status exceeded {} seconds",
            iteron_tunables::param_duration(
                "tools.git_observe.environment_git_timeout",
                ENVIRONMENT_GIT_TIMEOUT
            )
            .as_secs()
        )
    })??;
    render_environment_status(&bytes)
}

#[cfg(not(unix))]
pub(crate) async fn run_git_environment(_root: &Path) -> Result<String, String> {
    // The startup snapshot has a stricter three-second deadline than interactive Git tools.
    // Without Unix process-group semantics, cancelling that outer deadline cannot prove descendant
    // teardown. Fail closed instead of leaving a repository-controlled helper alive in the
    // background; the frontend renders only `git: unavailable`.
    Err("Git environment observation is unavailable on this platform".to_owned())
}

fn parse_log_count_with_policy(input: &Value, policy: GitPolicy) -> Result<usize, String> {
    let object = input
        .as_object()
        .ok_or_else(|| "git_log input must be an object".to_owned())?;
    if object.keys().any(|key| key != "max_count") {
        return Err("git_log accepts only the `max_count` field".to_owned());
    }
    let Some(value) = object.get("max_count") else {
        return Ok(iteron_tunables::param_integer(
            "tools.git_observe.default_log_count",
            DEFAULT_LOG_COUNT,
        )
        .min(policy.log_max_entries));
    };
    let count = value.as_u64().ok_or_else(|| {
        format!(
            "git_log max_count must be an integer from 1 through {}",
            policy.log_max_entries
        )
    })?;
    if !(1..=policy.log_max_entries as u64).contains(&count) {
        return Err(format!(
            "git_log max_count must be an integer from 1 through {}",
            policy.log_max_entries
        ));
    }
    usize::try_from(count).map_err(|_| "git_log max_count is not representable".to_owned())
}

#[cfg(test)]
fn parse_log_count(input: &Value) -> Result<usize, String> {
    parse_log_count_with_policy(input, crate::ObservationToolPolicy::default().git)
}

pub(crate) fn register(registry: &mut Registry) -> Result<(), ToolError> {
    let status_policy_cell = registry.observation_tool_policy_handle();
    registry.push_tool(
        ToolSpec {
            name: "git_status".into(),
            description: "Show bounded porcelain status for the confined repository. Runs the \
                          fixed read-only Git harness directly (never through a shell), ignores \
                          submodule worktrees, escapes deceptive path bytes, and uses the pinned \
                          runtime timeout/output/record ceilings."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{}
            }),
            purity: Purity::Effecting,
            capability: Capability::ReadOnly,
        },
        move |call, root| {
            let status_policy_cell = status_policy_cell.clone();
            boxfut::box_it(async move {
                let id = call.id.clone();
                let Some(policy) = status_policy_cell.get().copied().map(|p| p.git) else {
                    return err_result(
                        id,
                        "git_status refused: immutable observation-tool policy was not installed"
                            .to_owned(),
                    );
                };
                if !matches!(call.input.as_object(), Some(object) if object.is_empty()) {
                    return err_result(id, "git_status input must be an empty object".to_owned());
                }
                match run_git_status(&root, policy).await {
                    Ok(output) => ok_result(id, output),
                    Err(error) => err_result(id, error),
                }
            })
        },
    )?;
    let log_policy_cell = registry.observation_tool_policy_handle();
    registry.push_tool(
        ToolSpec {
            name: "git_log".into(),
            description: "Show a bounded recent commit log from the confined repository. Uses a \
                          fixed machine-readable format and executes Git directly with hooks, \
                          filters, ambient config, paging, signatures, and lazy fetch disabled; \
                          timeout, output, and count use the pinned runtime policy."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "max_count":{
                        "type":"integer",
                        "minimum":1,
                        "description":"recent commits to return (default 20, capped by the pinned runtime policy)"
                    }
                }
            }),
            purity: Purity::Effecting,
            capability: Capability::ReadOnly,
        },
        move |call, root| {
            let log_policy_cell = log_policy_cell.clone();
            boxfut::box_it(async move {
                let id = call.id.clone();
                let Some(policy) = log_policy_cell.get().copied().map(|p| p.git) else {
                    return err_result(
                        id,
                        "git_log refused: immutable observation-tool policy was not installed"
                            .to_owned(),
                    );
                };
                let max_count = match parse_log_count_with_policy(&call.input, policy) {
                    Ok(count) => count,
                    Err(error) => return err_result(id, error),
                };
                match run_git_log(&root, max_count, policy).await {
                    Ok(output) => ok_result(id, output),
                    Err(error) => err_result(id, error),
                }
            })
        },
    )
}

#[cfg(test)]
#[path = "git_observe_tests.rs"]
mod tests;
