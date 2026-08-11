//! Decoder for immutable first-party observation-tool limits.

use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use iteron_tunables::{ResolutionValue, RuntimeGetterId};
use std::collections::BTreeMap;

pub(crate) fn decode(
    view: &EffectiveTunablesView,
) -> Result<iteron_tools::ObservationToolPolicy, EffectiveObservationToolError> {
    view.with_getter(RuntimeGetterId::EffectiveObservationTools, || {
        decode_inner(view)
    })
}

fn decode_inner(
    view: &EffectiveTunablesView,
) -> Result<iteron_tools::ObservationToolPolicy, EffectiveObservationToolError> {
    let read = view.object("read_file_limits")?;
    let list = view.object("list_dir_limits")?;
    let glob = view.object("glob_limits")?;
    let repo = view.object("repo_map")?;
    let web = view.object("web_fetch_limits")?;
    let shell = view.object("shell_timeout_output")?;
    let grep = view.object("grep_limits")?;
    let git = view.object("git_limits")?;
    iteron_tools::ObservationToolPolicy {
        read_file: iteron_tools::ReadFilePolicy {
            source_max_bytes: usize_field(read, "read_file_limits", "source_max_bytes")?,
            output_max_bytes: usize_field(read, "read_file_limits", "output_max_bytes")?,
            max_lines: usize_field(read, "read_file_limits", "max_lines")?,
        },
        list_dir: iteron_tools::DirectoryListPolicy {
            max_depth: usize_field(list, "list_dir_limits", "max_depth")?,
            max_entries: usize_field(list, "list_dir_limits", "max_entries")?,
            output_max_bytes: usize_field(list, "list_dir_limits", "output_max_bytes")?,
        },
        glob: iteron_tools::GlobPolicy {
            max_depth: usize_field(glob, "glob_limits", "max_depth")?,
            max_results: usize_field(glob, "glob_limits", "max_results")?,
            output_max_bytes: usize_field(glob, "glob_limits", "output_max_bytes")?,
        },
        repo_map: iteron_tools::RepoMapPolicy {
            max_files: usize_field(repo, "repo_map", "max_files")?,
            max_depth: u8_field(repo, "repo_map", "max_depth")?,
            max_tokens: usize_field(repo, "repo_map", "max_tokens")?,
        },
        web_fetch: iteron_tools::WebFetchPolicy {
            body_max_bytes: usize_field(web, "web_fetch_limits", "body_max_bytes")?,
            max_redirects: usize_field(web, "web_fetch_limits", "max_redirects")?,
            timeout_seconds: u64_field(web, "web_fetch_limits", "timeout_seconds")?,
            max_lines: usize_field(web, "web_fetch_limits", "max_lines")?,
        },
        shell: iteron_tools::ShellPolicy {
            timeout_seconds: u64_field(shell, "shell_timeout_output", "timeout_seconds")?,
            stdout_max_bytes: usize_field(shell, "shell_timeout_output", "stdout_max_bytes")?,
            stderr_max_bytes: usize_field(shell, "shell_timeout_output", "stderr_max_bytes")?,
        },
        grep: iteron_tools::GrepPolicy {
            max_matches: usize_field(grep, "grep_limits", "max_matches")?,
            snippet_max_bytes: usize_field(grep, "grep_limits", "snippet_max_bytes")?,
            output_max_bytes: usize_field(grep, "grep_limits", "output_max_bytes")?,
        },
        git: iteron_tools::GitPolicy {
            timeout_seconds: u64_field(git, "git_limits", "timeout_seconds")?,
            output_max_bytes: usize_field(git, "git_limits", "output_max_bytes")?,
            status_max_entries: usize_field(git, "git_limits", "status_max_entries")?,
            log_max_entries: usize_field(git, "git_limits", "log_max_entries")?,
        },
    }
    .validate()
    .map_err(EffectiveObservationToolError::InvalidOwner)
}

fn integer_field(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<i64, EffectiveObservationToolError> {
    match fields.get(field) {
        Some(ResolutionValue::Integer { value }) => Ok(*value),
        Some(_) => Err(EffectiveObservationToolError::WrongFieldType { family, field }),
        None => Err(EffectiveObservationToolError::MissingField { family, field }),
    }
}

fn usize_field(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<usize, EffectiveObservationToolError> {
    usize::try_from(integer_field(fields, family, field)?)
        .map_err(|_| EffectiveObservationToolError::Range { family, field })
}

fn u64_field(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<u64, EffectiveObservationToolError> {
    u64::try_from(integer_field(fields, family, field)?)
        .map_err(|_| EffectiveObservationToolError::Range { family, field })
}

fn u8_field(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<u8, EffectiveObservationToolError> {
    u8::try_from(integer_field(fields, family, field)?)
        .map_err(|_| EffectiveObservationToolError::Range { family, field })
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EffectiveObservationToolError {
    #[error(transparent)]
    View(#[from] EffectiveViewError),
    #[error("effective tunable `{family}` is missing object field `{field}`")]
    MissingField {
        family: &'static str,
        field: &'static str,
    },
    #[error("effective tunable `{family}` object field `{field}` has the wrong type")]
    WrongFieldType {
        family: &'static str,
        field: &'static str,
    },
    #[error("effective tunable `{family}` field `{field}` is outside the runtime type range")]
    Range {
        family: &'static str,
        field: &'static str,
    },
    #[error("effective observation-tool policy violates its production owner: {0}")]
    InvalidOwner(&'static str),
}
