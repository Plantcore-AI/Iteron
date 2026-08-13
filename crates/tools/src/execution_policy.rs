//! Immutable runtime policy for bounded first-party observation tools.
//!
//! The registry installs this value exactly once from the run's tunables checkpoint. Tool
//! closures retain the same shared cell, so fresh, resumed, and child sessions cannot rediscover
//! process-local defaults after their checkpoint has been pinned.

// Shipped defaults for every bounded observation tool. Each is the value a run starts from when
// its tunables checkpoint names nothing, so each has to be addressable by name rather than by
// position inside the `Default` impl. The hard envelopes that reject an out-of-range override live
// in `validate` and are deliberately not defaults.

/// Largest file `read_file` will open at all; above this the read is refused rather than truncated.
const DEFAULT_READ_FILE_SOURCE_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Bytes of one `read_file` window kept in context — the truncation point, not the file limit.
const DEFAULT_READ_FILE_OUTPUT_MAX_BYTES: usize = 400_000;
/// Line ceiling for one `read_file` window; the byte cap is normally what binds first.
const DEFAULT_READ_FILE_MAX_LINES: usize = 1_000_000;

/// Directory levels `list_dir` descends. Shallow, because a deep listing answers no question a
/// targeted glob would not answer more cheaply.
const DEFAULT_LIST_DIR_MAX_DEPTH: usize = 6;
/// Entries returned by one `list_dir` before the listing is cut.
const DEFAULT_LIST_DIR_MAX_ENTRIES: usize = 400;
/// Byte ceiling on rendered `list_dir` output.
const DEFAULT_LIST_DIR_OUTPUT_MAX_BYTES: usize = 1_000_000;

/// Directory levels `glob` walks; deeper than `list_dir` because a pattern is already selective.
const DEFAULT_GLOB_MAX_DEPTH: usize = 20;
/// Paths returned by one `glob` before the result set is cut.
const DEFAULT_GLOB_MAX_RESULTS: usize = 400;
/// Byte ceiling on rendered `glob` output.
const DEFAULT_GLOB_OUTPUT_MAX_BYTES: usize = 1_000_000;

/// Files a repository map may summarize.
const DEFAULT_REPO_MAP_MAX_FILES: usize = 1_024;
/// Directory levels a repository map descends.
const DEFAULT_REPO_MAP_MAX_DEPTH: u8 = 8;
/// Token budget a repository map is allowed to occupy in context.
const DEFAULT_REPO_MAP_MAX_TOKENS: usize = 6_000;

/// Response body `web_fetch` will read before truncating.
const DEFAULT_WEB_FETCH_BODY_MAX_BYTES: usize = 1_000_000;
/// Same-host redirects followed on one fetch; cross-host hops are returned, never followed.
const DEFAULT_WEB_FETCH_MAX_REDIRECTS: usize = 5;
/// Overall deadline for one fetch, connect phase included.
const DEFAULT_WEB_FETCH_TIMEOUT_SECS: u64 = 60;
/// Line ceiling on extracted page text.
const DEFAULT_WEB_FETCH_MAX_LINES: usize = 15_000;

/// Matches `grep` reports before the search is declared incomplete.
const DEFAULT_GREP_MAX_MATCHES: usize = 1_000;
/// Bytes retained per reported match.
const DEFAULT_GREP_SNIPPET_MAX_BYTES: usize = 1_024;
/// Byte ceiling on rendered `grep` output across all matches.
const DEFAULT_GREP_OUTPUT_MAX_BYTES: usize = 512 * 1024;

/// Deadline for one Git invocation, after which the child process group is torn down.
const DEFAULT_GIT_TIMEOUT_SECS: u64 = 30;
/// Byte ceiling on captured Git output.
const DEFAULT_GIT_OUTPUT_MAX_BYTES: usize = 64 * 1024;
/// Entries reported by `git_status` before the listing is cut.
const DEFAULT_GIT_STATUS_MAX_ENTRIES: usize = 2_048;
/// Commits reported by `git_log` before the listing is cut.
const DEFAULT_GIT_LOG_MAX_ENTRIES: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadFilePolicy {
    pub source_max_bytes: usize,
    pub output_max_bytes: usize,
    pub max_lines: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryListPolicy {
    pub max_depth: usize,
    pub max_entries: usize,
    pub output_max_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobPolicy {
    pub max_depth: usize,
    pub max_results: usize,
    pub output_max_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoMapPolicy {
    pub max_files: usize,
    pub max_depth: u8,
    pub max_tokens: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebFetchPolicy {
    pub body_max_bytes: usize,
    pub max_redirects: usize,
    pub timeout_seconds: u64,
    pub max_lines: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellPolicy {
    pub timeout_seconds: u64,
    pub stdout_max_bytes: usize,
    pub stderr_max_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrepPolicy {
    pub max_matches: usize,
    pub snippet_max_bytes: usize,
    pub output_max_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitPolicy {
    pub timeout_seconds: u64,
    pub output_max_bytes: usize,
    pub status_max_entries: usize,
    pub log_max_entries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationToolPolicy {
    pub read_file: ReadFilePolicy,
    pub list_dir: DirectoryListPolicy,
    pub glob: GlobPolicy,
    pub repo_map: RepoMapPolicy,
    pub web_fetch: WebFetchPolicy,
    pub shell: ShellPolicy,
    pub grep: GrepPolicy,
    pub git: GitPolicy,
}

impl Default for ObservationToolPolicy {
    fn default() -> Self {
        Self {
            read_file: ReadFilePolicy {
                source_max_bytes: iteron_tunables::param_usize(
                    "tools.execution_policy.default_read_file_source_max_bytes",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_read_file_source_max_bytes",
                        DEFAULT_READ_FILE_SOURCE_MAX_BYTES,
                    ),
                ),
                output_max_bytes: iteron_tunables::param_usize(
                    "tools.execution_policy.default_read_file_output_max_bytes",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_read_file_output_max_bytes",
                        DEFAULT_READ_FILE_OUTPUT_MAX_BYTES,
                    ),
                ),
                max_lines: iteron_tunables::param_usize(
                    "tools.execution_policy.default_read_file_max_lines",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_read_file_max_lines",
                        DEFAULT_READ_FILE_MAX_LINES,
                    ),
                ),
            },
            list_dir: DirectoryListPolicy {
                max_depth: iteron_tunables::param_usize(
                    "tools.execution_policy.default_list_dir_max_depth",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_list_dir_max_depth",
                        DEFAULT_LIST_DIR_MAX_DEPTH,
                    ),
                ),
                max_entries: iteron_tunables::param_usize(
                    "tools.execution_policy.default_list_dir_max_entries",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_list_dir_max_entries",
                        DEFAULT_LIST_DIR_MAX_ENTRIES,
                    ),
                ),
                output_max_bytes: iteron_tunables::param_usize(
                    "tools.execution_policy.default_list_dir_output_max_bytes",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_list_dir_output_max_bytes",
                        DEFAULT_LIST_DIR_OUTPUT_MAX_BYTES,
                    ),
                ),
            },
            glob: GlobPolicy {
                max_depth: iteron_tunables::param_usize(
                    "tools.execution_policy.default_glob_max_depth",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_glob_max_depth",
                        DEFAULT_GLOB_MAX_DEPTH,
                    ),
                ),
                max_results: iteron_tunables::param_usize(
                    "tools.execution_policy.default_glob_max_results",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_glob_max_results",
                        DEFAULT_GLOB_MAX_RESULTS,
                    ),
                ),
                output_max_bytes: iteron_tunables::param_usize(
                    "tools.execution_policy.default_glob_output_max_bytes",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_glob_output_max_bytes",
                        DEFAULT_GLOB_OUTPUT_MAX_BYTES,
                    ),
                ),
            },
            repo_map: RepoMapPolicy {
                max_files: iteron_tunables::param_usize(
                    "tools.execution_policy.default_repo_map_max_files",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_repo_map_max_files",
                        DEFAULT_REPO_MAP_MAX_FILES,
                    ),
                ),
                max_depth: u8::try_from(iteron_tunables::param_i128(
                    "tools.execution_policy.default_repo_map_max_depth",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_repo_map_max_depth",
                        DEFAULT_REPO_MAP_MAX_DEPTH,
                    ) as i128,
                ))
                .unwrap_or(iteron_tunables::param_integer(
                    "tools.execution_policy.default_repo_map_max_depth",
                    DEFAULT_REPO_MAP_MAX_DEPTH,
                )),
                max_tokens: iteron_tunables::param_usize(
                    "tools.execution_policy.default_repo_map_max_tokens",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_repo_map_max_tokens",
                        DEFAULT_REPO_MAP_MAX_TOKENS,
                    ),
                ),
            },
            web_fetch: WebFetchPolicy {
                body_max_bytes: iteron_tunables::param_usize(
                    "tools.execution_policy.default_web_fetch_body_max_bytes",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_web_fetch_body_max_bytes",
                        DEFAULT_WEB_FETCH_BODY_MAX_BYTES,
                    ),
                ),
                max_redirects: iteron_tunables::param_usize(
                    "tools.execution_policy.default_web_fetch_max_redirects",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_web_fetch_max_redirects",
                        DEFAULT_WEB_FETCH_MAX_REDIRECTS,
                    ),
                ),
                timeout_seconds: iteron_tunables::param_u64(
                    "tools.execution_policy.default_web_fetch_timeout_secs",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_web_fetch_timeout_secs",
                        DEFAULT_WEB_FETCH_TIMEOUT_SECS,
                    ),
                ),
                max_lines: iteron_tunables::param_usize(
                    "tools.execution_policy.default_web_fetch_max_lines",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_web_fetch_max_lines",
                        DEFAULT_WEB_FETCH_MAX_LINES,
                    ),
                ),
            },
            shell: ShellPolicy {
                timeout_seconds: iteron_sandbox::Confinement::UNCONFINED_TIMEOUT_SECS,
                stdout_max_bytes: iteron_sandbox::Confinement::UNCONFINED_MAX_OUTPUT_BYTES,
                stderr_max_bytes: iteron_sandbox::Confinement::UNCONFINED_MAX_OUTPUT_BYTES,
            },
            grep: GrepPolicy {
                max_matches: iteron_tunables::param_usize(
                    "tools.execution_policy.default_grep_max_matches",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_grep_max_matches",
                        DEFAULT_GREP_MAX_MATCHES,
                    ),
                ),
                snippet_max_bytes: iteron_tunables::param_usize(
                    "tools.execution_policy.default_grep_snippet_max_bytes",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_grep_snippet_max_bytes",
                        DEFAULT_GREP_SNIPPET_MAX_BYTES,
                    ),
                ),
                output_max_bytes: iteron_tunables::param_usize(
                    "tools.execution_policy.default_grep_output_max_bytes",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_grep_output_max_bytes",
                        DEFAULT_GREP_OUTPUT_MAX_BYTES,
                    ),
                ),
            },
            git: GitPolicy {
                timeout_seconds: iteron_tunables::param_u64(
                    "tools.execution_policy.default_git_timeout_secs",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_git_timeout_secs",
                        DEFAULT_GIT_TIMEOUT_SECS,
                    ),
                ),
                output_max_bytes: iteron_tunables::param_usize(
                    "tools.execution_policy.default_git_output_max_bytes",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_git_output_max_bytes",
                        DEFAULT_GIT_OUTPUT_MAX_BYTES,
                    ),
                ),
                status_max_entries: iteron_tunables::param_usize(
                    "tools.execution_policy.default_git_status_max_entries",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_git_status_max_entries",
                        DEFAULT_GIT_STATUS_MAX_ENTRIES,
                    ),
                ),
                log_max_entries: iteron_tunables::param_usize(
                    "tools.execution_policy.default_git_log_max_entries",
                    iteron_tunables::param_integer(
                        "tools.execution_policy.default_git_log_max_entries",
                        DEFAULT_GIT_LOG_MAX_ENTRIES,
                    ),
                ),
            },
        }
    }
}

impl ObservationToolPolicy {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.read_file.source_max_bytes == 0
            || self.read_file.source_max_bytes > 128 * 1024 * 1024
            || self.read_file.output_max_bytes < 512
            || self.read_file.output_max_bytes > 16 * 1024 * 1024
            || self.read_file.output_max_bytes > self.read_file.source_max_bytes
            || self.read_file.max_lines == 0
            || self.read_file.max_lines > 1_000_000
        {
            return Err("read_file policy is outside its bounded owner envelope");
        }
        if self.list_dir.max_depth > 64
            || self.list_dir.max_entries == 0
            || self.list_dir.max_entries > 100_000
            || self.list_dir.output_max_bytes < 256
            || self.list_dir.output_max_bytes > 16 * 1024 * 1024
        {
            return Err("list_dir policy is outside its bounded owner envelope");
        }
        if self.glob.max_depth > 128
            || self.glob.max_results == 0
            || self.glob.max_results > 100_000
            || self.glob.output_max_bytes < 256
            || self.glob.output_max_bytes > 16 * 1024 * 1024
        {
            return Err("glob policy is outside its bounded owner envelope");
        }
        if self.repo_map.max_files == 0
            || self.repo_map.max_files > 1_000_000
            || self.repo_map.max_depth > 128
            || self.repo_map.max_tokens == 0
            || self.repo_map.max_tokens > 1_000_000
        {
            return Err("repo_map policy is outside its bounded owner envelope");
        }
        if self.web_fetch.body_max_bytes < 1_000
            || self.web_fetch.body_max_bytes > 16 * 1024 * 1024
            || self.web_fetch.max_redirects > 32
            || self.web_fetch.timeout_seconds == 0
            || self.web_fetch.timeout_seconds > 300
            || self.web_fetch.max_lines == 0
            || self.web_fetch.max_lines > 100_000
        {
            return Err("web_fetch policy is outside its bounded owner envelope");
        }
        if self.shell.timeout_seconds == 0
            || self.shell.timeout_seconds > 86_400
            || self.shell.stdout_max_bytes == 0
            || self.shell.stdout_max_bytes > 16 * 1024 * 1024
            || self.shell.stderr_max_bytes == 0
            || self.shell.stderr_max_bytes > 16 * 1024 * 1024
        {
            return Err("shell policy is outside its bounded owner envelope");
        }
        if self.grep.max_matches == 0
            || self.grep.max_matches > 1_000_000
            || self.grep.snippet_max_bytes == 0
            || self.grep.snippet_max_bytes > 1024 * 1024
            || self.grep.output_max_bytes == 0
            || self.grep.output_max_bytes > 16 * 1024 * 1024
            || self.grep.snippet_max_bytes > self.grep.output_max_bytes
        {
            return Err("grep policy is outside its bounded owner envelope");
        }
        if self.git.timeout_seconds == 0
            || self.git.timeout_seconds > 3_600
            || self.git.output_max_bytes == 0
            || self.git.output_max_bytes > 16 * 1024 * 1024
            || self.git.status_max_entries == 0
            || self.git.status_max_entries > 100_000
            || self.git.log_max_entries == 0
            || self.git.log_max_entries > 10_000
        {
            return Err("git policy is outside its bounded owner envelope");
        }
        Ok(self)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ObservationToolPolicyError {
    #[error("invalid observation-tool runtime policy: {0}")]
    Invalid(&'static str),
    #[error("observation-tool runtime policy was already installed")]
    AlreadyInstalled,
}
