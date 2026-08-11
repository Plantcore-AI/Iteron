//! Immutable runtime policy for bounded first-party observation tools.
//!
//! The registry installs this value exactly once from the run's tunables checkpoint. Tool
//! closures retain the same shared cell, so fresh, resumed, and child sessions cannot rediscover
//! process-local defaults after their checkpoint has been pinned.

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
                source_max_bytes: 8 * 1024 * 1024,
                output_max_bytes: 400_000,
                max_lines: 1_000_000,
            },
            list_dir: DirectoryListPolicy {
                max_depth: 6,
                max_entries: 400,
                output_max_bytes: 1_000_000,
            },
            glob: GlobPolicy {
                max_depth: 20,
                max_results: 400,
                output_max_bytes: 1_000_000,
            },
            repo_map: RepoMapPolicy {
                max_files: 1_024,
                max_depth: 8,
                max_tokens: 6_000,
            },
            web_fetch: WebFetchPolicy {
                body_max_bytes: 1_000_000,
                max_redirects: 5,
                timeout_seconds: 60,
                max_lines: 15_000,
            },
            shell: ShellPolicy {
                timeout_seconds: iteron_sandbox::Confinement::UNCONFINED_TIMEOUT_SECS,
                stdout_max_bytes: iteron_sandbox::Confinement::UNCONFINED_MAX_OUTPUT_BYTES,
                stderr_max_bytes: iteron_sandbox::Confinement::UNCONFINED_MAX_OUTPUT_BYTES,
            },
            grep: GrepPolicy {
                max_matches: 1_000,
                snippet_max_bytes: 1_024,
                output_max_bytes: 512 * 1024,
            },
            git: GitPolicy {
                timeout_seconds: 30,
                output_max_bytes: 64 * 1024,
                status_max_entries: 2_048,
                log_max_entries: 100,
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
