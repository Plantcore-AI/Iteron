//! One bounded repository-ignore reader/matcher used by implicit observation traversals.
//! Exact explicit path authorization remains with each tool's existing path owner.
use crate::edit::suspicious_unicode;
use crate::grep_tool::{
    MAX_GITIGNORE_FILE_BYTES, MAX_GITIGNORE_FILES, MAX_GITIGNORE_PATTERNS,
    MAX_GITIGNORE_TOTAL_BYTES, MAX_GREP_ENTRIES,
};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, IntoIter, WalkDir};

#[derive(Default)]
pub(super) struct IgnoreRules {
    rules: Vec<(PathBuf, Gitignore)>,
}

impl IgnoreRules {
    pub(super) fn push(&mut self, root: PathBuf, matcher: Gitignore) {
        self.rules.push((root, matcher));
        self.rules.sort_by(|(left, _), (right, _)| {
            left.components()
                .count()
                .cmp(&right.components().count())
                .then(left.cmp(right))
        });
    }

    pub(super) fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        let mut ignored = false;
        for (root, matcher) in &self.rules {
            if !path.starts_with(root) {
                continue;
            }
            let matched = matcher.matched_path_or_any_parents(path, is_dir);
            if matched.is_ignore() {
                ignored = true;
            } else if matched.is_whitelist() {
                ignored = false;
            }
        }
        ignored
    }
}

#[derive(Default)]
pub(super) struct IgnoreBudget {
    files: usize,
    bytes: usize,
    patterns: usize,
}

/// Per-call materialized rules and their actual cumulative source budget. Rules never grant
/// path, execution, or model instruction authority; they only prune implicit discovery.
pub(super) struct RepositoryIgnore {
    root: PathBuf,
    rules: IgnoreRules,
    budget: IgnoreBudget,
    directory_checks: usize,
}

impl RepositoryIgnore {
    pub(super) fn new(root: &Path, base: &Path) -> Result<Self, String> {
        let mut owner = Self {
            root: root.to_path_buf(),
            rules: IgnoreRules::default(),
            budget: IgnoreBudget::default(),
            directory_checks: 0,
        };
        owner.enter_directory(root)?;
        // Ancestor rules apply to a narrowed repository search. An explicitly authorized host
        // path outside this repository keeps its existing semantics; never inspect host/global
        // ignore files outside the repository source capability.
        if let Ok(relative) = base.strip_prefix(root) {
            let mut directory = root.to_path_buf();
            for component in relative.components() {
                directory.push(component);
                owner.enter_directory(&directory)?;
            }
        }
        Ok(owner)
    }

    pub(super) fn enter_directory(&mut self, directory: &Path) -> Result<(), String> {
        if !directory.starts_with(&self.root) {
            return Ok(());
        }
        let limit =
            iteron_tunables::param_usize("tools.grep_tool.max_grep_entries", MAX_GREP_ENTRIES)
                .clamp(1, MAX_GREP_ENTRIES);
        self.directory_checks = self
            .directory_checks
            .checked_add(1)
            .ok_or("repository ignore directory budget overflow")?;
        if self.directory_checks > limit {
            return Err(format!(
                "repository ignore traversal exceeds the {limit}-directory limit"
            ));
        }
        // The base has already loaded its ancestry; traversals call enter only for descendant
        // directories, so no rule body is repeatedly charged or read.
        if self.rules.rules.iter().any(|(root, _)| root == directory) {
            return Ok(());
        }
        if let Some((root, matcher)) =
            load_ignore(&self.root, &directory.join(".gitignore"), &mut self.budget)?
        {
            self.rules.push(root, matcher);
        }
        Ok(())
    }

    pub(super) fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        self.rules.is_ignored(path, is_dir)
    }
}

/// The actual implicit traversal. Child ignore sources are read only after their directory
/// survives inherited rules; an ignored parent is never searched for a possible exception.
pub(super) struct RepositoryWalk {
    walk: IntoIter,
    ignore: RepositoryIgnore,
    remaining: usize,
    depth: usize,
}

impl RepositoryWalk {
    pub(super) fn new(root: &Path, base: &Path, depth: usize) -> Result<Self, String> {
        Ok(Self {
            walk: WalkDir::new(base)
                .max_depth(depth)
                .follow_links(false)
                .into_iter(),
            depth,
            ignore: RepositoryIgnore::new(root, base)?,
            remaining: iteron_tunables::param_usize(
                "tools.grep_tool.max_grep_entries",
                MAX_GREP_ENTRIES,
            )
            .clamp(1, MAX_GREP_ENTRIES),
        })
    }

    pub(super) fn next_entry(&mut self) -> Result<Option<DirEntry>, String> {
        while let Some(entry) = self.walk.next() {
            self.remaining = self
                .remaining
                .checked_sub(1)
                .ok_or("repository discovery reached its traversal ceiling; narrow the path")?;
            let entry = entry.map_err(|_| "repository discovery cannot safely enumerate a path")?;
            // The explicitly selected base is authorized by the caller's path owner. Ignore rules
            // only prune its implicit descendants, and no symlink is followed or emitted.
            if entry.depth() == 0 {
                continue;
            }
            let kind = entry.file_type();
            if kind.is_symlink() || (!kind.is_dir() && !kind.is_file()) {
                continue;
            }
            if iteron_ctx::source::is_default_pruned_component(
                entry.file_name().to_str().unwrap_or(""),
            ) || self.ignore.is_ignored(entry.path(), kind.is_dir())
            {
                if kind.is_dir() {
                    self.walk.skip_current_dir();
                }
                continue;
            }
            if kind.is_dir() && entry.depth() < self.depth {
                self.ignore.enter_directory(entry.path())?;
            }
            return Ok(Some(entry));
        }
        Ok(None)
    }
}

pub(super) fn load_ignore(
    workspace_root: &Path,
    path: &Path,
    budget: &mut IgnoreBudget,
) -> Result<Option<(PathBuf, Gitignore)>, String> {
    let max_gitignore_files =
        iteron_tunables::param_usize("tools.grep_tool.max_gitignore_files", MAX_GITIGNORE_FILES);
    if budget.files >= max_gitignore_files {
        return Err(format!(
            "grep: repository exceeds the {max_gitignore_files}-file .gitignore limit"
        ));
    }
    let max_gitignore_total_bytes = iteron_tunables::param_usize(
        "tools.grep_tool.max_gitignore_total_bytes",
        iteron_tunables::param_integer(
            "tools.grep_tool.max_gitignore_total_bytes",
            MAX_GITIGNORE_TOTAL_BYTES,
        ),
    );
    let remaining = max_gitignore_total_bytes.saturating_sub(budget.bytes);
    if remaining == 0 {
        return Err(format!(
            "grep: .gitignore sources exceed the {max_gitignore_total_bytes}-byte total limit"
        ));
    }
    let content = match iteron_ctx::source::read_bounded_utf8(
        workspace_root,
        path,
        remaining.min(iteron_tunables::param_usize(
            "tools.grep_tool.max_gitignore_file_bytes",
            iteron_tunables::param_integer(
                "tools.grep_tool.max_gitignore_file_bytes",
                MAX_GITIGNORE_FILE_BYTES,
            ),
        )),
        iteron_ctx::source::SourceScope::Repository,
    ) {
        Ok(Some(content)) => content,
        Ok(None) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "grep cannot safely read .gitignore: {}",
                error.reason()
            ));
        }
    };
    if suspicious_unicode(&content).is_some() {
        return Err("grep: .gitignore contains bidi or zero-width control characters".into());
    }
    budget.files += 1;
    budget.bytes = budget.bytes.saturating_add(content.len());
    let rule_root = path
        .parent()
        .ok_or_else(|| "grep: .gitignore has no parent directory".to_string())?
        .to_path_buf();
    let mut builder = GitignoreBuilder::new(&rule_root);
    let max_gitignore_patterns = iteron_tunables::param_usize(
        "tools.grep_tool.max_gitignore_patterns",
        iteron_tunables::param_integer(
            "tools.grep_tool.max_gitignore_patterns",
            MAX_GITIGNORE_PATTERNS,
        ),
    );
    for (line_index, line) in content.lines().enumerate() {
        budget.patterns = budget.patterns.saturating_add(1);
        if budget.patterns > max_gitignore_patterns {
            return Err(format!(
                "grep: .gitignore sources exceed the {max_gitignore_patterns}-line limit"
            ));
        }
        let line = if line_index == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        builder
            .add_line(Some(path.to_path_buf()), line)
            .map_err(|error| format!("grep: invalid .gitignore pattern: {error}"))?;
    }
    let matcher = builder
        .build()
        .map_err(|error| format!("grep: cannot compile bounded .gitignore rules: {error}"))?;
    Ok(Some((rule_root, matcher)))
}
