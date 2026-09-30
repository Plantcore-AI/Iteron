//! Durable controller witnesses let a later writer continue its own known parent edits. Each
//! turn still gets a real isolated worktree; parent dirt is accepted only against exact host
//! evidence, and the merge composes sealed trees without changing the parent's index or HEAD.

use super::*;
use iteron_agents::AgentWorkspaceWitness;
use std::sync::atomic::{AtomicU64, Ordering};

pub(in crate::runtime) struct PersistentWriterWorktree {
    worktree: WriterWorktree,
    baseline_tree: String,
}

impl PersistentWriterWorktree {
    pub(in crate::runtime) async fn provision(
        parent: PathBuf,
        state: PathBuf,
        id: String,
        witness: Option<AgentWorkspaceWitness>,
    ) -> Result<(Self, AgentWorkspaceWitness), MergeFailure> {
        tokio::task::spawn_blocking(move || {
            let parent = repository_root(&parent)?;
            let witness = match witness {
                Some(witness) => {
                    validate_parent(&parent, &state, &witness)?;
                    witness
                }
                None => {
                    require_clean(&parent)?;
                    AgentWorkspaceWitness {
                        workspace_identity: workspace_identity(&parent)?,
                        base_head: head(&parent)?,
                        parent_index_tree: index_tree(&parent)?,
                        working_tree: workspace_tree(&parent, &state)?,
                    }
                }
            };
            let worktree = provision_at_head(parent, state, &id, witness.base_head.clone())?;
            // Materialize only the admitted tree delta from this controller's durable baseline.
            // No arbitrary dirty parent files, path/config overrides or model Git commands enter.
            let output = format!("--output={}", worktree.patch_path.display());
            require_git_success(
                &worktree.path,
                [
                    "diff",
                    "--binary",
                    "--full-index",
                    "--no-ext-diff",
                    &output,
                    &witness.base_head,
                    &witness.working_tree,
                    "--",
                ],
            )?;
            let patch = read_patch(&worktree.patch_path)?;
            if !patch.is_empty() {
                let result = git_capture_with_input(
                    &worktree.path,
                    ["apply", "--index", "--binary", "--whitespace=nowarn", "-"],
                    &patch,
                )?;
                if !result.status.success() {
                    return Err(MergeFailure::new(
                        MergeFailureKind::WorktreeProvision,
                        "admitted parent tree could not be isolated",
                    ));
                }
            }
            if index_tree(&worktree.path)? != witness.working_tree {
                return Err(MergeFailure::new(
                    MergeFailureKind::WorktreeState,
                    "isolated tree differs from durable parent evidence",
                ));
            }
            Ok((
                Self {
                    baseline_tree: witness.working_tree.clone(),
                    worktree,
                },
                witness,
            ))
        })
        .await
        .map_err(|_| {
            MergeFailure::new(
                MergeFailureKind::WorktreeProvision,
                "persistent isolation task did not settle",
            )
        })?
    }

    pub(in crate::runtime) fn path(&self) -> &Path {
        self.worktree.path()
    }

    pub(in crate::runtime) async fn prepare_patch(&self) -> Result<MergeReceipt, MergeFailure> {
        let path = self.worktree.path.clone();
        let patch = self.worktree.patch_path.clone();
        let head = self.worktree.base_head.clone();
        let baseline = self.baseline_tree.clone();
        tokio::task::spawn_blocking(move || prepare_patch_against(&path, &patch, &head, &baseline))
            .await
            .map_err(|_| {
                MergeFailure::new(
                    MergeFailureKind::WorktreeState,
                    "persistent patch did not settle",
                )
            })?
    }

    pub(in crate::runtime) async fn verify(
        &self,
        receipt: &MergeReceipt,
        command: Option<&str>,
        env: &[String],
        tail: usize,
    ) -> Result<(), MergeFailure> {
        self.worktree.verify(receipt, command, env, tail).await
    }

    pub(in crate::runtime) async fn merge(
        &mut self,
        receipt: &MergeReceipt,
        witness: AgentWorkspaceWitness,
        state: PathBuf,
    ) -> Result<AgentWorkspaceWitness, MergeFailure> {
        let parent = self.worktree.parent.clone();
        let patch_path = self.worktree.patch_path.clone();
        let receipt = receipt.clone();
        let next = tokio::task::spawn_blocking(move || {
            let patch = verified_patch_bytes(&patch_path, &receipt)?;
            validate_parent(&parent, &state, &witness)?;
            // Compute the resulting tree in a private index before any parent write. The prior
            // combined tree can contain other serialized siblings' already admitted writes.
            let scratch = ScratchIndex::new(&state)?;
            scratch.run(&parent, ["read-tree", &witness.working_tree])?;
            if !patch.is_empty() {
                let mut command = scratch.command(&parent)?;
                command.args(["apply", "--cached", "--binary", "--whitespace=nowarn", "-"]);
                let result = super::git_process::capture(
                    command,
                    Some(patch.clone()),
                    MAX_GIT_MESSAGE_BYTES,
                    false,
                )?;
                if !result.status.success() {
                    return Err(MergeFailure::new(
                        MergeFailureKind::PatchConflict,
                        "writer patch conflicts with admitted sibling writes",
                    ));
                }
            }
            let tree = scratch.tree(&parent)?;
            validate_parent(&parent, &state, &witness)?;
            if !patch.is_empty() {
                let check = parent_capture_with_input(
                    &parent,
                    &witness,
                    ["apply", "--check", "--binary", "--whitespace=nowarn", "-"],
                    &patch,
                )?;
                if !check.status.success() {
                    return Err(MergeFailure::new(
                        MergeFailureKind::PatchConflict,
                        "parent refused the exact sealed writer patch",
                    ));
                }
                let apply = parent_capture_with_input(
                    &parent,
                    &witness,
                    ["apply", "--binary", "--whitespace=nowarn", "-"],
                    &patch,
                )?;
                if !apply.status.success() {
                    return Err(MergeFailure::new(
                        MergeFailureKind::ApplyFailed,
                        "parent patch outcome requires reconciliation",
                    ));
                }
            }
            let next = AgentWorkspaceWitness {
                working_tree: tree,
                ..witness
            };
            validate_parent(&parent, &state, &next)?;
            Ok(next)
        })
        .await
        .map_err(|_| {
            MergeFailure::new(
                MergeFailureKind::ApplyFailed,
                "persistent merge task did not settle",
            )
        })??;
        self.worktree.cleanup().await?;
        Ok(next)
    }

    pub(in crate::runtime) async fn discard(&mut self) -> Result<(), MergeFailure> {
        self.worktree.discard().await
    }
}

fn validate_parent(
    parent: &Path,
    state: &Path,
    witness: &AgentWorkspaceWitness,
) -> Result<(), MergeFailure> {
    witness.validate().map_err(|_| {
        MergeFailure::new(
            MergeFailureKind::WorktreeState,
            "durable writer witness is malformed",
        )
    })?;
    if workspace_identity(parent)? != witness.workspace_identity {
        return Err(MergeFailure::new(
            MergeFailureKind::WorktreeState,
            "writer parent physical identity changed",
        ));
    }
    require_head(parent, &witness.base_head, MergeFailureKind::ParentAdvanced)?;
    if index_tree(parent)? != witness.parent_index_tree
        || workspace_tree(parent, state)? != witness.working_tree
    {
        return Err(MergeFailure::new(
            MergeFailureKind::ParentDirty,
            "parent no longer matches exact controller-owned writer evidence",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn workspace_identity(parent: &Path) -> Result<String, MergeFailure> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| {
        MergeFailure::new(
            MergeFailureKind::WorktreeState,
            "writer parent identity unavailable",
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(MergeFailure::new(
            MergeFailureKind::WorktreeState,
            "writer parent identity is not an exact directory",
        ));
    }
    Ok(format!("unix:{}:{}", metadata.dev(), metadata.ino()))
}
#[cfg(not(unix))]
fn workspace_identity(_: &Path) -> Result<String, MergeFailure> {
    Err(MergeFailure::new(
        MergeFailureKind::WorktreeState,
        "native persistent writer identity backend is unavailable",
    ))
}

#[cfg(unix)]
fn parent_capture_with_input<const N: usize>(
    parent: &Path,
    witness: &AgentWorkspaceWitness,
    args: [&str; N],
    input: &[u8],
) -> Result<GitOutput, MergeFailure> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::process::CommandExt;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|_| {
            MergeFailure::new(
                MergeFailureKind::WorktreeState,
                "writer parent descriptor unavailable",
            )
        })?;
    let metadata = directory.metadata().map_err(|_| {
        MergeFailure::new(
            MergeFailureKind::WorktreeState,
            "writer parent descriptor identity unavailable",
        )
    })?;
    if format!("unix:{}:{}", metadata.dev(), metadata.ino()) != witness.workspace_identity {
        return Err(MergeFailure::new(
            MergeFailureKind::WorktreeState,
            "writer parent descriptor exceeds admitted identity",
        ));
    }
    let mut command = git_command(parent)?;
    // The private host descriptor, never a model path, binds the final mutator's cwd. fchdir is
    // async-signal-safe; the captured descriptor stays alive until exec closes its CLOEXEC fd.
    unsafe {
        command.pre_exec(move || {
            if libc::fchdir(directory.as_raw_fd()) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.args(args);
    super::git_process::capture(command, Some(input.to_vec()), MAX_GIT_MESSAGE_BYTES, false)
}
#[cfg(not(unix))]
fn parent_capture_with_input<const N: usize>(
    _: &Path,
    _: &AgentWorkspaceWitness,
    _: [&str; N],
    _: &[u8],
) -> Result<GitOutput, MergeFailure> {
    Err(MergeFailure::new(
        MergeFailureKind::ApplyFailed,
        "native persistent writer mutation backend is unavailable",
    ))
}

fn read_patch(path: &Path) -> Result<Vec<u8>, MergeFailure> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(MAX_WRITER_PATCH_BYTES + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|_| {
            MergeFailure::new(
                MergeFailureKind::WorktreeState,
                "writer patch evidence unavailable",
            )
        })?;
    if bytes.len() as u64 > MAX_WRITER_PATCH_BYTES {
        return Err(MergeFailure::new(
            MergeFailureKind::PatchTooLarge,
            "writer patch exceeds its hard byte limit",
        ));
    }
    Ok(bytes)
}

struct ScratchIndex {
    directory: PathBuf,
    index: PathBuf,
}
impl ScratchIndex {
    fn new(state: &Path) -> Result<Self, MergeFailure> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let owner = state.join("writer-worktrees");
        std::fs::create_dir_all(&owner).map_err(|_| {
            MergeFailure::new(
                MergeFailureKind::WorktreeState,
                "private writer index owner unavailable",
            )
        })?;
        reject_symlink(&owner)?;
        set_private_directory(&owner)?;
        let directory = owner.join(format!(
            "index-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).map_err(|_| {
            MergeFailure::new(
                MergeFailureKind::WorktreeState,
                "private writer index identity unavailable",
            )
        })?;
        set_private_directory(&directory)?;
        Ok(Self {
            index: directory.join("index"),
            directory,
        })
    }
    fn command(&self, parent: &Path) -> Result<Command, MergeFailure> {
        let mut command = git_command(parent)?;
        command
            .env("GIT_INDEX_FILE", &self.index)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(command)
    }
    fn run<const N: usize>(&self, parent: &Path, args: [&str; N]) -> Result<(), MergeFailure> {
        let mut command = self.command(parent)?;
        command.args(args);
        if !super::git_process::capture(command, None, MAX_GIT_MESSAGE_BYTES, false)?
            .status
            .success()
        {
            return Err(MergeFailure::new(
                MergeFailureKind::WorktreeState,
                "private writer index command failed",
            ));
        }
        Ok(())
    }
    fn tree(&self, parent: &Path) -> Result<String, MergeFailure> {
        let mut command = self.command(parent)?;
        command.arg("write-tree");
        let output = super::git_process::capture(command, None, MAX_GIT_MESSAGE_BYTES, true)?;
        let id = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !output.status.success()
            || !matches!(id.len(), 40 | 64)
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(MergeFailure::new(
                MergeFailureKind::WorktreeState,
                "private writer tree evidence invalid",
            ));
        }
        Ok(id)
    }
}
impl Drop for ScratchIndex {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn workspace_tree(parent: &Path, state: &Path) -> Result<String, MergeFailure> {
    bound_workspace_delta(parent)?;
    let scratch = ScratchIndex::new(state)?;
    scratch.run(parent, ["read-tree", "HEAD"])?;
    scratch.run(parent, ["add", "-A", "--"])?;
    scratch.tree(parent)
}

fn bound_workspace_delta(parent: &Path) -> Result<(), MergeFailure> {
    let mut names = bounded_names(
        parent,
        &[
            "diff",
            "--name-only",
            "--no-ext-diff",
            "--no-textconv",
            "-z",
            "HEAD",
            "--",
        ],
    )?;
    names.extend(bounded_names(
        parent,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?);
    if names.len() > 4096 {
        return Err(MergeFailure::new(
            MergeFailureKind::PatchTooLarge,
            "writer parent delta exceeds its hard target limit",
        ));
    }
    let mut total = 0u64;
    for name in names {
        let path = parent.join(name);
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(MergeFailure::new(
                    MergeFailureKind::WorktreeState,
                    "writer parent delta metadata unavailable",
                ));
            }
        };
        if !metadata.is_file() && !metadata.file_type().is_symlink() {
            return Err(MergeFailure::new(
                MergeFailureKind::WorktreeState,
                "writer parent delta is not a file",
            ));
        }
        total = total.checked_add(metadata.len()).ok_or_else(|| {
            MergeFailure::new(
                MergeFailureKind::PatchTooLarge,
                "writer parent delta size overflowed",
            )
        })?;
        if total > MAX_WRITER_PATCH_BYTES {
            return Err(MergeFailure::new(
                MergeFailureKind::PatchTooLarge,
                "writer parent delta exceeds its hard byte limit",
            ));
        }
    }
    Ok(())
}

fn bounded_names(parent: &Path, args: &[&str]) -> Result<Vec<PathBuf>, MergeFailure> {
    const MAX_NAMES_BYTES: u64 = 2 * 1024 * 1024;
    let mut command = git_command(parent)?;
    command.args(args);
    let output = super::git_process::capture(command, None, MAX_NAMES_BYTES as usize, true)?;
    if !output.status.success() {
        return Err(MergeFailure::new(
            MergeFailureKind::WorktreeState,
            "writer delta inspection refused",
        ));
    }
    let names = output.stdout;
    names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| {
            let name = std::str::from_utf8(name).map_err(|_| {
                MergeFailure::new(
                    MergeFailureKind::WorktreeState,
                    "writer delta path is not UTF-8",
                )
            })?;
            let path = PathBuf::from(name);
            if !path
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
            {
                return Err(MergeFailure::new(
                    MergeFailureKind::WorktreeState,
                    "writer delta path is outside its repository",
                ));
            }
            Ok(path)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn git(path: &Path, args: &[&str]) {
        assert!(raw_git_command(path).args(args).status().unwrap().success());
    }
    #[tokio::test]
    async fn writer_followup_and_sibling_merge_preserve_exact_owned_parent_tree() {
        let root =
            std::env::temp_dir().join(format!("iteron-writer-continuation-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let parent = root.join("repo");
        let state = root.join("state");
        std::fs::create_dir_all(&parent).unwrap();
        git(&parent, &["init", "-q"]);
        git(&parent, &["config", "user.name", "fixture"]);
        git(
            &parent,
            &["config", "user.email", "fixture@example.invalid"],
        );
        std::fs::write(parent.join("first"), "initial\n").unwrap();
        git(&parent, &["add", "first"]);
        git(&parent, &["commit", "-q", "-m", "fixture"]);
        let mut witness = None;
        for (id, file, text) in [
            ("writer-a", "first", "one\n"),
            ("writer-b", "second", "sibling\n"),
            ("writer-a", "first", "followup\n"),
        ] {
            let (mut writer, prior) = PersistentWriterWorktree::provision(
                parent.clone(),
                state.clone(),
                id.into(),
                witness,
            )
            .await
            .unwrap();
            std::fs::write(writer.path().join(file), text).unwrap();
            let receipt = writer.prepare_patch().await.unwrap();
            writer
                .verify(&receipt, Some("true"), &[], 1024)
                .await
                .unwrap();
            witness = Some(writer.merge(&receipt, prior, state.clone()).await.unwrap());
        }
        assert_eq!(
            std::fs::read_to_string(parent.join("first")).unwrap(),
            "followup\n"
        );
        assert_eq!(
            std::fs::read_to_string(parent.join("second")).unwrap(),
            "sibling\n"
        );
        std::fs::write(parent.join("first"), "outside edit\n").unwrap();
        assert!(
            PersistentWriterWorktree::provision(parent, state, "writer-a".into(), witness)
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn inherited_filter_configuration_is_refused_without_running_driver() {
        let root =
            std::env::temp_dir().join(format!("iteron-writer-filter-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q"]);
        git(
            &root,
            &["config", "filter.fixture.clean", "touch executed-marker"],
        );
        assert!(git_command(&root).is_err());
        assert!(!root.join("executed-marker").exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
