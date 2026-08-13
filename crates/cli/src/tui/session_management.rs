//! Operator-owned session presentation state.
//!
//! Journals remain append-only authority. Rename/pin/archive are deliberately a separate,
//! immutable-generation view: deleting this directory loses only presentation preferences and a
//! reindex still reconstructs the conversation truth.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const SCHEMA: u8 = 1;
const MAX_STATE_BYTES: usize = 8 * 1024;
const MAX_TITLE_BYTES: usize = 256;
const MAX_GENERATIONS: usize = 256;
const RETAINED_GENERATIONS: usize = 16;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionPresentation {
    schema: u8,
    generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) title: Option<String>,
    #[serde(default)]
    pub(super) pinned: bool,
    #[serde(default)]
    pub(super) archived: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Mutation {
    Rename(String),
    Pin(bool),
    Archive(bool),
}

pub(super) fn load(runs: &Path, run: &str) -> Result<SessionPresentation, String> {
    let directory = state_directory(runs, run)?;
    let Ok(entries) = fs::read_dir(&directory) else {
        return Ok(SessionPresentation {
            schema: SCHEMA,
            ..SessionPresentation::default()
        });
    };
    let mut generations = generation_files(entries)?;
    generations.sort();
    let Some(path) = generations.last() else {
        return Ok(SessionPresentation {
            schema: SCHEMA,
            ..SessionPresentation::default()
        });
    };
    let bytes = read_bounded(
        path,
        iteron_tunables::param_integer(
            "cli.tui.session_management.max_state_bytes",
            MAX_STATE_BYTES,
        ),
    )
    .map_err(|error| error.to_string())?;
    let state: SessionPresentation =
        serde_json::from_slice(&bytes).map_err(|_| "session presentation state is malformed")?;
    if state.schema != SCHEMA {
        return Err("session presentation state has an unsupported schema".into());
    }
    Ok(state)
}

pub(super) fn update(runs: &Path, run: &str, mutation: Mutation) -> Result<(), String> {
    let mut state = load(runs, run)?;
    match mutation {
        Mutation::Rename(title) => {
            let title = title.trim();
            if title.is_empty()
                || title.len()
                    > iteron_tunables::param_integer(
                        "cli.tui.session_management.max_title_bytes",
                        MAX_TITLE_BYTES,
                    )
                || title.chars().any(|character| character.is_control())
            {
                return Err(format!(
                    "title must be visible text of 1..={MAX_TITLE_BYTES} UTF-8 bytes"
                ));
            }
            state.title = Some(title.to_owned());
        }
        Mutation::Pin(value) => state.pinned = value,
        Mutation::Archive(value) => state.archived = value,
    }
    state.schema = SCHEMA;
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| "session presentation generation is exhausted".to_owned())?;
    let bytes = serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?;
    if bytes.len()
        > iteron_tunables::param_integer(
            "cli.tui.session_management.max_state_bytes",
            MAX_STATE_BYTES,
        )
    {
        return Err("session presentation state exceeds its byte limit".into());
    }
    let root = state_root(runs)?;
    ensure_private_directory(&root)?;
    let directory = root.join(run);
    ensure_private_directory(&directory)?;
    let path = directory.join(format!("state-{:016}.json", state.generation));
    write_new_private(&path, &bytes).map_err(|error| error.to_string())?;
    sync_directory(&directory).map_err(|error| error.to_string())?;
    prune(&directory)?;
    sync_directory(&directory).map_err(|error| error.to_string())
}

pub(super) fn remove(runs: &Path, run: &str) -> Result<(), String> {
    let directory = state_directory(runs, run)?;
    let Ok(metadata) = fs::symlink_metadata(&directory) else {
        return Ok(());
    };
    if !metadata.file_type().is_dir() {
        return Err("session presentation path is not a regular directory".into());
    }
    fs::remove_dir_all(directory).map_err(|error| error.to_string())
}

fn state_directory(runs: &Path, run: &str) -> Result<PathBuf, String> {
    if run.is_empty()
        || run.len() > 240
        || run.chars().any(char::is_control)
        || run.contains(['/', '\\'])
        || matches!(run, "." | "..")
    {
        return Err("invalid session identity".into());
    }
    Ok(state_root(runs)?.join(run))
}

/// Validate the independently mutable namespace before any child is traversed. Checking only the
/// per-run directory would let a pre-existing `.session-views` symlink redirect presentation state
/// outside the runs store even though every final child looked like a regular directory.
fn state_root(runs: &Path) -> Result<PathBuf, String> {
    let root = runs.join(".session-views");
    match fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(root),
        Ok(_) => Err("session presentation root is not a regular directory".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(root),
        Err(error) => Err(error.to_string()),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        return if metadata.file_type().is_dir() {
            Ok(())
        } else {
            Err("session presentation path is not a regular directory".into())
        };
    }
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn generation_files(entries: fs::ReadDir) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for entry in entries.take(
        iteron_tunables::param_integer(
            "cli.tui.session_management.max_generations",
            MAX_GENERATIONS,
        ) + 1,
    ) {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_file()
            && name.starts_with("state-")
            && name.ends_with(".json")
        {
            files.push(entry.path());
        }
    }
    if files.len()
        > iteron_tunables::param_integer(
            "cli.tui.session_management.max_generations",
            MAX_GENERATIONS,
        )
    {
        return Err("too many session presentation generations".into());
    }
    Ok(files)
}

fn prune(directory: &Path) -> Result<(), String> {
    let mut files = generation_files(fs::read_dir(directory).map_err(|error| error.to_string())?)?;
    files.sort();
    let obsolete = files.len().saturating_sub(iteron_tunables::param_integer(
        "cli.tui.session_management.retained_generations",
        RETAINED_GENERATIONS,
    ));
    for path in files.into_iter().take(obsolete) {
        fs::remove_file(path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn read_bounded(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take((max + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "state exceeds its byte limit",
        ));
    }
    Ok(bytes)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_pin_archive_are_durable_bounded_and_operator_owned() {
        let root = std::env::temp_dir().join(format!(
            "core-session-view-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        fs::create_dir_all(&root).unwrap();
        update(&root, "run-1", Mutation::Rename("Parser repair".into())).unwrap();
        update(&root, "run-1", Mutation::Pin(true)).unwrap();
        update(&root, "run-1", Mutation::Archive(true)).unwrap();
        let state = load(&root, "run-1").unwrap();
        assert_eq!(state.title.as_deref(), Some("Parser repair"));
        assert!(state.pinned);
        assert!(state.archived);
        for index in 0..(RETAINED_GENERATIONS * 3) {
            update(&root, "run-1", Mutation::Pin(index % 2 == 0)).unwrap();
        }
        assert_eq!(
            fs::read_dir(state_directory(&root, "run-1").unwrap())
                .unwrap()
                .count(),
            RETAINED_GENERATIONS
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_identity_and_titles_fail_before_writing() {
        let root =
            std::env::temp_dir().join(format!("core-session-view-invalid-{}", std::process::id()));
        assert!(update(&root, "../escape", Mutation::Pin(true)).is_err());
        assert!(update(&root, "run-1", Mutation::Rename("bad\u{1b}".into())).is_err());
        assert!(!root.join(".session-views").exists());
    }

    #[cfg(unix)]
    #[test]
    fn presentation_root_symlink_is_refused_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("core-session-view-link-{}", std::process::id()));
        let target =
            std::env::temp_dir().join(format!("core-session-view-target-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&target);
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&target).unwrap();
        symlink(&target, root.join(".session-views")).unwrap();

        assert!(update(&root, "run-1", Mutation::Pin(true)).is_err());
        assert!(load(&root, "run-1").is_err());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(target).unwrap();
    }
}
