//! Dispatch-time path containment for ordinary coding writes and isolated-writer calls.
//!
//! Ordinary coding permits host-wide reads but confines built-in file mutations to its workspace
//! unless the operator explicitly selects the dangerous bypass. Isolated writers remain stricter.

use std::path::{Component, Path, PathBuf};

use iteron_protocol::ToolUse;

const MAX_BOUNDARY_PATHS_PER_CALL: usize = 64;

pub(super) fn validate_root(root: &Path) -> Result<(), String> {
    let canonical = root
        .canonicalize()
        .map_err(|error| format!("isolated writer root is unavailable: {error}"))?;
    if !canonical.is_dir() {
        return Err("isolated writer root is not a directory".into());
    }
    Ok(())
}

pub(super) fn validate_call(root: &Path, call: &ToolUse) -> Result<(), String> {
    let mut paths = Vec::new();
    collect_paths(None, &call.input, &mut paths)?;
    for path in paths {
        validate_path(root, path)
            .map_err(|reason| format!("isolated writer refused `{}` path: {reason}", call.name))?;
    }
    Ok(())
}

/// The ordinary coding posture is workspace-*write*, not a blanket read sandbox. Canonicalized
/// absolute paths inside the workspace remain usable; every file mutation target outside is
/// refused before executor construction. The isolated writer above retains its stricter rules.
pub(super) fn validate_coding_write_call(root: &Path, call: &ToolUse) -> Result<(), String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("workspace write root is unavailable: {error}"))?;
    let mut paths = Vec::new();
    collect_paths(None, &call.input, &mut paths)?;
    if paths.is_empty() {
        return Err(format!(
            "workspace write refused `{}`: no target path",
            call.name
        ));
    }
    for path in paths {
        let resolved = crate::resolve_in_root(&canonical_root, path)?;
        validate_coding_write_target(&canonical_root, &resolved)
            .map_err(|reason| format!("workspace write refused `{}`: {reason}", call.name))?;
    }
    Ok(())
}

/// Revalidate the resolved destination at the file transaction's final commit boundary. This
/// catches parent swaps made while content is being staged, before the destination is replaced.
pub(super) fn validate_coding_write_target(root: &Path, target: &Path) -> Result<(), String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("workspace write root is unavailable: {error}"))?;
    let requested = target.to_str().ok_or("non-UTF-8 write target")?;
    let resolved = crate::resolve_in_root(&canonical_root, requested)?;
    let relative = resolved
        .strip_prefix(&canonical_root)
        .map_err(|_| "target resolves outside workspace".to_owned())?;
    if relative.components().any(|component| match component {
        Component::Normal(name) => name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(".git")),
        _ => false,
    }) {
        return Err("Git administration paths require separate authority".into());
    }
    Ok(())
}

fn collect_paths<'a>(
    key: Option<&str>,
    value: &'a serde_json::Value,
    paths: &mut Vec<&'a str>,
) -> Result<(), String> {
    let max_boundary_paths = iteron_tunables::param_usize(
        "tools.workspace_boundary.max_boundary_paths_per_call",
        iteron_tunables::param_integer(
            "tools.workspace_boundary.max_boundary_paths_per_call",
            MAX_BOUNDARY_PATHS_PER_CALL,
        ),
    )
    .clamp(1, MAX_BOUNDARY_PATHS_PER_CALL);
    match value {
        serde_json::Value::String(path) if key == Some("path") => {
            if paths.len() >= max_boundary_paths {
                return Err(format!(
                    "workspace boundary path count exceeds {max_boundary_paths}"
                ));
            }
            paths.push(path);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_paths(None, value, paths)?;
            }
        }
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                collect_paths(Some(name), value, paths)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_path(root: &Path, requested: &str) -> Result<(), &'static str> {
    let path = Path::new(requested);
    if path.is_absolute() {
        return Err("absolute paths are outside the isolated worktree contract");
    }
    if path.components().any(|component| match component {
        Component::ParentDir | Component::RootDir | Component::Prefix(_) => true,
        Component::Normal(name) => name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(".git")),
        Component::CurDir => false,
    }) {
        return Err("parent traversal and Git administration paths are forbidden");
    }

    let canonical_root = root
        .canonicalize()
        .map_err(|_| "isolated worktree root disappeared")?;
    let resolved = resolve_existing_ancestor(&canonical_root.join(path))?;
    if resolved == canonical_root || resolved.starts_with(&canonical_root) {
        Ok(())
    } else {
        Err("the path resolves outside the isolated worktree")
    }
}

fn resolve_existing_ancestor(path: &Path) -> Result<PathBuf, &'static str> {
    if let Ok(canonical) = path.canonicalize() {
        return Ok(canonical);
    }
    let mut ancestor = path;
    let mut tail = Vec::new();
    loop {
        let name = ancestor
            .file_name()
            .ok_or("the path has no resolvable ancestor")?;
        tail.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or("the path has no resolvable ancestor")?;
        if let Ok(mut canonical) = ancestor.canonicalize() {
            for component in tail.iter().rev() {
                canonical.push(component);
            }
            return Ok(canonical);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The workspace has no `tempfile` dependency, so temp roots follow the in-tree idiom: a
    /// pid-and-nanos name, because two of these tests once collided on a shared fixed path.
    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "core-boundary-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn boundary_rejects_absolute_parent_and_git_paths() {
        let root = temp_root("reject");
        for path in ["/tmp/out", "../out", ".git/config", "nested/.GIT/config"] {
            assert!(validate_path(&root, path).is_err(), "{path}");
        }
        assert!(validate_path(&root, "src/new.rs").is_ok());
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn boundary_rejects_a_symlink_escape() {
        let root = temp_root("symlink-root");
        let outside = temp_root("symlink-outside");
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        assert!(validate_path(&root, "escape/file").is_err());
        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(outside).ok();
    }
}
