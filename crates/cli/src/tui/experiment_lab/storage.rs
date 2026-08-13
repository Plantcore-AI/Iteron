use super::*;
use std::io::Write as _;
use std::path::Component;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn list_requests(directory: &Path) -> Result<Vec<ExperimentRequest>, LabError> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    ensure_regular_directory(directory)?;
    let mut paths = std::fs::read_dir(directory)
        .map_err(|error| LabError::Io(error.to_string()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    paths.sort();
    paths.truncate(iteron_tunables::param_integer(
        "cli.tui.experiment_lab.max_listed_requests",
        MAX_LISTED_REQUESTS,
    ));
    Ok(paths
        .iter()
        .filter_map(|path| read_bounded(path).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect())
}

pub(super) fn list_bundles(directory: &Path) -> Result<Vec<String>, LabError> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    ensure_regular_directory(directory)?;
    let mut bundles = std::fs::read_dir(directory)
        .map_err(|error| LabError::Io(error.to_string()))?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_type()
                .is_ok_and(|kind| kind.is_dir() && !kind.is_symlink())
                && entry.path().join("bundle.index.json").is_file()
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    bundles.sort();
    bundles.truncate(iteron_tunables::param_integer(
        "cli.tui.experiment_lab.max_listed_bundles",
        MAX_LISTED_BUNDLES,
    ));
    Ok(bundles)
}

pub(super) fn secure_subdir(
    workspace: &Path,
    components: &[&str],
    create: bool,
) -> Result<Option<PathBuf>, LabError> {
    let root = workspace
        .canonicalize()
        .map_err(|error| LabError::UnsafePath(error.to_string()))?;
    let mut current = root.clone();
    for component in components {
        if !safe_component(component) {
            return Err(LabError::UnsafePath("invalid path component".into()));
        }
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(LabError::UnsafePath(format!(
                    "`{component}` is not a regular directory"
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                std::fs::create_dir(&current).map_err(|error| LabError::Io(error.to_string()))?;
                set_private_directory(&current)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(LabError::Io(error.to_string())),
        }
        let canonical = current
            .canonicalize()
            .map_err(|error| LabError::UnsafePath(error.to_string()))?;
        if !canonical.starts_with(&root) {
            return Err(LabError::UnsafePath(
                "experiment directory escapes the workspace".into(),
            ));
        }
        current = canonical;
    }
    Ok(Some(current))
}

pub(super) fn write_atomic(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), LabError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = directory.join(format!(
        ".experiment-request-{}-{nonce:x}.tmp",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| LabError::Io(error.to_string()))?;
    set_private_file(&temporary)?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temporary, destination))
        .map_err(|error| LabError::Io(error.to_string()));
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

pub(super) fn read_bounded(path: &Path) -> Result<Vec<u8>, LabError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| LabError::Io(error.to_string()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len()
            > iteron_tunables::param_integer(
                "cli.tui.experiment_lab.max_request_bytes",
                MAX_REQUEST_BYTES,
            )
    {
        return Err(LabError::UnsafePath(
            "request is not a bounded regular file".into(),
        ));
    }
    std::fs::read(path).map_err(|error| LabError::Io(error.to_string()))
}

fn ensure_regular_directory(path: &Path) -> Result<(), LabError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| LabError::Io(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LabError::UnsafePath("expected a regular directory".into()));
    }
    Ok(())
}

pub(super) fn safe_component(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), LabError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| LabError::Io(error.to_string()))
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<(), LabError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<(), LabError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| LabError::Io(error.to_string()))
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<(), LabError> {
    Ok(())
}
