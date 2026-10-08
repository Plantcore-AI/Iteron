//! Read-only native workspace source. No client can supply a different root or file handle.
use std::path::{Component, Path};
pub(crate) const SAFE_READ_REFUSAL: &str = "request could not be loaded safely from this workspace";
const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENTS: usize = 128;
const MAX_BYTES: usize = 8 * 1024 * 1024;

fn components(request: &str) -> Result<(Vec<String>, String), &'static str> {
    if request.is_empty() || request.len() > MAX_PATH_BYTES || request.chars().any(char::is_control)
    {
        return Err("expected one bounded workspace-relative JSON request path");
    }
    let mut names = Vec::new();
    for part in Path::new(request).components() {
        let Component::Normal(name) = part else {
            return Err("request path must stay inside the workspace");
        };
        let name = name.to_str().ok_or(SAFE_READ_REFUSAL)?;
        if name.len() > 255 || name.contains('\\') || name.contains(':') {
            return Err("request path must stay inside the workspace");
        }
        names.push(name.to_owned());
        if names.len() > MAX_COMPONENTS {
            return Err("request path contains too many components");
        }
    }
    let leaf = names.pop().ok_or("request path must name a file")?;
    Ok((names, leaf))
}
pub(crate) fn validate_path(request: &str) -> Result<(), &'static str> {
    components(request).map(|_| ())
}
pub(crate) fn read(root: &Path, request: &str, limit: usize) -> Result<Vec<u8>, &'static str> {
    if limit > MAX_BYTES {
        return Err(SAFE_READ_REFUSAL);
    }
    let _ = components(request)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        read_unix_with_hook(root, request, limit, || {})
    }
    #[cfg(windows)]
    {
        iteron_support::durable_windows_state::read_contained_regular_file(
            root,
            Path::new(request),
            limit,
        )
        .map_err(|_| SAFE_READ_REFUSAL)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = root;
        Err(SAFE_READ_REFUSAL)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn read_unix_with_hook(
    root: &Path,
    request: &str,
    limit: usize,
    acquired: impl FnOnce(),
) -> Result<Vec<u8>, &'static str> {
    use super::capability_fs::{self, RootBinding};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    if limit > MAX_BYTES {
        return Err(SAFE_READ_REFUSAL);
    }
    let (parents, leaf) = components(request)?;
    let binding = RootBinding::open(root).map_err(|_| SAFE_READ_REFUSAL)?;
    let parent =
        capability_fs::traverse(binding.root(), &parents).map_err(|_| SAFE_READ_REFUSAL)?;
    let mut file =
        capability_fs::open_regular_nonblocking(&parent, &leaf).map_err(|_| SAFE_READ_REFUSAL)?;
    let before = file.metadata().map_err(|_| SAFE_READ_REFUSAL)?;
    if before.len() > limit as u64 {
        return Err("request exceeds the resolver's 1 MiB input cap");
    }
    acquired();
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    (&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SAFE_READ_REFUSAL)?;
    if bytes.len() > limit {
        return Err("request exceeds the resolver's 1 MiB input cap");
    }
    let after = file.metadata().map_err(|_| SAFE_READ_REFUSAL)?;
    if before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(SAFE_READ_REFUSAL);
    }
    let rebound = binding.still_bound()
        && capability_fs::traverse(binding.root(), &parents)
            .and_then(|current| {
                if !capability_fs::same_file(&parent, &current)? {
                    return Ok(false);
                }
                let current_leaf = capability_fs::open_regular_nonblocking(&current, &leaf)?;
                capability_fs::same_file(&file, &current_leaf)
            })
            .unwrap_or(false)
        && binding.still_bound();
    if !rebound {
        return Err(SAFE_READ_REFUSAL);
    }
    Ok(bytes)
}
