//! Host-scoped bounded source reads through the existing retained filesystem capability.
//! Native I/O may remain stuck after the caller deadline: its fixed worker slot and descriptors
//! stay owned until it actually stops, so repeated requests cannot create unbounded work.
use std::{
    path::{Component, Path},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};
const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENTS: usize = 128;
const MAX_WORKERS: usize = 4;
static WORKERS: AtomicUsize = AtomicUsize::new(0);
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContainedSourceError {
    #[error("source is unavailable within the admitted filesystem scope")]
    Unavailable,
    #[error("source read exceeded its bounded caller deadline")]
    TimedOut,
    #[error("source read capacity is occupied by existing native I/O")]
    Capacity,
}
struct WorkerSlot;
impl Drop for WorkerSlot {
    fn drop(&mut self) {
        WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}
/// `root` is supplied by the host. The relative source is data, never a new root capability.
/// No symlinks, FIFO/device files or replaced namespace components can supply admitted bytes.
pub fn read_contained_utf8(
    root: &Path,
    relative: &Path,
    max_bytes: usize,
) -> Result<String, ContainedSourceError> {
    if !root.is_absolute()
        || root.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || relative.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || relative.is_absolute()
        || relative.as_os_str().is_empty()
        || max_bytes > MAX_SOURCE_BYTES
        || root.components().count() > MAX_COMPONENTS
        || relative.components().count() > MAX_COMPONENTS
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(ContainedSourceError::Unavailable);
    }
    WORKERS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_WORKERS).then_some(n + 1)
        })
        .map_err(|_| ContainedSourceError::Capacity)?;
    let slot = WorkerSlot;
    let root = root.to_owned();
    let relative = relative.to_owned();
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("iteron-contained-source".into())
        .spawn(move || {
            let _slot = slot;
            let result = read_native(&root, &relative, max_bytes);
            let _ = send.send(result);
        })
        .map_err(|_| ContainedSourceError::Unavailable)?;
    receive
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| ContainedSourceError::TimedOut)?
}
#[cfg(unix)]
fn read_native(root: &Path, relative: &Path, limit: usize) -> Result<String, ContainedSourceError> {
    use std::io::Read;
    let root = crate::lsp::capability::RootBinding::open(root)
        .map_err(|_| ContainedSourceError::Unavailable)?;
    let source = root
        .bind_source(relative)
        .map_err(|_| ContainedSourceError::Unavailable)?;
    if !source.still_visible(&root) {
        return Err(ContainedSourceError::Unavailable);
    }
    let file = source
        .file()
        .map_err(|_| ContainedSourceError::Unavailable)?;
    if file
        .metadata()
        .map_err(|_| ContainedSourceError::Unavailable)?
        .len()
        > limit as u64
    {
        return Err(ContainedSourceError::Unavailable);
    }
    let mut bytes = Vec::with_capacity(limit.min(8192));
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ContainedSourceError::Unavailable)?;
    if bytes.len() > limit || !source.still_visible(&root) {
        return Err(ContainedSourceError::Unavailable);
    }
    String::from_utf8(bytes).map_err(|_| ContainedSourceError::Unavailable)
}
#[cfg(windows)]
fn read_native(root: &Path, relative: &Path, limit: usize) -> Result<String, ContainedSourceError> {
    let bytes =
        iteron_support::durable_windows_state::read_contained_regular_file(root, relative, limit)
            .map_err(|_| ContainedSourceError::Unavailable)?;
    String::from_utf8(bytes).map_err(|_| ContainedSourceError::Unavailable)
}
#[cfg(not(any(unix, windows)))]
fn read_native(_: &Path, _: &Path, _: usize) -> Result<String, ContainedSourceError> {
    Err(ContainedSourceError::Unavailable)
}
#[cfg(all(test, unix))]
#[path = "contained_source/tests.rs"]
mod tests;
