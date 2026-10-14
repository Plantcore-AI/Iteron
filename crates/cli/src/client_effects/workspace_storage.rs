//! Small native directory capability used only by scoped host storage, never by presentation.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use unix::NativeDirectory;
#[cfg(windows)]
pub(crate) use windows::NativeDirectory;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorageError {
    Unavailable,
    PublicationUnknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Publication {
    Created,
    Existing,
    Unknown,
    NotPublished,
}
pub(crate) fn leaf(name: &str) -> Result<(), StorageError> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.chars().any(char::is_control)
        || name.contains(['/', '\\', ':'])
    {
        return Err(StorageError::Unavailable);
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) struct NativeDirectory;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl NativeDirectory {
    pub(crate) fn open(_: &std::path::Path) -> Result<Self, StorageError> {
        Err(StorageError::Unavailable)
    }
    pub(crate) fn cache_key(&self) -> Result<[u64; 3], StorageError> {
        Err(StorageError::Unavailable)
    }
    pub(crate) fn child(&self, _: &str, _: bool) -> Result<Option<Self>, StorageError> {
        Err(StorageError::Unavailable)
    }
    pub(crate) fn read(&self, _: &str, _: usize) -> Result<Vec<u8>, StorageError> {
        Err(StorageError::Unavailable)
    }
    pub(crate) fn list(&self, _: usize) -> Result<(Vec<(String, bool)>, bool), StorageError> {
        Err(StorageError::Unavailable)
    }
    pub(crate) fn publish(&self, _: &str, _: &[u8]) -> Publication {
        Publication::NotPublished
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos", windows)))]
mod tests;
