//! Small native directory capability used only by scoped host storage, never by presentation.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use unix::NativeDirectory;
#[cfg(windows)]
pub use windows::NativeDirectory;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    Unavailable,
    PublicationUnknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Publication {
    Created,
    Existing,
    Unknown,
    NotPublished,
}
pub fn leaf(name: &str) -> Result<(), StorageError> {
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
pub struct NativeDirectory;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl NativeDirectory {
    pub fn open(_: &std::path::Path) -> Result<Self, StorageError> {
        Err(StorageError::Unavailable)
    }
    pub fn cache_key(&self) -> Result<[u64; 3], StorageError> {
        Err(StorageError::Unavailable)
    }
    pub fn child(&self, _: &str, _: bool) -> Result<Option<Self>, StorageError> {
        Err(StorageError::Unavailable)
    }
    pub fn read(&self, _: &str, _: usize) -> Result<Vec<u8>, StorageError> {
        Err(StorageError::Unavailable)
    }
    pub fn list(&self, _: usize) -> Result<(Vec<(String, bool)>, bool), StorageError> {
        Err(StorageError::Unavailable)
    }
    pub fn publish(&self, _: &str, _: &[u8]) -> Publication {
        Publication::NotPublished
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos", windows)))]
mod tests;
