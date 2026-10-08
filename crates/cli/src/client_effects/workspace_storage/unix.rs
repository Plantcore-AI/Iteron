use super::{Publication, StorageError, leaf};
use crate::client_effects::capability_fs::{
    RootBinding, open_regular_nonblocking, same_file, traverse,
};
use crate::client_effects::export::{ExclusivePublication, publish_at};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::Read,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
    sync::Arc,
};
pub(crate) struct NativeDirectory {
    root: Arc<RootBinding>,
    components: Vec<String>,
    file: File,
}
impl NativeDirectory {
    pub(crate) fn open(path: &Path) -> Result<Self, StorageError> {
        let root = Arc::new(RootBinding::open(path).map_err(|_| StorageError::Unavailable)?);
        let file = root
            .root()
            .try_clone()
            .map_err(|_| StorageError::Unavailable)?;
        Ok(Self {
            root,
            components: Vec::new(),
            file,
        })
    }
    fn bound(&self) -> bool {
        self.root.still_bound()
            && traverse(self.root.root(), &self.components)
                .and_then(|file| same_file(&self.file, &file))
                .unwrap_or(false)
            && self.root.still_bound()
    }
    pub(crate) fn child(&self, name: &str, create: bool) -> Result<Option<Self>, StorageError> {
        leaf(name)?;
        if self.components.len() >= 128 || !self.bound() {
            return Err(StorageError::Unavailable);
        }
        let mut components = self.components.clone();
        components.push(name.into());
        let mut created = false;
        if create {
            let name = CString::new(name).map_err(|_| StorageError::Unavailable)?;
            // SAFETY: exact held directory and bounded NUL-terminated one-component name.
            created = unsafe { libc::mkdirat(self.file.as_raw_fd(), name.as_ptr(), 0o700) } == 0;
            if !created && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(StorageError::Unavailable);
            }
        }
        let file = match traverse(self.root.root(), &components) {
            Ok(file) => file,
            Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(_) => {
                return Err(if created {
                    StorageError::PublicationUnknown
                } else {
                    StorageError::Unavailable
                });
            }
        };
        let child = Self {
            root: self.root.clone(),
            components,
            file,
        };
        if created && (child.file.sync_all().is_err() || self.file.sync_all().is_err()) {
            return Err(StorageError::PublicationUnknown);
        }
        if !self.bound() || !child.bound() {
            return Err(if created {
                StorageError::PublicationUnknown
            } else {
                StorageError::Unavailable
            });
        }
        Ok(Some(child))
    }
    pub(crate) fn read(&self, name: &str, limit: usize) -> Result<Vec<u8>, StorageError> {
        leaf(name)?;
        if limit > 32 * 1024 * 1024 || !self.bound() {
            return Err(StorageError::Unavailable);
        }
        let mut file =
            open_regular_nonblocking(&self.file, name).map_err(|_| StorageError::Unavailable)?;
        let before = file.metadata().map_err(|_| StorageError::Unavailable)?;
        if before.len() > limit as u64 {
            return Err(StorageError::Unavailable);
        }
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        (&mut file)
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| StorageError::Unavailable)?;
        let after = file.metadata().map_err(|_| StorageError::Unavailable)?;
        if bytes.len() > limit
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || !self.bound()
            || !open_regular_nonblocking(&self.file, name)
                .and_then(|current| same_file(&file, &current))
                .unwrap_or(false)
        {
            return Err(StorageError::Unavailable);
        }
        Ok(bytes)
    }
    pub(crate) fn list(&self, limit: usize) -> Result<(Vec<(String, bool)>, bool), StorageError> {
        if limit == 0 || limit > 4096 || !self.bound() {
            return Err(StorageError::Unavailable);
        }
        // A new open description prevents enumeration from mutating the retained directory's
        // shared cursor. The constant dot resolves beneath this exact capability.
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(StorageError::Unavailable);
        }
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            unsafe { libc::close(fd) };
            return Err(StorageError::Unavailable);
        }
        struct Stream(*mut libc::DIR);
        impl Drop for Stream {
            fn drop(&mut self) {
                unsafe { libc::closedir(self.0) };
            }
        }
        let stream = Stream(stream);
        let mut rows = Vec::with_capacity(limit.min(128));
        let mut truncated = true;
        for _ in 0..limit + 3 {
            #[cfg(target_os = "linux")]
            let errno = unsafe { libc::__errno_location() };
            #[cfg(target_os = "macos")]
            let errno = unsafe { libc::__error() };
            unsafe { *errno = 0 };
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                if unsafe { *errno } != 0 {
                    return Err(StorageError::Unavailable);
                }
                truncated = false;
                break;
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let name = bytes.to_str().map_err(|_| StorageError::Unavailable)?;
            if name == "." || name == ".." {
                continue;
            }
            leaf(name)?;
            if rows.len() == limit {
                break;
            }
            let name_c = CString::new(name).map_err(|_| StorageError::Unavailable)?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe {
                libc::fstatat(
                    self.file.as_raw_fd(),
                    name_c.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(StorageError::Unavailable);
            }
            let stat = unsafe { stat.assume_init() };
            if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return Err(StorageError::Unavailable);
            }
            rows.push((
                name.to_owned(),
                stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
            ));
        }
        if !self.bound() {
            return Err(StorageError::Unavailable);
        }
        Ok((rows, truncated))
    }
    pub(crate) fn publish(&self, name: &str, bytes: &[u8]) -> Publication {
        if leaf(name).is_err() || !self.bound() {
            return Publication::NotPublished;
        }
        let published = match publish_at(&self.file, name, bytes) {
            ExclusivePublication::Created => Publication::Created,
            ExclusivePublication::Exists => Publication::Existing,
            ExclusivePublication::NotPublished => Publication::NotPublished,
            ExclusivePublication::OutcomeUnknown => Publication::Unknown,
        };
        if !self.bound() && matches!(published, Publication::Created | Publication::Unknown) {
            Publication::Unknown
        } else {
            published
        }
    }
}
