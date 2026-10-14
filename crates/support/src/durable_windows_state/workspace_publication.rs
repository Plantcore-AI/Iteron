//! Ordinary workspace publication with retained no-reparse/no-delete-share directory handles.
//! Existing workspace ACLs are never rewritten. The private staged inode alone gets the current
//! user's protected DACL and exclusive handle. Only by-handle rename may publish its full bytes.
use super::{
    Identity, WindowsStateError, flush_directory, open_file_relative, pin_directory_chain,
    rename_relative,
};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write as _;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;
use windows_sys::Wdk::Storage::FileSystem::FILE_CREATE;
use windows_sys::Win32::Foundation::STATUS_OBJECT_NAME_COLLISION;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspacePublishError {
    Exists,
    NotPublished,
    OutcomeUnknown,
}
/// Native low-level capability, not an actor/profile/source constructor. The calling domain owns
/// trusted workspace scope, source lineage, observer lifetime and admitted physical concurrency.
pub struct WindowsWorkspacePublisher {
    directories: Vec<File>,
    identity: Identity,
}
impl WindowsWorkspacePublisher {
    pub fn open(directory: &Path) -> Result<Self, WindowsStateError> {
        Ok(Self {
            directories: pin_directory_chain(directory)?,
            identity: Identity::current()?,
        })
    }

    /// Retain one actual child beneath this same held namespace. Existing directory ACLs are
    /// unchanged; a newly created component receives the current user's private descriptor.
    /// Both real directory and parent-link barriers precede a confirmed creation receipt.
    pub fn open_or_create_child(&self, name: &str) -> Result<(Self, bool), WindowsStateError> {
        let _ = super::filename_units(OsStr::new(name))?;
        let parent = self
            .directories
            .last()
            .ok_or(WindowsStateError::Unavailable)?;
        let identity = Identity::current()?;
        let (child, created) =
            super::open_directory_relative(parent, OsStr::new(name), Some(&identity))?;
        if created {
            identity
                .validate_handle(&child, true)
                .map_err(|_| WindowsStateError::OutcomeUnknown)?;
            flush_directory(&child).map_err(|_| WindowsStateError::OutcomeUnknown)?;
            flush_directory(parent).map_err(|_| WindowsStateError::OutcomeUnknown)?;
        }
        let mut directories = self
            .directories
            .iter()
            .map(File::try_clone)
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| {
                if created {
                    WindowsStateError::OutcomeUnknown
                } else {
                    WindowsStateError::Unavailable
                }
            })?;
        directories.push(child);
        Ok((
            Self {
                directories,
                identity,
            },
            created,
        ))
    }
    pub fn publish(
        &self,
        leaf: &str,
        bytes: &[u8],
        nonce: [u8; 16],
    ) -> Result<(), WorkspacePublishError> {
        self.publish_with_barrier(leaf, bytes, nonce, flush_directory)
    }
    fn publish_with_barrier(
        &self,
        leaf: &str,
        bytes: &[u8],
        nonce: [u8; 16],
        barrier: fn(&File) -> Result<(), WindowsStateError>,
    ) -> Result<(), WorkspacePublishError> {
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(WorkspacePublishError::NotPublished);
        }
        // Reuse the native adapter's strict single Win32 component grammar (no ADS/device aliases).
        let target = super::filename_units(OsStr::new(leaf))
            .map_err(|_| WorkspacePublishError::NotPublished)?;
        let parent = self
            .directories
            .last()
            .ok_or(WorkspacePublishError::NotPublished)?;
        let mut stage_name = String::from(".iteron-export-");
        for byte in nonce {
            use std::fmt::Write as _;
            write!(&mut stage_name, "{byte:02x}").expect("String write");
        }
        stage_name.push_str(".tmp");
        let file = open_file_relative(
            parent,
            &self.identity,
            OsStr::new(&stage_name),
            FILE_CREATE,
            true,
            0,
        )
        .map_err(|_| WorkspacePublishError::NotPublished)?
        .ok_or(WorkspacePublishError::NotPublished)?;
        let mut stage = StagedFile {
            file: Some(file),
            may_have_published: false,
        };
        // Mark before content is written. Native close/process death removes exactly this inode.
        // Unlike FILE_FLAG_DELETE_ON_CLOSE, this explicit disposition can be cleared for rename:
        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_disposition_info
        stage
            .disposition(true)
            .map_err(|_| WorkspacePublishError::OutcomeUnknown)?;
        let write = {
            let file = stage.file.as_mut().expect("stage handle");
            file.write_all(bytes).and_then(|_| file.sync_all())
        };
        if write.is_err() {
            stage.discard(parent, barrier)?;
            return Err(WorkspacePublishError::NotPublished);
        }
        stage
            .disposition(false)
            .map_err(|_| WorkspacePublishError::OutcomeUnknown)?;
        // Any ambiguous native return may already have published. Do not delete by guessed path
        // or mark the held final inode for deletion; the domain must preserve Unknown and custody.
        stage.may_have_published = true;
        let file = stage.file.as_ref().expect("stage handle");
        if let Err(status) = rename_relative(file, parent, &target, false) {
            if status == STATUS_OBJECT_NAME_COLLISION {
                stage.may_have_published = false;
                stage.discard(parent, barrier)?;
                return Err(WorkspacePublishError::Exists);
            }
            return Err(WorkspacePublishError::OutcomeUnknown);
        }
        self.identity
            .validate_handle(file, false)
            .map_err(|_| WorkspacePublishError::OutcomeUnknown)?;
        file.sync_all()
            .map_err(|_| WorkspacePublishError::OutcomeUnknown)?;
        barrier(parent).map_err(|_| WorkspacePublishError::OutcomeUnknown)?;
        Ok(())
    }
}
struct StagedFile {
    file: Option<File>,
    may_have_published: bool,
}
impl StagedFile {
    fn disposition(&self, delete: bool) -> Result<(), WindowsStateError> {
        let information = FILE_DISPOSITION_INFO { DeleteFile: delete };
        let file = self.file.as_ref().ok_or(WindowsStateError::Unavailable)?;
        // SAFETY: structure has the exact native BOOLEAN size, and the held file has DELETE access.
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&information as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(WindowsStateError::OutcomeUnknown);
        }
        Ok(())
    }
    fn discard(
        mut self,
        parent: &File,
        barrier: fn(&File) -> Result<(), WindowsStateError>,
    ) -> Result<(), WorkspacePublishError> {
        self.disposition(true)
            .map_err(|_| WorkspacePublishError::OutcomeUnknown)?;
        drop(self.file.take());
        barrier(parent).map_err(|_| WorkspacePublishError::OutcomeUnknown)
    }
}
impl Drop for StagedFile {
    fn drop(&mut self) {
        if !self.may_have_published && self.file.is_some() {
            let _ = self.disposition(true);
        }
        // A destructor never confirms cleanup. Published/possibly-published inode is left intact.
    }
}

#[cfg(test)]
mod tests;
