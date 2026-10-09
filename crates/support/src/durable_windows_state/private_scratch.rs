//! Create-only native scratch custody. It is private to the physical launch owner; retirement
//! deletes only the same retained namespace object after the process/profile owner is terminal.
use super::{Identity, filename_units, flush_directory, local_ntfs, pin_directory_chain};
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, OBJ_CASE_INSENSITIVE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES, FileDispositionInfo,
    GetFileInformationByHandle, GetFileType, READ_CONTROL, SYNCHRONIZE, SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const MAX_OBJECTS: usize = 4096;
const MAX_DEPTH: usize = 64;
#[derive(Clone, Copy, PartialEq, Eq)]
struct IdentityStamp(u32, u32, u32);
pub(crate) struct WindowsPrivateScratch {
    path: PathBuf,
    parents: Vec<File>,
    directory: Option<File>,
    identity: Option<IdentityStamp>,
    created: bool,
    disposition_set: bool,
    deleted: bool,
}
impl WindowsPrivateScratch {
    /// Existing ancestors are pinned before mutation. The guard is installed in the launch's
    /// retirement owner before `provision` can create a native directory.
    pub(crate) fn bind(path: &Path) -> io::Result<Self> {
        let parent = path.parent().ok_or_else(unavailable)?;
        let name = path.file_name().ok_or_else(unavailable)?;
        filename_units(name).map_err(|_| unavailable())?;
        let parents = pin_directory_chain(parent).map_err(|_| unavailable())?;
        Ok(Self {
            path: path.to_owned(),
            parents,
            directory: None,
            identity: None,
            created: false,
            disposition_set: false,
            deleted: false,
        })
    }
    pub(crate) fn provision(&mut self) -> io::Result<()> {
        if self.created || self.deleted {
            return Err(unavailable());
        }
        let identity = Identity::current().map_err(|_| unavailable())?;
        let directory = open(
            self.parent()?,
            self.path.file_name().ok_or_else(unavailable)?,
            true,
            false,
            Some(&identity),
            FILE_CREATE,
        )?
        .ok_or_else(unavailable)?;
        // Adopt the actual newly created handle before any fallible validation/barrier.
        self.created = true;
        self.directory = Some(directory);
        let directory = self.directory.as_ref().expect("adopted above");
        self.identity = Some(stamp(directory, true)?);
        local_ntfs(directory).map_err(|_| unavailable())?;
        identity
            .validate_handle(directory, true)
            .map_err(|_| unavailable())?;
        flush_directory(directory).map_err(|_| unavailable())?;
        flush_directory(self.parent()?).map_err(|_| unavailable())?;
        Ok(())
    }
    pub(crate) fn file(&self) -> io::Result<&File> {
        self.directory.as_ref().ok_or_else(unavailable)
    }
    pub(crate) fn retire(&mut self) -> io::Result<()> {
        if !self.created || self.deleted {
            return Ok(());
        }
        // Capture the original object's identity while its no-delete-share handle still exists.
        if let Some(directory) = &self.directory {
            self.identity = Some(stamp(directory, true)?);
        }
        let expected = self.identity.ok_or_else(unavailable)?;
        // After profile pins are retired, acquire DELETE on the same name in the held parent.
        // Any replacement fails identity validation before a deletion is attempted.
        self.directory = None;
        let Some(directory) = open(
            self.parent()?,
            self.path.file_name().ok_or_else(unavailable)?,
            true,
            true,
            None,
            FILE_OPEN,
        )?
        else {
            // Absence alone cannot prove disposal: another host actor could have moved the
            // object after the original no-delete-share handle was released. Only a successful
            // exact-object delete disposition followed by absence closes this custody owner.
            if !self.disposition_set {
                return Err(unavailable());
            }
            flush_directory(self.parent()?).map_err(|_| unavailable())?;
            self.deleted = true;
            return Ok(());
        };
        if stamp(&directory, true)? != expected {
            return Err(unavailable());
        }
        let mut remaining = MAX_OBJECTS;
        delete_children(&directory, &mut remaining, 0)?;
        mark_delete(&directory)?;
        self.disposition_set = true;
        drop(directory);
        // A pending-delete handle elsewhere is not namespace absence. Keep custody and retry
        // until the same held-parent lookup actually returns name-not-found.
        if open(
            self.parent()?,
            self.path.file_name().ok_or_else(unavailable)?,
            true,
            false,
            None,
            FILE_OPEN,
        )?
        .is_some()
        {
            return Err(unavailable());
        }
        flush_directory(self.parent()?).map_err(|_| unavailable())?;
        self.deleted = true;
        Ok(())
    }
    fn parent(&self) -> io::Result<&File> {
        self.parents.last().ok_or_else(unavailable)
    }
}

fn delete_children(directory: &File, remaining: &mut usize, depth: usize) -> io::Result<()> {
    if depth >= MAX_DEPTH || *remaining == 0 {
        return Err(unavailable());
    }
    let (rows, truncated) =
        super::workspace_directory_read::list(directory, *remaining).map_err(|_| unavailable())?;
    if truncated || rows.len() > *remaining {
        return Err(unavailable());
    }
    *remaining -= rows.len();
    for (name, is_directory) in rows {
        let child = open(
            directory,
            std::ffi::OsStr::new(&name),
            is_directory,
            true,
            None,
            FILE_OPEN,
        )?
        .ok_or_else(unavailable)?;
        let _ = stamp(&child, is_directory)?;
        if is_directory {
            delete_children(&child, remaining, depth + 1)?;
        }
        mark_delete(&child)?;
        drop(child);
    }
    Ok(())
}

fn open(
    parent: &File,
    name: &std::ffi::OsStr,
    directory: bool,
    delete: bool,
    identity: Option<&Identity>,
    disposition: u32,
) -> io::Result<Option<File>> {
    let mut units = filename_units(name).map_err(|_| unavailable())?;
    let unicode = UNICODE_STRING {
        Length: (units.len() * 2) as u16,
        MaximumLength: (units.len() * 2) as u16,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: identity.map_or(null(), |identity| identity.descriptor.0.cast()),
        SecurityQualityOfService: null(),
    };
    let access = FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | SYNCHRONIZE
        | if directory {
            FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_WRITE_ATTRIBUTES
        } else {
            0
        }
        | if delete { DELETE } else { 0 };
    let mut raw: HANDLE = null_mut();
    let mut info = IO_STATUS_BLOCK::default();
    // SAFETY: bounded one-component name, retained no-follow parent and live aligned outputs.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &attributes,
            &mut info,
            null(),
            if directory {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            disposition,
            FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_WRITE_THROUGH
                | if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                },
            null(),
            0,
        )
    };
    if disposition == FILE_OPEN
        && matches!(
            status,
            STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND
        )
    {
        return Ok(None);
    }
    if status < 0 {
        return Err(unavailable());
    }
    // SAFETY: successful NtCreateFile transfers this fresh owned handle exactly once.
    Ok(Some(unsafe { File::from_raw_handle(raw) }))
}
fn stamp(file: &File, directory: bool) -> io::Result<IdentityStamp> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(unavailable());
    }
    Ok(IdentityStamp(
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}
fn mark_delete(file: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    // SAFETY: DELETE-authorized exact retained file, native fixed disposition and live input.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(unavailable());
    }
    Ok(())
}
fn unavailable() -> io::Error {
    io::Error::other("private Windows scratch remains unavailable or unretired")
}
