//! Handle-bound permission grants for one package SID. Retirement removes only this fresh SID.

mod entries;
mod open;

use super::acl_lock::NativeAclLock;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::null_mut;
use windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject;
use windows_sys::Win32::Foundation::{LocalFree, RtlNtStatusToDosError};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, REVOKE_ACCESS, SE_FILE_OBJECT,
    SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, InitializeSecurityDescriptor,
    OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR, SetSecurityDescriptorDacl,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    GetDriveTypeW, GetFileInformationByHandle, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
};
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    volume: u32,
    index: u64,
    directory: bool,
}

pub(super) struct BoundObject {
    path: PathBuf,
    file: File,
    identity: Identity,
    _ancestors: Vec<File>,
    namespace_pinned: bool,
}

impl BoundObject {
    pub(super) fn open(path: &Path, directory: bool, manage_acl: bool) -> io::Result<Self> {
        let ancestors = validate_local_path(path)?;
        let share = FILE_SHARE_READ | if directory { FILE_SHARE_WRITE } else { 0 };
        let file = if let (Some(parent), Some(name)) = (ancestors.last(), path.file_name()) {
            open::relative(parent, name, directory, manage_acl, share, false)?
        } else {
            // Only the fixed local drive root is opened absolutely. All subsequent components
            // resolve beneath the retained parent, never a later string-path substitution.
            let access = FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE
                | FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | if manage_acl { WRITE_DAC } else { 0 };
            let mut options = OpenOptions::new();
            options
                .read(true)
                .access_mode(access)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .share_mode(share);
            let file = options.open(path)?;
            if let Some(root) = ancestors.last()
                && identity(&information(root)?) != identity(&information(&file)?)
            {
                return Err(io::Error::other("Windows sandbox drive binding changed"));
            }
            file
        };
        let information = information(&file)?;
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows sandbox scope is a reparse point or has the wrong object type",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            identity: identity(&information),
            file,
            _ancestors: ancestors,
            namespace_pinned: true,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn validate(&self) -> io::Result<()> {
        if !self.namespace_pinned {
            return self.validate_held(true);
        }
        let current = Self::open(&self.path, self.identity.directory, false)?;
        if current.identity != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows sandbox scope identity changed",
            ));
        }
        Ok(())
    }

    pub(super) fn key(&self) -> (u32, u64) {
        (self.identity.volume, self.identity.index)
    }

    pub(super) fn is_directory(&self) -> bool {
        self.identity.directory
    }

    pub(super) fn validate_held(&self, installing: bool) -> io::Result<()> {
        let current = information(&self.file)?;
        if identity(&current) != self.identity
            || (installing && current.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
            || (installing && !self.identity.directory && current.nNumberOfLinks != 1)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows sandbox scoped object is changed, reparsed or multiply linked",
            ));
        }
        Ok(())
    }

    /// The tree walker retains every parent setup pin before descending. The cleanup handle
    /// itself allows writes/deletes so normal edits, atomic replacements and directory removal
    /// remain possible while the child is live. It still denotes the same actual object.
    pub(super) fn open_descendant(
        parent: &File,
        name: &str,
        path: &Path,
        directory: bool,
        retiring: bool,
    ) -> io::Result<(Self, File, bool)> {
        let pin = open::relative(
            parent,
            std::ffi::OsStr::new(name),
            directory,
            false,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            retiring,
        )?;
        let actual = information(&pin)?;
        let directory = actual.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let reparse = actual.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        if !retiring && (reparse || (!directory && actual.nNumberOfLinks != 1)) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows sandbox cannot grant a reparse or multiply-linked descendant",
            ));
        }
        let file = open::relative(
            parent,
            std::ffi::OsStr::new(name),
            directory,
            true,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            retiring,
        )?;
        if identity(&information(&file)?) != identity(&actual) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows sandbox descendant changed during admission",
            ));
        }
        Ok((
            Self {
                path: path.to_path_buf(),
                file,
                identity: identity(&actual),
                _ancestors: Vec::new(),
                namespace_pinned: false,
            },
            pin,
            directory && !reparse,
        ))
    }

    pub(super) fn file(&self) -> &File {
        &self.file
    }

    pub(super) fn matches(&self, path: &Path) -> io::Result<()> {
        if path != self.path {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows sandbox launch uses a different scoped path",
            ));
        }
        self.validate()
    }

    pub(super) fn matches_file(&self, file: &File) -> io::Result<()> {
        let actual = information(file)?;
        if actual.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || identity(&actual) != self.identity
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows sandbox workspace differs from its actual directory capability",
            ));
        }
        Ok(())
    }

    pub(super) fn grant(&self, sid: PSID, writable: bool) -> io::Result<()> {
        self.validate()?;
        self.validate_held(true)?;
        // Standard read/write/execute plus local deletion, never WRITE_DAC or WRITE_OWNER.
        let access = FILE_GENERIC_READ
            | FILE_GENERIC_EXECUTE
            | if writable {
                FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD
            } else {
                0
            };
        self.change_acl(sid, GRANT_ACCESS, access)
    }

    pub(super) fn revoke(&self, sid: PSID) -> io::Result<()> {
        // Operate on the original held handle even if a user renamed its ancestors. Do not restore
        // an old whole ACL: unrelated user permission edits must survive this retirement.
        self.change_acl(sid, REVOKE_ACCESS, 0)
    }

    fn change_acl(&self, sid: PSID, mode: i32, access: u32) -> io::Result<()> {
        let _transaction = NativeAclLock::acquire(self.identity.volume, self.identity.index)?;
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let mut old_acl: *mut ACL = null_mut();
        // SAFETY: this is the live, non-reparse handle admitted by this owner; output pointers
        // belong to the returned security descriptor until LocalFree.
        win32(unsafe {
            GetSecurityInfo(
                self.file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut old_acl,
                null_mut(),
                &mut descriptor,
            )
        })?;
        let descriptor = LocalAllocation(descriptor);
        if old_acl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows sandbox refuses an unbounded null discretionary ACL",
            ));
        }
        if mode == REVOKE_ACCESS && !entries::contains(old_acl, sid)? {
            // A child can add a link to an object whose ACL never acquired this SID. Inspecting
            // such an alias during bounded cleanup must not write that foreign object's ACL.
            return Ok(());
        }
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access,
            grfAccessMode: mode,
            grfInheritance: if self.identity.directory {
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            } else {
                0
            },
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.cast(),
                ..Default::default()
            },
        };
        let mut new_acl = if mode == REVOKE_ACCESS {
            // SetEntriesInAcl's explicit-access removal cannot prove inherited ACE removal.
            // Preserve all foreign bytes and remove this SID from every supported actual ACE.
            Replacement::Owned(entries::without_sid(old_acl, sid)?)
        } else {
            let mut new_acl = null_mut();
            win32(unsafe { SetEntriesInAclW(1, &entry, old_acl, &mut new_acl) })?;
            Replacement::Native(LocalAllocation(new_acl.cast()))
        };
        let mut projection = SECURITY_DESCRIPTOR::default();
        let projection_ptr = (&mut projection as *mut SECURITY_DESCRIPTOR).cast();
        if unsafe { InitializeSecurityDescriptor(projection_ptr, SECURITY_DESCRIPTOR_REVISION) }
            == 0
            || unsafe { SetSecurityDescriptorDacl(projection_ptr, 1, new_acl.pointer(), 0) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // Direct object update deliberately avoids SetSecurityInfo's recursive automatic ACE
        // propagation. Only independently admitted actual objects acquire the fresh SID.
        let result = unsafe {
            NtSetSecurityObject(
                self.file.as_raw_handle(),
                DACL_SECURITY_INFORMATION,
                projection_ptr,
            )
        };
        drop(descriptor);
        if result < 0 {
            return Err(io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(result) } as i32,
            ));
        }
        if mode == REVOKE_ACCESS && self.has_sid(sid)? {
            return Err(io::Error::other(
                "Windows scope permission retirement remains unconfirmed",
            ));
        }
        Ok(())
    }

    pub(super) fn has_sid(&self, sid: PSID) -> io::Result<bool> {
        let mut descriptor = null_mut();
        let mut acl = null_mut();
        win32(unsafe {
            GetSecurityInfo(
                self.file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        })?;
        let _descriptor = LocalAllocation(descriptor);
        entries::contains(acl, sid)
    }
}

enum Replacement {
    Native(LocalAllocation),
    Owned(Box<[u32]>),
}
impl Replacement {
    fn pointer(&mut self) -> *mut ACL {
        match self {
            Self::Native(allocation) => allocation.0.cast(),
            Self::Owned(storage) => storage.as_mut_ptr().cast(),
        }
    }
}

struct LocalAllocation(*mut std::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: output is writable, correctly sized native storage for this retained handle.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

fn identity(information: &BY_HANDLE_FILE_INFORMATION) -> Identity {
    Identity {
        volume: information.dwVolumeSerialNumber,
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        directory: information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
    }
}

fn validate_local_path(path: &Path) -> io::Result<Vec<File>> {
    use std::os::windows::ffi::OsStrExt;
    if !path.is_absolute()
        || path.as_os_str().encode_wide().any(|unit| unit == 0)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Windows sandbox scope path",
        ));
    }
    let drive = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows sandbox scope requires a local disk path",
                ));
            }
        },
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows sandbox scope requires a local disk path",
            ));
        }
    };
    let root = [u16::from(drive), b':' as u16, b'\\' as u16, 0];
    if unsafe { GetDriveTypeW(root.as_ptr()) } != DRIVE_FIXED {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows sandbox scope does not support remote or removable volumes",
        ));
    }
    let parent = if path.file_name().is_some() {
        path.parent()
            .ok_or_else(|| io::Error::other("Windows scope parent is absent"))?
    } else {
        path
    };
    crate::durable_windows_state::pin_read_directory_chain(parent).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows sandbox ancestry is not a retained local no-reparse directory chain",
        )
    })
}

fn win32(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
