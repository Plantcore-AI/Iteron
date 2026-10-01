//! Bounded local-NTFS publication adapter; no agent/workflow domain state lives here.
//!
//! The directory and every child are accessed through pinned handles. File publication uses a
//! write-through source handle and handle-relative rename, followed by a file flush. Microsoft
//! documents that NTFS write-through requests also flush associated metadata, including rename:
//! https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
//! Relative rename uses the documented RootDirectory field:
//! https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info
//! Actual device durability still relies on the supported local NTFS/storage contract and must be
//! validated with platform fault tests. FAT, remote shares and other filesystems are refused.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH, NtCreateFile,
    NtFlushBuffersFileEx,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree, OBJ_CASE_INSENSITIVE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, IsValidAcl, IsValidSid,
    OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, DRIVE_FIXED, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_WRITE_THROUGH, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO,
    FILE_RENAME_INFO_0, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES,
    FileDispositionInfo, FileRenameInfo, GetDriveTypeW, GetFileInformationByHandle,
    GetVolumeInformationByHandleW, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
    SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, FILE_PERSISTENT_ACLS,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

mod contained_read;
/// Ordinary bounded local-NTFS source reading. No private ACL or write authority is requested.
pub fn read_contained_regular_file(
    root: &Path,
    relative: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, WindowsStateError> {
    contained_read::read(root, relative, max_bytes)
}

const HARD_MAX_BYTES: usize = 32 * 1_024 * 1_024;
const MAX_SECURITY_BYTES: u32 = 64 * 1_024;
const MAX_ACES: u16 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WindowsStateError {
    #[error("private local NTFS state unavailable or outside its authority bounds")]
    Unavailable,
    #[error("state namespace already has an active writer")]
    Conflict,
    #[error("durable publication outcome unknown")]
    OutcomeUnknown,
}

struct LocalAllocation(*mut core::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointers originate from Win32 APIs documented to require LocalFree.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct Identity {
    token_user: Box<[usize]>,
    descriptor: LocalAllocation,
}

impl Identity {
    fn current() -> Result<Self, WindowsStateError> {
        let mut token = null_mut();
        // SAFETY: writable token output and current-process pseudo-handle are valid.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(WindowsStateError::Unavailable);
        }
        let mut needed = 0;
        // SAFETY: size-query form accepts a null buffer; token is a valid owned handle.
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        }
        if needed < size_of::<TOKEN_USER>() as u32 || needed > MAX_SECURITY_BYTES {
            // SAFETY: token was returned by OpenProcessToken and is closed exactly once.
            unsafe {
                CloseHandle(token);
            }
            return Err(WindowsStateError::Unavailable);
        }
        let mut buffer =
            vec![0usize; (needed as usize).div_ceil(size_of::<usize>())].into_boxed_slice();
        // SAFETY: aligned buffer holds at least the requested number of bytes.
        let result = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        // SAFETY: CloseHandle releases the owned token after its data has been copied.
        unsafe {
            CloseHandle(token);
        }
        if result == 0 {
            return Err(WindowsStateError::Unavailable);
        }
        // SAFETY: the successful TokenUser call initializes the aligned TOKEN_USER prefix.
        let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        let mut sid_text = null_mut();
        // SAFETY: token-owned SID remains valid in the stable boxed buffer.
        if unsafe { IsValidSid(sid) } == 0
            || unsafe { ConvertSidToStringSidW(sid, &mut sid_text) } == 0
        {
            return Err(WindowsStateError::Unavailable);
        }
        let sid_allocation = LocalAllocation(sid_text.cast());
        let mut sid_units = Vec::new();
        for index in 0..256 {
            // SAFETY: ConvertSidToStringSidW returns a terminated bounded SID string.
            let unit = unsafe { *sid_text.add(index) };
            if unit == 0 {
                break;
            }
            sid_units.push(unit);
        }
        if sid_units.len() >= 256 {
            return Err(WindowsStateError::Unavailable);
        }
        let sid_string =
            String::from_utf16(&sid_units).map_err(|_| WindowsStateError::Unavailable)?;
        drop(sid_allocation);
        let sddl = format!("O:{sid_string}D:P(A;OICI;FA;;;{sid_string})");
        let wide = wide_text(&sddl)?;
        let mut descriptor = null_mut();
        // SAFETY: terminated SDDL input and writable descriptor output are valid.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(WindowsStateError::Unavailable);
        }
        Ok(Self {
            token_user: buffer,
            descriptor: LocalAllocation(descriptor),
        })
    }

    fn sid(&self) -> PSID {
        // SAFETY: TokenUser is retained in aligned stable storage for the identity lifetime.
        unsafe { (*(self.token_user.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }

    fn validate_handle(&self, file: &File, directory: bool) -> Result<(), WindowsStateError> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: file owns the live handle and information is a valid output structure.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0
            || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            || (!directory && information.nNumberOfLinks != 1)
        {
            return Err(WindowsStateError::Unavailable);
        }
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: outputs point to local variables; returned pointers belong to descriptor.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(WindowsStateError::Unavailable);
        }
        let descriptor = LocalAllocation(descriptor);
        let mut control = 0u16;
        let mut revision = 0;
        // SAFETY: security pointers are returned by GetSecurityInfo and valid until LocalFree.
        if owner.is_null()
            || acl.is_null()
            || unsafe { EqualSid(owner, self.sid()) } == 0
            || unsafe { IsValidAcl(acl) } == 0
            || unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) }
                == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(WindowsStateError::Unavailable);
        }
        // SAFETY: IsValidAcl validated the header and serialized ACE list.
        let count = unsafe { (*acl).AceCount };
        if count == 0 || count > MAX_ACES {
            return Err(WindowsStateError::Unavailable);
        }
        let mut owner_allowed = false;
        for index in 0..u32::from(count) {
            let mut raw = null_mut();
            // SAFETY: index is in the validated ACL's bounded list.
            if unsafe { GetAce(acl, index, &mut raw) } == 0 {
                return Err(WindowsStateError::Unavailable);
            }
            // SAFETY: GetAce returns a valid ACE header inside the ACL.
            let header = unsafe { &*raw.cast::<ACE_HEADER>() };
            if u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE {
                continue;
            }
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                || usize::from(header.AceSize) < offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
            {
                return Err(WindowsStateError::Unavailable);
            }
            // SAFETY: accepted standard ACE layout has a SID at SidStart.
            let ace_sid = unsafe {
                raw.cast::<u8>()
                    .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                    .cast()
            };
            // SAFETY: the ACE contains the complete eight-byte SID prefix. IsValidAcl proves list
            // bounds only; GetLengthSid is checked before EqualSid may read subauthorities.
            if unsafe { IsValidSid(ace_sid) } == 0
                || unsafe { GetLengthSid(ace_sid) } as usize
                    + offset_of!(ACCESS_ALLOWED_ACE, SidStart)
                    > usize::from(header.AceSize)
                || unsafe { EqualSid(ace_sid, self.sid()) } == 0
            {
                return Err(WindowsStateError::Unavailable);
            }
            owner_allowed = true;
        }
        if !owner_allowed {
            return Err(WindowsStateError::Unavailable);
        }
        Ok(())
    }
}

/// Create one private component below an existing host-computed parent, then persist both
/// directory metadata and the parent's namespace link before reporting success. Existing ACLs
/// are never changed. Callers provision an absent chain from its existing ancestor outward.
///
/// Every ancestor is opened relative to a pinned, non-reparse handle; directory creation uses
/// FILE_DIRECTORY_FILE + FILE_WRITE_THROUGH. The explicit normal NtFlushBuffersFileEx barrier
/// writes metadata and synchronizes the storage cache, rather than inferring directory durability
/// from a later descendant file flush:
/// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntflushbuffersfileex
/// Native fault/restart validation remains required for supported local NTFS/storage devices.
pub fn provision_private_directory(path: &Path) -> Result<(), WindowsStateError> {
    provision_directory_with_barrier(path, flush_directory)
}

fn provision_directory_with_barrier(
    path: &Path,
    barrier: fn(&File) -> Result<(), WindowsStateError>,
) -> Result<(), WindowsStateError> {
    let identity = Identity::current()?;
    let parent = path.parent().ok_or(WindowsStateError::Unavailable)?;
    let name = path.file_name().ok_or(WindowsStateError::Unavailable)?;
    let parents = pin_directory_chain(parent)?;
    let parent = parents.last().ok_or(WindowsStateError::Unavailable)?;
    let (child, created) = open_directory_relative(parent, name, Some(&identity))?;
    // After creation, any validation or flush failure leaves namespace publication uncertain.
    // The owner must quarantine/reconcile instead of accepting Completed or retrying effects.
    let uncertainty = if created {
        WindowsStateError::OutcomeUnknown
    } else {
        WindowsStateError::Unavailable
    };
    identity
        .validate_handle(&child, true)
        .map_err(|_| uncertainty)?;
    barrier(&child).map_err(|_| WindowsStateError::OutcomeUnknown)?;
    barrier(parent).map_err(|_| WindowsStateError::OutcomeUnknown)?;
    Ok(())
}

fn pin_directory_chain(path: &Path) -> Result<Vec<File>, WindowsStateError> {
    pin_directory_chain_mode(path, true)
}
fn pin_read_directory_chain(path: &Path) -> Result<Vec<File>, WindowsStateError> {
    pin_directory_chain_mode(path, false)
}
fn pin_directory_chain_mode(
    path: &Path,
    writable_leaf: bool,
) -> Result<Vec<File>, WindowsStateError> {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(WindowsStateError::Unavailable);
    };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        || components.next() != Some(Component::RootDir)
    {
        return Err(WindowsStateError::Unavailable);
    }
    let root = PathBuf::from(prefix.as_os_str()).join(r"\");
    let names = components.take(65).collect::<Vec<_>>();
    if names.len() > 64 {
        return Err(WindowsStateError::Unavailable);
    }
    let wide = wide_path(&root)?;
    // Only the final parent needs create/flush access. Earlier pinned ancestors need traversal
    // and attribute access; requesting write access to a drive root would need excess authority.
    let writable = writable_leaf && names.is_empty();
    // SAFETY: terminated local drive root, fixed flags and non-inherited fresh handle output.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            directory_access(writable),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(WindowsStateError::Unavailable);
    }
    // SAFETY: successful CreateFileW transfers a fresh owned directory handle exactly once.
    let root = unsafe { File::from_raw_handle(raw) };
    validate_directory_geometry(&root)?;
    local_ntfs(&root)?;
    let mut pinned = vec![root];
    for (index, name) in names.iter().enumerate() {
        let Component::Normal(name) = name else {
            return Err(WindowsStateError::Unavailable);
        };
        let (file, _) = open_directory_at(
            pinned.last().ok_or(WindowsStateError::Unavailable)?,
            name,
            None,
            writable_leaf && index + 1 == names.len(),
        )?;
        pinned.push(file);
    }
    Ok(pinned)
}

fn directory_access(writable: bool) -> u32 {
    FILE_LIST_DIRECTORY
        | FILE_TRAVERSE
        | FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | SYNCHRONIZE
        | if writable {
            FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_ATTRIBUTES
        } else {
            0
        }
}

fn open_directory_relative(
    parent: &File,
    name: &std::ffi::OsStr,
    identity: Option<&Identity>,
) -> Result<(File, bool), WindowsStateError> {
    open_directory_at(parent, name, identity, true)
}

fn open_directory_at(
    parent: &File,
    name: &std::ffi::OsStr,
    identity: Option<&Identity>,
    writable: bool,
) -> Result<(File, bool), WindowsStateError> {
    let mut units = name.encode_wide().collect::<Vec<_>>();
    if units.is_empty()
        || units.len() > 255
        || units.contains(&0)
        || units.iter().any(|unit| matches!(*unit, 47 | 58 | 92))
        || name == std::ffi::OsStr::new(".")
        || name == std::ffi::OsStr::new("..")
    {
        return Err(WindowsStateError::Unavailable);
    }
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
        SecurityDescriptor: identity.map_or(null(), |value| value.descriptor.0.cast()),
        SecurityQualityOfService: null(),
    };
    let mut raw = null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: bounded single component resolves beneath the retained parent; outputs are aligned.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            directory_access(writable),
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            if identity.is_some() {
                FILE_OPEN_IF
            } else {
                FILE_OPEN
            },
            FILE_DIRECTORY_FILE
                | FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_WRITE_THROUGH,
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(WindowsStateError::Unavailable);
    }
    // SAFETY: successful NtCreateFile returned a fresh owned directory handle.
    let file = unsafe { File::from_raw_handle(raw) };
    let created = status_block.Information == 2; // FILE_CREATED (documented IO_STATUS_BLOCK value).
    validate_directory_geometry(&file).map_err(|_| {
        if created {
            WindowsStateError::OutcomeUnknown
        } else {
            WindowsStateError::Unavailable
        }
    })?;
    Ok((file, created))
}

fn validate_directory_geometry(file: &File) -> Result<(), WindowsStateError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live pinned handle and writable structure are valid.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(WindowsStateError::Unavailable);
    }
    Ok(())
}

fn flush_directory(file: &File) -> Result<(), WindowsStateError> {
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: synchronous live directory handle has write/append access; flags0 includes metadata
    // and the physical storage-cache synchronization. No DATA_ONLY/NO_SYNC shortcut is accepted.
    if unsafe { NtFlushBuffersFileEx(file.as_raw_handle(), 0, null(), 0, &mut status) } < 0 {
        return Err(WindowsStateError::OutcomeUnknown);
    }
    Ok(())
}

/// Publish an exact host-derived package filename without adding metadata files to its signed tree.
/// Create-new semantics preserve an existing file. Empty package files are legitimate. A failed
/// write/flush after creation reports unknown; callers must not confirm a registry reference.
pub fn publish_private_file(path: &Path, bytes: &[u8]) -> Result<(), WindowsStateError> {
    publish_private_file_with_barrier(path, bytes, flush_directory)
}

fn publish_private_file_with_barrier(
    path: &Path,
    bytes: &[u8],
    barrier: fn(&File) -> Result<(), WindowsStateError>,
) -> Result<(), WindowsStateError> {
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(WindowsStateError::Unavailable);
    }
    let identity = Identity::current()?;
    let parent = path.parent().ok_or(WindowsStateError::Unavailable)?;
    let name = path.file_name().ok_or(WindowsStateError::Unavailable)?;
    let pinned = pin_directory_chain(parent)?;
    let directory = pinned.last().ok_or(WindowsStateError::Unavailable)?;
    identity.validate_handle(directory, true)?;
    let mut file = open_file_relative(directory, &identity, name, FILE_CREATE, false, 0)?
        .ok_or(WindowsStateError::Unavailable)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| WindowsStateError::OutcomeUnknown)?;
    barrier(directory).map_err(|_| WindowsStateError::OutcomeUnknown)?;
    Ok(())
}

/// Synchronize the real private directory namespace through retained non-reparse ancestor handles.
pub fn sync_private_directory(path: &Path) -> Result<(), WindowsStateError> {
    let identity = Identity::current()?;
    let pinned = pin_directory_chain(path)?;
    let directory = pinned.last().ok_or(WindowsStateError::Unavailable)?;
    identity.validate_handle(directory, true)?;
    flush_directory(directory)
}

/// Confirm an existing verified package file before a new registry generation references it.
pub fn sync_private_file(path: &Path) -> Result<(), WindowsStateError> {
    let identity = Identity::current()?;
    let pinned = pin_directory_chain(path.parent().ok_or(WindowsStateError::Unavailable)?)?;
    let parent = pinned.last().ok_or(WindowsStateError::Unavailable)?;
    identity.validate_handle(parent, true)?;
    let file = open_file_relative(
        parent,
        &identity,
        path.file_name().ok_or(WindowsStateError::Unavailable)?,
        FILE_OPEN,
        false,
        FILE_SHARE_READ,
    )?
    .ok_or(WindowsStateError::Unavailable)?;
    if file
        .metadata()
        .map_err(|_| WindowsStateError::Unavailable)?
        .len()
        > 8 * 1024 * 1024
    {
        return Err(WindowsStateError::Unavailable);
    }
    file.sync_all()
        .map_err(|_| WindowsStateError::OutcomeUnknown)
}

/// Flush a host-derived parent link through non-reparse pinned handles. This does not rewrite ACLs
/// or grant write access: the native handle must already authorize the real namespace barrier.
pub fn sync_directory_namespace(path: &Path) -> Result<(), WindowsStateError> {
    let pinned = pin_directory_chain(path)?;
    flush_directory(pinned.last().ok_or(WindowsStateError::Unavailable)?)
}

/// One private namespace and one writer lease. Names are fixed by a trusted adapter, never by a
/// model or workspace payload; snapshots and their schema/CAS remain owned by the domain caller.
pub struct WindowsSnapshotStore {
    directory: File,
    lease: File,
    identity: Identity,
    snapshot_name: String,
    pending_name: String,
    poisoned: bool,
}

// Handles and boxed security data have no thread affinity. All mutations require exclusive &mut.
// SAFETY: retained descriptor/SID buffers are immutable, and owned files move with the store.
unsafe impl Send for WindowsSnapshotStore {}

impl WindowsSnapshotStore {
    pub fn open(path: &Path, basename: &str) -> Result<Self, WindowsStateError> {
        component(basename)?;
        let identity = Identity::current()?;
        let wide = wide_path(path)?;
        // Denying directory-delete sharing protects its identity; all children use its pinned fd.
        // SAFETY: terminated path, non-inherited handle and valid flags.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_TRAVERSE | READ_CONTROL | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(WindowsStateError::Unavailable);
        }
        // SAFETY: CreateFile returned a fresh owned handle, transferred exactly once.
        let directory = unsafe { File::from_raw_handle(raw) };
        identity.validate_handle(&directory, true)?;
        local_ntfs(&directory)?;
        let lease_name = format!("{basename}.lock");
        let lease = open_relative(&directory, &identity, &lease_name, FILE_OPEN_IF, false, 0)?
            .ok_or(WindowsStateError::Unavailable)?;
        identity.validate_handle(&lease, false)?;
        Ok(Self {
            directory,
            lease,
            identity,
            snapshot_name: format!("{basename}.json"),
            pending_name: format!("{basename}.pending"),
            poisoned: false,
        })
    }

    pub fn load(&mut self) -> Result<Option<Vec<u8>>, WindowsStateError> {
        self.live()?;
        let file = open_relative(
            &self.directory,
            &self.identity,
            &self.snapshot_name,
            FILE_OPEN,
            false,
            FILE_SHARE_READ,
        )?;
        let Some(mut file) = file else {
            if self
                .lease
                .metadata()
                .map_err(|_| WindowsStateError::Unavailable)?
                .len()
                != 0
            {
                self.poisoned = true;
                return Err(WindowsStateError::OutcomeUnknown);
            }
            return Ok(None);
        };
        self.identity.validate_handle(&file, false)?;
        let length = file
            .metadata()
            .map_err(|_| WindowsStateError::Unavailable)?
            .len();
        if length > HARD_MAX_BYTES as u64 {
            return Err(WindowsStateError::Unavailable);
        }
        let mut bytes = Vec::with_capacity(length as usize);
        Read::by_ref(&mut file)
            .take(HARD_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| WindowsStateError::Unavailable)?;
        if bytes.len() > HARD_MAX_BYTES {
            return Err(WindowsStateError::Unavailable);
        }
        Ok(Some(bytes))
    }

    pub fn publish(&mut self, bytes: &[u8], first: bool) -> Result<(), WindowsStateError> {
        self.live()?;
        if bytes.is_empty() || bytes.len() > HARD_MAX_BYTES {
            return Err(WindowsStateError::Unavailable);
        }
        if first
            && self
                .lease
                .seek(SeekFrom::Start(0))
                .and_then(|_| self.lease.write_all(b"private-state-genesis-v1"))
                .and_then(|_| self.lease.sync_all())
                .is_err()
        {
            self.poisoned = true;
            return Err(WindowsStateError::OutcomeUnknown);
        }
        self.remove_pending()?;
        let mut file = open_relative(
            &self.directory,
            &self.identity,
            &self.pending_name,
            FILE_CREATE,
            true,
            0,
        )?
        .ok_or(WindowsStateError::Unavailable)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| WindowsStateError::Unavailable)?;
        let target = self.snapshot_name.encode_utf16().collect::<Vec<_>>();
        let header = offset_of!(FILE_RENAME_INFO, FileName);
        let length = header + (target.len() + 1) * size_of::<u16>();
        let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: aligned buffer covers the fixed structure plus complete UTF-16 name and NUL.
        unsafe {
            (*info).Anonymous = FILE_RENAME_INFO_0 {
                ReplaceIfExists: true,
            };
            (*info).RootDirectory = self.directory.as_raw_handle();
            (*info).FileNameLength = (target.len() * size_of::<u16>()) as u32;
            std::ptr::copy_nonoverlapping(
                target.as_ptr(),
                (*info).FileName.as_mut_ptr(),
                target.len(),
            );
        }
        // SAFETY: the source has DELETE + write-through access; target resolves only in pinned dir.
        let renamed = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileRenameInfo,
                info.cast(),
                length as u32,
            )
        };
        if renamed == 0 || file.sync_all().is_err() {
            self.poisoned = true;
            return Err(WindowsStateError::OutcomeUnknown);
        }
        Ok(())
    }

    fn remove_pending(&mut self) -> Result<(), WindowsStateError> {
        if let Some(file) = open_relative(
            &self.directory,
            &self.identity,
            &self.pending_name,
            FILE_OPEN,
            true,
            0,
        )? {
            self.identity.validate_handle(&file, false)?;
            let delete = 1i32;
            // SAFETY: FILE_DISPOSITION_INFO contains one BOOL; file has DELETE access.
            if unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileDispositionInfo,
                    (&delete as *const i32).cast(),
                    size_of::<i32>() as u32,
                )
            } == 0
            {
                return Err(WindowsStateError::Unavailable);
            }
        }
        Ok(())
    }

    fn live(&self) -> Result<(), WindowsStateError> {
        if self.poisoned {
            Err(WindowsStateError::OutcomeUnknown)
        } else {
            Ok(())
        }
    }
}

fn open_relative(
    directory: &File,
    identity: &Identity,
    name: &str,
    disposition: u32,
    delete: bool,
    share: u32,
) -> Result<Option<File>, WindowsStateError> {
    component(name)?;
    open_file_relative(
        directory,
        identity,
        std::ffi::OsStr::new(name),
        disposition,
        delete,
        share,
    )
}

fn open_file_relative(
    directory: &File,
    identity: &Identity,
    name: &std::ffi::OsStr,
    disposition: u32,
    delete: bool,
    share: u32,
) -> Result<Option<File>, WindowsStateError> {
    let mut units = name.encode_wide().collect::<Vec<_>>();
    // A single Win32 filename; aliases/ADS/device syntax cannot escape its pinned parent.
    if units.is_empty()
        || units.len() > 255
        || units
            .iter()
            .any(|unit| *unit < 32 || matches!(*unit, 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124))
        || units.last().is_some_and(|unit| matches!(*unit, 32 | 46))
        || name == std::ffi::OsStr::new(".")
        || name == std::ffi::OsStr::new("..")
    {
        return Err(WindowsStateError::Unavailable);
    }
    let text = name.to_str().ok_or(WindowsStateError::Unavailable)?;
    let base = text
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(WindowsStateError::Unavailable);
    }
    let unicode = UNICODE_STRING {
        Length: (units.len() * 2) as u16,
        MaximumLength: (units.len() * 2) as u16,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: directory.as_raw_handle(),
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: identity.descriptor.0.cast(),
        SecurityQualityOfService: null(),
    };
    let mut raw: HANDLE = null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    let access =
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL | SYNCHRONIZE | if delete { DELETE } else { 0 };
    // SAFETY: all pointers are aligned and live; bounded component resolves under pinned handle.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            FILE_NON_DIRECTORY_FILE
                | FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_WRITE_THROUGH,
            null(),
            0,
        )
    };
    if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
        return Ok(None);
    }
    if status < 0 {
        // STATUS_SHARING_VIOLATION: another process owns the independent writer lease.
        return Err(if status as u32 == 0xc0000043 {
            WindowsStateError::Conflict
        } else {
            WindowsStateError::Unavailable
        });
    }
    // SAFETY: successful NtCreateFile returned a fresh owned file handle.
    let file = unsafe { File::from_raw_handle(raw) };
    identity.validate_handle(&file, false)?;
    Ok(Some(file))
}

fn local_ntfs(file: &File) -> Result<(), WindowsStateError> {
    let mut filesystem = [0u16; 32];
    let mut flags = 0;
    // SAFETY: bounded output buffers and live pinned directory handle are valid.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(WindowsStateError::Unavailable);
    }
    let end = filesystem
        .iter()
        .position(|u| *u == 0)
        .ok_or(WindowsStateError::Unavailable)?;
    if String::from_utf16_lossy(&filesystem[..end]) != "NTFS" || flags & FILE_PERSISTENT_ACLS == 0 {
        return Err(WindowsStateError::Unavailable);
    }
    Ok(())
}

fn component(name: &str) -> Result<(), WindowsStateError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || name == "."
        || name == ".."
    {
        return Err(WindowsStateError::Unavailable);
    }
    Ok(())
}

fn wide_text(text: &str) -> Result<Vec<u16>, WindowsStateError> {
    if text.contains('\0') || text.len() > 32_000 {
        return Err(WindowsStateError::Unavailable);
    }
    Ok(text.encode_utf16().chain(Some(0)).collect())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, WindowsStateError> {
    if !path.is_absolute() {
        return Err(WindowsStateError::Unavailable);
    }
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(WindowsStateError::Unavailable);
    };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
        return Err(WindowsStateError::Unavailable);
    }
    let root = PathBuf::from(prefix.as_os_str()).join(r"\");
    let root_units = root
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: terminated drive-root path; only supported local fixed disks can claim this contract.
    if unsafe { GetDriveTypeW(root_units.as_ptr()) } != DRIVE_FIXED {
        return Err(WindowsStateError::Unavailable);
    }
    let mut units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if units.is_empty() || units.len() > 32_000 || units.contains(&0) {
        return Err(WindowsStateError::Unavailable);
    }
    units.push(0);
    Ok(units)
}

#[cfg(test)]
mod directory_barrier_tests {
    use super::{WindowsStateError, flush_directory, provision_directory_with_barrier};
    use std::fs::File;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn failed_parent_barrier_after_real_creation_never_reports_success() {
        static BARRIERS: AtomicUsize = AtomicUsize::new(0);
        fn child_flush_then_refuse_parent(file: &File) -> Result<(), WindowsStateError> {
            if BARRIERS.fetch_add(1, Ordering::SeqCst) == 0 {
                flush_directory(file)
            } else {
                Err(WindowsStateError::OutcomeUnknown)
            }
        }
        let path = std::env::temp_dir().join(format!(
            "iteron-directory-barrier-fault-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir(&path);
        let result = provision_directory_with_barrier(&path, child_flush_then_refuse_parent);
        assert_eq!(result, Err(WindowsStateError::OutcomeUnknown));
        assert!(
            path.is_dir(),
            "fixture reached the actual namespace creation boundary"
        );
        assert_eq!(BARRIERS.load(Ordering::SeqCst), 2);
        // Explicit reconciliation reopens the exact existing directory and performs both actual
        // native barriers; the failed prior attempt never became a success or a fresh namespace.
        super::provision_private_directory(&path).unwrap();
        std::fs::remove_dir(path).unwrap();
    }
    #[test]
    fn exact_package_files_are_create_new_and_failed_namespace_barrier_is_unknown() {
        let directory =
            std::env::temp_dir().join(format!("iteron-package-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        super::provision_private_directory(&directory).unwrap();
        let exact = directory.join("SKILL.md");
        super::publish_private_file(&exact, b"body").unwrap();
        assert_eq!(std::fs::read(&exact).unwrap(), b"body");
        assert!(super::publish_private_file(&exact, b"replacement").is_err());
        assert_eq!(std::fs::read(&exact).unwrap(), b"body");
        super::publish_private_file(&directory.join("empty"), b"").unwrap();
        super::publish_private_file(&directory.join("notes-中文.md"), b"unicode filename").unwrap();
        for name in [
            "CON",
            "NUL.txt",
            "nested/file",
            "alternate:stream",
            "trailing.",
        ] {
            assert!(super::publish_private_file(&directory.join(name), b"unreachable").is_err());
        }
        let lost = directory.join("signature.json");
        fn refuse(_directory: &File) -> Result<(), WindowsStateError> {
            Err(WindowsStateError::OutcomeUnknown)
        }
        assert_eq!(
            super::publish_private_file_with_barrier(&lost, b"signed", refuse),
            Err(WindowsStateError::OutcomeUnknown)
        );
        assert_eq!(std::fs::read(&lost).unwrap(), b"signed");
        super::sync_private_directory(&directory).unwrap();
        assert_eq!(
            std::fs::read_dir(&directory).unwrap().count(),
            4,
            "no .json suffix, lock or sidecar invented in signed tree"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
