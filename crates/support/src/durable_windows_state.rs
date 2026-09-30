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
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree, OBJ_CASE_INSENSITIVE, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, IsValidAcl, IsValidSid,
    OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, DELETE, FILE_ADD_FILE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
    FILE_LIST_DIRECTORY, FILE_RENAME_INFO, FILE_RENAME_INFO_0, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_TRAVERSE, FileDispositionInfo, FileRenameInfo, GetFileInformationByHandle,
    GetVolumeInformationByHandleW, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
    SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, FILE_PERSISTENT_ACLS,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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
                || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(WindowsStateError::Unavailable);
            }
            // SAFETY: accepted standard ACE layout has a SID at SidStart.
            let ace_sid = unsafe {
                raw.cast::<u8>()
                    .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                    .cast()
            };
            // SAFETY: IsValidAcl verifies the ACE structure; enforce SID length within its size.
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

/// Provision only a new, private application directory. Existing directories are never granted
/// authority or rewritten; opening a store validates their owner and protected DACL separately.
pub fn provision_private_directory(path: &Path) -> Result<(), WindowsStateError> {
    let identity = Identity::current()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: identity.descriptor.0,
        bInheritHandle: 0,
    };
    let wide = wide_path(path)?;
    // SAFETY: path and security descriptor outlive the CreateDirectory call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0
        && std::io::Error::last_os_error().raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32)
    {
        return Err(WindowsStateError::Unavailable);
    }
    Ok(())
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
    let mut units = name.encode_utf16().collect::<Vec<_>>();
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
    let mut units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if units.is_empty() || units.len() > 32_000 || units.contains(&0) {
        return Err(WindowsStateError::Unavailable);
    }
    units.push(0);
    Ok(units)
}
