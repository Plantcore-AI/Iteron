//! Ordinary read capability: local NTFS, retained non-reparse ancestry and a disk file.
//! It requests read/traverse access only and imposes no private-state ACL requirement.
use super::{WindowsStateError, local_ntfs, open_directory_at, pin_read_directory_chain};
use std::{
    fs::File,
    io::Read,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path},
    ptr::{null, null_mut},
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
            FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
        },
    },
    Win32::{
        Foundation::{GENERIC_READ, HANDLE, OBJ_CASE_INSENSITIVE, UNICODE_STRING},
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ, FILE_TYPE_DISK,
            GetFileInformationByHandle, GetFileType, SYNCHRONIZE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_READER_BYTES: usize = 32 * 1024 * 1024;
#[derive(PartialEq, Eq)]
struct FileStamp {
    volume: u32,
    index_hi: u32,
    index_lo: u32,
    size_hi: u32,
    size_lo: u32,
    written_hi: u32,
    written_lo: u32,
    attributes: u32,
}
/// Ordinary read-only capability. Every ancestor retains a no-delete-share, non-reparse handle.
/// Reads and enumeration use the actual held directory handles without pathname reopening.
pub struct WindowsWorkspaceReader {
    directories: Vec<File>,
}
impl WindowsWorkspaceReader {
    pub fn open(path: &Path) -> Result<Self, WindowsStateError> {
        let directories = pin_read_directory_chain(path)?;
        local_ntfs(directories.last().ok_or(WindowsStateError::Unavailable)?)?;
        Ok(Self { directories })
    }
    pub fn open_child(&self, name: &str) -> Result<Option<Self>, WindowsStateError> {
        let _ = super::filename_units(std::ffi::OsStr::new(name))?;
        let parent = self
            .directories
            .last()
            .ok_or(WindowsStateError::Unavailable)?;
        let Some(child) = optional_directory(parent, name)? else {
            return Ok(None);
        };
        let mut directories = self
            .directories
            .iter()
            .map(File::try_clone)
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| WindowsStateError::Unavailable)?;
        directories.push(child);
        Ok(Some(Self { directories }))
    }
    /// Identity of the actual held ordinary directory; this value is not an access capability.
    pub fn identity(&self) -> Result<[u64; 3], WindowsStateError> {
        let file = self
            .directories
            .last()
            .ok_or(WindowsStateError::Unavailable)?;
        let info = stamp(file, true)?;
        Ok([
            u64::from(info.volume),
            u64::from(info.index_hi),
            u64::from(info.index_lo),
        ])
    }
    pub fn read_leaf(&self, name: &str, limit: usize) -> Result<Vec<u8>, WindowsStateError> {
        if limit > MAX_READER_BYTES {
            return Err(WindowsStateError::Unavailable);
        }
        let parent = self
            .directories
            .last()
            .ok_or(WindowsStateError::Unavailable)?;
        let mut file = read_leaf(parent, std::ffi::OsStr::new(name))?;
        let before = stamp(&file, false)?;
        let size = (u64::from(before.size_hi) << 32) | u64::from(before.size_lo);
        if size > limit as u64 {
            return Err(WindowsStateError::Unavailable);
        }
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        (&mut file)
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| WindowsStateError::Unavailable)?;
        if bytes.len() > limit || before != stamp(&file, false)? {
            return Err(WindowsStateError::Unavailable);
        }
        Ok(bytes)
    }
    pub fn list(&self, limit: usize) -> Result<(Vec<(String, bool)>, bool), WindowsStateError> {
        let directory = self
            .directories
            .last()
            .ok_or(WindowsStateError::Unavailable)?;
        super::workspace_directory_read::list(directory, limit)
    }
}
fn optional_directory(parent: &File, name: &str) -> Result<Option<File>, WindowsStateError> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_DIRECTORY_FILE;
    use windows_sys::Win32::Foundation::{
        STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_WRITE, FILE_TRAVERSE,
    };
    let mut units = super::filename_units(std::ffi::OsStr::new(name))?;
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
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut raw: HANDLE = null_mut();
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: held parent, bounded native component and live aligned outputs.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
            &attributes,
            &mut io,
            null(),
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
        return Ok(None);
    }
    if status < 0 {
        return Err(WindowsStateError::Unavailable);
    }
    // SAFETY: successful native open returned a new owned handle exactly once.
    let child = unsafe { File::from_raw_handle(raw) };
    let _ = stamp(&child, true)?;
    Ok(Some(child))
}

fn stamp(file: &File, directory: bool) -> Result<FileStamp, WindowsStateError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(WindowsStateError::Unavailable);
    }
    Ok(FileStamp {
        volume: info.dwVolumeSerialNumber,
        index_hi: info.nFileIndexHigh,
        index_lo: info.nFileIndexLow,
        size_hi: info.nFileSizeHigh,
        size_lo: info.nFileSizeLow,
        written_hi: info.ftLastWriteTime.dwHighDateTime,
        written_lo: info.ftLastWriteTime.dwLowDateTime,
        attributes: info.dwFileAttributes,
    })
}
fn same_directory(a: &File, b: &File) -> Result<bool, WindowsStateError> {
    let a = stamp(a, true)?;
    let b = stamp(b, true)?;
    Ok((a.volume, a.index_hi, a.index_lo) == (b.volume, b.index_hi, b.index_lo))
}
fn read_leaf(parent: &File, name: &std::ffi::OsStr) -> Result<File, WindowsStateError> {
    let mut units = name.encode_wide().collect::<Vec<_>>();
    if units.is_empty()
        || units.len() > 255
        || units
            .iter()
            .any(|n| *n < 32 || matches!(*n, 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124))
        || units.last().is_some_and(|n| matches!(*n, 32 | 46))
    {
        return Err(WindowsStateError::Unavailable);
    }
    let base = name
        .to_str()
        .ok_or(WindowsStateError::Unavailable)?
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
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut raw: HANDLE = null_mut();
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: bounded one-component name, retained directory, live aligned output pointers.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            GENERIC_READ | SYNCHRONIZE,
            &attributes,
            &mut io,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(WindowsStateError::Unavailable);
    }
    // SAFETY: successful native open transfers a newly owned handle exactly once.
    let file = unsafe { File::from_raw_handle(raw) };
    let _ = stamp(&file, false)?;
    Ok(file)
}
pub(super) fn read(
    root: &Path,
    relative: &Path,
    limit: usize,
) -> Result<Vec<u8>, WindowsStateError> {
    if limit > MAX_BYTES
        || root.as_os_str().encode_wide().take(4097).count() > 4096
        || relative.is_absolute()
        || relative.as_os_str().encode_wide().take(4097).count() > 4096
    {
        return Err(WindowsStateError::Unavailable);
    }
    let names = relative
        .components()
        .filter(|component| *component != Component::CurDir)
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(WindowsStateError::Unavailable),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if names.is_empty() || names.len() > 64 {
        return Err(WindowsStateError::Unavailable);
    }
    let root_chain = pin_read_directory_chain(root)?;
    let mut parents = Vec::new();
    let mut parent = root_chain
        .last()
        .ok_or(WindowsStateError::Unavailable)?
        .try_clone()
        .map_err(|_| WindowsStateError::Unavailable)?;
    for name in &names[..names.len() - 1] {
        parent = open_directory_at(&parent, name, None, false)?.0;
        parents.push(
            parent
                .try_clone()
                .map_err(|_| WindowsStateError::Unavailable)?,
        );
    }
    let mut file = read_leaf(&parent, names[names.len() - 1])?;
    local_ntfs(&file)?;
    let before = stamp(&file, false)?;
    if file
        .metadata()
        .map_err(|_| WindowsStateError::Unavailable)?
        .len()
        > limit as u64
    {
        return Err(WindowsStateError::Unavailable);
    }
    let mut bytes = Vec::with_capacity(limit.min(8192));
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WindowsStateError::Unavailable)?;
    if bytes.len() > limit {
        return Err(WindowsStateError::Unavailable);
    }
    let current = pin_read_directory_chain(root)?;
    if current.len() != root_chain.len() {
        return Err(WindowsStateError::Unavailable);
    }
    for (expected, now) in root_chain.iter().zip(&current) {
        if !same_directory(expected, now)? {
            return Err(WindowsStateError::Unavailable);
        }
    }
    let mut current = current
        .last()
        .ok_or(WindowsStateError::Unavailable)?
        .try_clone()
        .map_err(|_| WindowsStateError::Unavailable)?;
    for (name, expected) in names[..names.len() - 1].iter().zip(&parents) {
        current = open_directory_at(&current, name, None, false)?.0;
        if !same_directory(expected, &current)? {
            return Err(WindowsStateError::Unavailable);
        }
    }
    let after = read_leaf(&current, names[names.len() - 1])?;
    if before != stamp(&after, false)? {
        return Err(WindowsStateError::Unavailable);
    }
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn held_workspace_reader_enumerates_and_reads_exact_native_namespace() {
        let path = std::env::temp_dir().join(format!(
            "iteron-workspace-reader-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("alpha.json"), b"actual complete bytes").unwrap();
        std::fs::create_dir(path.join("child")).unwrap();
        let reader = WindowsWorkspaceReader::open(&path).unwrap();
        assert_eq!(
            reader.read_leaf("alpha.json", 64).unwrap(),
            b"actual complete bytes"
        );
        assert!(reader.read_leaf("alpha.json", 2).is_err());
        assert!(reader.open_child("missing").unwrap().is_none());
        assert!(reader.open_child("child").unwrap().is_some());
        assert!(reader.open_child("../escape").is_err());
        let (rows, truncated) = reader.list(1).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(truncated);
        let (mut rows, truncated) = reader.list(4).unwrap();
        rows.sort();
        assert_eq!(
            rows,
            vec![("alpha.json".into(), false), ("child".into(), true)]
        );
        assert!(!truncated);
        assert!(std::fs::rename(&path, path.with_extension("moved")).is_err());
        drop(reader);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn ordinary_checkout_source_reads_without_private_directory_acl_or_write_permission() {
        let path =
            std::env::temp_dir().join(format!("iteron-contained-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("src")).unwrap();
        std::fs::write(path.join("src/script.js"), b"return 5;").unwrap();
        assert_eq!(
            read(&path, Path::new("src/script.js"), 64).unwrap(),
            b"return 5;"
        );
        assert!(read(&path, Path::new("src/script.js"), 2).is_err());
        assert!(read(&path, Path::new("src/CON"), 64).is_err());
        assert!(read(&path, Path::new("../escape"), 64).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}
