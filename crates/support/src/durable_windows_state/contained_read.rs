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
