//! Bounded native enumeration of the actual held directory, without reopening a pathname.
use super::WindowsStateError;
use std::fs::File;
use std::mem::{offset_of, size_of};
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO,
    FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, GetFileInformationByHandleEx,
};
const BUFFER_BYTES: usize = 64 * 1024;
pub(super) fn list(
    directory: &File,
    limit: usize,
) -> Result<(Vec<(String, bool)>, bool), WindowsStateError> {
    if limit == 0 || limit > 4096 {
        return Err(WindowsStateError::Unavailable);
    }
    let mut rows = Vec::with_capacity(limit.min(128));
    let mut buffer = vec![0u64; BUFFER_BYTES / size_of::<u64>()];
    let mut first = true;
    // One native call must return at least one non-dot row or end; at most two additional calls
    // cover dot-only chunks. The output row/count and native buffer are independently bounded.
    for _ in 0..limit + 2 {
        buffer.fill(0);
        let class = if first {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        first = false;
        // SAFETY: aligned 64KiB storage, retained real directory handle and exact buffer size.
        if unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                BUFFER_BYTES as u32,
            )
        } == 0
        {
            return if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                Ok((rows, false))
            } else {
                Err(WindowsStateError::Unavailable)
            };
        }
        let mut offset = 0usize;
        for _ in 0..BUFFER_BYTES / offset_of!(FILE_ID_BOTH_DIR_INFO, FileName) {
            let header = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            if offset % 8 != 0
                || offset
                    .checked_add(size_of::<FILE_ID_BOTH_DIR_INFO>())
                    .is_none_or(|end| end > BUFFER_BYTES)
            {
                return Err(WindowsStateError::Unavailable);
            }
            // SAFETY: header is checked within aligned native storage; trailing name validated next.
            let entry = unsafe {
                &*buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<FILE_ID_BOTH_DIR_INFO>()
            };
            let name_bytes = entry.FileNameLength as usize;
            if name_bytes == 0
                || name_bytes % 2 != 0
                || name_bytes > 510
                || offset
                    .checked_add(header + name_bytes)
                    .is_none_or(|end| end > BUFFER_BYTES)
            {
                return Err(WindowsStateError::Unavailable);
            }
            let units =
                unsafe { std::slice::from_raw_parts(entry.FileName.as_ptr(), name_bytes / 2) };
            let name = String::from_utf16(units).map_err(|_| WindowsStateError::Unavailable)?;
            if name != "." && name != ".." {
                if entry.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(WindowsStateError::Unavailable);
                }
                if rows.len() == limit {
                    return Ok((rows, true));
                }
                rows.push((name, entry.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0));
            }
            let next = entry.NextEntryOffset as usize;
            if next == 0 {
                break;
            }
            if next < header + name_bytes || next % 8 != 0 {
                return Err(WindowsStateError::Unavailable);
            }
            offset = offset
                .checked_add(next)
                .ok_or(WindowsStateError::Unavailable)?;
        }
    }
    // The scan itself exhausted its native operation budget. No complete inventory is claimed.
    Ok((rows, true))
}
