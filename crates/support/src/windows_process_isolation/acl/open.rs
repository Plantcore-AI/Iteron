//! A bounded single-component open beneath an actual retained parent directory.
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::{null, null_mut};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_TRAVERSE, READ_CONTROL,
    SYNCHRONIZE, WRITE_DAC,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

pub(super) fn relative(
    parent: &File,
    name: &std::ffi::OsStr,
    directory: bool,
    manage_acl: bool,
    share: u32,
    inspect_reparse: bool,
) -> io::Result<File> {
    let mut units = crate::durable_windows_state::filename_units(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid scoped Windows component",
        )
    })?;
    let unicode = UNICODE_STRING {
        Length: (units.len() * 2) as u16,
        MaximumLength: (units.len() * 2) as u16,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE | if inspect_reparse { 0 } else { OBJ_DONT_REPARSE },
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut raw = null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE
                | if directory {
                    FILE_LIST_DIRECTORY | FILE_TRAVERSE
                } else {
                    0
                }
                | if manage_acl { WRITE_DAC } else { 0 },
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                },
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    Ok(unsafe { File::from_raw_handle(raw) })
}
