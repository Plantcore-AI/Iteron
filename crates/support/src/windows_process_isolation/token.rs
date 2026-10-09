//! Attest the actual suspended process token before it can execute its first instruction.

use super::profile::Profile;
use std::io;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, PSID, SE_GROUP_ENABLED, SID_AND_ATTRIBUTES,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
    TokenAppContainerSid, TokenCapabilities, TokenIsAppContainer,
    TokenIsLessPrivilegedAppContainer,
};
use windows_sys::Win32::System::Threading::OpenProcessToken;

pub(super) fn verify(profile: &Profile, process: BorrowedHandle<'_>) -> io::Result<()> {
    let mut raw_token = null_mut();
    // SAFETY: the caller lends its actual owned suspended process, not a model-provided PID.
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    for class in [TokenIsAppContainer, TokenIsLessPrivilegedAppContainer] {
        let data = information(&token, class)?;
        if data.bytes < std::mem::size_of::<u32>()
            || unsafe { *data.storage.as_ptr().cast::<u32>() } == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "actual Windows process is not the requested restricted AppContainer",
            ));
        }
    }
    let data = information(&token, TokenAppContainerSid)?;
    if data.bytes < std::mem::size_of::<TOKEN_APPCONTAINER_INFORMATION>() {
        return Err(io::Error::other(
            "actual Windows package token information is incomplete",
        ));
    }
    let package = unsafe {
        &*data
            .storage
            .as_ptr()
            .cast::<TOKEN_APPCONTAINER_INFORMATION>()
    };
    data.validate_sid(package.TokenAppContainer)?;
    if unsafe { EqualSid(package.TokenAppContainer, profile.sid()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "actual Windows process has a different package identity",
        ));
    }
    verify_capabilities(profile, &token)
}

fn verify_capabilities(profile: &Profile, token: &OwnedHandle) -> io::Result<()> {
    let data = information(token, TokenCapabilities)?;
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    if data.bytes < offset {
        return Err(io::Error::other(
            "actual Windows capabilities header is incomplete",
        ));
    }
    let count = unsafe { *data.storage.as_ptr().cast::<u32>() } as usize;
    let expected = profile.capabilities();
    if count != expected.CapabilityCount as usize
        || offset
            .checked_add(count * std::mem::size_of::<SID_AND_ATTRIBUTES>())
            .is_none_or(|size| size > data.bytes)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "actual Windows process capabilities differ from the sealed host policy",
        ));
    }
    // Exact count plus one-to-one SID matching refuses both extra permissions and duplicate
    // entries. Storage is pointer-aligned, and every pointed-to SID is bounds checked first.
    let entries = unsafe {
        std::slice::from_raw_parts(
            data.storage
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let mut matched = vec![false; count];
    for entry in entries {
        data.validate_sid(entry.Sid)?;
        let index = (0..count).find(|index| {
            !matched[*index]
                && unsafe { EqualSid(entry.Sid, (*expected.Capabilities.add(*index)).Sid) } != 0
        });
        if entry.Attributes & SE_GROUP_ENABLED == 0 || index.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "actual Windows process capability was not requested or is disabled",
            ));
        }
        matched[index.expect("capability index checked above")] = true;
    }
    Ok(())
}

struct Information {
    storage: Box<[usize]>,
    bytes: usize,
}

impl Information {
    fn validate_sid(&self, pointer: PSID) -> io::Result<()> {
        let start = self.storage.as_ptr() as usize;
        let end = start + self.bytes;
        let sid = pointer as usize;
        if sid < start || sid.checked_add(8).is_none_or(|minimum| minimum > end) {
            return Err(io::Error::other(
                "actual Windows identity is outside its token buffer",
            ));
        }
        // A SID has an eight-byte header followed by its declared 32-bit subauthorities.
        let count = unsafe { *pointer.cast::<u8>().add(1) } as usize;
        if sid
            .checked_add(8 + 4 * count)
            .is_none_or(|limit| limit > end)
        {
            return Err(io::Error::other(
                "actual Windows identity exceeds its token buffer",
            ));
        }
        Ok(())
    }
}

fn information(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Information> {
    let mut required = 0_u32;
    let probe =
        unsafe { GetTokenInformation(token.as_raw_handle(), class, null_mut(), 0, &mut required) };
    if probe != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || required == 0
        || required > 64 * 1024
    {
        return Err(io::Error::other(
            "Windows sandbox token information size was refused",
        ));
    }
    let mut storage = vec![0_usize; (required as usize).div_ceil(std::mem::size_of::<usize>())]
        .into_boxed_slice();
    let mut returned = 0_u32;
    // SAFETY: pointer-aligned owned storage is at least the exact requested native size.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            storage.as_mut_ptr().cast(),
            required,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned > required {
        return Err(io::Error::other(
            "Windows sandbox token information changed size",
        ));
    }
    Ok(Information {
        storage,
        bytes: returned as usize,
    })
}
