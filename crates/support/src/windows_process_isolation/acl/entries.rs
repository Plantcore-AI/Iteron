//! Remove only this fresh package SID, retaining every other ACE byte-for-byte.
use std::io;
use std::mem::size_of;
use std::ptr::null_mut;
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, AddAce, EqualSid, GetAce, InitializeAcl, IsValidAcl, PSID,
};

pub(super) fn without_sid(acl: *const ACL, sid: PSID) -> io::Result<Box<[u32]>> {
    validate(acl)?;
    let size = unsafe { (*acl).AclSize } as usize;
    let revision = unsafe { (*acl).AclRevision } as u32;
    let mut storage = vec![0_u32; size.div_ceil(size_of::<u32>())].into_boxed_slice();
    let replacement = storage.as_mut_ptr().cast::<ACL>();
    if unsafe { InitializeAcl(replacement, size as u32, revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    for index in 0..unsafe { (*acl).AceCount } as u32 {
        let ace = entry(acl, index)?;
        if !has_sid(ace, sid)?
            && unsafe {
                AddAce(
                    replacement,
                    revision,
                    u32::MAX,
                    ace.as_ptr().cast(),
                    ace.len() as u32,
                )
            } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(storage)
}

pub(super) fn contains(acl: *const ACL, sid: PSID) -> io::Result<bool> {
    validate(acl)?;
    for index in 0..unsafe { (*acl).AceCount } as u32 {
        if has_sid(entry(acl, index)?, sid)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate(acl: *const ACL) -> io::Result<()> {
    if acl.is_null()
        || unsafe { IsValidAcl(acl) } == 0
        || unsafe { (*acl).AclSize } < size_of::<ACL>() as u16
    {
        return Err(io::Error::other(
            "Windows scope has no valid bounded discretionary ACL",
        ));
    }
    Ok(())
}

fn entry<'a>(acl: *const ACL, index: u32) -> io::Result<&'a [u8]> {
    let mut raw = null_mut();
    if unsafe { GetAce(acl, index, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let header = unsafe { &*raw.cast::<ACE_HEADER>() };
    let size = header.AceSize as usize;
    let start = acl as usize;
    let end = start + unsafe { (*acl).AclSize } as usize;
    if size < size_of::<ACE_HEADER>()
        || (raw as usize) < start
        || (raw as usize)
            .checked_add(size)
            .is_none_or(|limit| limit > end)
    {
        return Err(io::Error::other(
            "Windows scope ACE is outside its retained ACL",
        ));
    }
    // The caller owns the security descriptor for the entire inspection. No slice escapes it.
    Ok(unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), size) })
}

fn has_sid(ace: &[u8], sid: PSID) -> io::Result<bool> {
    let offset = match ace[0] {
        // Ordinary, callback, mandatory-label, resource-attribute and policy/trust ACEs.
        0..=3 | 9 | 10 | 13 | 14 | 17..=21 => 8,
        // Object ACEs place optional object/inherited-object GUIDs before the SID.
        5..=8 | 11 | 12 | 15 | 16 => {
            if ace.len() < 12 {
                return Err(incomplete());
            }
            let flags = u32::from_le_bytes(ace[8..12].try_into().map_err(|_| incomplete())?);
            if flags & !3 != 0 {
                return Err(incomplete());
            }
            12 + 16 * usize::from(flags & 1 != 0) + 16 * usize::from(flags & 2 != 0)
        }
        _ => return Err(io::Error::other("Windows scope ACE kind is unsupported")),
    };
    if offset + 8 > ace.len() {
        return Err(incomplete());
    }
    let size = 8 + 4 * ace[offset + 1] as usize;
    if offset + size > ace.len() || ace[offset] != 1 {
        return Err(incomplete());
    }
    // Both SIDs are complete and valid within their owned storage; Windows performs equality.
    Ok(unsafe { EqualSid(ace.as_ptr().add(offset).cast_mut().cast(), sid) } != 0)
}

fn incomplete() -> io::Error {
    io::Error::other("Windows scope ACE identity is incomplete")
}
