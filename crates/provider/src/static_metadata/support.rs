use super::*;
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[cfg(unix)]
pub(super) fn validate_operator_file_metadata(
    named: &std::fs::Metadata,
    opened: &std::fs::Metadata,
    _file: &std::fs::File,
) -> Result<(), ProviderError> {
    use std::os::unix::fs::MetadataExt as _;

    // SAFETY: `geteuid` has no preconditions and only reads the effective uid of this process.
    let effective_uid = unsafe { libc::geteuid() };
    if named.dev() != opened.dev()
        || named.ino() != opened.ino()
        || opened.nlink() != 1
        || opened.uid() != effective_uid
        || opened.mode() & 0o077 != 0
    {
        return Err(configuration(
            "provider metadata ownership or permissions are unsafe (require owner-only, single-link file)",
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn validate_operator_file_metadata(
    _named: &std::fs::Metadata,
    opened: &std::fs::Metadata,
    file: &std::fs::File,
) -> Result<(), ProviderError> {
    if !opened.is_file() || !windows_file_security_is_safe(file) {
        return Err(configuration(
            "provider metadata handle, ownership, link count, reparse status, or write ACL is unsafe",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_file_security_is_safe(file: &std::fs::File) -> bool {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        IsValidSid, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            // SAFETY: this guard owns the non-null token handle returned by OpenProcessToken.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    struct DescriptorGuard(PSECURITY_DESCRIPTOR);
    impl Drop for DescriptorGuard {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocates this descriptor with LocalAlloc on success.
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }

    // File-content mutation rights. Read-only inherited entries are harmless because the
    // document contains public strategy data; any non-owner writer could replace authorization
    // facts and is therefore rejected. SYSTEM and Administrators are the Windows analogue of the
    // privileged host administrator that can bypass Unix mode bits.
    const MUTATING_RIGHTS: u32 = 0x4000_0000 // GENERIC_WRITE
        | 0x1000_0000 // GENERIC_ALL
        | 0x0008_0000 // WRITE_OWNER
        | 0x0004_0000 // WRITE_DAC
        | 0x0001_0000 // DELETE
        | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
        | 0x0000_0010 // FILE_WRITE_EA
        | 0x0000_0004 // FILE_APPEND_DATA
        | 0x0000_0002; // FILE_WRITE_DATA
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
    const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
    const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 11;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    // SAFETY: every Windows call receives an initialized out pointer and a live file/token
    // handle. Token storage is usize-aligned and remains alive while its SID is compared. The
    // security descriptor owns the returned owner/DACL pointers and is freed only after the ACE
    // walk. GetAce validates each returned pointer; the fixed ACE header/size is checked before
    // reading ACCESS_ALLOWED_ACE fields.
    unsafe {
        let raw_file = file.as_raw_handle() as HANDLE;
        let mut file_info = BY_HANDLE_FILE_INFORMATION::default();
        if GetFileInformationByHandle(raw_file, &mut file_info) == 0
            || file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || file_info.nNumberOfLinks != 1
        {
            return false;
        }

        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 || token.is_null() {
            return false;
        }
        let token = HandleGuard(token);

        let mut token_bytes = 0u32;
        let _ = GetTokenInformation(
            token.0,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut token_bytes,
        );
        if token_bytes < std::mem::size_of::<TOKEN_USER>() as u32 {
            return false;
        }
        let word = std::mem::size_of::<usize>();
        let mut token_storage = vec![0usize; (token_bytes as usize).div_ceil(word)];
        if GetTokenInformation(
            token.0,
            TokenUser,
            token_storage.as_mut_ptr().cast(),
            token_bytes,
            &mut token_bytes,
        ) == 0
        {
            return false;
        }
        let user_sid = (*token_storage.as_ptr().cast::<TOKEN_USER>()).User.Sid;
        if user_sid.is_null() || IsValidSid(user_sid) == 0 {
            return false;
        }

        let mut owner_sid: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let security_status = GetSecurityInfo(
            raw_file,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner_sid,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if security_status != 0 {
            if !descriptor.is_null() {
                let _ = LocalFree(descriptor);
            }
            return false;
        }
        if descriptor.is_null() {
            return false;
        }
        let _descriptor = DescriptorGuard(descriptor);
        if owner_sid.is_null() || EqualSid(owner_sid, user_sid) == 0 || dacl.is_null() {
            return false;
        }

        let mut acl_info = ACL_SIZE_INFORMATION::default();
        if GetAclInformation(
            dacl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
        {
            return false;
        }
        for index in 0..acl_info.AceCount {
            let mut raw_ace: *mut c_void = std::ptr::null_mut();
            if GetAce(dacl, index, &mut raw_ace) == 0 || raw_ace.is_null() {
                return false;
            }
            let header = &*raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>();
            match header.AceType {
                ACCESS_ALLOWED_ACE_TYPE => {
                    if usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
                        return false;
                    }
                    let ace = &*raw_ace.cast::<ACCESS_ALLOWED_ACE>();
                    if ace.Mask
                        & iteron_tunables::param_integer(
                            "provider.static_metadata.support.mutating_rights",
                            MUTATING_RIGHTS,
                        )
                        == 0
                    {
                        continue;
                    }
                    let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
                    if IsValidSid(sid) == 0
                        || (EqualSid(sid, user_sid) == 0
                            && IsWellKnownSid(sid, WinLocalSystemSid) == 0
                            && IsWellKnownSid(sid, WinBuiltinAdministratorsSid) == 0)
                    {
                        return false;
                    }
                }
                ACCESS_ALLOWED_COMPOUND_ACE_TYPE
                | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => return false,
                _ => {}
            }
        }
        true
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn validate_operator_file_metadata(
    _named: &std::fs::Metadata,
    opened: &std::fs::Metadata,
    _file: &std::fs::File,
) -> Result<(), ProviderError> {
    if !opened.is_file() {
        return Err(configuration("provider metadata must be a regular file"));
    }
    Ok(())
}

pub(super) fn digest_named_snapshot<T: Serialize>(
    name: &str,
    snapshot: &T,
) -> Result<String, ProviderError> {
    let mut snapshot = serde_json::to_value(snapshot)
        .map_err(|_| configuration("provider metadata cannot be canonicalized"))?;
    snapshot
        .as_object_mut()
        .ok_or_else(|| configuration("provider metadata snapshot is not an object"))?
        .remove("version");
    canonical_digest(&serde_json::json!({"name": name, "snapshot": snapshot}))
}

pub(super) fn digest_without_fields<T: Serialize>(
    value: &T,
    fields: &[&str],
) -> Result<String, ProviderError> {
    let mut value = serde_json::to_value(value)
        .map_err(|_| configuration("provider metadata cannot be canonicalized"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| configuration("provider metadata snapshot is not an object"))?;
    for field in fields {
        object.remove(*field);
    }
    canonical_digest(&value)
}

fn canonical_digest(value: &serde_json::Value) -> Result<String, ProviderError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| configuration("provider metadata cannot be canonicalized"))?;
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    Ok(encoded)
}

pub(super) fn require_content_version(
    version: &str,
    digest: &str,
    label: &str,
) -> Result<(), ProviderError> {
    let expected = format!("+sha256:{digest}");
    if !version.ends_with(&expected) {
        return Err(configuration(format!(
            "{label} version does not match its canonical content digest"
        )));
    }
    Ok(())
}

pub(super) fn stamped_version(version: &str, digest: &str) -> Result<String, ProviderError> {
    let prefix = version
        .split_once("+sha256:")
        .map_or(version, |(prefix, _)| prefix);
    if prefix.is_empty() {
        return Err(configuration("provider metadata version prefix is empty"));
    }
    Ok(format!("{prefix}+sha256:{digest}"))
}

pub(super) fn validate_snapshot(
    version: &str,
    source: &str,
    captured: u64,
) -> Result<(), ProviderError> {
    validate_identifier(version, MAX_REVISION_BYTES, "snapshot version")?;
    validate_label(
        source,
        iteron_tunables::param_integer(
            "provider.static_metadata.max_source_bytes",
            MAX_SOURCE_BYTES,
        ),
        "snapshot source",
    )?;
    let url = Url::parse(source).map_err(|_| configuration("snapshot source must be a URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(configuration(
            "snapshot source must be an authority-free HTTPS URL",
        ));
    }
    if captured == 0 {
        return Err(configuration("snapshot capture time must be positive"));
    }
    Ok(())
}

pub(super) fn validate_models(models: &[String]) -> Result<(), ProviderError> {
    if models.is_empty() || models.len() > MAX_MODELS {
        return Err(configuration(
            "static model manifest exceeds its bound or is empty",
        ));
    }
    let mut unique = BTreeSet::new();
    for model in models {
        validate_identifier(model, MAX_MODEL_ID_BYTES, "static model id")?;
        if !unique.insert(model) {
            return Err(configuration("static model manifest contains a duplicate"));
        }
    }
    Ok(())
}

pub(super) fn validate_label(value: &str, max: usize, name: &str) -> Result<(), ProviderError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(configuration(format!(
            "provider metadata {name} is invalid"
        )));
    }
    Ok(())
}

pub(super) fn validate_identifier(
    value: &str,
    max: usize,
    name: &str,
) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|byte| matches!(byte, b'!'..=b'~'))
    {
        return Err(configuration(format!(
            "provider metadata {name} is invalid"
        )));
    }
    Ok(())
}

pub(super) fn format_notice(
    snapshots: &[(&str, &str, u64, &str)],
    now: u64,
    bundle_changed: bool,
) -> String {
    let mut ages = Vec::with_capacity(snapshots.len());
    let mut versions = Vec::with_capacity(snapshots.len());
    let mut revision_changed = bundle_changed;
    for (kind, version, captured, baseline) in snapshots {
        if *captured > now {
            let days =
                captured.saturating_sub(now).saturating_add(
                    iteron_tunables::param_integer("provider.static_metadata.day_secs", DAY_SECS)
                        - 1,
                ) / iteron_tunables::param_integer("provider.static_metadata.day_secs", DAY_SECS);
            ages.push(format!(
                "{kind} capture time is {days} days in the future (invalid)"
            ));
        } else {
            let days = now.saturating_sub(*captured)
                / iteron_tunables::param_integer("provider.static_metadata.day_secs", DAY_SECS);
            let state = if days
                > iteron_tunables::param_integer(
                    "provider.static_metadata.stale_after_days",
                    STALE_AFTER_DAYS,
                ) {
                "stale"
            } else {
                "fresh"
            };
            ages.push(format!("{kind} is {days} days old ({state})"));
        }
        versions.push(format!("{kind}={version}"));
        if version != baseline {
            revision_changed = true;
        }
    }
    let mut message = String::from("static provider metadata: ");
    if revision_changed {
        message.push_str("provider revision changed; ");
    }
    message.push_str(&ages.join("; "));
    message.push_str("; active versions: ");
    message.push_str(&versions.join(", "));
    truncate_notice(message)
}

fn truncate_notice(mut message: String) -> String {
    const ELLIPSIS: &str = "…";
    if message.len()
        <= iteron_tunables::param_integer(
            "provider.static_metadata.max_notice_bytes",
            MAX_NOTICE_BYTES,
        )
    {
        return message;
    }
    let mut end =
        iteron_tunables::param_integer(
            "provider.static_metadata.max_notice_bytes",
            MAX_NOTICE_BYTES,
        ) - iteron_tunables::param_str("provider.static_metadata.support.ellipsis", ELLIPSIS).len();
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message.push_str(iteron_tunables::param_str(
        "provider.static_metadata.support.ellipsis",
        ELLIPSIS,
    ));
    message
}

pub(super) fn configuration(message: impl Into<String>) -> ProviderError {
    ProviderError::Configuration(message.into())
}

pub(super) fn current_unix_secs() -> Result<u64, ProviderError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| configuration("system clock is before the Unix epoch"))
}
