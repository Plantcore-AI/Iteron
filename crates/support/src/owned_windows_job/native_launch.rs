//! Bounded native ABI projection for owned terminal or pipe transport and a frozen environment.
//! The application path is explicit; CreateProcess cannot search ambient PATH/current-directory.
use super::conpty::console::Console;
use crate::windows_process_isolation::WindowsProcessIsolation;
use std::ffi::{OsStr, OsString};
use std::io;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
};
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

const MAX_COMMAND_UNITS: usize = 32_767;
const MAX_ENV_ENTRIES: usize = 4096;
const MAX_ENV_UNITS: usize = 1_048_576;
const MAX_ATTRIBUTE_BYTES: usize = 64 * 1024;

pub(super) enum Transport<'a> {
    Console(&'a Console),
    Pipes {
        input: &'a OwnedHandle,
        output: &'a OwnedHandle,
        error: &'a OwnedHandle,
    },
}

pub(super) struct Launch {
    executable: Vec<u16>,
    command: Vec<u16>,
    directory: Vec<u16>,
    environment: Vec<u16>,
}

impl Launch {
    pub(super) fn capture(
        executable: &Path,
        arguments: &[OsString],
        directory: &Path,
        environment: &[(OsString, OsString)],
    ) -> io::Result<Self> {
        if !executable.is_absolute() || !directory.is_absolute() || arguments.len() > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native process launch requires exact absolute paths and bounded arguments",
            ));
        }
        let executable_wide = terminated(executable.as_os_str(), MAX_COMMAND_UNITS)?;
        let directory = terminated(directory.as_os_str(), MAX_COMMAND_UNITS)?;
        let mut command = Vec::new();
        for argument in
            std::iter::once(executable.as_os_str()).chain(arguments.iter().map(OsString::as_os_str))
        {
            if !command.is_empty() {
                command.push(u16::from(b' '));
            }
            quote(argument, &mut command)?;
            if command.len() >= MAX_COMMAND_UNITS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "native process command exceeds the Windows ABI bound",
                ));
            }
        }
        command.push(0);
        if environment.len() > MAX_ENV_ENTRIES {
            return Err(invalid_environment());
        }
        // Windows environment names are case-insensitive. Reject duplicate aliases instead of
        // silently overriding the caller's frozen snapshot with a platform-dependent value.
        let mut ordered = Vec::with_capacity(environment.len());
        let mut total_units = 2_usize;
        for (name, value) in environment {
            let key: Vec<u16> = name.encode_wide().take(MAX_ENV_UNITS).collect();
            let value: Vec<u16> = value.encode_wide().take(MAX_ENV_UNITS).collect();
            if key.is_empty()
                || key
                    .iter()
                    .any(|unit| *unit == 0 || *unit == u16::from(b'='))
                || value.contains(&0)
            {
                return Err(invalid_environment());
            }
            total_units = total_units
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .and_then(|size| size.checked_add(2))
                .filter(|size| *size <= MAX_ENV_UNITS)
                .ok_or_else(invalid_environment)?;
            let comparison = name
                .to_str()
                .ok_or_else(invalid_environment)?
                .to_uppercase();
            ordered.push((comparison, key, value));
        }
        ordered.sort_by(|left, right| left.0.cmp(&right.0));
        if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(invalid_environment());
        }
        let mut environment = Vec::new();
        for (_, key, value) in ordered {
            let next = environment
                .len()
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .and_then(|size| size.checked_add(2))
                .filter(|size| *size < MAX_ENV_UNITS)
                .ok_or_else(invalid_environment)?;
            environment.reserve(next - environment.len());
            environment.extend(key);
            environment.push(u16::from(b'='));
            environment.extend(value);
            environment.push(0);
        }
        environment.push(0);
        if environment.len() == 1 {
            environment.push(0);
        }
        Ok(Self {
            executable: executable_wide,
            command,
            directory,
            environment,
        })
    }

    pub(super) fn create_suspended(
        &mut self,
        transport: Transport<'_>,
        isolation: Option<&WindowsProcessIsolation>,
    ) -> io::Result<PROCESS_INFORMATION> {
        if let Some(isolation) = isolation {
            isolation.validate_scope_still_bound()?;
        }
        let lpac_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        let (console, handles) = match transport {
            Transport::Console(console) => (Some(console.raw()?), None),
            Transport::Pipes {
                input,
                output,
                error,
            } => (
                None,
                Some([
                    input.as_raw_handle(),
                    output.as_raw_handle(),
                    error.as_raw_handle(),
                ]),
            ),
        };
        let mut attributes = Attributes::new(console, handles.as_ref(), isolation, &lpac_policy)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.pointer();
        if let Some(handles) = handles {
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = handles[0];
            startup.StartupInfo.hStdOutput = handles[1];
            startup.StartupInfo.hStdError = handles[2];
        }
        let mut information = PROCESS_INFORMATION::default();
        let created = unsafe {
            CreateProcessW(
                self.executable.as_ptr(),
                self.command.as_mut_ptr(),
                null(),
                null(),
                i32::from(handles.is_some()),
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                self.environment.as_ptr().cast(),
                self.directory.as_ptr(),
                &startup.StartupInfo,
                &mut information,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(information)
    }
}

struct Attributes {
    buffer: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new(
        console: Option<isize>,
        handles: Option<&[windows_sys::Win32::Foundation::HANDLE; 3]>,
        isolation: Option<&WindowsProcessIsolation>,
        lpac_policy: &u32,
    ) -> io::Result<Self> {
        let count = 1
            + u32::from(isolation.is_some())
            + u32::from(isolation.is_some_and(WindowsProcessIsolation::is_lpac));
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), count, 0, &mut bytes);
        }
        if bytes == 0 || bytes > MAX_ATTRIBUTE_BYTES {
            return Err(io::Error::other(
                "native process attribute envelope unavailable",
            ));
        }
        let mut attributes = Self {
            buffer: vec![0; bytes.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        if unsafe { InitializeProcThreadAttributeList(attributes.pointer(), count, 0, &mut bytes) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        attributes.initialized = true;
        let (attribute, value, size) = if let Some(console) = console {
            (
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                console as *const std::ffi::c_void,
                size_of::<isize>(),
            )
        } else {
            let handles =
                handles.ok_or_else(|| io::Error::other("native transport handles missing"))?;
            (
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_ptr().cast(),
                size_of_val(handles),
            )
        };
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.pointer(),
                0,
                attribute as usize,
                value,
                size,
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if let Some(isolation) = isolation {
            if unsafe {
                UpdateProcThreadAttribute(
                    attributes.pointer(),
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    (isolation.security_capabilities() as *const SECURITY_CAPABILITIES).cast(),
                    size_of::<SECURITY_CAPABILITIES>(),
                    null_mut(),
                    null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if isolation.is_lpac()
                && unsafe {
                    UpdateProcThreadAttribute(
                        attributes.pointer(),
                        0,
                        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
                        (lpac_policy as *const u32).cast(),
                        size_of::<u32>(),
                        null_mut(),
                        null(),
                    )
                } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(attributes)
    }
    fn pointer(&mut self) -> windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer());
            }
        }
    }
}

fn terminated(value: &OsStr, limit: usize) -> io::Result<Vec<u16>> {
    let units: Vec<u16> = value.encode_wide().take(limit).collect();
    if units.is_empty() || units.len() >= limit || units.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native process path exceeds its terminated ABI envelope",
        ));
    }
    Ok(units.into_iter().chain([0]).collect())
}

fn quote(value: &OsStr, output: &mut Vec<u16>) -> io::Result<()> {
    let units: Vec<u16> = value.encode_wide().take(MAX_COMMAND_UNITS).collect();
    if units.len() >= MAX_COMMAND_UNITS || units.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native process argument exceeds its ABI envelope",
        ));
    }
    output.push(u16::from(b'"'));
    let mut slashes = 0;
    for unit in units {
        if unit == u16::from(b'\\') {
            slashes += 1;
            continue;
        }
        let count = if unit == u16::from(b'"') {
            slashes * 2 + 1
        } else {
            slashes
        };
        output.extend(std::iter::repeat_n(u16::from(b'\\'), count));
        slashes = 0;
        output.push(unit);
    }
    output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes * 2));
    output.push(u16::from(b'"'));
    Ok(())
}
fn invalid_environment() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "native process environment exceeds its exact frozen envelope",
    )
}
