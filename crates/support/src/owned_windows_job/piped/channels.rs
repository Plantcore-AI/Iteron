//! The only inheritable handles are these three private peers named in the launch attribute list.
use super::super::conpty::pipes::channel;
use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::ptr::null_mut;
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
pub(super) struct Channels {
    pub(super) input: NamedPipeServer,
    pub(super) output: NamedPipeServer,
    pub(super) error: NamedPipeServer,
    pub(super) child_handles: [OwnedHandle; 3],
}
impl Channels {
    pub(super) async fn create() -> io::Result<Self> {
        let mut nonce = [0_u8; 16];
        if unsafe {
            BCryptGenRandom(
                null_mut(),
                nonce.as_mut_ptr(),
                nonce.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } < 0
        {
            return Err(io::Error::other("native pipe identity unavailable"));
        }
        let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let (input, child_input) =
            channel(&format!(r"\\.\pipe\iteron-child-{nonce}-input"), true).await?;
        let (output, child_output) =
            channel(&format!(r"\\.\pipe\iteron-child-{nonce}-output"), false).await?;
        let (error, child_error) =
            channel(&format!(r"\\.\pipe\iteron-child-{nonce}-error"), false).await?;
        let child_handles = [child_input, child_output, child_error];
        for handle in &child_handles {
            if unsafe {
                SetHandleInformation(
                    handle.as_raw_handle(),
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            input,
            output,
            error,
            child_handles,
        })
    }
}
