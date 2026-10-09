//! Two private byte streams: overlapped parent endpoints and synchronous ConPTY endpoints.
//! No inherited/public name, remote client, blocking writer task or unbounded message queue.
use super::super::own_handle;
use crate::durable_windows_state::PrivateObjectSecurity;
use std::future::{Future, poll_fn};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::OwnedHandle;
use std::ptr::{null, null_mut};
use std::task::Poll;
use std::time::Duration;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};

const PIPE_BUFFER_BYTES: u32 = 16 * 1024;
const PIPE_CONNECT_LIMIT: Duration = Duration::from_secs(1);

pub(super) struct Pipes {
    pub(super) input: NamedPipeServer,
    pub(super) output: NamedPipeServer,
    pub(super) console_input: OwnedHandle,
    pub(super) console_output: OwnedHandle,
}

impl Pipes {
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
            return Err(io::Error::other("ConPTY pipe identity unavailable"));
        }
        let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let (input, console_input) =
            channel(&format!(r"\\.\pipe\iteron-conpty-{nonce}-input"), true).await?;
        let (output, console_output) =
            channel(&format!(r"\\.\pipe\iteron-conpty-{nonce}-output"), false).await?;
        Ok(Self {
            input,
            output,
            console_input,
            console_output,
        })
    }
}

pub(in crate::owned_windows_job) async fn channel(
    name: &str,
    parent_writes: bool,
) -> io::Result<(NamedPipeServer, OwnedHandle)> {
    let server = {
        let security = PrivateObjectSecurity::current()?;
        let mut attributes = security.attributes();
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .max_instances(1)
                .reject_remote_clients(true)
                .access_inbound(!parent_writes)
                .access_outbound(parent_writes)
                .in_buffer_size(PIPE_BUFFER_BYTES)
                .out_buffer_size(PIPE_BUFFER_BYTES)
                .create_with_security_attributes_raw(
                    name,
                    (&mut attributes as *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES)
                        .cast(),
                )?
        }
    };
    let path: Vec<u16> = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain([0])
        .collect();
    let mut peer = None;
    let mut connecting = Box::pin(server.connect());
    let result = tokio::time::timeout(
        PIPE_CONNECT_LIMIT,
        poll_fn(|context| {
            let connected = match connecting.as_mut().poll(context) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => true,
                Poll::Pending => false,
            };
            if peer.is_none() {
                // Poll the actual overlapped listener before this finite native open; the CP side is
                // deliberately synchronous, as required by CreatePseudoConsole's contract.
                let raw = unsafe {
                    CreateFileW(
                        path.as_ptr(),
                        if parent_writes {
                            GENERIC_READ
                        } else {
                            GENERIC_WRITE
                        },
                        0,
                        null(),
                        OPEN_EXISTING,
                        0,
                        null_mut(),
                    )
                };
                match own_handle(raw) {
                    Ok(handle) => peer = Some(handle),
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            if connected {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "ConPTY private pipe connection timed out",
        )
    })?;
    drop(connecting);
    result?;
    Ok((
        server,
        peer.ok_or_else(|| io::Error::other("ConPTY pipe peer unavailable"))?,
    ))
}
