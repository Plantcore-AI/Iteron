//! Serialize this host's permission transactions across processes and Windows sessions.
//! This is coordination between Iteron owners, not an ACL compare-and-swap with outside editors.

use std::io;
use std::marker::PhantomData;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null;
use std::rc::Rc;
use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

const ACL_LOCK_WAIT_MS: u32 = 5_000;

pub(super) struct NativeAclLock {
    handle: OwnedHandle,
    owned: bool,
    // Windows mutex ownership belongs to a thread. Prevent moving a held guard to another one.
    _thread: PhantomData<Rc<()>>,
}

impl NativeAclLock {
    pub(super) fn acquire(volume: u32, index: u64) -> io::Result<Self> {
        let name = format!("Global\\Iteron.ScopeAcl.v1.{volume:08x}.{index:016x}");
        let name = name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // The default descriptor comes from the trusted host token, and the handle is never
        // inheritable. A foreign pre-created object/denied access is a refusal, not a bypass.
        let raw = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut guard = Self {
            handle: unsafe { OwnedHandle::from_raw_handle(raw) },
            owned: false,
            _thread: PhantomData,
        };
        let observed =
            unsafe { WaitForSingleObject(guard.handle.as_raw_handle(), ACL_LOCK_WAIT_MS) };
        match observed {
            WAIT_OBJECT_0 => {
                guard.owned = true;
                Ok(guard)
            }
            WAIT_ABANDONED => {
                guard.owned = true;
                Err(io::Error::other(
                    "Windows scope permission transaction was abandoned",
                ))
            }
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Windows scope permission transaction is busy",
            )),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other(
                "Windows scope permission transaction is unobserved",
            )),
        }
    }
}

impl Drop for NativeAclLock {
    fn drop(&mut self) {
        if self.owned {
            // Every held guard remains on its acquiring thread. Closing the OwnedHandle follows
            // this release even on error; no caller can infer a successful ACL edit from Drop.
            unsafe { ReleaseMutex(self.handle.as_raw_handle()) };
        }
    }
}
