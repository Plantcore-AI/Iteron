//! Native package identity owned by one physical launch. Names are never reused on recovery.

use std::ffi::c_void;
use std::io;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, FreeSid, PSID, SECURITY_CAPABILITIES, SECURITY_MAX_SID_SIZE,
    SID_AND_ATTRIBUTES, WELL_KNOWN_SID_TYPE, WinCapabilityInternetClientSid,
    WinCapabilityPrivateNetworkClientServerSid,
};
use windows_sys::Win32::System::Com::CoCreateGuid;
use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;

pub(super) struct Profile {
    name: Vec<u16>,
    package: PSID,
    _network_sids: Vec<Box<[u32]>>,
    _attributes: Box<[SID_AND_ATTRIBUTES]>,
    capabilities: SECURITY_CAPABILITIES,
    alive: AtomicBool,
}

// SAFETY: SID buffers and their pointer table are immutable, independently owned allocations.
// The containing isolation owner serializes lifecycle changes; Windows copies the capabilities
// while creating a token. No pointer is exposed outside the native launch attributes owner.
unsafe impl Send for Profile {}
unsafe impl Sync for Profile {}

impl Profile {
    pub(super) fn prepare(allow_egress: bool) -> io::Result<Self> {
        let mut network_sids = Vec::new();
        if allow_egress {
            for kind in [
                WinCapabilityInternetClientSid,
                WinCapabilityPrivateNetworkClientServerSid,
            ] {
                network_sids.push(well_known_sid(kind)?);
            }
        }
        let mut attributes = network_sids
            .iter_mut()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: sid.as_mut_ptr().cast(),
                Attributes: SE_GROUP_ENABLED as u32,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let mut guid: windows_sys::core::GUID = unsafe { std::mem::zeroed() };
        // SAFETY: guid is a writable native GUID. There is no predictable time/pid fallback.
        hresult(unsafe { CoCreateGuid(&mut guid) })?;
        let name = format!(
            "iteron-{:08x}{:04x}{:04x}{}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        let name = wide(&name);
        let mut package = null_mut();
        // Deriving the SID allocates memory only. No profile or permissions exist until the
        // sole reserved physical owner activates this identity in its admitted worker.
        hresult(unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut package) })?;
        if package.is_null() {
            return Err(io::Error::other(
                "new Windows sandbox name has no package identity",
            ));
        }
        let capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: package,
            Capabilities: if attributes.is_empty() {
                null_mut()
            } else {
                attributes.as_mut_ptr()
            },
            CapabilityCount: attributes.len() as u32,
            Reserved: 0,
        };
        Ok(Self {
            name,
            package,
            _network_sids: network_sids,
            _attributes: attributes,
            capabilities,
            alive: AtomicBool::new(false),
        })
    }

    pub(super) fn activate(&self) -> io::Result<()> {
        if self.alive.load(Ordering::Acquire) {
            return Err(io::Error::other(
                "Windows sandbox profile already activated",
            ));
        }
        let description = wide("Iteron isolated process");
        let mut actual = null_mut();
        // A collision is refused. An existing profile cannot provide a new launch's authority.
        hresult(unsafe {
            CreateAppContainerProfile(
                self.name.as_ptr(),
                description.as_ptr(),
                description.as_ptr(),
                if self._attributes.is_empty() {
                    null()
                } else {
                    self._attributes.as_ptr()
                },
                self._attributes.len() as u32,
                &mut actual,
            )
        })?;
        // Record the created store before inspecting the result: even an anomalous successful
        // API with a null SID remains the physical owner's cleanup responsibility.
        self.alive.store(true, Ordering::Release);
        let matches = !actual.is_null() && unsafe { EqualSid(actual, self.package) } != 0;
        if !actual.is_null() {
            unsafe { FreeSid(actual) };
        }
        if !matches {
            return Err(io::Error::other(
                "created Windows sandbox profile identity changed",
            ));
        }
        Ok(())
    }

    pub(super) fn sid(&self) -> PSID {
        self.package
    }

    pub(super) fn capabilities(&self) -> &SECURITY_CAPABILITIES {
        &self.capabilities
    }

    pub(super) fn retire(&self) -> io::Result<()> {
        if !self.alive.load(Ordering::Acquire) {
            return Ok(());
        }
        // SAFETY: the sole retirement owner invokes this only after the actual tree is gone.
        hresult(unsafe { DeleteAppContainerProfile(self.name.as_ptr()) })?;
        self.alive.store(false, Ordering::Release);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn network_capability_count(&self) -> usize {
        self._attributes.len()
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        // This releases pointer memory, not OS permissions. Profile/ACL retirement requires the
        // retained process owner's terminal proof and cannot be inferred from dropping an Arc.
        if !self.package.is_null() {
            unsafe { FreeSid(self.package) };
        }
    }
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Box<[u32]>> {
    // DWORD storage supplies the SID's required alignment; the SDK fixes its maximum shape.
    let mut storage = vec![0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)].into_boxed_slice();
    let mut bytes = SECURITY_MAX_SID_SIZE;
    // SAFETY: aligned owned storage is sized to the SDK ceiling and retained with the profile.
    if unsafe {
        CreateWellKnownSid(
            kind,
            null_mut(),
            storage.as_mut_ptr().cast::<c_void>(),
            &mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(storage)
}

pub(super) fn hresult(result: i32) -> io::Result<()> {
    if result >= 0 {
        Ok(())
    } else if (result as u32 >> 16) & 0x1fff == 7 {
        Err(io::Error::from_raw_os_error(result & 0xffff))
    } else {
        Err(io::Error::other(format!(
            "Windows sandbox API failed (HRESULT {result:#x})"
        )))
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
