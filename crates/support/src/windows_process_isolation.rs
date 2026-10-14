//! A sealed OS isolation lease for one actual Windows native launch.
//! The Job owner retains this through tree exit and retires it in its bounded custody worker.

mod acl;
mod acl_lock;
mod profile;
mod token;
mod tree;

use acl::BoundObject;
use profile::Profile;
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::BorrowedHandle;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;

/// Only a trusted confinement host constructs this. It is not a wire command or saved grant.
pub struct WindowsIsolationPolicy<'a> {
    pub workspace: &'a Path,
    pub scratch: &'a Path,
    pub executable: &'a Path,
    /// Already-filtered immutable environment from the actual host confinement snapshot.
    pub environment: &'a [(OsString, OsString)],
    /// Exact writable subtrees inside workspace; an empty list makes workspace read-only.
    pub write_roots: &'a [PathBuf],
    /// Explicit host-approved read roots. Never populated from a model's launch payload.
    pub read_only_roots: &'a [PathBuf],
    pub allow_egress: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Reserved,
    Installing,
    Installed,
    Retired,
}
struct Grant {
    bound: BoundObject,
    writable: bool,
    manage_acl: bool,
    installed: bool,
}
struct State {
    phase: Phase,
    grants: Vec<Grant>,
    root_count: usize,
    cleanup_discovered: bool,
}

pub struct WindowsProcessIsolation {
    profile: Profile,
    state: Mutex<State>,
    environment: Box<[(OsString, OsString)]>,
    executable_index: usize,
    write_roots: Box<[PathBuf]>,
    scratch: PathBuf,
}

/// Cleanup authority for one physical launch. Cloning the public prepared Arc never clones this
/// reservation; a second launch cannot retire permissions owned by a running first launch.
pub(crate) struct WindowsIsolationLaunch {
    isolation: Arc<WindowsProcessIsolation>,
}

impl WindowsIsolationLaunch {
    pub(crate) fn isolation(&self) -> &WindowsProcessIsolation {
        &self.isolation
    }

    /// Called in the pre-admitted physical worker, before native process creation.
    pub(crate) fn install(&self) -> io::Result<()> {
        self.isolation.install_reserved()
    }

    /// The physical owner first proves no process was created, or observes Job0 and transport
    /// closure. A live Arc holder cannot manufacture the non-Clone reservation required here.
    pub(crate) fn retire_after_terminal(&self) -> io::Result<()> {
        self.isolation.retire_reserved()
    }
}

impl std::fmt::Debug for WindowsProcessIsolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsProcessIsolation")
            .field("backend", &"windows-lpac")
            .finish_non_exhaustive()
    }
}

impl WindowsProcessIsolation {
    /// Bind paths and derive a new package identity. This creates neither a profile store nor
    /// permission grants. The reserved physical worker installs them immediately before launch.
    pub fn prepare(policy: WindowsIsolationPolicy<'_>) -> io::Result<Arc<Self>> {
        Self::prepare_bound(policy, None)
    }

    /// Preserve the actual directory capability admitted by a workspace-scoped helper such as
    /// LSP. A different pathname or directory object never substitutes for that retained File.
    pub fn prepare_from_workspace(
        policy: WindowsIsolationPolicy<'_>,
        workspace: &std::fs::File,
    ) -> io::Result<Arc<Self>> {
        Self::prepare_bound(policy, Some(workspace))
    }

    fn prepare_bound(
        policy: WindowsIsolationPolicy<'_>,
        workspace_file: Option<&std::fs::File>,
    ) -> io::Result<Arc<Self>> {
        validate_policy(&policy)?;
        let workspace = BoundObject::open(policy.workspace, true, true)?;
        if let Some(actual) = workspace_file {
            workspace.matches_file(actual)?;
        }
        let scratch = BoundObject::open(policy.scratch, true, true)?;
        let mut grants = vec![
            Grant {
                bound: workspace,
                writable: false,
                manage_acl: true,
                installed: false,
            },
            Grant {
                bound: scratch,
                writable: true,
                manage_acl: true,
                installed: false,
            },
        ];
        for root in policy.write_roots {
            if root == policy.workspace {
                grants[0].writable = true;
            } else {
                grants.push(Grant {
                    bound: BoundObject::open(root, true, true)?,
                    writable: true,
                    manage_acl: true,
                    installed: false,
                });
            }
        }
        for root in policy.read_only_roots {
            if !grants.iter().any(|grant| grant.bound.path() == root) {
                let existing = BoundObject::open(root, true, false)?;
                let (bound, manage_acl) = match BoundObject::open(root, true, true) {
                    Ok(bound) => (bound, true),
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        (existing, false)
                    }
                    Err(error) => return Err(error),
                };
                grants.push(Grant {
                    bound,
                    writable: false,
                    manage_acl,
                    installed: false,
                });
            }
        }
        // Operating-system images keep their existing protected ACLs. LPAC's actual token must
        // be able to load them; a failed native creation is a refusal, never an unconfined retry.
        let root_count = grants.len();
        let image = BoundObject::open(policy.executable, false, false)?;
        let system_image = is_system_image(image.path())?;
        let (image, manage_image_acl) = if system_image {
            (image, false)
        } else {
            match BoundObject::open(policy.executable, false, true) {
                Ok(bound) => (bound, true),
                // An ordinary host may execute a protected toolchain image without WRITE_DAC.
                // Keep its existing ACL; actual LPAC native creation must still authorize it.
                // This never supplies an unrestricted token or retries an unconfined process.
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => (image, false),
                Err(error) => return Err(error),
            }
        };
        let executable_index = grants.len();
        grants.push(Grant {
            bound: image,
            writable: false,
            manage_acl: manage_image_acl,
            installed: false,
        });
        let environment = policy.environment.to_vec().into_boxed_slice();
        let profile = Profile::prepare(policy.allow_egress)?;
        Ok(Arc::new(Self {
            profile,
            state: Mutex::new(State {
                phase: Phase::Prepared,
                grants,
                root_count,
                cleanup_discovered: false,
            }),
            environment,
            executable_index,
            write_roots: policy.write_roots.to_vec().into_boxed_slice(),
            scratch: policy.scratch.to_path_buf(),
        }))
    }

    pub(crate) fn security_capabilities(&self) -> &SECURITY_CAPABILITIES {
        self.profile.capabilities()
    }

    pub(crate) fn is_lpac(&self) -> bool {
        true
    }

    pub(crate) fn validate_scope_still_bound(&self) -> io::Result<()> {
        let state = self.lock()?;
        if state.phase == Phase::Retired {
            return Err(refused("Windows sandbox lease was retired"));
        }
        for grant in &state.grants {
            grant.bound.validate()?;
        }
        Ok(())
    }

    pub(crate) fn validate_launch(&self, executable: &Path, directory: &Path) -> io::Result<()> {
        let state = self.lock()?;
        if state.phase == Phase::Retired {
            return Err(refused("Windows sandbox lease was retired"));
        }
        state.grants[0].bound.matches(directory)?;
        state.grants[self.executable_index]
            .bound
            .matches(executable)?;
        Ok(())
    }

    pub(crate) fn validate_environment(
        &self,
        environment: &[(OsString, OsString)],
    ) -> io::Result<()> {
        if environment != self.environment.as_ref() {
            return Err(refused(
                "Windows sandbox launch environment differs from its host snapshot",
            ));
        }
        Ok(())
    }

    pub(crate) fn reserve_launch(self: &Arc<Self>) -> io::Result<WindowsIsolationLaunch> {
        let mut state = self.lock()?;
        if state.phase != Phase::Prepared {
            return Err(refused(
                "Windows sandbox lease already has a physical launch owner",
            ));
        }
        state.phase = Phase::Reserved;
        Ok(WindowsIsolationLaunch {
            isolation: self.clone(),
        })
    }

    fn install_reserved(&self) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.phase != Phase::Reserved {
            return Err(refused("Windows sandbox reservation cannot install twice"));
        }
        // Reserve before any fallible OS mutation. A failed install remains owned by this launch
        // and cannot be retried or borrowed by another launch while cleanup is outstanding.
        state.phase = Phase::Installing;
        let mut snapshot = tree::snapshot(
            &state.grants[..state.root_count]
                .iter()
                .filter(|grant| grant.manage_acl)
                .map(|grant| &grant.bound)
                .collect::<Vec<_>>(),
            false,
        )?;
        let known = state
            .grants
            .iter()
            .map(|grant| grant.bound.key())
            .collect::<std::collections::BTreeSet<_>>();
        for bound in snapshot.objects.drain(..) {
            if known.contains(&bound.key()) {
                continue;
            }
            let writable = bound.path().starts_with(&self.scratch)
                || self
                    .write_roots
                    .iter()
                    .any(|root| bound.path().starts_with(root));
            state.grants.push(Grant {
                bound,
                writable,
                manage_acl: true,
                installed: false,
            });
        }
        self.profile.activate()?;
        for grant in &mut state.grants {
            grant.bound.validate()?;
            if grant.manage_acl && !grant.installed {
                // Native ACL update failure may be ambiguous. Retain cleanup custody even then;
                // revoking this fresh SID is safe when the attempted grant was never installed.
                grant.installed = true;
                grant.bound.grant(self.profile.sid(), grant.writable)?;
            }
        }
        state.phase = Phase::Installed;
        Ok(())
    }

    pub(crate) fn verify_child(&self, process: BorrowedHandle<'_>) -> io::Result<()> {
        if self.lock()?.phase != Phase::Installed {
            return Err(refused("Windows process has no claimed sandbox lease"));
        }
        token::verify(&self.profile, process)
    }

    /// Only the actual native owner calls this after Job0 and pipe/console closure. There is no
    /// public caller-supplied boolean that can manufacture process terminal proof.
    fn retire_reserved(&self) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.phase == Phase::Retired {
            return Ok(());
        }
        // Child-created objects inherited this launch's SID. Enumerate their actual objects after
        // physical terminal proof, without following reparse points, before retiring the profile.
        // A failed/incomplete census remains retryable cleanup custody and never claims Retired.
        let mut snapshot =
            if !state.cleanup_discovered && state.grants.iter().any(|grant| grant.installed) {
                Some(tree::snapshot(
                    &state.grants[..state.root_count]
                        .iter()
                        .filter(|grant| grant.manage_acl)
                        .map(|grant| &grant.bound)
                        .collect::<Vec<_>>(),
                    true,
                )?)
            } else {
                None
            };
        if let Some(snapshot) = &mut snapshot {
            let known = state
                .grants
                .iter()
                .map(|grant| grant.bound.key())
                .collect::<std::collections::BTreeSet<_>>();
            for bound in snapshot.objects.drain(..) {
                if known.contains(&bound.key()) {
                    continue;
                }
                state.grants.push(Grant {
                    bound,
                    writable: false,
                    manage_acl: true,
                    installed: true,
                });
            }
        }
        state.cleanup_discovered = true;
        // Remove roots before children so inherited-permission reconciliation cannot reacquire
        // this SID from an already retired parent. Every successful removal is read back.
        for grant in &mut state.grants {
            if grant.installed {
                grant.bound.revoke(self.profile.sid())?;
                grant.installed = false;
            }
        }
        self.profile.retire()?;
        state.phase = Phase::Retired;
        state.grants.clear(); // release pins so the same custody owner can remove its scratch
        Ok(())
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("Windows sandbox lease owner is poisoned"))
    }
}

fn validate_policy(policy: &WindowsIsolationPolicy<'_>) -> io::Result<()> {
    if policy
        .write_roots
        .len()
        .saturating_add(policy.read_only_roots.len())
        > 128
    {
        return Err(refused(
            "Windows sandbox scope exceeds its root-count limit",
        ));
    }
    if policy.scratch == policy.workspace || policy.workspace.starts_with(policy.scratch) {
        return Err(refused(
            "Windows sandbox scratch cannot contain its workspace",
        ));
    }
    for root in policy.write_roots {
        if !root.starts_with(policy.workspace) {
            return Err(refused(
                "Windows sandbox writable subtree is outside the host workspace",
            ));
        }
    }
    if policy.environment.len() > 1_024 {
        return Err(refused(
            "Windows sandbox environment exceeds its entry limit",
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    let mut units = 0_usize;
    for (key, value) in policy.environment {
        let name = key
            .to_str()
            .ok_or_else(|| refused("Windows sandbox environment has an invalid key"))?;
        if name.is_empty() || name.contains(['=', '\0']) || !names.insert(name.to_ascii_uppercase())
        {
            return Err(refused(
                "Windows sandbox environment has an invalid or duplicate key",
            ));
        }
        for unit in key.encode_wide().chain(value.encode_wide()) {
            if unit == 0 {
                return Err(refused("Windows sandbox environment contains a null unit"));
            }
            units = units
                .checked_add(1)
                .ok_or_else(|| refused("Windows sandbox environment size overflow"))?;
            if units > 128 * 1024 {
                return Err(refused(
                    "Windows sandbox environment exceeds its aggregate limit",
                ));
            }
        }
    }
    Ok(())
}

fn is_system_image(path: &Path) -> io::Result<bool> {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut directory = vec![0_u16; 32_768];
    let length = unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) };
    if length == 0 || length as usize >= directory.len() {
        return Err(io::Error::last_os_error());
    }
    use std::os::windows::ffi::OsStringExt;
    let directory = PathBuf::from(OsString::from_wide(&directory[..length as usize]));
    // Both paths are resolved by the native filesystem to the same canonical spelling. A plain
    // C:\ path and its \\?\C:\ alias cannot misclassify a protected image and demand WRITE_DAC.
    // The caller already retains the executable and non-reparse ancestry before this lookup.
    Ok(path.canonicalize()?.starts_with(directory.canonicalize()?))
}

fn refused(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

#[cfg(test)]
mod tests;
