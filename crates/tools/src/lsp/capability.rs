//! Descriptor-relative Linux workspace admission for live language-server effects.
//!
//! Pathnames are used only to select the initial object and to prove that the operator-visible
//! path still names it. Every source component and the workspace itself remain held by a file
//! descriptor for the complete query. The sandbox binds the held workspace descriptor, not a
//! pathname that can be substituted after admission.

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

/// Verdict when the kernel cannot answer whether two descriptors name the same object. An
/// unanswerable identity question is not proof of identity, so the binding is treated as no
/// longer visible rather than silently accepted.
const IDENTITY_UNPROVABLE: bool = false;
const MAX_CAPABILITY_PATH_BYTES: usize = 4 * 1024;
const MAX_CAPABILITY_COMPONENTS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileStamp {
    device: u64,
    inode: u64,
    len: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileStamp {
    pub(super) fn capture(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        // `metadata.is_file()` is exactly `mode & S_IFMT == S_IFREG`, and unlike the raw comparison
        // it does not depend on the width of `libc::mode_t`, which is `u16` on macOS and `u32` on
        // Linux -- the `u32::from` this replaces was required on one and a clippy error on the
        // other.
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source is not a regular file",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

#[derive(Debug)]
pub(super) struct RootBinding {
    anchor: File,
    components: Vec<OsString>,
    chain: Vec<File>,
}

#[derive(Debug)]
pub(super) struct SourceBinding {
    components: Vec<OsString>,
    parents: Vec<File>,
    leaf: File,
    stamp: FileStamp,
}

impl RootBinding {
    pub(super) fn open(canonical_path: &Path) -> io::Result<Self> {
        if !canonical_path.is_absolute()
            || canonical_path.as_os_str().as_bytes().len() > MAX_CAPABILITY_PATH_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "workspace path is not a bounded absolute path",
            ));
        }
        let mut components = Vec::new();
        for component in canonical_path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(component) => {
                    components.push(component.to_os_string());
                    if components.len() > MAX_CAPABILITY_COMPONENTS {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "workspace path has too many components",
                        ));
                    }
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "workspace path contains a non-ordinary component",
                    ));
                }
            }
        }

        let anchor = open_absolute_directory(Path::new("/"))?;
        let mut chain = Vec::with_capacity(components.len());
        let mut current = anchor.try_clone()?;
        for component in &components {
            current = open_directory_at(&current, component)?;
            chain.push(current.try_clone()?);
        }
        Ok(Self {
            anchor,
            components,
            chain,
        })
    }

    pub(super) fn root(&self) -> &File {
        self.chain.last().unwrap_or(&self.anchor)
    }

    pub(super) fn bind_source(&self, relative: &Path) -> io::Result<SourceBinding> {
        let components = relative_components(relative)?;
        let (leaf, parents) = components
            .split_last()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source path is empty"))?;
        let mut parent = self.root().try_clone()?;
        let mut parent_chain = Vec::with_capacity(parents.len());
        for component in parents {
            parent = open_directory_at(&parent, component)?;
            parent_chain.push(parent.try_clone()?);
        }
        let leaf = open_regular_nonblocking_at(&parent, leaf)?;
        let stamp = FileStamp::capture(&leaf)?;
        Ok(SourceBinding {
            components,
            parents: parent_chain,
            leaf,
            stamp,
        })
    }

    pub(super) fn still_visible(&self) -> bool {
        let Ok(mut current) = self.anchor.try_clone() else {
            return false;
        };
        for (component, expected) in self.components.iter().zip(&self.chain) {
            let Ok(reopened) = open_directory_at(&current, component) else {
                return false;
            };
            if !same_directory(expected, &reopened).unwrap_or(IDENTITY_UNPROVABLE) {
                return false;
            }
            current = reopened;
        }
        true
    }
}

impl SourceBinding {
    pub(super) fn file(&self) -> io::Result<File> {
        self.leaf.try_clone()
    }

    pub(super) fn stamp(&self) -> &FileStamp {
        &self.stamp
    }

    pub(super) fn still_visible(&self, root: &RootBinding) -> bool {
        if !root.still_visible() {
            return false;
        }
        let Some((leaf_name, parent_names)) = self.components.split_last() else {
            return false;
        };
        let mut current = match root.root().try_clone() {
            Ok(current) => current,
            Err(_) => return false,
        };
        for (name, expected) in parent_names.iter().zip(&self.parents) {
            let Ok(reopened) = open_directory_at(&current, name) else {
                return false;
            };
            if !same_directory(expected, &reopened).unwrap_or(IDENTITY_UNPROVABLE) {
                return false;
            }
            current = reopened;
        }
        let Ok(leaf) = open_regular_nonblocking_at(&current, leaf_name) else {
            return false;
        };
        same_file(&self.leaf, &leaf).unwrap_or(IDENTITY_UNPROVABLE)
            && FileStamp::capture(&leaf).is_ok_and(|stamp| stamp == self.stamp)
    }
}

fn relative_components(path: &Path) -> io::Result<Vec<OsString>> {
    if path.is_absolute() || path.as_os_str().as_bytes().len() > MAX_CAPABILITY_PATH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source path is not a bounded relative path",
        ));
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(component) => {
                components.push(component.to_os_string());
                if components.len() > MAX_CAPABILITY_COMPONENTS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "source path has too many components",
                    ));
                }
            }
            Component::CurDir => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "source path contains a non-ordinary component",
                ));
            }
        }
    }
    Ok(components)
}

fn c_string(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn open_absolute_directory(path: &Path) -> io::Result<File> {
    let path = c_string(path.as_os_str())?;
    // SAFETY: `path` is a live NUL-terminated string; successful `open` returns one owned fd.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_file(descriptor)
}

fn open_directory_at(parent: &File, component: &OsStr) -> io::Result<File> {
    let component = c_string(component)?;
    // SAFETY: the retained parent fd and NUL-terminated component remain live for the call.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_file(descriptor)
}

fn open_regular_nonblocking_at(parent: &File, leaf: &OsStr) -> io::Result<File> {
    let leaf = c_string(leaf)?;
    // `O_NONBLOCK` is load-bearing for a leaf swapped to a FIFO/device between observations.
    // SAFETY: the retained parent fd and NUL-terminated leaf remain live for the call.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    let file = owned_file(descriptor)?;
    let _ = FileStamp::capture(&file)?;
    Ok(file)
}

fn owned_file(descriptor: libc::c_int) -> io::Result<File> {
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a non-negative result from `open`/`openat` is one newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn same_directory(left: &File, right: &File) -> io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn same_file(left: &File, right: &File) -> io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(test)]
mod tests {
    use super::{FileStamp, RootBinding};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant, SystemTime};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "iteron-lsp-capability-{label}-{}-{nonce:x}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn fifo_leaf_refuses_without_waiting_for_a_writer() {
        let fixture = Fixture::new("fifo");
        let fifo = fixture.path().join("source.rs");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the fixture path is a live NUL-terminated string and names no existing object.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let canonical = fixture.path().canonicalize().unwrap();
        let binding = RootBinding::open(&canonical).unwrap();
        let started = Instant::now();
        assert!(binding.bind_source(Path::new("source.rs")).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn leaf_replacement_invalidates_the_admitted_identity() {
        let fixture = Fixture::new("leaf-swap");
        let source = fixture.path().join("source.rs");
        std::fs::write(&source, "fn before() {}\n").unwrap();
        let canonical = fixture.path().canonicalize().unwrap();
        let binding = RootBinding::open(&canonical).unwrap();
        let admitted = binding.bind_source(Path::new("source.rs")).unwrap();
        std::fs::write(fixture.path().join("replacement"), "fn after() {}\n").unwrap();
        std::fs::rename(fixture.path().join("replacement"), &source).unwrap();
        assert!(!admitted.still_visible(&binding));
    }

    #[test]
    fn workspace_replacement_invalidates_the_retained_root_chain() {
        let fixture = Fixture::new("root-swap");
        let workspace = fixture.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("source.rs"), "fn before() {}\n").unwrap();
        let canonical_workspace = workspace.canonicalize().unwrap();
        let binding = RootBinding::open(&canonical_workspace).unwrap();
        let admitted = binding.bind_source(Path::new("source.rs")).unwrap();
        std::fs::rename(&workspace, fixture.path().join("detached")).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("source.rs"), "fn replacement() {}\n").unwrap();
        assert!(!binding.still_visible());
        assert!(!admitted.still_visible(&binding));
    }

    #[test]
    fn parent_replacement_with_the_same_hardlinked_leaf_is_detected() {
        let fixture = Fixture::new("parent-hardlink-swap");
        let workspace = fixture.path().join("workspace");
        std::fs::create_dir_all(workspace.join("src")).unwrap();
        std::fs::write(workspace.join("src/source.rs"), "fn same_leaf() {}\n").unwrap();
        let canonical_workspace = workspace.canonicalize().unwrap();
        let binding = RootBinding::open(&canonical_workspace).unwrap();
        let admitted = binding.bind_source(Path::new("src/source.rs")).unwrap();
        std::fs::create_dir(workspace.join("replacement")).unwrap();
        std::fs::hard_link(
            workspace.join("src/source.rs"),
            workspace.join("replacement/source.rs"),
        )
        .unwrap();
        std::fs::rename(workspace.join("src"), workspace.join("detached-src")).unwrap();
        std::fs::rename(workspace.join("replacement"), workspace.join("src")).unwrap();
        assert!(
            FileStamp::capture(&admitted.file().unwrap()).is_ok(),
            "the held leaf itself remains valid"
        );
        assert!(
            !admitted.still_visible(&binding),
            "the substituted relative parent must invalidate the source binding even for a hardlink"
        );
    }
}
