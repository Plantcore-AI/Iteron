//! Descriptor-source, create-only APFS publication. No workspace staging pathname is created.
//! Apple documents atomic fclonefileat and EEXIST preservation:
//! https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/clonefile.2
//! A native tmpfile must be a held, unlinked, current-user regular inode on the destination volume.
//! Unsupported/cross-volume clone is an explicit prepublication refusal, never a rename fallback.
use super::capability_fs;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::MetadataExt as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteError {
    Exists,
    Known,
    OutcomeUnknown,
}

fn anonymous_source(parent: &File) -> io::Result<File> {
    // SAFETY: tmpfile returns a native stream owner or NULL. It unlinks its backing name; we
    // verify that fact before writing transcript bytes and retain only a CLOEXEC duplicate fd.
    let stream = unsafe { libc::tmpfile() };
    if stream.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the returned stream stays live through fileno/dup/fclose; only the duplicate is owned
    // by File. Closing the empty stdio stream cannot delete a workspace-controlled pathname.
    let fd = unsafe { libc::fcntl(libc::fileno(stream), libc::F_DUPFD_CLOEXEC, 0) };
    unsafe {
        libc::fclose(stream);
    }
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned exactly one new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 0
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.dev() != parent.metadata()?.dev()
    {
        return Err(io::Error::other(
            "anonymous source is not a same-volume private regular inode",
        ));
    }
    // SAFETY: private held inode; restrict access before bytes are written.
    if unsafe { libc::fchmod(fd, 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}
fn full_sync(file: &File) -> io::Result<()> {
    file.sync_all()?;
    // SAFETY: live file descriptor and Apple's documented full storage-cache barrier.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn write_exclusive(
    parent: &File,
    leaf: &str,
    bytes: &[u8],
    before_publish: &mut dyn FnMut(),
) -> Result<(), WriteError> {
    let name = CString::new(leaf).map_err(|_| WriteError::Known)?;
    let mut source = anonymous_source(parent).map_err(|_| WriteError::Known)?;
    source
        .write_all(bytes)
        .and_then(|_| full_sync(&source))
        .map_err(|_| WriteError::Known)?;
    before_publish();
    // SAFETY: source is the held unlinked inode; destination is one bounded component relative
    // to a retained no-follow directory. Flags0 never replace an existing object or copy ACLs.
    if unsafe { libc::fclonefileat(source.as_raw_fd(), parent.as_raw_fd(), name.as_ptr(), 0) } != 0
    {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            WriteError::Exists
        } else {
            WriteError::Known
        });
    }
    // The clone has already published. All later verification/durability failures are Unknown;
    // no pathname unlink tries to undo a file another writer might have replaced.
    let mut published = capability_fs::open_regular_nonblocking(parent, leaf)
        .map_err(|_| WriteError::OutcomeUnknown)?;
    let metadata = published
        .metadata()
        .map_err(|_| WriteError::OutcomeUnknown)?;
    if metadata.len() != bytes.len() as u64 {
        return Err(WriteError::OutcomeUnknown);
    }
    let mut observed = Vec::with_capacity(bytes.len());
    Read::by_ref(&mut published)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut observed)
        .map_err(|_| WriteError::OutcomeUnknown)?;
    if observed != bytes {
        return Err(WriteError::OutcomeUnknown);
    }
    parent
        .sync_all()
        .and_then(|_| full_sync(&published))
        .map_err(|_| WriteError::OutcomeUnknown)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_anonymous_descriptor_clone_is_complete_and_create_only() {
        let raw = std::env::temp_dir().join(format!(
            "iteron-apfs-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&raw).unwrap();
        let root = std::fs::canonicalize(&raw).unwrap(); // fixture only: macOS /var alias
        let binding = capability_fs::RootBinding::open(&root).unwrap();
        let bytes = vec![b'x'; 300_000];
        let mut check = || {
            assert!(
                std::fs::read_dir(&root).unwrap().next().is_none(),
                "the complete staged source has no reachable workspace name"
            )
        };
        write_exclusive(binding.root(), "complete.md", &bytes, &mut check).unwrap();
        assert_eq!(std::fs::read(root.join("complete.md")).unwrap(), bytes);
        assert_eq!(
            write_exclusive(binding.root(), "complete.md", b"replacement", &mut || {}),
            Err(WriteError::Exists)
        );
        assert_eq!(std::fs::read(root.join("complete.md")).unwrap(), bytes);
        std::fs::remove_dir_all(raw).unwrap();
    }
    #[test]
    fn source_inode_is_unlinked_private_regular_and_on_the_actual_destination_volume() {
        let raw = std::env::temp_dir().join(format!(
            "iteron-apfs-source-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&raw).unwrap();
        let root = std::fs::canonicalize(&raw).unwrap();
        let binding = capability_fs::RootBinding::open(&root).unwrap();
        let file = anonymous_source(binding.root()).unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.nlink(), 0);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.dev(), binding.root().metadata().unwrap().dev());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        drop(file);
        std::fs::remove_dir_all(raw).unwrap();
    }
}
