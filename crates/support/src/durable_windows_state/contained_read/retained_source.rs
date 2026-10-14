//! A retained ordinary source file. Parent/leaf handles exclude delete sharing and reparse opens;
//! a consumer reads the actual file with explicit offsets, never a later pathname replacement.
use super::{
    FileStamp, MAX_READER_BYTES, WindowsStateError, WindowsWorkspaceReader, local_ntfs, read_leaf,
    stamp,
};
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::FileExt;
use std::path::{Component, Path};

pub struct WindowsWorkspaceSource {
    _reader: WindowsWorkspaceReader,
    workspace: File,
    file: File,
    stamp: FileStamp,
}
impl std::fmt::Debug for WindowsWorkspaceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsWorkspaceSource")
            .finish_non_exhaustive()
    }
}
impl WindowsWorkspaceReader {
    pub fn bind_source(
        &self,
        relative: &Path,
    ) -> Result<WindowsWorkspaceSource, WindowsStateError> {
        if relative.is_absolute() || relative.as_os_str().encode_wide().take(4097).count() > 4096 {
            return Err(WindowsStateError::Unavailable);
        }
        let names = relative
            .components()
            .filter(|part| *part != Component::CurDir)
            .map(|part| match part {
                Component::Normal(name) => Ok(name),
                _ => Err(WindowsStateError::Unavailable),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if names.is_empty() || names.len() > 64 {
            return Err(WindowsStateError::Unavailable);
        }
        let workspace = self
            .directories
            .last()
            .ok_or(WindowsStateError::Unavailable)?
            .try_clone()
            .map_err(|_| WindowsStateError::Unavailable)?;
        let mut reader = Self {
            directories: self
                .directories
                .iter()
                .map(File::try_clone)
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|_| WindowsStateError::Unavailable)?,
        };
        for name in &names[..names.len() - 1] {
            let name = name.to_str().ok_or(WindowsStateError::Unavailable)?;
            reader = reader
                .open_child(name)?
                .ok_or(WindowsStateError::Unavailable)?;
        }
        let file = read_leaf(
            reader
                .directories
                .last()
                .ok_or(WindowsStateError::Unavailable)?,
            names[names.len() - 1],
        )?;
        local_ntfs(&file)?;
        let captured = stamp(&file, false)?;
        Ok(WindowsWorkspaceSource {
            _reader: reader,
            workspace,
            file,
            stamp: captured,
        })
    }
}
impl WindowsWorkspaceSource {
    /// The actual readonly workspace handle from which this source was bound. The sandbox verifies
    /// this identity before giving a child access; a path string cannot replace this capability.
    pub fn workspace(&self) -> &File {
        &self.workspace
    }
    pub fn byte_len(&self) -> u64 {
        (u64::from(self.stamp.size_hi) << 32) | u64::from(self.stamp.size_lo)
    }
    pub fn read_bounded(&self, limit: usize) -> Result<Vec<u8>, WindowsStateError> {
        let size = self.byte_len();
        if limit > MAX_READER_BYTES
            || size > limit as u64
            || stamp(&self.file, false)? != self.stamp
        {
            return Err(WindowsStateError::Unavailable);
        }
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            let available = (limit + 1 - bytes.len()).min(chunk.len());
            let count = self
                .file
                .seek_read(&mut chunk[..available], bytes.len() as u64)
                .map_err(|_| WindowsStateError::Unavailable)?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.len() > limit {
                return Err(WindowsStateError::Unavailable);
            }
        }
        if stamp(&self.file, false)? != self.stamp {
            return Err(WindowsStateError::Unavailable);
        }
        Ok(bytes)
    }
}
