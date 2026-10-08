use super::{Publication, StorageError, leaf};
use iteron_support::durable_windows_state::{
    WindowsStateError, WindowsWorkspacePublisher, WindowsWorkspaceReader, WorkspacePublishError,
};
use std::path::{Path, PathBuf};
pub(crate) struct NativeDirectory {
    reader: WindowsWorkspaceReader,
    path: PathBuf,
    publisher: Option<WindowsWorkspacePublisher>,
}
impl NativeDirectory {
    pub(crate) fn open(path: &Path) -> Result<Self, StorageError> {
        Ok(Self {
            reader: WindowsWorkspaceReader::open(path).map_err(|_| StorageError::Unavailable)?,
            path: path.into(),
            publisher: None,
        })
    }
    pub(crate) fn child(&self, name: &str, create: bool) -> Result<Option<Self>, StorageError> {
        leaf(name)?;
        let publisher = if create {
            let root;
            let parent = if let Some(publisher) = &self.publisher {
                publisher
            } else {
                root = WindowsWorkspacePublisher::open(&self.path)
                    .map_err(|_| StorageError::Unavailable)?;
                &root
            };
            Some(
                parent
                    .open_or_create_child(name)
                    .map_err(|error| match error {
                        WindowsStateError::OutcomeUnknown => StorageError::PublicationUnknown,
                        _ => StorageError::Unavailable,
                    })?
                    .0,
            )
        } else {
            None
        };
        let reader = self.reader.open_child(name).map_err(|_| {
            if create {
                StorageError::PublicationUnknown
            } else {
                StorageError::Unavailable
            }
        })?;
        match reader {
            Some(reader) => Ok(Some(Self {
                reader,
                path: self.path.join(name),
                publisher,
            })),
            None if create => Err(StorageError::PublicationUnknown),
            None => Ok(None),
        }
    }
    pub(crate) fn read(&self, name: &str, limit: usize) -> Result<Vec<u8>, StorageError> {
        leaf(name)?;
        self.reader
            .read_leaf(name, limit)
            .map_err(|_| StorageError::Unavailable)
    }
    pub(crate) fn list(&self, limit: usize) -> Result<(Vec<(String, bool)>, bool), StorageError> {
        self.reader
            .list(limit)
            .map_err(|_| StorageError::Unavailable)
    }
    pub(crate) fn publish(&self, name: &str, bytes: &[u8]) -> Publication {
        let Some(publisher) = &self.publisher else {
            return Publication::NotPublished;
        };
        if leaf(name).is_err() {
            return Publication::NotPublished;
        }
        let mut nonce = [0u8; 16];
        if getrandom::fill(&mut nonce).is_err() {
            return Publication::NotPublished;
        }
        match publisher.publish(name, bytes, nonce) {
            Ok(()) => Publication::Created,
            Err(WorkspacePublishError::Exists) => Publication::Existing,
            Err(WorkspacePublishError::NotPublished) => Publication::NotPublished,
            Err(WorkspacePublishError::OutcomeUnknown) => Publication::Unknown,
        }
    }
}
