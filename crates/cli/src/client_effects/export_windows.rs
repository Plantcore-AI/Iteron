//! Local NTFS descriptor-relative output. Only the native support owner touches handles/ACLs.
use super::{
    CollisionPolicy, ExportError, MAX_TRANSCRIPT_EXPORT_BYTES, MAX_VERSION_ATTEMPTS,
    parse_relative, versioned_leaf,
};
use iteron_support::durable_windows_state::{WindowsWorkspacePublisher, WorkspacePublishError};
use std::path::{Path, PathBuf};

pub(super) fn export_bytes(
    workspace: &Path,
    requested: &str,
    bytes: &[u8],
    collision: CollisionPolicy,
) -> Result<PathBuf, ExportError> {
    if bytes.len() > MAX_TRANSCRIPT_EXPORT_BYTES {
        return Err(ExportError::known(
            "transcript export exceeds its byte bound",
        ));
    }
    let (parents, leaf) = parse_relative(requested).map_err(ExportError::known)?;
    let mut parent = workspace.to_owned();
    for component in &parents {
        parent.push(component);
    }
    // The native owner pins the complete absolute chain; no canonicalization launders a reparse.
    let publisher = WindowsWorkspacePublisher::open(&parent).map_err(|_| {
        ExportError::known("export requires an accessible ordinary local NTFS directory")
    })?;
    let attempts = match collision {
        CollisionPolicy::Refuse => 1,
        CollisionPolicy::Versioned => MAX_VERSION_ATTEMPTS,
    };
    for attempt in 1..=attempts {
        let candidate = versioned_leaf(&leaf, attempt);
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| ExportError::known("native staging nonce is unavailable"))?;
        match publisher.publish(&candidate, bytes, nonce) {
            Ok(()) => return Ok(parent.join(candidate)),
            Err(WorkspacePublishError::Exists) if collision == CollisionPolicy::Versioned => {
                continue;
            }
            Err(WorkspacePublishError::Exists) => {
                return Err(ExportError::known(
                    "export target already exists; choose a new path",
                ));
            }
            Err(WorkspacePublishError::NotPublished) => {
                return Err(ExportError::known("native export was not published"));
            }
            Err(WorkspacePublishError::OutcomeUnknown) => {
                return Err(ExportError::unknown(
                    "native export was dispatched; target/staging publication or durability is unknown",
                ));
            }
        }
    }
    Err(ExportError::known(
        "could not allocate a unique export filename within 100 attempts",
    ))
}
