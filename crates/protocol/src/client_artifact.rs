//! Bounded, permission-scoped artifacts published to ordinary clients.

use crate::SessionId;
use serde::{Deserialize, Serialize};

pub const CLIENT_ARTIFACT_VERSION: u32 = 1;
pub const MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientArtifactCommandV1 {
    List {
        thread_id: SessionId,
    },
    Read {
        thread_id: SessionId,
        artifact_id: String,
        offset: u64,
        max_bytes: u32,
    },
}

impl ClientArtifactCommandV1 {
    pub fn thread_id(&self) -> &SessionId {
        match self {
            Self::List { thread_id } | Self::Read { thread_id, .. } => thread_id,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if let Self::Read {
            artifact_id,
            max_bytes,
            ..
        } = self
        {
            if artifact_id.len() != 64
                || !artifact_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err("artifact identity must be a content SHA-256");
            }
            if *max_bytes == 0 || *max_bytes as usize > MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES {
                return Err("artifact download chunk exceeds its byte limit");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientArtifactDescriptorV1 {
    pub artifact_id: String,
    pub schema: String,
    pub mime_type: String,
    pub bytes: u64,
    pub complete: bool,
    pub required_capability: crate::Capability,
    /// First retained publication's source. `retained_owner_manifest` provenance names the
    /// runtime rollout sequence; resident event provenance names the public event sequence.
    /// Byte-identical republication preserves this source and schema; this is not a later
    /// producer receipt or an assertion that the current operation created these bytes.
    pub source_event_seq: u64,
}
