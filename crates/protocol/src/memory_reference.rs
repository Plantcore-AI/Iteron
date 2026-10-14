//! Content-free admission intent for a real host-resolved reference. This is not a consumed
//! provider receipt, instruction approval, or replacement for historical ContextInjection.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryReferenceAdmissionV1 {
    pub version: u32,
    pub deleted: bool,
    pub record_id: String,
    pub record_revision: u64,
    pub record_sha256: String,
    pub workspace_sha256: String,
    pub source_sha256: String,
    pub body_sha256: String,
    pub message_sha256: String,
}
impl MemoryReferenceAdmissionV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || self.record_revision == 0
            || self.record_id.is_empty()
            || self.record_id.len() > 128
            || !self
                .record_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || [
                &self.record_sha256,
                &self.workspace_sha256,
                &self.source_sha256,
                &self.body_sha256,
                &self.message_sha256,
            ]
            .iter()
            .any(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
        {
            return Err("invalid memory reference admission");
        }
        Ok(())
    }
}
