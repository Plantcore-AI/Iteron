//! Owner of bounded resident artifact bytes. Client IDs never resolve arbitrary file locators.
//!
//! Only redacted bytes observed on the session's public event boundary are admitted. The catalog
//! belongs to one thread, is cleared on adoption, and explicitly reports truncation and eviction.

use std::collections::{BTreeMap, VecDeque};

use base64::Engine;
use iteron_protocol::client_artifact::{
    CLIENT_ARTIFACT_VERSION, ClientArtifactCommandV1, ClientArtifactDescriptorV1,
};
use iteron_protocol::{Capability, SessionId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_ARTIFACT_BYTES: usize = 256 * 1024;
const MAX_CATALOG_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 128;

#[derive(Default)]
pub(super) struct ArtifactCatalog {
    thread: Option<SessionId>,
    entries: BTreeMap<String, Entry>,
    order: VecDeque<String>,
    bytes: usize,
    evicted: u64,
}

struct Entry {
    descriptor: ClientArtifactDescriptorV1,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for ArtifactCatalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArtifactCatalog")
            .field("entries", &self.entries.len())
            .field("bytes", &self.bytes)
            .field("evicted", &self.evicted)
            .finish_non_exhaustive()
    }
}

impl ArtifactCatalog {
    pub(super) fn bind_thread(&mut self, thread: &SessionId) {
        if self.thread.as_ref() != Some(thread) {
            *self = Self {
                thread: Some(thread.clone()),
                ..Self::default()
            };
        }
    }

    pub(super) fn publish(&mut self, seq: u64, schema: &str, mime: &str, content: &[u8]) {
        if self.thread.is_none() {
            return;
        }
        let complete = content.len() <= MAX_ARTIFACT_BYTES;
        let bytes = content[..content.len().min(MAX_ARTIFACT_BYTES)].to_vec();
        let artifact_id = hex::encode(Sha256::digest(&bytes));
        if self.entries.contains_key(&artifact_id) {
            return;
        }
        while self.entries.len() >= MAX_ARTIFACTS
            || self.bytes.saturating_add(bytes.len()) > MAX_CATALOG_BYTES
        {
            let Some(id) = self.order.pop_front() else {
                return;
            };
            if let Some(old) = self.entries.remove(&id) {
                self.bytes -= old.bytes.len();
                self.evicted = self.evicted.saturating_add(1);
            }
        }
        let descriptor = ClientArtifactDescriptorV1 {
            artifact_id: artifact_id.clone(),
            schema: schema.to_owned(),
            mime_type: mime.to_owned(),
            bytes: bytes.len() as u64,
            complete,
            required_capability: Capability::ReadOnly,
            source_event_seq: seq,
        };
        self.bytes += bytes.len();
        self.order.push_back(artifact_id.clone());
        self.entries
            .insert(artifact_id, Entry { descriptor, bytes });
    }

    pub(super) fn read(&self, command: ClientArtifactCommandV1) -> Value {
        if let Err(reason) = command.validate() {
            return refused(reason);
        }
        if self.thread.as_ref() != Some(command.thread_id()) {
            return refused("artifact thread does not match the authenticated resident session");
        }
        match command {
            ClientArtifactCommandV1::List { .. } => json!({
                "type":"artifacts_v1", "contract_version":CLIENT_ARTIFACT_VERSION,
                "artifacts":self.order.iter().filter_map(|id| self.entries.get(id).map(|entry| &entry.descriptor)).collect::<Vec<_>>(),
                "evicted_artifacts":self.evicted, "retention":"resident_thread",
            }),
            ClientArtifactCommandV1::Read {
                artifact_id,
                offset,
                max_bytes,
                ..
            } => {
                let Some(entry) = self.entries.get(&artifact_id) else {
                    return refused("artifact unavailable or expired");
                };
                if entry.descriptor.required_capability != Capability::ReadOnly {
                    return refused(
                        "artifact requires authority unavailable on this read capability",
                    );
                }
                let Ok(start) = usize::try_from(offset) else {
                    return refused("artifact offset is outside its content");
                };
                if start > entry.bytes.len() {
                    return refused("artifact offset is outside its content");
                }
                let end = start
                    .saturating_add(max_bytes as usize)
                    .min(entry.bytes.len());
                json!({
                    "type":"artifact_chunk_v1", "contract_version":CLIENT_ARTIFACT_VERSION,
                    "artifact":entry.descriptor, "offset":offset, "next_offset":end,
                    "eof":end == entry.bytes.len(),
                    "content_base64":base64::engine::general_purpose::STANDARD.encode(&entry.bytes[start..end]),
                })
            }
        }
    }
}

fn refused(reason: &str) -> Value {
    json!({"type":"artifact_refused_v1", "contract_version":CLIENT_ARTIFACT_VERSION, "reason":reason})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_published_session_bytes_are_downloadable_and_adoption_revokes_handles() {
        let thread = SessionId("a".into());
        let mut catalog = ArtifactCatalog::default();
        catalog.bind_thread(&thread);
        catalog.publish(1, "tool_output", "text/plain", b"result");
        let id = hex::encode(Sha256::digest(b"result"));
        let read = |thread_id| ClientArtifactCommandV1::Read {
            thread_id,
            artifact_id: id.clone(),
            offset: 0,
            max_bytes: 64,
        };
        assert_eq!(
            catalog.read(read(thread.clone()))["content_base64"],
            "cmVzdWx0"
        );
        assert_eq!(
            catalog.read(read(SessionId("b".into())))["type"],
            "artifact_refused_v1"
        );
        catalog.bind_thread(&SessionId("b".into()));
        assert_eq!(
            catalog.read(read(SessionId("b".into())))["type"],
            "artifact_refused_v1"
        );
        assert_eq!(
            catalog.read(ClientArtifactCommandV1::Read {
                thread_id: SessionId("b".into()),
                artifact_id: "../../etc/passwd".into(),
                offset: 0,
                max_bytes: 64
            })["type"],
            "artifact_refused_v1"
        );
    }

    #[test]
    fn catalog_and_chunk_budgets_report_truncation_and_eviction() {
        let thread = SessionId("a".into());
        let mut catalog = ArtifactCatalog::default();
        catalog.bind_thread(&thread);
        for seq in 0..32 {
            catalog.publish(
                seq,
                "tool_output",
                "application/octet-stream",
                &vec![seq as u8; MAX_ARTIFACT_BYTES + 1],
            );
        }
        let listing = catalog.read(ClientArtifactCommandV1::List {
            thread_id: thread.clone(),
        });
        assert_eq!(
            listing["artifacts"].as_array().unwrap().len(),
            MAX_CATALOG_BYTES / MAX_ARTIFACT_BYTES
        );
        assert_eq!(listing["evicted_artifacts"], 16);
        assert_eq!(listing["artifacts"][0]["complete"], false);
        assert!(catalog.bytes <= MAX_CATALOG_BYTES);
        let id = listing["artifacts"][0]["artifact_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            catalog.read(ClientArtifactCommandV1::Read {
                thread_id: thread,
                artifact_id: id,
                offset: u64::MAX,
                max_bytes: 1
            })["type"],
            "artifact_refused_v1"
        );
    }
}
