//! Actual binary observation retention. PNG bytes are preserved exactly in private CAS;
//! source metadata is a typed derivative of the retained image receipt. Only free text is scrubbed.
use super::{ArtifactSchema, ArtifactStoreError, DurableArtifactStore};
use iteron_protocol::{ToolUse, client_artifact::ClientArtifactDescriptorV1};
use iteron_tools::CapturedToolImage;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct ViewportImageObservationV1 {
    schema: &'static str,
    source_event_seq: u64,
    tool_use_id_display: String,
    tool_use_id_sha256: String,
    tool_name: &'static str,
    observed_unix_ms: u64,
    source_url_sha256: String,
    scope: &'static str,
    evidence_source: &'static str,
    width: u32,
    height: u32,
    binary_redaction: &'static str,
    retained_image: ClientArtifactDescriptorV1,
}

impl DurableArtifactStore {
    pub(crate) fn publish_tool_image(
        &self,
        source_event_seq: u64,
        call: &ToolUse,
        image: &CapturedToolImage,
    ) -> Result<ClientArtifactDescriptorV1, ArtifactStoreError> {
        let observation = image.observation().ok_or(ArtifactStoreError::Unavailable)?;
        if call.id.is_empty() || call.id.len() > 512 {
            return Err(ArtifactStoreError::InvalidRequest);
        }
        let tool_name = match call.name.as_str() {
            "browser" => "browser",
            "computer" => "computer",
            "desktop" => "desktop",
            _ => return Err(ArtifactStoreError::InvalidRequest),
        };
        if (call.name == "desktop")
            != (observation.scope()
                == iteron_protocol::tool_image::ToolImageScopeV1::NativeMacDesktop)
        {
            return Err(ArtifactStoreError::InvalidRequest);
        }
        let png = self.publish_bytes(
            source_event_seq,
            ArtifactSchema::ViewportImage,
            image.bytes(),
            &[],
            &[],
        )?;
        if png.artifact_id != image.sha256() || png.mime_type != image.media_type() {
            return Err(ArtifactStoreError::Corrupt);
        }
        let metadata = ViewportImageObservationV1 {
            schema: "iteron.viewport-image-observation.v1",
            source_event_seq,
            tool_use_id_display: iteron_record::redact::scrub(&call.id),
            tool_use_id_sha256: hex::encode(Sha256::digest(call.id.as_bytes())),
            tool_name,
            observed_unix_ms: observation.observed_unix_ms(),
            source_url_sha256: hex::encode(Sha256::digest(observation.source_url().as_bytes())),
            scope: observation.execution_scope(),
            evidence_source: observation.evidence_source(),
            width: image.width(),
            height: image.height(),
            binary_redaction: "not_applied",
            retained_image: png.clone(),
        };
        let served =
            serde_json::to_string(&metadata).map_err(|_| ArtifactStoreError::InvalidRequest)?;
        // The dependency writer revalidates this exact retained descriptor under its lock.
        // Generic whole-JSON scrubbing would corrupt these structural hashes and locators.
        self.publish_served(
            source_event_seq,
            ArtifactSchema::ViewportImageObservation,
            &served,
            &[],
            &[png],
        )
    }
}
