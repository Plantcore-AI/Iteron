//! Typed native diff manifests preserve only validated retained structural references.
//! Arbitrary JSON and all free text continue through ordinary secret redaction.

use super::{ArtifactStoreError, ArtifactTextSchema, DurableArtifactStore};
use iteron_protocol::client_artifact::ClientArtifactDescriptorV1;
use iteron_tools::NativeMutationReceipt;
use serde::Serialize;

#[derive(Serialize)]
struct NativeDiffManifest {
    #[serde(rename = "type")]
    kind: &'static str,
    tool_use_id_display: String,
    tool: String,
    basis: &'static str,
    encoding: &'static str,
    redaction: &'static str,
    files: Vec<ServedDiffFile>,
}

#[derive(Serialize)]
struct ServedDiffFile {
    path: String,
    before: Option<ClientArtifactDescriptorV1>,
    after: ClientArtifactDescriptorV1,
}

impl DurableArtifactStore {
    pub(crate) fn publish_native_diff(
        &self,
        source: u64,
        receipt: &NativeMutationReceipt,
    ) -> Result<ClientArtifactDescriptorV1, ArtifactStoreError> {
        if source == 0
            || receipt.files().is_empty()
            || receipt.files().len() > 64
            || receipt.tool_use_id().is_empty()
            || receipt.tool_use_id().len() > 512
            || !matches!(receipt.tool_name(), "write_file" | "edit" | "apply_patch")
        {
            return Err(ArtifactStoreError::InvalidRequest);
        }
        // Only the native execution owner can construct this receipt. Validate the complete
        // UTF8 envelope before publishing anything; opaque binary snapshots remain unavailable.
        let mut snapshots = Vec::with_capacity(receipt.files().len());
        for file in receipt.files() {
            let path = file
                .path()
                .strip_prefix(&self.workspace)
                .ok()
                .and_then(std::path::Path::to_str)
                .ok_or(ArtifactStoreError::Scope)?;
            if path.is_empty() || path.len() > 16_384 {
                return Err(ArtifactStoreError::InvalidRequest);
            }
            let before = file
                .before()
                .map(std::str::from_utf8)
                .transpose()
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            let after =
                std::str::from_utf8(file.after()).map_err(|_| ArtifactStoreError::Unavailable)?;
            snapshots.push((path, before, after));
        }
        let mut dependencies = Vec::with_capacity(snapshots.len() * 2);
        let mut served = Vec::with_capacity(snapshots.len());
        for (path, before, after) in snapshots {
            let before = before
                .map(|text| self.publish_text(source, ArtifactTextSchema::FileSnapshot, text, &[]))
                .transpose()?;
            let after = self.publish_text(source, ArtifactTextSchema::FileSnapshot, after, &[])?;
            dependencies.extend(before.iter().cloned());
            dependencies.push(after.clone());
            served.push(ServedDiffFile {
                path: iteron_record::redact::scrub(path),
                before,
                after,
            });
        }
        let body = serde_json::to_string(&NativeDiffManifest {
            kind: "native_file_diff_v1",
            tool_use_id_display: iteron_record::redact::scrub(receipt.tool_use_id()),
            tool: receipt.tool_name().into(),
            basis: "guarded_native_commit",
            encoding: "utf8",
            redaction: "served_content",
            files: served,
        })
        .map_err(|_| ArtifactStoreError::InvalidRequest)?;
        // This private publication gate verifies every exact descriptor against the live scoped
        // catalog and CAS, then binds actual private source handles under the same writer lease.
        self.publish_served(
            source,
            ArtifactTextSchema::FileDiff,
            &body,
            &[],
            &dependencies,
        )
    }
}
