//! Invocation-scoped image bytes on the record-owned private-content graph.
//!
//! Images remain provider-local rather than being replayed into future model turns, but they must
//! not exist only as an untracked in-memory copy between SQ admission and the durable user Message.
//! This lease publishes each bounded base64 payload on the run's Attachment surface, hydrates the
//! provider copy through the tombstone gate, and retains every reference until the whole admitted
//! run returns. Exact release then removes only these handles, never older file-attachment edges.

use iteron_protocol::{ImageContent, RunId, Seq, TenantId, TurnId};
use iteron_record::{
    MAX_PRIVATE_CONTENT_BYTES, PrivateContentClass, PrivateContentDerivativeStore,
    PrivateContentHandle, PrivateContentNamespace, PrivateContentRetention,
};
use std::path::Path;

const ATTACHMENT_SEQUENCE_BASE: u64 = 1_u64 << 62;
const ATTACHMENTS_PER_TURN: u64 = iteron_protocol::input::MAX_INPUT_IMAGES as u64;

pub(super) struct InvocationImages {
    store: Option<PrivateContentDerivativeStore>,
    references: Vec<(Seq, PrivateContentHandle)>,
    images: Vec<ImageContent>,
}

impl InvocationImages {
    pub(super) fn stage(
        runs_dir: &Path,
        tenant: TenantId,
        run: RunId,
        turn: TurnId,
        input: &[ImageContent],
    ) -> Result<Self, iteron_record::ContentStoreError> {
        if input.is_empty() {
            return Ok(Self {
                store: None,
                references: Vec::new(),
                images: Vec::new(),
            });
        }
        let store = PrivateContentDerivativeStore::open_registered(
            runs_dir,
            tenant,
            run,
            PrivateContentNamespace::Attachment,
            PrivateContentClass::Attachment,
            PrivateContentRetention::Session,
            MAX_PRIVATE_CONTENT_BYTES,
        )?;
        let turn_offset = u64::from(turn.0)
            .checked_mul(ATTACHMENTS_PER_TURN)
            .ok_or(iteron_record::ContentStoreError::Corrupt)?;
        let first = ATTACHMENT_SEQUENCE_BASE
            .checked_add(turn_offset)
            .ok_or(iteron_record::ContentStoreError::Corrupt)?;
        let mut references = Vec::with_capacity(input.len());
        let mut images = Vec::with_capacity(input.len());
        for (index, image) in input.iter().enumerate() {
            let index =
                u64::try_from(index).map_err(|_| iteron_record::ContentStoreError::Corrupt)?;
            let seq = Seq(first
                .checked_add(index)
                .ok_or(iteron_record::ContentStoreError::Corrupt)?);
            let handle = match store.put(seq, image.data.as_str().as_bytes()) {
                Ok(handle) => handle,
                Err(error) => {
                    release_all(&store, &references);
                    return Err(error);
                }
            };
            let bytes = match store.read_at(seq, &handle) {
                Ok(bytes) => bytes,
                Err(error) => {
                    references.push((seq, handle));
                    release_all(&store, &references);
                    return Err(error);
                }
            };
            let encoded = match String::from_utf8(bytes) {
                Ok(encoded) => encoded,
                Err(_) => {
                    references.push((seq, handle));
                    release_all(&store, &references);
                    return Err(iteron_record::ContentStoreError::Corrupt);
                }
            };
            let hydrated = match ImageContent::new(image.media_type, encoded) {
                Ok(image) => image,
                Err(_) => {
                    references.push((seq, handle));
                    release_all(&store, &references);
                    return Err(iteron_record::ContentStoreError::Corrupt);
                }
            };
            references.push((seq, handle));
            images.push(hydrated);
        }
        Ok(Self {
            store: Some(store),
            references,
            images,
        })
    }

    pub(super) fn images(&self) -> &[ImageContent] {
        &self.images
    }
}

impl Drop for InvocationImages {
    fn drop(&mut self) {
        if let Some(store) = &self.store {
            release_all(store, &self.references);
        }
    }
}

fn release_all(store: &PrivateContentDerivativeStore, references: &[(Seq, PrivateContentHandle)]) {
    for (seq, handle) in references {
        // A failed cleanup conservatively retains encrypted material and its reference. The next
        // exact-session cleanup/recovery sees it; silently unlinking only one side would be worse.
        let _ = store.release(*seq, &handle.digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::ImageMediaType;

    fn temporary_runs_dir() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "core-private-attachments-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).expect("create private attachment fixture");
        root
    }

    #[test]
    fn invocation_lease_keeps_attachment_readable_until_the_run_handoff_returns() {
        let runs_dir = temporary_runs_dir();
        let tenant = TenantId::default();
        let run = RunId("private-attachment-handoff".into());
        let image = ImageContent::new(ImageMediaType::Png, "iVBORw0KGgo=")
            .expect("canonical bounded PNG fixture");
        let staged = InvocationImages::stage(
            &runs_dir,
            tenant.clone(),
            run,
            TurnId(7),
            std::slice::from_ref(&image),
        )
        .expect("stage attachment");
        assert_eq!(staged.images(), std::slice::from_ref(&image));

        let (seq, handle) = staged.references.first().expect("one durable reference");
        let handle = handle.clone();
        assert_eq!(
            staged
                .store
                .as_ref()
                .expect("non-empty staging owns a store")
                .read_at(*seq, &handle)
                .expect("the provider handoff re-enters the read gate"),
            image.data.as_str().as_bytes()
        );
        iteron_record::content_store::guard_private_content(&runs_dir, &tenant, &handle.digest)
            .expect("the reference remains live for the entire invocation lease");

        // `runtime.rs` deliberately keeps this value in scope across the awaited drive. Dropping
        // it models that drive returning, after its user Message was either durably appended or
        // the submission failed before admission. Only then may this exact invocation ref leave.
        drop(staged);
        assert!(matches!(
            iteron_record::content_store::guard_private_content(&runs_dir, &tenant, &handle.digest),
            Err(iteron_record::ContentStoreError::Unresolved { .. })
        ));
        std::fs::remove_dir_all(runs_dir).expect("remove private attachment fixture");
    }
}
