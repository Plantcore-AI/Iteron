//! A content publication lease scoped to one bounded journal append batch.
//!
//! No state survives the batch: the next append reacquires the process-shared store lock and
//! reloads revocation and peer metadata. Control-only events do not open the content store.

use super::{
    ContentReferenceSurface, ContentStoreError, Layout, StoreLock, digest_bytes, encoding,
    ensure_available_locked, ensure_content_bound, ensure_layout, fields, lineage, lock_store,
    lock_store_for_record, mark_externalized_payload, private_content_sources_for_run, references,
    semantic_namespace, storage, store_locked,
};
use iteron_protocol::{RunId, Seq, TenantId};
use std::path::Path;

pub(crate) struct EventPayloadBatch<'a> {
    runs_dir: &'a Path,
    tenant: &'a TenantId,
    run: &'a RunId,
    lease: Option<(Layout, StoreLock)>,
}

impl<'a> EventPayloadBatch<'a> {
    pub(crate) fn new(runs_dir: &'a Path, tenant: &'a TenantId, run: &'a RunId) -> Self {
        Self {
            runs_dir,
            tenant,
            run,
            lease: None,
        }
    }

    pub(crate) fn externalize(
        &mut self,
        seq: Seq,
        payload: &mut serde_json::Value,
    ) -> Result<(), ContentStoreError> {
        if !fields::has_content_fields(payload) {
            return mark_externalized_payload(payload);
        }
        let checkpoint = payload
            .get("kind")
            .and_then(serde_json::Value::as_object)
            .and_then(|event| event.get("kind"))
            .and_then(serde_json::Value::as_str)
            == Some("checkpoint");
        let checkpoint_sources = if checkpoint {
            // The inventory acquires its own read lease. Release the current write lease first,
            // so a checkpoint can include earlier fields in this same batch without self-locking.
            // Revalidate the inventory under the new exclusive lease before publishing lineage.
            self.lease.take();
            private_content_sources_for_run(self.runs_dir, self.tenant, self.run)?
        } else {
            Vec::new()
        };
        if self.lease.is_none() {
            let layout = Layout::new(self.runs_dir, self.tenant);
            ensure_layout(&layout)?;
            let store_lock = lock_store_for_record(&layout, lock_store)?;
            self.lease = Some((layout, store_lock));
        }
        let (layout, store_lock) = self.lease.as_ref().ok_or(ContentStoreError::Corrupt)?;
        let state = store_lock.write_state()?;
        for source in &checkpoint_sources {
            references::verify_source_owner_locked(layout, source)?;
            ensure_available_locked(layout, state, &source.digest)?;
        }
        let mut ordinal = 0u16;
        fields::visit_content_fields(payload, |field_class, value| {
            let semantic_namespace = semantic_namespace(field_class, value);
            let (bytes, encoding) = encoding::encode(value)?;
            ensure_content_bound(&bytes)?;
            let digest = digest_bytes(&bytes);
            store_locked(layout, state, &digest, &bytes)?;
            let semantic = semantic_namespace.map(|namespace| namespace.surface());
            // Publish checkpoint lineage before the atomic root/semantic pair. A crash may leave
            // conservative lineage, but no readable checkpoint missing a source. Ordinary edge
            // publication failure rolls that lineage back; the event is not yet appended.
            let lineage = if semantic == Some(ContentReferenceSurface::Checkpoint) {
                Some(lineage::publish_locked(
                    layout,
                    &checkpoint_sources,
                    self.run,
                    &digest,
                    seq,
                    ContentReferenceSurface::Checkpoint,
                )?)
            } else {
                None
            };
            if let Err(error) = storage::write_record_edges_locked(
                layout,
                &digest,
                self.run,
                seq,
                ordinal,
                field_class,
                semantic,
            ) {
                if let Some(lineage) = lineage {
                    lineage.rollback()?;
                }
                return Err(error);
            }
            ordinal = ordinal
                .checked_add(1)
                .ok_or(ContentStoreError::ReferenceBound {
                    max: usize::from(u16::MAX),
                })?;
            *value = serde_json::Value::String(encoding::marker(&digest, encoding));
            Ok::<(), ContentStoreError>(())
        })?;
        mark_externalized_payload(payload)
    }
}
