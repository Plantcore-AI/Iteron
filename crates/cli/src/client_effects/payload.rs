//! Invocation-scoped private content lineage; only the native host can mint its source scope.
use std::sync::atomic::{AtomicU64, Ordering};

const EXPORT_SEQUENCE_BASE: u64 = (1_u64 << 63) | (1_u64 << 61);
static NEXT_EXPORT_SEQUENCE: AtomicU64 = AtomicU64::new(EXPORT_SEQUENCE_BASE);
const EXPORT_STORE_BUSY_RETRY_ATTEMPTS: usize = 401;
const EXPORT_STORE_BUSY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(5);

fn retry_export_store_busy<T>(
    mut operation: impl FnMut() -> Result<T, iteron_record::ContentStoreError>,
) -> Result<T, iteron_record::ContentStoreError> {
    let attempts = iteron_tunables::param_integer(
        "cli.tui.transcript_effect.export_store_busy_retry_attempts",
        EXPORT_STORE_BUSY_RETRY_ATTEMPTS,
    )
    .clamp(1, EXPORT_STORE_BUSY_RETRY_ATTEMPTS);
    for attempt in 0..attempts {
        match operation() {
            Err(iteron_record::ContentStoreError::Busy) if attempt + 1 < attempts => {
                std::thread::sleep(
                    iteron_tunables::param_duration(
                        "cli.tui.transcript_effect.export_store_busy_retry_delay",
                        EXPORT_STORE_BUSY_RETRY_DELAY,
                    )
                    .min(EXPORT_STORE_BUSY_RETRY_DELAY),
                );
            }
            result => return result,
        }
    }
    unreachable!("the bounded transcript export store retry loop always returns")
}

/// One invocation-scoped transcript export rooted in the record private-content graph.
///
/// The UI first renders a bounded snapshot in memory, but the worker is never handed that copy.
/// It receives bytes hydrated through this exact handle after every record source has been bound
/// as durable lineage. The owner lease remains live through worker settlement, so revocation and
/// export cannot race to produce a post-tombstone copy.
pub(super) struct ManagedExportPayload {
    store: iteron_record::PrivateContentDerivativeStore,
    seq: iteron_protocol::Seq,
    handle: iteron_record::PrivateContentHandle,
    cleanup_on_drop: bool,
}

impl ManagedExportPayload {
    pub(super) fn stage(
        source: &super::NativeExportScope,
        bytes: &[u8],
    ) -> Result<Self, &'static str> {
        let runs_dir = &source.runs_dir;
        let tenant = source.tenant.clone();
        let run = source.run.clone();
        let sequence = NEXT_EXPORT_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| "transcript export sequence space is exhausted")?;
        let seq = iteron_protocol::Seq(sequence);
        let store = iteron_record::PrivateContentDerivativeStore::open_registered(
            runs_dir,
            tenant,
            run.clone(),
            iteron_record::PrivateContentNamespace::Export,
            iteron_record::PrivateContentClass::Export,
            iteron_record::PrivateContentRetention::Session,
            super::MAX_TRANSCRIPT_EXPORT_BYTES,
        )
        .map_err(|_| "transcript export private store is unavailable")?;
        let handle = retry_export_store_busy(|| store.put_derived_from_run(seq, bytes, &run))
            .map_err(|_| "transcript export source lineage is unavailable")?;
        Ok(Self {
            store,
            seq,
            handle,
            cleanup_on_drop: true,
        })
    }

    pub(super) fn read(&self) -> Result<Vec<u8>, &'static str> {
        self.store
            .read_at(self.seq, &self.handle)
            .map_err(|_| "transcript export content is revoked or unavailable")
    }

    pub(super) fn finish(mut self) -> super::ContentCleanup {
        // One explicit bounded cleanup observation; Drop never retries an ambiguous graph write.
        self.cleanup_on_drop = false;
        match retry_export_store_busy(|| self.store.release(self.seq, &self.handle.digest)) {
            Ok(_) => super::ContentCleanup::Released,
            Err(_) => super::ContentCleanup::Unobserved,
        }
    }

    #[cfg(test)]
    fn abandon_for_recovery(
        mut self,
    ) -> (iteron_protocol::Seq, iteron_record::PrivateContentHandle) {
        self.cleanup_on_drop = false;
        (self.seq, self.handle.clone())
    }
}

impl Drop for ManagedExportPayload {
    fn drop(&mut self) {
        if !self.cleanup_on_drop {
            return;
        }
        // A failed release leaves the encrypted reference for exact-session recovery. It must not
        // unlink one side of the graph or turn a cleanup failure into an untracked plaintext copy.
        let _ = self.store.release(self.seq, &self.handle.digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(
        tag: &str,
    ) -> (
        std::path::PathBuf,
        iteron_record::Rollout,
        super::super::NativeExportScope,
    ) {
        let root = std::env::temp_dir().join(format!(
            "iteron-export-cleanup-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut record = iteron_record::Rollout::open(
            &root,
            &iteron_protocol::RunId("cleanup-source".into()),
            iteron_protocol::TenantId::default(),
        )
        .unwrap();
        record
            .append(&iteron_protocol::Event {
                seq: iteron_protocol::Seq::ZERO,
                turn: iteron_protocol::TurnId(0),
                kind: iteron_protocol::EventKind::Notice {
                    text: "actual source".into(),
                },
            })
            .unwrap();
        let source = super::super::NativeExportScope::from_verified_fixture(record.path());
        (root, record, source)
    }
    #[test]
    fn explicit_release_confirms_actual_derivative_reference_is_unavailable() {
        let (root, record, source) = fixture("released");
        let payload = ManagedExportPayload::stage(&source, b"actual export").unwrap();
        let seq = payload.seq;
        let handle = payload.handle.clone();
        assert_eq!(payload.finish(), super::super::ContentCleanup::Released);
        let reopened = iteron_record::PrivateContentDerivativeStore::open_registered(
            &source.runs_dir,
            source.tenant.clone(),
            source.run.clone(),
            iteron_record::PrivateContentNamespace::Export,
            iteron_record::PrivateContentClass::Export,
            iteron_record::PrivateContentRetention::Session,
            super::super::MAX_TRANSCRIPT_EXPORT_BYTES,
        )
        .unwrap();
        assert!(reopened.read_at(seq, &handle).is_err());
        drop(reopened);
        drop(record);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn actual_corrupt_graph_refuses_cleanup_confirmation_and_preserves_source() {
        use sha2::{Digest as _, Sha256};
        let (root, record, source) = fixture("unobserved");
        let payload = ManagedExportPayload::stage(&source, b"actual export").unwrap();
        // Corrupt one real reverse edge. The release must refuse before claiming the graph clean.
        let refs = root
            .join(".content")
            .join("v1")
            .join(hex::encode(Sha256::digest(source.tenant.0.as_bytes())))
            .join("run-refs")
            .join(hex::encode(Sha256::digest(source.run.0.as_bytes())));
        let edge = std::fs::read_dir(&refs)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let original = std::fs::read(&edge).unwrap();
        std::fs::write(&edge, b"not a graph edge").unwrap();
        assert_eq!(payload.finish(), super::super::ContentCleanup::Unobserved);
        assert!(record.path().exists());
        std::fs::write(edge, original).unwrap();
        drop(record);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn export_payload_is_lineaged_and_refuses_a_revoked_transcript_source() {
        use iteron_protocol::{
            ErasureAuthorityId, ErasureOperationId, ErasureRequest, ErasureScopeId, ErasureTarget,
            Event as RecordEvent, EventKind, RunId, Seq, TenantId, TurnId,
        };

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock after epoch")
            .as_nanos();
        let runs_dir = std::env::temp_dir().join(format!(
            "core-private-export-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&runs_dir).expect("create export fixture");
        let tenant = TenantId::default();
        let run = RunId("private-export-source".into());
        let mut rollout = iteron_record::Rollout::open(&runs_dir, &run, tenant.clone())
            .expect("open source rollout");
        rollout
            .append(&RecordEvent {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::Notice {
                    text: "operator-visible transcript source".into(),
                },
            })
            .expect("append transcript source");
        let path = rollout.path().to_path_buf();
        let sources =
            iteron_record::content_store::private_content_sources_for_run(&runs_dir, &tenant, &run)
                .expect("inventory source record fields");
        assert_eq!(sources.len(), 1);

        let payload = ManagedExportPayload::stage(
            &crate::client_effects::NativeExportScope::from_verified_fixture(&path),
            b"# bounded export\nprivate transcript",
        )
        .expect("stage lineaged export");
        assert_eq!(
            payload.read().expect("read through export gate"),
            b"# bounded export\nprivate transcript"
        );
        let (seq, handle) = payload.abandon_for_recovery();
        drop(rollout);

        iteron_record::erasure::execute_erasure(
            &runs_dir,
            ErasureRequest {
                operation_id: ErasureOperationId::new("revoke-export-source").unwrap(),
                authority_id: ErasureAuthorityId::new("wire-value-is-not-authority").unwrap(),
                target: ErasureTarget::ContentRevocation {
                    scope_id: ErasureScopeId::new(tenant.0.clone()).unwrap(),
                    content_digest: sources[0].digest.clone(),
                },
                requested_at_unix_ms: 1,
            },
        )
        .expect("revoke source and propagate to export");

        let recovered = iteron_record::PrivateContentDerivativeStore::open_registered(
            &runs_dir,
            tenant,
            run,
            iteron_record::PrivateContentNamespace::Export,
            iteron_record::PrivateContentClass::Export,
            iteron_record::PrivateContentRetention::Session,
            super::super::MAX_TRANSCRIPT_EXPORT_BYTES,
        )
        .expect("open recovered export owner");
        assert!(matches!(
            recovered.read_at(seq, &handle),
            Err(iteron_record::ContentStoreError::Revoked { .. })
                | Err(iteron_record::ContentStoreError::Unresolved { .. })
        ));
        drop(recovered);
        std::fs::remove_dir_all(runs_dir).expect("remove export fixture");
    }
}
