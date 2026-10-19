//! Trusted root composition; diagnostics are explicitly enabled outside provider dispatch.
use super::{Agent, request_manifest::RequestManifestFactory};
use std::sync::Arc;

impl Agent {
    /// Enable complete scrubbed request/material diagnostics for subsequent physical requests.
    /// The default effect journal remains sufficient for provider accounting and recovery.
    /// Queue bounds and IO errors are reported by status/flush, never as provider send failure.
    pub fn set_request_archiving(&mut self, enabled: bool) -> Result<(), String> {
        if enabled {
            self.request_archive.enable(&self.rollout, &self.workspace)
        } else {
            self.request_archive.disable()
        }
    }

    /// Publish queued diagnostics at a quiescent completion/inspection boundary.
    /// This must not be called from provider preparation or dispatch callbacks.
    pub fn flush_request_archive(&self) -> Result<(), String> {
        self.request_archive.flush()
    }

    #[allow(
        dead_code,
        reason = "synchronous inspection port; the resident host uses the cloneable live reader"
    )]
    pub fn request_archive_status(&self) -> serde_json::Value {
        self.request_archive.status()
    }

    pub fn request_archive_reader(&self) -> Arc<dyn Fn() -> serde_json::Value + Send + Sync> {
        self.request_archive.reader()
    }

    pub(super) fn request_manifest_factory(&self) -> RequestManifestFactory {
        let mut factory = RequestManifestFactory::capture(&self.budget);
        if let Some(archive) = self.request_archive.capture(&self.rollout, &self.workspace) {
            let reference = self
                .task_plan
                .captured_reference(self.rollout.tenant(), self.rollout.run_id());
            let (materials, dropped) = self
                .context_source_evidence
                .request_material_snapshot(reference);
            factory = factory.with_archive(
                archive,
                self.context_source_evidence.segments(),
                materials,
                dropped,
            );
        }
        factory.with_mailbox(self.persistent_mailbox.clone())
    }
}
