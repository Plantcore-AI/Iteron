//! Trusted root composition; physical execution receives only an immutable publication factory.
use super::{Agent, request_manifest::RequestManifestFactory};

impl Agent {
    pub(super) fn request_manifest_factory(&self) -> RequestManifestFactory {
        let reference = self
            .task_plan
            .captured_reference(self.rollout.tenant(), self.rollout.run_id());
        let (materials, dropped) = self
            .context_source_evidence
            .request_material_snapshot(reference);
        RequestManifestFactory::capture(
            &self.rollout,
            &self.workspace,
            &self.budget,
            self.context_source_evidence.segments(),
            &materials,
            dropped,
        )
        .with_mailbox(self.persistent_mailbox.clone())
    }
}
