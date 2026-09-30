//! Trusted root composition; physical execution receives only an immutable publication factory.
use super::{Agent, request_manifest::RequestManifestFactory};

impl Agent {
    pub(super) fn request_manifest_factory(&self) -> RequestManifestFactory {
        RequestManifestFactory::capture(
            &self.rollout,
            &self.workspace,
            &self.budget,
            self.context_source_evidence.segments(),
        )
    }
}
