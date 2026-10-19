//! Standalone builds cannot install the legacy project's recording transport.
use crate::config::ProviderConfig;
use iteron_provider::RecordingProviderTransport;
use std::path::Path;

pub fn prepare(
    _path: &Path,
    _configured: &[ProviderConfig],
    _selected_provider_id: &str,
) -> anyhow::Result<RecordingProviderTransport> {
    anyhow::bail!("legacy recording transport is unavailable in standalone Iteron")
}
