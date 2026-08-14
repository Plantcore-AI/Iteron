use anyhow::{Context, Result, bail};
use std::io::Read;
use std::path::Path;

const EVOLVE_SOURCE: &str = "crates/evolve/src/lib.rs";
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

/// Source-level guard for the frozen-model product boundary. Runtime admission is enforced by
/// `PolicyManifest::validate`; this guard makes removing that refusal or reintroducing a
/// model-training trajectory target a conformance failure.
pub(super) fn validate(root: &Path) -> Result<()> {
    let path = root.join(EVOLVE_SOURCE);
    let mut source = String::new();
    std::fs::File::open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_string(&mut source)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if source.len() as u64 > MAX_SOURCE_BYTES {
        bail!("{EVOLVE_SOURCE} exceeds the frozen-model conformance byte bound");
    }
    for required in [
        "ArtifactKind::ModelAdapter | ArtifactKind::ModelWeights",
        "model artifacts are reserved: Iteron only admits harness artifacts",
        "The projection has no\n/// model-training export target.",
        "provenance labels only; none of them authorizes changing or exporting data to train a model",
        "pub enum TrajectoryExportTarget",
    ] {
        if !source.contains(required) {
            bail!("frozen-model conformance marker missing from {EVOLVE_SOURCE}: {required}");
        }
    }
    let export_targets = source
        .split_once("pub enum TrajectoryExportTarget")
        .and_then(|(_, tail)| tail.split_once('}'))
        .map(|(body, _)| body)
        .context("cannot locate the closed TrajectoryExportTarget body")?;
    if export_targets.contains("ModelTraining") {
        bail!("trajectory export must not gain a model-training target");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_model_contract_is_structurally_guarded() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        validate(root).unwrap();
    }
}
