//! Immutable policy identity sidecar for standalone workflow runs.

use core_protocol::RunGenesisPolicyBundleSnapshot;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const POLICY_CHECKPOINT_FILE: &str = "policy-bundle.json";
const MAX_POLICY_CHECKPOINT_BYTES: usize = 64 * 1024;

pub(crate) fn persist(
    workflows_dir: &Path,
    run_id: &str,
    snapshot: &RunGenesisPolicyBundleSnapshot,
) -> anyhow::Result<()> {
    if !super::valid_run_id(run_id) {
        anyhow::bail!("invalid workflow run id `{run_id}`");
    }
    core_record::validate_policy_bundle_snapshot(snapshot)?;
    let bytes = serde_json::to_vec_pretty(snapshot)?;
    if bytes.len() > MAX_POLICY_CHECKPOINT_BYTES {
        anyhow::bail!(
            "workflow policy checkpoint exceeds the {} byte bound",
            MAX_POLICY_CHECKPOINT_BYTES
        );
    }

    let dir = super::run_dir(workflows_dir, run_id);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(POLICY_CHECKPOINT_FILE);
    match std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::File::open(&dir)?.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let recorded = load_path(&path)?;
            if &recorded == snapshot {
                Ok(())
            } else {
                anyhow::bail!(
                    "workflow `{run_id}` already has a different immutable policy checkpoint"
                )
            }
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn load(
    workflows_dir: &Path,
    run_id: &str,
) -> anyhow::Result<RunGenesisPolicyBundleSnapshot> {
    if !super::valid_run_id(run_id) {
        anyhow::bail!("invalid workflow run id `{run_id}`");
    }
    let path = super::run_dir(workflows_dir, run_id).join(POLICY_CHECKPOINT_FILE);
    load_path(&path).map_err(|error| {
        anyhow::anyhow!(
            "workflow `{run_id}` has no usable immutable policy checkpoint at {}: {error}",
            path.display()
        )
    })
}

fn load_path(path: &PathBuf) -> anyhow::Result<RunGenesisPolicyBundleSnapshot> {
    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_POLICY_CHECKPOINT_BYTES as u64 {
        anyhow::bail!(
            "policy checkpoint exceeds the {} byte bound",
            MAX_POLICY_CHECKPOINT_BYTES
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_POLICY_CHECKPOINT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_POLICY_CHECKPOINT_BYTES {
        anyhow::bail!(
            "policy checkpoint exceeds the {} byte bound",
            MAX_POLICY_CHECKPOINT_BYTES
        );
    }
    let snapshot: RunGenesisPolicyBundleSnapshot = serde_json::from_slice(&bytes)?;
    core_record::validate_policy_bundle_snapshot(&snapshot)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn workflow_checkpoint_is_bounded_validated_and_immutable() {
        let root = std::env::temp_dir().join(format!(
            "core-workflow-policy-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let snapshot = crate::bundle_adapter::baseline_compiled_bundle()
            .genesis_snapshot()
            .clone();
        persist(&root, "wf-test", &snapshot).unwrap();
        assert_eq!(load(&root, "wf-test").unwrap(), snapshot);
        persist(&root, "wf-test", &snapshot).expect("an identical write is idempotent");

        let mut different = snapshot;
        different.bundle_id = "different".into();
        for row in &mut different.slots {
            row.policy.bundle_id = different.bundle_id.clone();
        }
        let different = core_record::seal_policy_bundle_snapshot(different).unwrap();
        assert!(persist(&root, "wf-test", &different).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
