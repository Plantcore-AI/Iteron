//! Immutable V2 runtime-tunables sidecar for standalone workflow runs.

use core_protocol::RunGenesisTunablesSnapshotV2;
use core_record::TunablesCheckpoint;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const TUNABLES_CHECKPOINT_FILE: &str = "runtime-tunables.json";
const MAX_TUNABLES_CHECKPOINT_BYTES: usize = 512 * 1024;

pub(crate) fn persist(
    workflows_dir: &Path,
    run_id: &str,
    checkpoint: &TunablesCheckpoint,
) -> anyhow::Result<()> {
    if !super::valid_run_id(run_id) {
        anyhow::bail!("invalid workflow run id `{run_id}`");
    }
    let TunablesCheckpoint::V2(snapshot) = checkpoint else {
        anyhow::bail!("fresh workflow runs require a complete V2 tunables checkpoint");
    };
    core_record::validate_tunables_snapshot_v2(snapshot)?;
    let bytes = serde_json::to_vec_pretty(snapshot)?;
    if bytes.len() > MAX_TUNABLES_CHECKPOINT_BYTES {
        anyhow::bail!(
            "workflow tunables checkpoint exceeds the {} byte bound",
            MAX_TUNABLES_CHECKPOINT_BYTES
        );
    }

    let dir = super::run_dir(workflows_dir, run_id);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(TUNABLES_CHECKPOINT_FILE);
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
                    "workflow `{run_id}` already has a different immutable tunables checkpoint"
                )
            }
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn load(workflows_dir: &Path, run_id: &str) -> anyhow::Result<TunablesCheckpoint> {
    if !super::valid_run_id(run_id) {
        anyhow::bail!("invalid workflow run id `{run_id}`");
    }
    let path = super::run_dir(workflows_dir, run_id).join(TUNABLES_CHECKPOINT_FILE);
    load_path(&path)
        .map(TunablesCheckpoint::V2)
        .map_err(|error| {
            anyhow::anyhow!(
                "workflow `{run_id}` has no usable immutable tunables checkpoint at {}: {error}",
                path.display()
            )
        })
}

fn load_path(path: &PathBuf) -> anyhow::Result<RunGenesisTunablesSnapshotV2> {
    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_TUNABLES_CHECKPOINT_BYTES as u64 {
        anyhow::bail!(
            "tunables checkpoint exceeds the {} byte bound",
            MAX_TUNABLES_CHECKPOINT_BYTES
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_TUNABLES_CHECKPOINT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_TUNABLES_CHECKPOINT_BYTES {
        anyhow::bail!(
            "tunables checkpoint exceeds the {} byte bound",
            MAX_TUNABLES_CHECKPOINT_BYTES
        );
    }
    let snapshot: RunGenesisTunablesSnapshotV2 = serde_json::from_slice(&bytes)?;
    core_record::validate_tunables_snapshot_v2(&snapshot)?;
    Ok(snapshot)
}
