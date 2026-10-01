//! Exact frozen context evidence from the actual scoped, verified native journal.
use crate::runtime::workflow_spawner::KernelSpawner;
use iteron_agents::ControllerError;
use iteron_protocol::native_child_context::{NativeChildContextRefV1, NativeChildContextV1};
use std::path::PathBuf;
const MAX_ARCHIVE_BYTES: usize = 8 * 1024 * 1024;
pub(super) fn load(
    spawner: &KernelSpawner,
    reference: &NativeChildContextRefV1,
) -> Result<NativeChildContextV1, ControllerError> {
    reference.validate().map_err(ControllerError::Invalid)?;
    let state = spawner.native_state_root();
    let name = format!("{}.jsonl", reference.run);
    // The source is a host journal identity. The retained reader rejects absolute/parent paths,
    // symlink ancestors, devices and namespace substitution before returning bounded bytes.
    let roots = [PathBuf::from(&name), PathBuf::from("subagents").join(&name)];
    for relative in roots {
        if let Ok(bytes) =
            iteron_tools::contained_source::read_contained_utf8(state, &relative, MAX_ARCHIVE_BYTES)
        {
            return iteron_record::native_child_context::read_reference(
                bytes.as_bytes(),
                reference,
            )
            .map_err(|_| ControllerError::RecoveryRequired);
        }
    }
    Err(ControllerError::RecoveryRequired)
}
