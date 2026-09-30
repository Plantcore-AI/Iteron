//! Bounded explicit operator bootstrap reader. Public client commands never call this port.
use super::types::{HighAssurancePolicy, HighAssuranceProfileV1};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

pub(crate) fn load_operator_profile(path: &Path) -> Result<Arc<HighAssurancePolicy>, &'static str> {
    let file = std::fs::File::open(path).map_err(|_| "high_assurance_profile_io")?;
    if !file
        .metadata()
        .map_err(|_| "high_assurance_profile_io")?
        .is_file()
    {
        return Err("high_assurance_profile_not_regular");
    }
    // The CLI-selected file is the operator's enrollment trust source, read once through its
    // pinned descriptor. Its public keys are not secret credentials; no private key is accepted.
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "high_assurance_profile_io")?;
    if bytes.len() > 64 * 1024 {
        return Err("high_assurance_profile_capacity");
    }
    let profile: HighAssuranceProfileV1 =
        serde_json::from_slice(&bytes).map_err(|_| "high_assurance_profile_shape")?;
    Ok(Arc::new(HighAssurancePolicy::from_operator(profile)?))
}
