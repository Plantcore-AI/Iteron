//! Durable host installation locator. This records identity, never an arbitrary filesystem path.
use crate::{RunId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AGENT_COHORT_VERSION: u32 = 1;
pub const MAX_COHORT_MAIN_RUNS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCohortOriginV1 {
    pub version: u32,
    pub tenant: TenantId,
    pub run_id: RunId,
    pub config_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCohortInstallationV1 {
    pub origin: AgentCohortOriginV1,
    pub installed_run: RunId,
}

/// Exact physical run admitted under the original root's remaining lifetime budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCohortMainRunV1 {
    pub tenant: TenantId,
    pub run_id: RunId,
    pub scope_sha256: String,
    pub admitted_through_sequence: u64,
    pub admission_sha256: String,
}

impl AgentCohortOriginV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != AGENT_COHORT_VERSION || !valid_sha(&self.config_sha256) {
            return Err("invalid cohort installation version or commitment");
        }
        validate_tenant(&self.tenant)?;
        validate_run(&self.run_id)
    }
    pub fn provider_scope(&self) -> String {
        provider_scope(&self.tenant, &self.run_id)
    }
    /// Reconstructed only from a verified host receipt and the trusted runtime-state root.
    pub fn directory_component(&self) -> String {
        let mut hash = Sha256::new();
        for part in [&self.tenant.0, &self.run_id.0] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        let digest = hash.finalize();
        let namespace = digest[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("agents-controller-{namespace}-t00000000-n0000")
    }
}
impl AgentCohortInstallationV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.origin.validate()?;
        validate_run(&self.installed_run)
    }
}
impl AgentCohortMainRunV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_tenant(&self.tenant)?;
        validate_run(&self.run_id)?;
        if self.admitted_through_sequence == 0
            || !valid_sha(&self.admission_sha256)
            || self.scope_sha256 != provider_scope(&self.tenant, &self.run_id)
        {
            return Err("invalid cohort physical run admission");
        }
        Ok(())
    }
}
pub fn provider_scope(tenant: &TenantId, run: &RunId) -> String {
    let mut hash = Sha256::new();
    hash.update(b"iteron-persistent-provider-run-v1\0");
    for part in [&tenant.0, &run.0] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    format!("sha256:{:x}", hash.finalize())
}
fn valid_sha(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn validate_tenant(tenant: &TenantId) -> Result<(), &'static str> {
    if tenant.0.is_empty() || tenant.0.len() > 256 || tenant.0.chars().any(char::is_control) {
        return Err("invalid cohort tenant");
    }
    Ok(())
}
fn validate_run(run: &RunId) -> Result<(), &'static str> {
    let name = &run.0;
    if name.is_empty()
        || name.len() > 128
        || name == "."
        || name == ".."
        || name.ends_with('.')
        || name.ends_with(' ')
        || name.chars().any(|c| {
            c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '\"' | '<' | '>' | '|')
        })
    {
        return Err("invalid cohort portable run component");
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    {
        return Err("cohort run is a reserved device name");
    }
    Ok(())
}
