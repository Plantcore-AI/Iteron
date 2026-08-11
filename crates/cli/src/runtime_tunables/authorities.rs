//! Content-free authority identities captured before tunables resolution.
//!
//! Constraints are useful only when their evidence comes from a different owner than the value
//! being constrained. This module hashes typed production-owner snapshots into the identities the
//! resolver accepts; it never copies configuration text, prompts, paths, credentials, or tool
//! arguments into the checkpoint.

use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{Budget, PermissionMode, PermissionRules, TenantId};
use iteron_tools::Registry;
use iteron_tunables::{ExternalCeiling, RuntimeAuthoritySet, RuntimeProfile, RuntimeResolutionError};
use iteron_verify::{VerifierPlan, VerifierSlotObservation};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const CANONICALIZATION: &str = "iteron-cli-runtime-authority-v1";

#[derive(Debug, Clone, Copy)]
pub(crate) enum VerificationAuthority<'a> {
    Configured {
        floor: &'a VerifierSlotObservation,
        plan: &'a VerifierPlan,
    },
    Disabled,
}

pub(crate) struct AuthorityFactsInput<'a> {
    pub operator_ceiling: CapabilitySet,
    pub permission_mode: PermissionMode,
    pub permission_rules: &'a PermissionRules,
    pub bypass_permissions: bool,
    pub budget: &'a Budget,
    pub registry: &'a Registry,
    pub verification: VerificationAuthority<'a>,
    pub tenant: &'a TenantId,
    pub tenant_allows_memory: bool,
    pub profile: RuntimeProfile,
    /// Content-free benchmark attempt identifier, when one is explicitly active.
    pub benchmark_scope_digest_sha256: Option<&'a str>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthorityFactError {
    #[error("runtime authority evidence could not be encoded")]
    EvidenceEncoding,
    #[error(transparent)]
    Resolution(#[from] RuntimeResolutionError),
}

/// Bind every non-route ceiling to an independently sampled typed owner snapshot.
pub(crate) fn collect_runtime_authorities(
    input: AuthorityFactsInput<'_>,
) -> Result<RuntimeAuthoritySet, AuthorityFactError> {
    let operator = digest(
        "operator",
        &(
            input.operator_ceiling,
            input.permission_mode,
            input.permission_rules,
            input.bypass_permissions,
        ),
    )?;
    let mut authorities = RuntimeAuthoritySet::new(operator)?;

    let registry_specs = input.registry.specs();
    let process_surface = registry_specs
        .iter()
        .map(|spec| spec.name.as_str())
        .filter(|name| name.starts_with("process_"))
        .collect::<Vec<_>>();
    let verification = match input.verification {
        VerificationAuthority::Configured { floor, plan } => {
            digest("verification_floor", &(true, floor, plan))?
        }
        VerificationAuthority::Disabled => digest("verification_floor", &(false,))?,
    };

    for (ceiling, owner_digest) in [
        (
            ExternalCeiling::ParentTurns,
            digest("parent_turns", &input.budget.max_turns)?,
        ),
        (
            ExternalCeiling::ParentTokens,
            digest("parent_tokens", &input.budget.max_tokens)?,
        ),
        (
            ExternalCeiling::ParentWall,
            digest("parent_wall", &input.budget.max_wall_secs)?,
        ),
        (
            ExternalCeiling::ParentCost,
            digest("parent_cost", &input.budget.max_usd.map(f64::to_bits))?,
        ),
        (
            ExternalCeiling::ToolBudget,
            digest("tool_budget", &registry_specs)?,
        ),
        (
            ExternalCeiling::ProcessBudget,
            digest("process_budget", &process_surface)?,
        ),
        (ExternalCeiling::VerificationFloor, verification),
        (
            ExternalCeiling::TenantScope,
            digest(
                "tenant_scope",
                &(&input.tenant.0, input.tenant_allows_memory),
            )?,
        ),
        (
            ExternalCeiling::RunBudget,
            digest("run_budget", input.budget)?,
        ),
        (
            ExternalCeiling::BenchmarkProtocol,
            digest(
                "benchmark_protocol",
                &(input.profile, input.benchmark_scope_digest_sha256),
            )?,
        ),
    ] {
        authorities = authorities.bind_ceiling(ceiling, owner_digest)?;
    }
    Ok(authorities)
}

fn digest(label: &'static str, value: &impl Serialize) -> Result<String, AuthorityFactError> {
    serde_json::to_vec(&(CANONICALIZATION, label, value))
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|_| AuthorityFactError::EvidenceEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_digest_is_content_free_deterministic_and_owner_sensitive() {
        let first = digest("parent_turns", &7_u32).unwrap();
        let second = digest("parent_turns", &7_u32).unwrap();
        let changed = digest("parent_turns", &8_u32).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, changed);
        assert_eq!(first.len(), 64);
    }
}
