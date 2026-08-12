use super::RuntimeResolutionError;
use crate::{
    DefaultResolver, EvidenceState, EvidenceSubject, ExternalCeiling, ResolutionValue,
    RouteIdentity,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub(super) fn evidence_digest(
    domain: &str,
    value: &impl Serialize,
) -> Result<String, RuntimeResolutionError> {
    let mut digest = Sha256::new();
    digest.update(b"core-runtime-tunable-evidence-v1\0");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain.as_bytes());
    let encoded =
        serde_json::to_vec(value).map_err(|_| RuntimeResolutionError::EvidenceEncoding)?;
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

pub(super) fn resolver_id(resolver: DefaultResolver) -> String {
    match resolver {
        DefaultResolver::Literal => "iteron://tunables/resolvers/literal-v1".to_owned(),
        DefaultResolver::Builtin { resolver_id } => resolver_id.to_owned(),
        DefaultResolver::ModelMetadata { field } => {
            format!("iteron://tunables/resolvers/model-metadata/{field}-v1")
        }
        DefaultResolver::ProviderCapability { capability } => {
            format!("iteron://tunables/resolvers/provider-capability/{capability}-v1")
        }
        DefaultResolver::Transport { field } => {
            format!("iteron://tunables/resolvers/transport/{field}-v1")
        }
        DefaultResolver::RuntimeObservation { field } => {
            format!("iteron://tunables/resolvers/runtime-observation/{field}-v1")
        }
        DefaultResolver::GovernedCatalog { catalog_id } => catalog_id.to_owned(),
        DefaultResolver::Operator { input_id } => input_id.to_owned(),
    }
}

pub(super) fn default_subject(
    resolver: DefaultResolver,
    route: &RouteIdentity,
    authority_digest: &str,
    state: &EvidenceState,
) -> Result<EvidenceSubject, RuntimeResolutionError> {
    Ok(match resolver {
        DefaultResolver::Builtin { .. } => EvidenceSubject::Global,
        DefaultResolver::ModelMetadata { .. }
        | DefaultResolver::ProviderCapability { .. }
        | DefaultResolver::Transport { .. } => EvidenceSubject::Route {
            route: route.clone(),
        },
        DefaultResolver::RuntimeObservation { field } => EvidenceSubject::RuntimeSeam {
            seam: field.to_owned(),
            subject_digest_sha256: evidence_digest("runtime-observation", &(field, state))?,
        },
        DefaultResolver::GovernedCatalog { catalog_id } => {
            let digest_sha256 = match state {
                EvidenceState::Present {
                    value: ResolutionValue::CatalogRef { digest_sha256, .. },
                } => digest_sha256.clone(),
                _ => {
                    return Err(RuntimeResolutionError::InvalidAuthorityDigest(format!(
                        "governed catalog default `{catalog_id}` needs a catalog reference"
                    )));
                }
            };
            EvidenceSubject::Catalog {
                catalog_id: catalog_id.to_owned(),
                digest_sha256,
            }
        }
        DefaultResolver::Operator { .. } => EvidenceSubject::Operator {
            authority_digest_sha256: authority_digest.to_owned(),
        },
        DefaultResolver::Literal => unreachable!("literal defaults reject evidence"),
    })
}

pub(super) fn constraint_subject(
    ceiling: ExternalCeiling,
    route: &RouteIdentity,
    authority_digest: &str,
) -> EvidenceSubject {
    match ceiling {
        ExternalCeiling::OperatorAuthority => EvidenceSubject::Operator {
            authority_digest_sha256: authority_digest.to_owned(),
        },
        ExternalCeiling::ProviderCapability | ExternalCeiling::ContextWindow => {
            EvidenceSubject::Route {
                route: route.clone(),
            }
        }
        other => {
            let seam = match other {
                ExternalCeiling::ParentTurns => "parent_turns",
                ExternalCeiling::ParentTokens => "parent_tokens",
                ExternalCeiling::ParentWall => "parent_wall",
                ExternalCeiling::ParentCost => "parent_cost",
                ExternalCeiling::ToolBudget => "tool_budget",
                ExternalCeiling::ProcessBudget => "process_budget",
                ExternalCeiling::VerificationFloor => "verification_floor",
                ExternalCeiling::TenantScope => "tenant_scope",
                ExternalCeiling::RunBudget => "run_budget",
                ExternalCeiling::BenchmarkProtocol => "benchmark_protocol",
                ExternalCeiling::OperatorAuthority
                | ExternalCeiling::ProviderCapability
                | ExternalCeiling::ContextWindow => unreachable!(),
            };
            EvidenceSubject::RuntimeSeam {
                seam: seam.to_owned(),
                subject_digest_sha256: authority_digest.to_owned(),
            }
        }
    }
}
