//! Complete, provenance-bearing scalar catalogs for production tunables resolution.
//!
//! Values discovered from live composition objects are collected here. Catalogs whose owning
//! subsystem has no query API yet must arrive as an explicit [`CatalogObservation`]; an unknown
//! fact can never collapse into an observed empty set.

use crate::providers::{ModelCapabilities, ModelSelection, ProviderDirectory};
use core_agents::AgentCatalog;
use core_protocol::{Capability as ToolCapability, ReasoningEffort};
use core_provider::Selectability;
use core_tools::Registry;
use core_tunables::{CatalogSnapshot, RuntimeResolutionError, runtime_catalog_snapshot};
use std::collections::{BTreeMap, BTreeSet};

const PROVIDERS: &str = "core://tunables/catalogs/providers-v1";
const MODELS: &str = "core://tunables/catalogs/models-v1";
const REASONING_LEVELS: &str = "core://tunables/catalogs/provider-reasoning-levels-v1";
const TOKEN_ESTIMATORS: &str = "core://tunables/catalogs/token-estimators-v1";
const TOOL_CAPABILITIES: &str = "core://tunables/catalogs/tool-capabilities-v1";
const MODEL_ROUTES: &str = "core://tunables/catalogs/model-routes-v1";
const SERVICE_TIERS: &str = "core://tunables/catalogs/provider-service-tiers-v1";
const AGENT_ROLES: &str = "core://tunables/catalogs/agent-roles-v1";
const BINARY_INSPECTORS: &str = "core://tunables/catalogs/binary-inspectors-v1";

const PROVIDER_DIRECTORY_OWNER: &str = "core-provider:directory-v1";
const PROVIDER_REASONING_OWNER: &str = "core-provider:reasoning-effort-v1";
const TOOL_REGISTRY_OWNER: &str = "core-tools:registry-v1";
const AGENT_CATALOG_OWNER: &str = "core-agents:catalog-v1";
const MAX_CATALOG_VALUES: usize = 4_096;
const MAX_CATALOG_VALUE_BYTES: usize = 96;
const MAX_OWNER_ID_BYTES: usize = 128;

/// Why an owner cannot currently produce a catalog observation. Kept typed so an error cannot
/// accidentally render arbitrary provider output or secret-bearing configuration text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatalogUnavailableReason {
    CapabilityUnknown,
    NotDiscovered,
    NotImplemented,
    OwnerOffline,
    UnsupportedRoute,
}

/// One owner-authored catalog fact. `ObservedEmpty` is deliberately separate from `Observed`:
/// callers cannot pass an empty collection and accidentally assert that unknown means none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CatalogObservation {
    Observed {
        owner_id: String,
        values: BTreeSet<String>,
    },
    ObservedEmpty {
        owner_id: String,
    },
    Missing,
    Unavailable {
        owner_id: String,
        reason: CatalogUnavailableReason,
    },
}

impl CatalogObservation {
    pub(crate) fn observed(
        owner_id: impl Into<String>,
        values: impl IntoIterator<Item = String>,
    ) -> Self {
        Self::Observed {
            owner_id: owner_id.into(),
            values: values.into_iter().collect(),
        }
    }

    pub(crate) fn observed_empty(owner_id: impl Into<String>) -> Self {
        Self::ObservedEmpty {
            owner_id: owner_id.into(),
        }
    }
}

pub(crate) struct ScalarCatalogInput<'a> {
    pub directory: &'a ProviderDirectory,
    pub selection: &'a ModelSelection,
    pub model_capabilities: &'a ModelCapabilities,
    pub registry: &'a Registry,
    pub agent_catalog: &'a AgentCatalog,
    /// Exact estimator IDs exposed by the context owner for this binary.
    pub token_estimators: &'a CatalogObservation,
    /// Exact tier IDs exposed by the selected provider route.
    pub provider_service_tiers: &'a CatalogObservation,
    /// Exact inspector IDs registered by the binary/media owner.
    pub binary_inspectors: &'a CatalogObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservedCatalogState {
    Values(usize),
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogProvenance {
    pub owner_id: String,
    pub state: ObservedCatalogState,
}

/// The exact nine snapshots plus their owner observation state. The resolver consumes
/// `snapshots`; explain/status surfaces may retain `provenance` without reconstructing it.
pub(crate) struct ScalarCatalogFacts {
    snapshots: Vec<CatalogSnapshot>,
    provenance: BTreeMap<String, CatalogProvenance>,
}

impl ScalarCatalogFacts {
    pub(crate) fn snapshots(&self) -> &[CatalogSnapshot] {
        &self.snapshots
    }

    pub(crate) fn provenance(&self) -> &BTreeMap<String, CatalogProvenance> {
        &self.provenance
    }

    pub(crate) fn into_snapshots(self) -> Vec<CatalogSnapshot> {
        self.snapshots
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CatalogFactError {
    #[error("the selected provider is absent from the settled provider directory")]
    UnknownProvider,
    #[error("the selected route is not currently admitted: {0}")]
    RouteBlocked(String),
    #[error("the supplied model capabilities do not match the selected directory route")]
    StaleModelCapabilities,
    #[error("catalog `{catalog_id}` has no owner observation")]
    Missing { catalog_id: &'static str },
    #[error("catalog `{catalog_id}` is unavailable from `{owner_id}` ({reason:?})")]
    Unavailable {
        catalog_id: &'static str,
        owner_id: String,
        reason: CatalogUnavailableReason,
    },
    #[error("catalog `{catalog_id}` used an invalid deterministic owner id")]
    InvalidOwner { catalog_id: &'static str },
    #[error("catalog `{catalog_id}` must use ObservedEmpty for an observed empty set")]
    AmbiguousEmpty { catalog_id: &'static str },
    #[error("catalog `{catalog_id}` exceeds the {MAX_CATALOG_VALUES}-value runtime bound")]
    TooManyValues { catalog_id: &'static str },
    #[error("catalog `{catalog_id}` contains a value outside its bounded namespaced-id domain")]
    InvalidValue { catalog_id: &'static str },
    #[error(transparent)]
    Snapshot(#[from] RuntimeResolutionError),
}

/// Collect all nine scalar catalogs in registry order. This function is atomic: no partial list is
/// returned when any owner fact is missing, unavailable, oversized, or malformed.
pub(crate) fn collect_scalar_catalogs(
    input: ScalarCatalogInput<'_>,
) -> Result<ScalarCatalogFacts, CatalogFactError> {
    let selected_entry = input
        .directory
        .entry(&input.selection.provider_id)
        .ok_or(CatalogFactError::UnknownProvider)?;
    if let Some(reason) = input.directory.blocked_reason(selected_entry).or_else(|| {
        input
            .directory
            .model_blocked_reason(&input.selection.provider_id, &input.selection.model_id)
    }) {
        return Err(CatalogFactError::RouteBlocked(reason));
    }
    if input.directory.selection_capabilities(input.selection) != *input.model_capabilities {
        return Err(CatalogFactError::StaleModelCapabilities);
    }

    let (providers, models, routes) = provider_catalog_values(input.directory, input.selection);
    let reasoning = reasoning_observation(input.model_capabilities);
    let tool_capabilities = input
        .registry
        .specs()
        .into_iter()
        .map(|spec| tool_capability_id(spec.capability).to_owned())
        .collect::<BTreeSet<_>>();
    let roles = input
        .agent_catalog
        .defs()
        .iter()
        .map(|definition| definition.name.clone())
        .collect::<BTreeSet<_>>();

    let observations = [
        (PROVIDERS, observed(PROVIDER_DIRECTORY_OWNER, providers)),
        (MODELS, observed(PROVIDER_DIRECTORY_OWNER, models)),
        (REASONING_LEVELS, reasoning),
        (TOKEN_ESTIMATORS, input.token_estimators.clone()),
        (
            TOOL_CAPABILITIES,
            observed_or_empty(TOOL_REGISTRY_OWNER, tool_capabilities),
        ),
        (MODEL_ROUTES, observed(PROVIDER_DIRECTORY_OWNER, routes)),
        (SERVICE_TIERS, input.provider_service_tiers.clone()),
        (AGENT_ROLES, observed_or_empty(AGENT_CATALOG_OWNER, roles)),
        (BINARY_INSPECTORS, input.binary_inspectors.clone()),
    ];

    let mut snapshots = Vec::with_capacity(observations.len());
    let mut provenance = BTreeMap::new();
    for (catalog_id, observation) in observations {
        let (snapshot, source) = materialize(catalog_id, observation)?;
        snapshots.push(snapshot);
        provenance.insert(catalog_id.to_owned(), source);
    }
    debug_assert_eq!(snapshots.len(), 9);
    Ok(ScalarCatalogFacts {
        snapshots,
        provenance,
    })
}

fn provider_catalog_values(
    directory: &ProviderDirectory,
    selected: &ModelSelection,
) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let mut providers = BTreeSet::new();
    let mut models = BTreeSet::new();
    let mut routes = BTreeSet::new();
    for entry in directory.entries() {
        if directory.blocked_reason(entry).is_some() {
            continue;
        }
        providers.insert(entry.id().to_owned());
        let Some(catalog) = entry.catalog.as_ref().filter(|_| !entry.catalog_stale) else {
            continue;
        };
        for model in &catalog.models {
            if model.selectability != Selectability::Selectable
                || directory
                    .model_blocked_reason(entry.id(), &model.raw.id)
                    .is_some()
            {
                continue;
            }
            models.insert(model.raw.id.clone());
            routes.insert(format!("{}:{}", entry.id(), model.raw.id));
        }
    }
    // An explicitly typed route is real admission evidence even when its provider deliberately has
    // no discovery endpoint. It must therefore appear in the effective scalar catalogs.
    providers.insert(selected.provider_id.clone());
    models.insert(selected.model_id.clone());
    routes.insert(format!("{}:{}", selected.provider_id, selected.model_id));
    (providers, models, routes)
}

fn reasoning_observation(model: &ModelCapabilities) -> CatalogObservation {
    match model.semantic_effort {
        Some(true) => observed(
            PROVIDER_REASONING_OWNER,
            [
                ReasoningEffort::Low,
                ReasoningEffort::Medium,
                ReasoningEffort::High,
                ReasoningEffort::XHigh,
                ReasoningEffort::Max,
            ]
            .into_iter()
            .map(|effort| effort.label().to_owned())
            .collect(),
        ),
        Some(false) => CatalogObservation::observed_empty(PROVIDER_REASONING_OWNER),
        // Route admission is the authoritative boundary here. An explicitly admitted route whose
        // discovery metadata does not attest semantic-effort control exposes no selectable effort
        // levels in this process. This is an owner-observed empty catalog, not a claim about every
        // capability the remote service might have and not an unavailable fact that should abort
        // unrelated runs.
        None => CatalogObservation::observed_empty(PROVIDER_REASONING_OWNER),
    }
}

fn observed(owner_id: &str, values: BTreeSet<String>) -> CatalogObservation {
    CatalogObservation::Observed {
        owner_id: owner_id.to_owned(),
        values,
    }
}

fn observed_or_empty(owner_id: &str, values: BTreeSet<String>) -> CatalogObservation {
    if values.is_empty() {
        CatalogObservation::observed_empty(owner_id)
    } else {
        observed(owner_id, values)
    }
}

fn materialize(
    catalog_id: &'static str,
    observation: CatalogObservation,
) -> Result<(CatalogSnapshot, CatalogProvenance), CatalogFactError> {
    let (owner_id, values, state) = match observation {
        CatalogObservation::Observed {
            owner_id: _,
            values,
        } if values.is_empty() => {
            return Err(CatalogFactError::AmbiguousEmpty { catalog_id });
        }
        CatalogObservation::Observed { owner_id, values } => {
            let count = values.len();
            (owner_id, values, ObservedCatalogState::Values(count))
        }
        CatalogObservation::ObservedEmpty { owner_id } => {
            (owner_id, BTreeSet::new(), ObservedCatalogState::Empty)
        }
        CatalogObservation::Missing => return Err(CatalogFactError::Missing { catalog_id }),
        CatalogObservation::Unavailable { owner_id, reason } => {
            validate_owner(catalog_id, &owner_id)?;
            return Err(CatalogFactError::Unavailable {
                catalog_id,
                owner_id,
                reason,
            });
        }
    };
    validate_owner(catalog_id, &owner_id)?;
    validate_values(catalog_id, &values)?;
    let snapshot = runtime_catalog_snapshot(catalog_id, values)?;
    Ok((snapshot, CatalogProvenance { owner_id, state }))
}

fn validate_owner(catalog_id: &'static str, owner_id: &str) -> Result<(), CatalogFactError> {
    let valid = !owner_id.is_empty()
        && owner_id.len() <= MAX_OWNER_ID_BYTES
        && owner_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'+')
        });
    valid
        .then_some(())
        .ok_or(CatalogFactError::InvalidOwner { catalog_id })
}

fn validate_values(
    catalog_id: &'static str,
    values: &BTreeSet<String>,
) -> Result<(), CatalogFactError> {
    if values.len() > MAX_CATALOG_VALUES {
        return Err(CatalogFactError::TooManyValues { catalog_id });
    }
    let valid = values.iter().all(|value| {
        !value.is_empty()
            && value.len() <= MAX_CATALOG_VALUE_BYTES
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
            })
    });
    valid
        .then_some(())
        .ok_or(CatalogFactError::InvalidValue { catalog_id })
}

const fn tool_capability_id(capability: ToolCapability) -> &'static str {
    match capability {
        ToolCapability::ReadOnly => "read_only",
        ToolCapability::ReversibleLocal => "reversible_local",
        ToolCapability::CodeExecuting => "code_executing",
        ToolCapability::TrustMutating => "trust_mutating",
        ToolCapability::IrreversibleExternal => "irreversible_external",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_admitted_route_without_effort_attestation_exposes_an_empty_catalog() {
        let observation = reasoning_observation(&ModelCapabilities {
            context_window_tokens: None,
            max_output_tokens: None,
            tool_calling: None,
            semantic_effort: None,
            image_input: None,
            image_input_version: None,
            image_input_source: None,
            version: None,
            source: None,
        });
        let (snapshot, provenance) = materialize(REASONING_LEVELS, observation).unwrap();

        assert!(snapshot.values.is_empty());
        assert_eq!(provenance.owner_id, PROVIDER_REASONING_OWNER);
        assert_eq!(provenance.state, ObservedCatalogState::Empty);
    }
}
