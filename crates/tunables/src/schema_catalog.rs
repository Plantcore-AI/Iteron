use crate::{ScalarDomain, StringFormat};
use serde::Serialize;

/// Executable leaf contract for an admitted open catalog. Family-owned catalog roots carry their
/// entry schema inline; these definitions cover only catalog-backed scalar selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScalarCatalogDefinition {
    pub id: &'static str,
    pub value_domain: ScalarDomain,
}

const fn namespaced_id() -> ScalarDomain {
    ScalarDomain::Text {
        min_bytes: 1,
        max_bytes: 96,
        format: StringFormat::NamespacedId,
    }
}

/// Immutable, versioned definitions for every scalar catalog ID used by a family schema.
pub const SCALAR_CATALOGS: &[ScalarCatalogDefinition] = &[
    ScalarCatalogDefinition {
        id: "core://tunables/catalogs/providers-v1",
        value_domain: namespaced_id(),
    },
    ScalarCatalogDefinition {
        id: "core://tunables/catalogs/models-v1",
        value_domain: namespaced_id(),
    },
    ScalarCatalogDefinition {
        id: "core://tunables/catalogs/provider-reasoning-levels-v1",
        value_domain: namespaced_id(),
    },
    ScalarCatalogDefinition {
        id: "core://tunables/catalogs/token-estimators-v1",
        value_domain: namespaced_id(),
    },
    ScalarCatalogDefinition {
        id: "core://tunables/catalogs/tool-capabilities-v1",
        value_domain: namespaced_id(),
    },
    ScalarCatalogDefinition {
        id: "core://tunables/catalogs/model-routes-v1",
        value_domain: namespaced_id(),
    },
    ScalarCatalogDefinition {
        id: "core://tunables/catalogs/provider-service-tiers-v1",
        value_domain: namespaced_id(),
    },
    ScalarCatalogDefinition {
        id: "core://tunables/catalogs/agent-roles-v1",
        value_domain: namespaced_id(),
    },
    ScalarCatalogDefinition {
        id: "core://tunables/catalogs/binary-inspectors-v1",
        value_domain: namespaced_id(),
    },
];

pub(crate) fn contains_scalar_catalog(id: &str) -> bool {
    SCALAR_CATALOGS.iter().any(|catalog| catalog.id == id)
}
