use crate::{ReferencedSchema, ReferencedSchemaShape};

pub const ADMITTED_VALUE_CATALOG: &str = "core://tunables/catalogs/admitted-values-v1";
pub const NAMESPACED_ID_SCHEMA: &str = "core://tunables/schemas/namespaced-id-v1";
pub const BOUNDED_MAP_VALUE_SCHEMA: &str = "core://tunables/schemas/bounded-map-value-v1";
pub const BOUNDED_POLICY_SCHEMA: &str = "core://tunables/schemas/bounded-policy-v1";
pub const VERSIONED_CATALOG_ENTRY_SCHEMA: &str =
    "core://tunables/schemas/versioned-catalog-entry-v1";

/// Immutable referenced-schema catalog. URI versions are semantic versions: changing a definition
/// requires a new URI, so a family semantic digest remains sufficient when it includes the URI.
pub const REFERENCED_SCHEMAS: &[ReferencedSchema] = &[
    ReferencedSchema {
        id: ADMITTED_VALUE_CATALOG,
        shape: ReferencedSchemaShape::AdmittedCatalogValue,
        max_bytes: 16 * 1024,
        max_nodes: 64,
        max_depth: 4,
    },
    ReferencedSchema {
        id: NAMESPACED_ID_SCHEMA,
        shape: ReferencedSchemaShape::NamespacedId,
        max_bytes: 512,
        max_nodes: 1,
        max_depth: 1,
    },
    ReferencedSchema {
        id: BOUNDED_MAP_VALUE_SCHEMA,
        shape: ReferencedSchemaShape::BoundedScalarOrObject,
        max_bytes: 64 * 1024,
        max_nodes: 1_024,
        max_depth: 16,
    },
    ReferencedSchema {
        id: BOUNDED_POLICY_SCHEMA,
        shape: ReferencedSchemaShape::BoundedPolicyObject,
        max_bytes: 256 * 1024,
        max_nodes: 4_096,
        max_depth: 32,
    },
    ReferencedSchema {
        id: VERSIONED_CATALOG_ENTRY_SCHEMA,
        shape: ReferencedSchemaShape::VersionedCatalogEntry,
        max_bytes: 256 * 1024,
        max_nodes: 4_096,
        max_depth: 32,
    },
];

pub(crate) fn contains_schema(id: &str) -> bool {
    REFERENCED_SCHEMAS.iter().any(|schema| schema.id == id)
}
