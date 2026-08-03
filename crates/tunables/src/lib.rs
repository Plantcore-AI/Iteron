//! Versioned, non-authoritative metadata for Core's tunable semantic families.
//!
//! Boundary: this crate describes knobs; it does not read configuration, choose values, mutate the
//! runtime, load a policy bundle, or grant authority. Security, permission, durability, replay,
//! budget, and effect-ledger guarantees remain outside the learnable policy surface. Consumers may
//! use the registry for analysis and offline candidate generation, but the runtime remains the sole
//! authority for admitting any resulting value.
//!
//! Invariants:
//! - the public registry contains exactly [`EXPECTED_FAMILY_COUNT`] stable family identities;
//! - its canonical payload has one versioned byte representation and SHA-256 digest;
//! - every family declares a typed value domain, default provenance, explicit availability,
//!   benchmark relevance, and trainability;
//! - metadata never silently turns an invariant or operator ceiling into an adaptive choice.

mod canonical;
mod families;
mod types;
mod validate;
mod value_schemas;

pub use canonical::{
    CanonicalArtifact, CanonicalDigest, CanonicalPayload, canonical_artifact,
    canonical_artifact_json, canonical_payload_json, registry_digest,
};
pub use families::families;
pub use types::{
    Availability, BenchmarkImpact, BenchmarkRelevance, DefaultKind, DefaultSpec, Domain, Family,
    SourceKind, SourceSpec, Trainability, ValueKind, ValueSchema,
};
pub use validate::{RegistryError, validate_registry};

/// Registry DTO schema. A breaking field or semantic change requires a new version.
pub const REGISTRY_SCHEMA_VERSION: u16 = 1;
/// Stable logical registry identity.
pub const REGISTRY_ID: &str = "core-tunables";
/// Revision of the family set under schema v1.
pub const REGISTRY_REVISION: u16 = 1;
/// Exact family cardinality required by the R0/R1 contract.
pub const EXPECTED_FAMILY_COUNT: usize = 160;
/// Canonical byte encoding used as the digest input.
pub const CANONICALIZATION: &str = "core-tunables-json-v1";
/// Digest algorithm for canonical artifacts.
pub const DIGEST_ALGORITHM: &str = "sha256";
/// Golden digest for revision 1; metadata changes require an explicit revision and digest update.
pub const REGISTRY_DIGEST_SHA256: &str =
    "244ab0cf6b25b3404f35ebc849e079cc52c72656eeac4c06bef72ff55a4f10ea";
