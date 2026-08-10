//! Immutable, content-free identity for the policy checkpoint installed at run genesis.
//!
//! The checkpoint contains only bounded machine identities and application status. Policy code,
//! configuration text, prompts, source, memory, and credentials have no representation here.

use crate::{PolicyRuntimeIdentity, slot::SlotId};
use serde::{Deserialize, Serialize};

pub const RUN_GENESIS_POLICY_BUNDLE_SLOT_COUNT: usize = 9;
pub const MAX_POLICY_IMPLEMENTATION_ID_BYTES: usize = 256;
pub const RUN_GENESIS_POLICY_BUNDLE_CANONICALIZATION: &str =
    "core-run-genesis-policy-bundle-json-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunGenesisPolicyBundleVersion {
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyBundleCoverage {
    Baseline,
    Partial,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySlotApplicationStatus {
    Baseline,
    Applied,
}

/// One fixed-order slot row from the successful compiler receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGenesisPolicySlotBinding {
    pub ordinal: u8,
    pub slot: SlotId,
    pub requested: bool,
    pub status: PolicySlotApplicationStatus,
    pub implementation: String,
    pub policy: PolicyRuntimeIdentity,
}

/// Successful, immutable policy compilation receipt written before any model/tool effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGenesisPolicyBundleSnapshot {
    pub version: RunGenesisPolicyBundleVersion,
    pub canonicalization: String,
    pub bundle_id: String,
    pub bundle_digest_sha256: String,
    pub coverage: PolicyBundleCoverage,
    /// Exactly nine rows in the canonical `core/*` order.
    pub slots: Vec<RunGenesisPolicySlotBinding>,
    /// SHA-256 over the canonical snapshot fields above, excluding this digest itself.
    pub receipt_digest_sha256: String,
}

/// A child/fork binds its copied receipt to the direct parent's actual genesis receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGenesisPolicyBundleInheritance {
    pub parent_run: String,
    pub parent_receipt_digest_sha256: String,
}
