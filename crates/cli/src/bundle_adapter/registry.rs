use super::schema::{
    CoreSlot, IMPLEMENTATION_ARTIFACT_SCHEMA_VERSION, ImplementationArtifact, ImplementationFlavor,
    ImplementationIdentity, MAX_IMPLEMENTATION_ARTIFACT_BYTES, MAX_REGISTERED_IMPLEMENTATIONS,
    RejectionCode,
};
use super::strategies::{implementation_name, instantiate};
use iteron_protocol::slot::StrategySlot;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

pub(crate) const BASELINE_BUNDLE_ID: &str = "core-baseline-v1";

#[derive(Debug, Clone, Copy)]
struct Descriptor {
    slot: CoreSlot,
    policy_id: &'static str,
    version: &'static str,
    implementation: &'static str,
    flavor: ImplementationFlavor,
}

impl Descriptor {
    const fn baseline(slot: CoreSlot) -> Self {
        Self {
            slot,
            policy_id: "baseline",
            version: "1",
            implementation: implementation_name(slot, ImplementationFlavor::Baseline),
            flavor: ImplementationFlavor::Baseline,
        }
    }

    const fn alternative(
        slot: CoreSlot,
        policy_id: &'static str,
        implementation: &'static str,
    ) -> Self {
        Self {
            slot,
            policy_id,
            version: "1",
            implementation,
            flavor: ImplementationFlavor::Alternative,
        }
    }
}

const DESCRIPTORS: [Descriptor; 19] = [
    Descriptor::baseline(CoreSlot::Context),
    Descriptor::alternative(CoreSlot::Context, "minimal-context", "context.minimal.v1"),
    Descriptor::baseline(CoreSlot::ToolPolicy),
    Descriptor::alternative(
        CoreSlot::ToolPolicy,
        "read-only-tools",
        "tool_policy.read_only.v1",
    ),
    // Compatibility identity already emitted by the evolution demo. Registry narrowing, owned by
    // `BootBundle`, is the implementation; the frozen tool-policy decision remains the baseline.
    Descriptor {
        slot: CoreSlot::ToolPolicy,
        policy_id: "prefer-structural-search",
        version: "1",
        implementation: "tool_policy.prefer_structural_search.v1",
        flavor: ImplementationFlavor::Baseline,
    },
    Descriptor::baseline(CoreSlot::Memory),
    Descriptor::alternative(
        CoreSlot::Memory,
        "single-memory-recall",
        "memory.single_recall.v1",
    ),
    Descriptor::baseline(CoreSlot::Router),
    Descriptor::alternative(CoreSlot::Router, "direct-only", "router.direct_only.v1"),
    Descriptor::baseline(CoreSlot::Planner),
    Descriptor::alternative(CoreSlot::Planner, "single-leaf", "planner.single_leaf.v1"),
    Descriptor::baseline(CoreSlot::Collaboration),
    Descriptor::alternative(
        CoreSlot::Collaboration,
        "serial-collaboration",
        "collaboration.serial.v1",
    ),
    Descriptor::baseline(CoreSlot::Scheduler),
    Descriptor::alternative(
        CoreSlot::Scheduler,
        "serial-scheduler",
        "scheduler.serial.v1",
    ),
    Descriptor::baseline(CoreSlot::Verifier),
    Descriptor::alternative(
        CoreSlot::Verifier,
        "workspace-gate",
        "verifier.workspace_gate.v1",
    ),
    Descriptor::baseline(CoreSlot::ModelRouter),
    Descriptor::alternative(
        CoreSlot::ModelRouter,
        "bound-route-only",
        "model_router.bound_route.v1",
    ),
];

pub(crate) struct ImplementationEntry {
    pub slot: CoreSlot,
    pub policy_id: String,
    pub version: String,
    pub digest: String,
    pub implementation: String,
    pub flavor: ImplementationFlavor,
    artifact: Vec<u8>,
}

impl ImplementationEntry {
    pub(crate) fn instantiate(&self) -> Arc<dyn StrategySlot> {
        instantiate(self.slot, self.flavor)
    }

    fn identity(&self) -> ImplementationIdentity {
        ImplementationIdentity {
            slot: self.slot.as_str().to_owned(),
            policy_id: self.policy_id.clone(),
            version: self.version.clone(),
            digest: self.digest.clone(),
            implementation: self.implementation.clone(),
            artifact_bytes: u32::try_from(self.artifact.len()).unwrap_or(u32::MAX),
            baseline: self.flavor == ImplementationFlavor::Baseline && self.policy_id == "baseline",
        }
    }
}

pub(crate) struct ImplementationRegistry {
    entries: Vec<ImplementationEntry>,
}

impl ImplementationRegistry {
    fn build() -> Result<Self, RejectionCode> {
        if DESCRIPTORS.len()
            > iteron_tunables::param_integer(
                "cli.bundle_adapter.schema.max_registered_implementations",
                MAX_REGISTERED_IMPLEMENTATIONS,
            )
        {
            return Err(RejectionCode::RegistryBoundExceeded);
        }
        let mut entries = Vec::with_capacity(DESCRIPTORS.len());
        let mut identities = BTreeSet::new();
        for descriptor in DESCRIPTORS {
            let artifact = ImplementationArtifact {
                schema_version: IMPLEMENTATION_ARTIFACT_SCHEMA_VERSION,
                slot: descriptor.slot.as_str().to_owned(),
                policy_id: descriptor.policy_id.to_owned(),
                version: descriptor.version.to_owned(),
                implementation: descriptor.implementation.to_owned(),
            };
            validate_artifact(&artifact)?;
            let bytes =
                serde_json::to_vec(&artifact).map_err(|_| RejectionCode::MalformedArtifact)?;
            if bytes.len()
                > iteron_tunables::param_integer(
                    "cli.bundle_adapter.schema.max_implementation_artifact_bytes",
                    MAX_IMPLEMENTATION_ARTIFACT_BYTES,
                )
            {
                return Err(RejectionCode::MalformedArtifact);
            }
            let round_trip: ImplementationArtifact =
                serde_json::from_slice(&bytes).map_err(|_| RejectionCode::MalformedArtifact)?;
            if round_trip != artifact
                || serde_json::to_vec(&round_trip).ok().as_deref() != Some(bytes.as_slice())
            {
                return Err(RejectionCode::MalformedArtifact);
            }
            let identity = (descriptor.slot, descriptor.policy_id, descriptor.version);
            if !identities.insert(identity) {
                return Err(RejectionCode::DuplicateImplementation);
            }
            entries.push(ImplementationEntry {
                slot: descriptor.slot,
                policy_id: descriptor.policy_id.to_owned(),
                version: descriptor.version.to_owned(),
                digest: hex::encode(Sha256::digest(&bytes)),
                implementation: descriptor.implementation.to_owned(),
                flavor: descriptor.flavor,
                artifact: bytes,
            });
        }
        Ok(Self { entries })
    }

    pub(crate) fn lookup(
        &self,
        slot: CoreSlot,
        policy_id: &str,
        version: &str,
        digest: &str,
    ) -> Result<&ImplementationEntry, RejectionCode> {
        let matching_identity = self
            .entries
            .iter()
            .filter(|entry| entry.slot == slot && entry.policy_id == policy_id)
            .collect::<Vec<_>>();
        if matching_identity.is_empty() {
            return Err(RejectionCode::UnknownImplementation);
        }
        let Some(entry) = matching_identity
            .into_iter()
            .find(|entry| entry.version == version)
        else {
            return Err(RejectionCode::UnknownVersion);
        };
        if entry.digest != digest {
            return Err(RejectionCode::DigestMismatch);
        }
        Ok(entry)
    }

    pub(crate) fn baseline(&self, slot: CoreSlot) -> &ImplementationEntry {
        self.entries
            .iter()
            .find(|entry| entry.slot == slot && entry.policy_id == "baseline")
            .expect("the validated fixed registry contains every baseline")
    }

    /// Stable identity for the built-in nine-slot checkpoint. Even an operator who selected no
    /// promoted bundle gets one fully identified policy generation; policy evidence must never
    /// use `None` as a synonym for an unknown baseline.
    pub(crate) fn baseline_bundle_digest(&self) -> String {
        let identities = CoreSlot::ALL.map(|slot| {
            let entry = self.baseline(slot);
            (
                slot.as_str(),
                entry.policy_id.as_str(),
                entry.version.as_str(),
                entry.digest.as_str(),
                entry.implementation.as_str(),
            )
        });
        let canonical = serde_json::to_vec(&identities)
            .expect("the fixed baseline identity tuple is JSON representable");
        hex::encode(Sha256::digest(canonical))
    }

    fn catalog(&self) -> Vec<ImplementationIdentity> {
        self.entries
            .iter()
            .map(ImplementationEntry::identity)
            .collect()
    }
}

fn validate_artifact(artifact: &ImplementationArtifact) -> Result<(), RejectionCode> {
    if artifact.schema_version != IMPLEMENTATION_ARTIFACT_SCHEMA_VERSION
        || CoreSlot::parse(&artifact.slot).is_none()
        || artifact.policy_id.is_empty()
        || artifact.policy_id.len() > 256
        || artifact.version.is_empty()
        || artifact.version.len() > 256
        || artifact.implementation.is_empty()
        || artifact.implementation.len() > 256
        || artifact
            .policy_id
            .chars()
            .chain(artifact.version.chars())
            .chain(artifact.implementation.chars())
            .any(char::is_control)
    {
        return Err(RejectionCode::MalformedArtifact);
    }
    Ok(())
}

pub(crate) fn registry() -> Result<&'static ImplementationRegistry, RejectionCode> {
    static REGISTRY: OnceLock<Result<ImplementationRegistry, RejectionCode>> = OnceLock::new();
    match REGISTRY.get_or_init(ImplementationRegistry::build) {
        Ok(registry) => Ok(registry),
        Err(code) => Err(*code),
    }
}

pub(crate) fn implementation_catalog() -> Result<Vec<ImplementationIdentity>, RejectionCode> {
    registry().map(ImplementationRegistry::catalog)
}
