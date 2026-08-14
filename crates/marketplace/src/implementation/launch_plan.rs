use super::{AdmittedImplementation, EvidenceLimits, ImplementationFailurePolicy};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_tunables::ModuleId;
use std::collections::BTreeMap;

/// Registry-minted direct-exec plan bound to one verified implementation and content digest.
///
/// Every field is private: safe callers can clone a plan or inspect it, but cannot fabricate or
/// mix an identity, module, digest, executable, authority ceiling, or resource bound. The registry
/// is the sole constructor. Environment clearing remains explicit so the runtime can fail closed
/// if this type evolves without preserving that invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLaunchPlan {
    implementation_id: String,
    module: ModuleId,
    artifact_sha256: String,
    program: String,
    argv: Vec<String>,
    clear_environment: bool,
    environment: BTreeMap<String, String>,
    protocol_version: u16,
    runtime_deadline_ms: u64,
    cancellation_deadline_ms: u64,
    evidence_limits: EvidenceLimits,
    admitted_capabilities: CapabilitySet,
    failure_policy: ImplementationFailurePolicy,
}

impl ProcessLaunchPlan {
    pub(super) fn mint(
        implementation: &AdmittedImplementation,
        artifact_sha256: String,
        program: String,
    ) -> Self {
        Self {
            implementation_id: implementation.manifest.implementation_id.clone(),
            module: implementation.manifest.module,
            artifact_sha256,
            program,
            argv: implementation.manifest.argv.clone(),
            clear_environment: true,
            environment: BTreeMap::new(),
            protocol_version: implementation.manifest.protocol_version,
            runtime_deadline_ms: implementation.manifest.runtime_deadline_ms,
            cancellation_deadline_ms: implementation.manifest.cancellation_deadline_ms,
            evidence_limits: implementation.manifest.evidence_limits.clone(),
            admitted_capabilities: implementation.admitted_capabilities,
            failure_policy: implementation.manifest.failure_policy,
        }
    }

    #[must_use]
    pub fn implementation_id(&self) -> &str {
        &self.implementation_id
    }

    #[must_use]
    pub fn module(&self) -> ModuleId {
        self.module
    }

    #[must_use]
    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    #[must_use]
    pub fn clears_environment(&self) -> bool {
        self.clear_environment
    }

    #[must_use]
    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    #[must_use]
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    #[must_use]
    pub fn runtime_deadline_ms(&self) -> u64 {
        self.runtime_deadline_ms
    }

    #[must_use]
    pub fn cancellation_deadline_ms(&self) -> u64 {
        self.cancellation_deadline_ms
    }

    #[must_use]
    pub fn evidence_limits(&self) -> &EvidenceLimits {
        &self.evidence_limits
    }

    #[must_use]
    pub fn admitted_capabilities(&self) -> CapabilitySet {
        self.admitted_capabilities
    }

    #[must_use]
    pub fn failure_policy(&self) -> ImplementationFailurePolicy {
        self.failure_policy
    }
}
