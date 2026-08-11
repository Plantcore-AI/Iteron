use super::compiler::compile_operator_bundle;
use super::schema::{
    BundleCompilationReceipt, BundleCompileFailure, BundleCoverage, SlotReceiptStatus,
};
use super::strategies::CompiledSlots;
use crate::runtime::policy_evidence_recorder::FrozenSlotPolicyBinding;
use iteron_protocol::{
    PolicyBundleCoverage as GenesisCoverage, PolicyRuntimeIdentity, PolicySlotApplicationStatus,
    RUN_GENESIS_POLICY_BUNDLE_CANONICALIZATION, RunGenesisPolicyBundleSnapshot,
    RunGenesisPolicyBundleVersion, RunGenesisPolicySlotBinding, slot::SlotId,
};
use std::sync::{Arc, OnceLock};

pub(crate) struct CompiledPolicyBundle {
    boot_bundle: Arc<iteron_agents::BootBundle>,
    slots: CompiledSlots,
    receipt: BundleCompilationReceipt,
    runtime_bindings: Vec<FrozenSlotPolicyBinding>,
    genesis_snapshot: RunGenesisPolicyBundleSnapshot,
}

impl std::fmt::Debug for CompiledPolicyBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledPolicyBundle")
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

impl CompiledPolicyBundle {
    pub(crate) fn boot_bundle(&self) -> Arc<iteron_agents::BootBundle> {
        self.boot_bundle.clone()
    }

    pub(crate) fn receipt(&self) -> &BundleCompilationReceipt {
        &self.receipt
    }

    pub(crate) fn slots(&self) -> &CompiledSlots {
        &self.slots
    }

    /// Fixed-order immutable identities consumed directly by the run-local evidence recorder.
    /// Baseline rows are fully identified too; absence of a promoted bundle is not an unknown
    /// policy generation.
    pub(crate) fn policy_runtime_bindings(&self) -> &[FrozenSlotPolicyBinding] {
        &self.runtime_bindings
    }

    pub(crate) fn genesis_snapshot(&self) -> &RunGenesisPolicyBundleSnapshot {
        &self.genesis_snapshot
    }
}

/// Process-cached built-in checkpoint used while composition is being assembled. A promoted
/// checkpoint replaces this atomically before turn zero; children always inherit the parent's Arc.
pub(crate) fn baseline_compiled_bundle() -> Arc<CompiledPolicyBundle> {
    static BASELINE: OnceLock<Arc<CompiledPolicyBundle>> = OnceLock::new();
    BASELINE
        .get_or_init(|| {
            compile_operator_bundle(None)
                .expect("the source-controlled baseline policy registry must compile")
        })
        .clone()
}

/// Reconstruct an executable checkpoint only from the complete, validated genesis identity. The
/// current user configuration is deliberately absent from this API, so resume cannot drift to a
/// newly selected bundle.
pub(crate) fn compile_recorded_bundle(
    snapshot: &RunGenesisPolicyBundleSnapshot,
) -> Result<Arc<CompiledPolicyBundle>, BundleCompileFailure> {
    iteron_record::validate_policy_bundle_snapshot(snapshot)
        .map_err(|_| malformed_snapshot_failure())?;
    let compiled = match snapshot.coverage {
        GenesisCoverage::Baseline => compile_operator_bundle(None)?,
        GenesisCoverage::Partial | GenesisCoverage::Full => {
            let policies = snapshot
                .slots
                .iter()
                .filter(|row| row.requested)
                .map(|row| {
                    Ok(iteron_evolve::PolicyRef {
                        slot: iteron_evolve::StrategySlot::new(row.slot.as_persisted_str())
                            .map_err(|_| malformed_snapshot_failure())?,
                        policy_id: row.policy.policy_id.clone(),
                        version: row.policy.policy_version.clone(),
                        digest: row.policy.policy_digest_sha256.clone(),
                    })
                })
                .collect::<Result<Vec<_>, BundleCompileFailure>>()?;
            compile_operator_bundle(Some(&iteron_evolve::PolicyBundle {
                bundle_id: snapshot.bundle_id.clone(),
                digest: snapshot.bundle_digest_sha256.clone(),
                policies,
                rollback_to: None,
            }))?
        }
    };
    if compiled.genesis_snapshot() != snapshot {
        return Err(malformed_snapshot_failure());
    }
    Ok(compiled)
}

pub(crate) fn install_compiled_bundle(
    agent: &mut crate::runtime::Agent,
    compiled: Arc<CompiledPolicyBundle>,
) -> Result<(), crate::runtime::KernelError> {
    agent.install_compiled_policy_bundle(compiled)
}

pub(super) fn assemble_compiled_bundle(
    boot_bundle: Arc<iteron_agents::BootBundle>,
    slots: CompiledSlots,
    receipt: BundleCompilationReceipt,
) -> Result<Arc<CompiledPolicyBundle>, BundleCompileFailure> {
    let runtime_bindings = bindings_from_receipt(&receipt);
    let genesis_snapshot = snapshot_from_receipt(&receipt, &runtime_bindings).map_err(|_| {
        let mut failed = receipt.clone();
        failed.coverage = BundleCoverage::Rejected;
        BundleCompileFailure {
            code: super::schema::RejectionCode::MalformedBundle,
            receipt: failed,
        }
    })?;
    Ok(Arc::new(CompiledPolicyBundle {
        boot_bundle,
        slots,
        receipt,
        runtime_bindings,
        genesis_snapshot,
    }))
}

fn snapshot_from_receipt(
    receipt: &BundleCompilationReceipt,
    bindings: &[FrozenSlotPolicyBinding],
) -> Result<RunGenesisPolicyBundleSnapshot, iteron_record::PolicyBundleCheckpointError> {
    let coverage = match receipt.coverage {
        BundleCoverage::Baseline => GenesisCoverage::Baseline,
        BundleCoverage::Partial => GenesisCoverage::Partial,
        BundleCoverage::Full => GenesisCoverage::Full,
        BundleCoverage::Rejected => {
            return Err(iteron_record::PolicyBundleCheckpointError::Invalid(
                "a rejected bundle cannot become run genesis",
            ));
        }
    };
    let slots = receipt
        .slots
        .iter()
        .zip(bindings)
        .enumerate()
        .map(|(index, (row, binding))| {
            let status = match row.status {
                SlotReceiptStatus::Baseline => PolicySlotApplicationStatus::Baseline,
                SlotReceiptStatus::Applied => PolicySlotApplicationStatus::Applied,
                SlotReceiptStatus::Rejected => {
                    return Err(iteron_record::PolicyBundleCheckpointError::Invalid(
                        "a rejected slot cannot become run genesis",
                    ));
                }
            };
            Ok(RunGenesisPolicySlotBinding {
                ordinal: u8::try_from(index + 1).map_err(|_| {
                    iteron_record::PolicyBundleCheckpointError::Invalid("slot ordinal overflow")
                })?,
                slot: binding.slot.clone(),
                requested: row.requested,
                status,
                implementation: row.implementation.clone(),
                policy: binding.policy.clone(),
            })
        })
        .collect::<Result<Vec<_>, iteron_record::PolicyBundleCheckpointError>>()?;
    iteron_record::seal_policy_bundle_snapshot(RunGenesisPolicyBundleSnapshot {
        version: RunGenesisPolicyBundleVersion::V1,
        canonicalization: RUN_GENESIS_POLICY_BUNDLE_CANONICALIZATION.to_owned(),
        bundle_id: receipt.bundle_id.clone().ok_or(
            iteron_record::PolicyBundleCheckpointError::Invalid(
                "compiled receipt has no bundle id",
            ),
        )?,
        bundle_digest_sha256: receipt.bundle_digest.clone().ok_or(
            iteron_record::PolicyBundleCheckpointError::Invalid(
                "compiled receipt has no bundle digest",
            ),
        )?,
        coverage,
        slots,
        receipt_digest_sha256: String::new(),
    })
}

fn bindings_from_receipt(receipt: &BundleCompilationReceipt) -> Vec<FrozenSlotPolicyBinding> {
    let bundle_id = receipt
        .bundle_id
        .clone()
        .expect("every successfully compiled checkpoint has a bundle id");
    let bundle_digest_sha256 = receipt
        .bundle_digest
        .clone()
        .expect("every successfully compiled checkpoint has a bundle digest");
    receipt
        .slots
        .iter()
        .map(|row| FrozenSlotPolicyBinding {
            slot: SlotId(row.slot.clone()),
            policy: PolicyRuntimeIdentity {
                bundle_id: bundle_id.clone(),
                bundle_digest_sha256: bundle_digest_sha256.clone(),
                policy_id: row
                    .policy_id
                    .clone()
                    .expect("every compiled slot has a policy id"),
                policy_version: row
                    .version
                    .clone()
                    .expect("every compiled slot has a policy version"),
                policy_digest_sha256: row
                    .digest
                    .clone()
                    .expect("every compiled slot has a policy digest"),
            },
        })
        .collect()
}

fn malformed_snapshot_failure() -> BundleCompileFailure {
    let mut receipt = super::compiler::baseline_receipt();
    receipt.coverage = BundleCoverage::Rejected;
    BundleCompileFailure {
        code: super::schema::RejectionCode::MalformedBundle,
        receipt,
    }
}
