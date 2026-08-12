use super::ActiveBundleResolver;
use super::checkpoint::{CompiledPolicyBundle, assemble_compiled_bundle};
use super::registry::{BASELINE_BUNDLE_ID, ImplementationEntry, implementation_catalog, registry};
use super::schema::{
    BundleCompilationReceipt, BundleCompileFailure, BundleCoverage, CoreSlot,
    ImplementationIdentity, RejectedPolicyReceipt, RejectionCode, SlotCompilationReceipt,
    SlotReceiptStatus,
};
use super::strategies::{CompiledSlots, implementation_name};
use crate::config::ConfigOrigin;
use iteron_protocol::bundle::PolicyBundleResolver;
use std::sync::Arc;

/// Compile only a bundle selected by the trusted user configuration. Workspace configuration can
/// carry the same JSON shape, but its origin is refused before any implementation lookup occurs.
pub(crate) fn compile_configured_bundle(
    active: Option<&iteron_evolve::PolicyBundle>,
    origin: ConfigOrigin,
) -> Result<Arc<CompiledPolicyBundle>, BundleCompileFailure> {
    if active.is_some() && origin != ConfigOrigin::UserConfig {
        let mut receipt = baseline_receipt();
        receipt.coverage = BundleCoverage::Rejected;
        if let Some(bundle) = active {
            receipt.bundle_id = Some(bundle.bundle_id.clone());
            receipt.bundle_digest = Some(bundle.digest.clone());
            reject_requests(
                &mut receipt,
                bundle,
                RejectionCode::ProjectSelectionForbidden,
            );
        }
        return Err(BundleCompileFailure {
            code: RejectionCode::ProjectSelectionForbidden,
            receipt,
        });
    }
    compile_operator_bundle(active)
}

pub(crate) fn compile_operator_bundle(
    active: Option<&iteron_evolve::PolicyBundle>,
) -> Result<Arc<CompiledPolicyBundle>, BundleCompileFailure> {
    let implementation_registry = registry().map_err(registry_failure)?;
    let mut receipt = baseline_receipt_with_registry(implementation_registry);
    let Some(bundle) = active else {
        return assemble_compiled_bundle(
            Arc::new(iteron_agents::BootBundle::baseline()),
            CompiledSlots::baseline(),
            receipt,
        );
    };
    receipt.bundle_id = Some(bundle.bundle_id.clone());
    receipt.bundle_digest = Some(bundle.digest.clone());

    if let Err(error) = bundle.validate() {
        let code = if matches!(error, iteron_evolve::ContractError::DuplicateSlot(_)) {
            RejectionCode::DuplicateSlot
        } else {
            RejectionCode::MalformedBundle
        };
        receipt.coverage = BundleCoverage::Rejected;
        reject_requests(&mut receipt, bundle, code);
        return Err(BundleCompileFailure { code, receipt });
    }
    if super::project(bundle).is_err() {
        receipt.coverage = BundleCoverage::Rejected;
        reject_requests(&mut receipt, bundle, RejectionCode::MalformedBundle);
        return Err(BundleCompileFailure {
            code: RejectionCode::MalformedBundle,
            receipt,
        });
    }

    let mut resolutions = Vec::with_capacity(bundle.policies.len());
    let mut rejected = Vec::new();
    let mut policies = bundle.policies.iter().collect::<Vec<_>>();
    policies.sort_by(|left, right| {
        left.slot
            .as_str()
            .cmp(right.slot.as_str())
            .then_with(|| left.policy_id.cmp(&right.policy_id))
            .then_with(|| left.version.cmp(&right.version))
            .then_with(|| left.digest.cmp(&right.digest))
    });
    for policy in policies {
        let Some(slot) = CoreSlot::parse(policy.slot.as_str()) else {
            rejected.push((policy, RejectionCode::UnknownSlot));
            continue;
        };
        match implementation_registry.lookup(
            slot,
            &policy.policy_id,
            &policy.version,
            &policy.digest,
        ) {
            Ok(entry) => resolutions.push((policy, slot, entry)),
            Err(code) => rejected.push((policy, code)),
        }
    }

    if !rejected.is_empty() {
        receipt.coverage = BundleCoverage::Rejected;
        for (policy, slot, _) in &resolutions {
            reject_one(
                &mut receipt,
                policy,
                Some(*slot),
                RejectionCode::AtomicBundleRejected,
            );
        }
        for (policy, code) in &rejected {
            reject_one(
                &mut receipt,
                policy,
                CoreSlot::parse(policy.slot.as_str()),
                *code,
            );
        }
        receipt.rejected_requests.sort_by(rejection_order);
        let code = rejected
            .iter()
            .map(|(_, code)| *code)
            .min()
            .unwrap_or(RejectionCode::AtomicBundleRejected);
        return Err(BundleCompileFailure { code, receipt });
    }

    let mut slots = CompiledSlots::baseline();
    for (policy, slot, entry) in resolutions {
        let implementation = entry.instantiate();
        if implementation.slot().as_persisted_str() != slot.as_str() {
            receipt.coverage = BundleCoverage::Rejected;
            reject_one(
                &mut receipt,
                policy,
                Some(slot),
                RejectionCode::WrongImplementationSlot,
            );
            return Err(BundleCompileFailure {
                code: RejectionCode::WrongImplementationSlot,
                receipt,
            });
        }
        slots.replace(slot, implementation);
        apply_receipt(&mut receipt, policy, slot, entry);
    }
    receipt.coverage = if bundle.policies.len() == CoreSlot::ALL.len() {
        BundleCoverage::Full
    } else {
        BundleCoverage::Partial
    };

    let resolved = ActiveBundleResolver::from_active(Some(bundle.clone()))
        .active_bundle()
        .map_err(|_| malformed_after_lookup(&receipt, bundle))?;
    let resolver = ResolvedOnce(resolved);
    let boot_bundle = iteron_agents::BootBundle::resolve(&resolver)
        .map_err(|_| malformed_after_lookup(&receipt, bundle))?;
    assemble_compiled_bundle(Arc::new(boot_bundle), slots, receipt)
}

pub(crate) fn registered_implementations() -> Result<Vec<ImplementationIdentity>, RejectionCode> {
    implementation_catalog()
}

struct ResolvedOnce(Option<iteron_protocol::bundle::ResolvedBundle>);

impl PolicyBundleResolver for ResolvedOnce {
    fn active_bundle(
        &self,
    ) -> Result<
        Option<iteron_protocol::bundle::ResolvedBundle>,
        iteron_protocol::bundle::BundleResolutionError,
    > {
        Ok(self.0.clone())
    }
}

pub(super) fn baseline_receipt() -> BundleCompilationReceipt {
    match registry() {
        Ok(registry) => baseline_receipt_with_registry(registry),
        Err(_) => BundleCompilationReceipt::baseline(
            CoreSlot::ALL
                .into_iter()
                .map(|slot| {
                    SlotCompilationReceipt::baseline(
                        slot,
                        "baseline".to_owned(),
                        "1".to_owned(),
                        "0".repeat(64),
                        implementation_name(slot, super::schema::ImplementationFlavor::Baseline)
                            .to_owned(),
                    )
                })
                .collect(),
        ),
    }
}

fn baseline_receipt_with_registry(
    registry: &super::registry::ImplementationRegistry,
) -> BundleCompilationReceipt {
    let mut receipt = BundleCompilationReceipt::baseline(
        CoreSlot::ALL
            .into_iter()
            .map(|slot| {
                let entry = registry.baseline(slot);
                SlotCompilationReceipt::baseline(
                    slot,
                    entry.policy_id.clone(),
                    entry.version.clone(),
                    entry.digest.clone(),
                    entry.implementation.clone(),
                )
            })
            .collect(),
    );
    receipt.bundle_id = Some(BASELINE_BUNDLE_ID.to_owned());
    receipt.bundle_digest = Some(registry.baseline_bundle_digest());
    receipt
}

fn apply_receipt(
    receipt: &mut BundleCompilationReceipt,
    policy: &iteron_evolve::PolicyRef,
    slot: CoreSlot,
    entry: &ImplementationEntry,
) {
    let row = &mut receipt.slots[slot_index(slot)];
    row.status = if entry.policy_id == "baseline" {
        SlotReceiptStatus::Baseline
    } else {
        SlotReceiptStatus::Applied
    };
    row.requested = true;
    row.policy_id = Some(policy.policy_id.clone());
    row.version = Some(policy.version.clone());
    row.digest = Some(policy.digest.clone());
    row.implementation = entry.implementation.clone();
    row.rejection = None;
}

fn reject_requests(
    receipt: &mut BundleCompilationReceipt,
    bundle: &iteron_evolve::PolicyBundle,
    code: RejectionCode,
) {
    let mut policies = bundle.policies.iter().collect::<Vec<_>>();
    policies.sort_by(|left, right| {
        left.slot
            .as_str()
            .cmp(right.slot.as_str())
            .then_with(|| left.policy_id.cmp(&right.policy_id))
            .then_with(|| left.version.cmp(&right.version))
            .then_with(|| left.digest.cmp(&right.digest))
    });
    for policy in policies {
        reject_one(receipt, policy, CoreSlot::parse(policy.slot.as_str()), code);
    }
    receipt.rejected_requests.sort_by(rejection_order);
}

fn reject_one(
    receipt: &mut BundleCompilationReceipt,
    policy: &iteron_evolve::PolicyRef,
    slot: Option<CoreSlot>,
    code: RejectionCode,
) {
    if let Some(slot) = slot {
        let row = &mut receipt.slots[slot_index(slot)];
        row.status = SlotReceiptStatus::Rejected;
        row.requested = true;
        row.policy_id = Some(policy.policy_id.clone());
        row.version = Some(policy.version.clone());
        row.digest = Some(policy.digest.clone());
        row.rejection = Some(code);
    }
    receipt.rejected_requests.push(RejectedPolicyReceipt {
        slot: policy.slot.as_str().to_owned(),
        policy_id: policy.policy_id.clone(),
        version: policy.version.clone(),
        digest: policy.digest.clone(),
        rejection: code,
    });
}

fn slot_index(slot: CoreSlot) -> usize {
    CoreSlot::ALL
        .iter()
        .position(|candidate| *candidate == slot)
        .expect("a fixed iteron slot has a fixed receipt row")
}

fn rejection_order(
    left: &RejectedPolicyReceipt,
    right: &RejectedPolicyReceipt,
) -> std::cmp::Ordering {
    left.slot
        .cmp(&right.slot)
        .then_with(|| left.policy_id.cmp(&right.policy_id))
        .then_with(|| left.version.cmp(&right.version))
        .then_with(|| left.digest.cmp(&right.digest))
        .then_with(|| left.rejection.cmp(&right.rejection))
}

fn registry_failure(code: RejectionCode) -> BundleCompileFailure {
    let mut receipt = baseline_receipt();
    receipt.coverage = BundleCoverage::Rejected;
    BundleCompileFailure { code, receipt }
}

fn malformed_after_lookup(
    receipt: &BundleCompilationReceipt,
    bundle: &iteron_evolve::PolicyBundle,
) -> BundleCompileFailure {
    let mut receipt = receipt.clone();
    receipt.coverage = BundleCoverage::Rejected;
    reject_requests(&mut receipt, bundle, RejectionCode::MalformedBundle);
    BundleCompileFailure {
        code: RejectionCode::MalformedBundle,
        receipt,
    }
}
