use super::external_consumption::{ConsumptionLedger, Stage};
use super::external_mapping::{ModulePort, module_port_for};
use super::schema::{
    BundleCompilationReceipt, BundleCompileFailure, BundleCoverage, CoreSlot,
    RejectedPolicyReceipt, RejectionCode, SlotReceiptStatus,
};
use super::strategies::CompiledSlots;
use crate::plugin_runtime::VerifiedImplementationActivation;
use iteron_marketplace::{
    ImplementationActivation, ImplementationRuntime, MAX_IMPLEMENTATION_PAYLOAD_BYTES,
    ProcessLaunchPlan, RuntimeState,
};
use iteron_protocol::Capability;
use iteron_protocol::RunGenesisPolicyBundleSnapshot;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot};
use iteron_tunables::ModuleId;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

pub(super) fn apply_external_activation(
    verified: &VerifiedImplementationActivation,
    runs_dir: &Path,
    cli_run_id: &str,
    slots: &mut CompiledSlots,
    receipt: &mut BundleCompilationReceipt,
) -> Result<(), BundleCompileFailure> {
    let activation = verified.activation();
    let mut resolved = Vec::with_capacity(activation.len());
    for module in ModuleId::ALL {
        let Some(plan) = activation.plan(module) else {
            continue;
        };
        let slot = module_port_for(module).core_slot;
        let Some(identity) = activation.identity(module) else {
            return Err(reject_external(
                receipt,
                module,
                RejectionCode::ExternalIdentityMismatch,
            ));
        };
        if identity.implementation_id() != plan.implementation_id()
            || identity.artifact_sha256().strip_prefix("sha256:") != Some(plan.artifact_sha256())
            || (verified.is_plugin_governed()
                && !plan
                    .admitted_capabilities()
                    .contains(Capability::CodeExecuting))
        {
            return Err(reject_external(
                receipt,
                module,
                RejectionCode::ExternalIdentityMismatch,
            ));
        }
        resolved.push((module, slot, plan.clone()));
    }
    for (module, slot, _) in &resolved {
        let row = &receipt.slots[slot_index(*slot)];
        if row.requested && !receipt_row_is_external(row) {
            return Err(reject_external(
                receipt,
                *module,
                RejectionCode::ExternalIdentityMismatch,
            ));
        }
    }
    let ledger = ConsumptionLedger::new(
        runs_dir,
        activation.candidate_sha256(),
        verified.activation_sha256(),
        cli_run_id,
        &resolved,
    )
    .map_err(|_| {
        reject_external(
            receipt,
            resolved
                .first()
                .map(|row| row.0)
                .unwrap_or(ModuleId::ContextAssembly),
            RejectionCode::ExternalReceiptUnavailable,
        )
    })?;

    let mut chains: Vec<(CoreSlot, Vec<ExternalModule>)> = Vec::new();
    for (module, slot, plan) in resolved {
        let entry = ExternalModule {
            module,
            plan,
            port: module_port_for(module),
        };
        if let Some((_, modules)) = chains.iter_mut().find(|(candidate, _)| *candidate == slot) {
            modules.push(entry);
        } else {
            chains.push((slot, vec![entry]));
        }
    }
    for (slot, chain) in chains {
        let (implementation, manifest, artifact) = aggregate_receipt(activation, &chain);
        let baseline = slots.get(slot);
        slots.replace(
            slot,
            Arc::new(ExternalStrategySlot::new(
                slot,
                chain,
                activation.candidate_sha256().to_owned(),
                ledger.clone(),
                baseline,
            )),
        );
        let row = &mut receipt.slots[slot_index(slot)];
        row.status = SlotReceiptStatus::Applied;
        row.requested = true;
        row.policy_id = Some(format!("external-manifest:{manifest}"));
        row.version = Some(format!("external-artifact:{artifact}"));
        row.digest = Some(bare_digest(activation.candidate_sha256()).to_owned());
        row.implementation = implementation;
        row.rejection = None;
    }
    let requested = receipt.slots.iter().filter(|row| row.requested).count();
    receipt.coverage = if requested == CoreSlot::ALL.len() {
        BundleCoverage::Full
    } else {
        BundleCoverage::Partial
    };
    receipt.bundle_digest = Some(external_bundle_digest(
        receipt,
        verified.activation_sha256(),
    ));
    Ok(())
}

pub(super) fn snapshot_has_external(snapshot: &RunGenesisPolicyBundleSnapshot) -> bool {
    snapshot.slots.iter().any(snapshot_external_row)
}

pub(super) fn snapshot_external_row(row: &iteron_protocol::RunGenesisPolicySlotBinding) -> bool {
    row.policy.policy_id.starts_with("external-manifest:")
        && row.policy.policy_version.starts_with("external-artifact:")
}

fn receipt_row_is_external(row: &super::schema::SlotCompilationReceipt) -> bool {
    matches!(
        (row.policy_id.as_deref(), row.version.as_deref()),
        (Some(policy), Some(version))
            if policy.starts_with("external-manifest:")
                && version.starts_with("external-artifact:")
    )
}

fn reject_external(
    receipt: &BundleCompilationReceipt,
    module: ModuleId,
    code: RejectionCode,
) -> BundleCompileFailure {
    let mut receipt = receipt.clone();
    receipt.coverage = BundleCoverage::Rejected;
    receipt.rejected_requests.push(RejectedPolicyReceipt {
        slot: module.as_str().to_owned(),
        policy_id: "external".to_owned(),
        version: "1".to_owned(),
        digest: "0".repeat(64),
        rejection: code,
    });
    BundleCompileFailure { code, receipt }
}

fn external_bundle_digest(receipt: &BundleCompilationReceipt, activation_sha256: &str) -> String {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema: &'static str,
        activation_sha256: &'a str,
        bundle_id: &'a str,
        slots: &'a [super::schema::SlotCompilationReceipt],
    }
    let bytes = serde_json::to_vec(&DigestInput {
        schema: "iteron-external-policy-bundle/1",
        activation_sha256,
        bundle_id: receipt.bundle_id.as_deref().unwrap_or("core-baseline-v1"),
        slots: &receipt.slots,
    })
    .expect("bounded external receipt serializes");
    hex::encode(sha2::Sha256::digest(bytes))
}

fn bare_digest(value: &str) -> &str {
    value.strip_prefix("sha256:").unwrap_or(value)
}

fn aggregate_receipt(
    activation: &ImplementationActivation,
    chain: &[ExternalModule],
) -> (String, String, String) {
    if let [entry] = chain {
        let identity = activation
            .identity(entry.module)
            .expect("verified activation keeps every plan identity");
        return (
            entry.plan.implementation_id().to_owned(),
            bare_digest(identity.manifest_sha256()).to_owned(),
            bare_digest(identity.artifact_sha256()).to_owned(),
        );
    }
    let aggregate = aggregate_digest(activation, chain);
    (
        format!("external-chain:{}:{aggregate}", chain.len()),
        aggregate.clone(),
        aggregate,
    )
}

fn aggregate_digest(activation: &ImplementationActivation, chain: &[ExternalModule]) -> String {
    #[derive(Serialize)]
    struct Aggregate<'a> {
        schema_id: &'static str,
        entries: Vec<AggregateEntry<'a>>,
    }
    #[derive(Serialize)]
    struct AggregateEntry<'a> {
        module: ModuleId,
        implementation_id: &'a str,
        manifest_sha256: &'a str,
        artifact_sha256: &'a str,
    }
    let entries = chain
        .iter()
        .map(|entry| {
            let identity = activation
                .identity(entry.module)
                .expect("verified activation keeps every plan identity");
            AggregateEntry {
                module: entry.module,
                implementation_id: entry.plan.implementation_id(),
                manifest_sha256: identity.manifest_sha256(),
                artifact_sha256: identity.artifact_sha256(),
            }
        })
        .collect();
    let bytes = serde_json::to_vec(&Aggregate {
        schema_id: "iteron-external-slot-chain/1",
        entries,
    })
    .expect("verified bounded chain identity serializes");
    hex::encode(sha2::Sha256::digest(bytes))
}

fn slot_index(slot: CoreSlot) -> usize {
    CoreSlot::ALL
        .iter()
        .position(|candidate| *candidate == slot)
        .expect("fixed slot has a fixed receipt row")
}

struct ExternalStrategySlot {
    slot: SlotId,
    core_slot: CoreSlot,
    chain: Vec<ExternalModule>,
    candidate_sha256: String,
    runtime: Mutex<Option<ImplementationRuntime>>,
    ledger: Arc<ConsumptionLedger>,
    baseline: Arc<dyn StrategySlot>,
}

struct ExternalModule {
    module: ModuleId,
    plan: ProcessLaunchPlan,
    port: ModulePort,
}

impl ExternalStrategySlot {
    fn new(
        slot: CoreSlot,
        chain: Vec<ExternalModule>,
        candidate_sha256: String,
        ledger: Arc<ConsumptionLedger>,
        baseline: Arc<dyn StrategySlot>,
    ) -> Self {
        Self {
            slot: SlotId(slot.as_str().to_owned()),
            core_slot: slot,
            chain,
            candidate_sha256,
            runtime: Mutex::new(None),
            ledger,
            baseline,
        }
    }

    fn decide_external(&self, observation: &SlotObservation) -> Result<SlotOutcome, ()> {
        if observation.slot != self.slot {
            return Err(());
        }
        let mut locked = self.runtime.lock().map_err(|_| ())?;
        if locked.is_some() {
            return Err(());
        }
        let mut prior = None;
        let mut ceiling = observation.ceiling;
        for entry in &self.chain {
            self.ledger.record(entry.module, Stage::Begin)?;
            *locked = Some(ImplementationRuntime::launch(entry.plan.clone()).map_err(|_| ())?);
            let run_id = format!(
                "external-{}-{}",
                std::process::id(),
                NEXT_RUN.fetch_add(1, Ordering::Relaxed)
            );
            let result = self.drive(
                entry,
                locked.as_mut().expect("runtime was installed"),
                observation,
                prior.as_ref(),
                ceiling,
                &run_id,
            );
            if result.is_err() {
                self.cancel_and_stop(
                    entry.module,
                    locked.as_mut().expect("runtime remains installed"),
                    &run_id,
                );
            }
            locked.take();
            let outcome = result?;
            ceiling = ceiling.intersect(outcome.admitted);
            prior = Some(SlotOutcome {
                admitted: ceiling,
                decision: outcome.decision,
            });
        }
        prior.ok_or(())
    }

    fn drive(
        &self,
        entry: &ExternalModule,
        runtime: &mut ImplementationRuntime,
        observation: &SlotObservation,
        prior: Option<&SlotOutcome>,
        ceiling: CapabilitySet,
        run_id: &str,
    ) -> Result<SlotOutcome, ()> {
        runtime.load().map_err(|_| ())?;
        self.ledger.record(entry.module, Stage::Loaded)?;
        let input = serde_json::to_value(ModuleObservation {
            schema_id: "iteron-module-observation/2",
            module: entry.module,
            core_slot: self.core_slot,
            production_port: entry.port.production_port,
            stage: entry.port.stage,
            original: &observation.payload,
            prior,
        })
        .map_err(|_| ())?;
        if serde_json::to_vec(&input).map_err(|_| ())?.len() > MAX_IMPLEMENTATION_PAYLOAD_BYTES {
            return Err(());
        }
        let deadline_ms = entry
            .plan
            .runtime_deadline_ms()
            .saturating_sub(entry.plan.cancellation_deadline_ms())
            .max(1);
        runtime
            .start(run_id, self.candidate_sha256.clone(), input, deadline_ms)
            .map_err(|_| ())?;
        self.ledger.record(entry.module, Stage::Started)?;

        let terminal = loop {
            let envelope = runtime
                .next_observation(Duration::from_millis(deadline_ms))
                .map_err(|_| ())?;
            if envelope.terminal {
                break envelope;
            }
        };
        let decision: ExternalDecision =
            serde_json::from_value(terminal.observation).map_err(|_| ())?;
        if decision.inherit == decision.decision.is_some() {
            return Err(());
        }
        if let Some(value) = decision.decision.as_ref() {
            validate_decision_schema(self.core_slot, value)?;
        }
        self.ledger.record(entry.module, Stage::Terminal)?;
        runtime
            .stop("terminal observation consumed")
            .map_err(|_| ())?;
        self.ledger.record(entry.module, Stage::Stopped)?;
        let inherited = if decision.inherit {
            Some(
                prior
                    .cloned()
                    .unwrap_or_else(|| self.baseline.decide(observation)),
            )
        } else {
            None
        };
        let admitted = decision
            .admitted
            .intersect(entry.plan.admitted_capabilities())
            .intersect(ceiling);
        Ok(match inherited {
            Some(outcome) => SlotOutcome {
                admitted: outcome.admitted.intersect(admitted),
                decision: outcome.decision,
            },
            None => SlotOutcome {
                admitted,
                decision: decision.decision.expect("validated custom decision exists"),
            },
        })
    }

    fn cancel_and_stop(&self, module: ModuleId, runtime: &mut ImplementationRuntime, run_id: &str) {
        if runtime.state() == RuntimeState::Running {
            let _ = runtime.cancel(run_id, "external slot failed closed");
        }
        if runtime.state() == RuntimeState::Loaded
            && runtime.stop("external slot failed closed").is_ok()
        {
            let _ = self.ledger.record(module, Stage::Stopped);
        }
    }
}

impl StrategySlot for ExternalStrategySlot {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        self.decide_external(observation)
            .unwrap_or_else(|()| rejected_outcome(self.core_slot))
    }
}

#[derive(Serialize)]
struct ModuleObservation<'a> {
    schema_id: &'static str,
    module: ModuleId,
    core_slot: CoreSlot,
    production_port: iteron_tunables::ProductionPortId,
    stage: u8,
    original: &'a serde_json::Value,
    prior: Option<&'a SlotOutcome>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalDecision {
    admitted: CapabilitySet,
    #[serde(default)]
    inherit: bool,
    #[serde(default)]
    decision: Option<serde_json::Value>,
}

fn validate_decision_schema(slot: CoreSlot, value: &serde_json::Value) -> Result<(), ()> {
    let known = match slot {
        CoreSlot::Context => !matches!(
            serde_json::from_value::<iteron_ctx::ContextSlotDecision>(value.clone())
                .map_err(|_| ())?,
            iteron_ctx::ContextSlotDecision::Unknown
        ),
        CoreSlot::ToolPolicy => !matches!(
            serde_json::from_value::<iteron_tools::ToolPolicyDecision>(value.clone())
                .map_err(|_| ())?,
            iteron_tools::ToolPolicyDecision::Unknown
        ),
        CoreSlot::Memory => !matches!(
            serde_json::from_value::<iteron_ctx::MemorySlotDecision>(value.clone())
                .map_err(|_| ())?,
            iteron_ctx::MemorySlotDecision::Unknown
        ),
        CoreSlot::Planner => !matches!(
            serde_json::from_value::<iteron_agents::PlannerDecision>(value.clone())
                .map_err(|_| ())?,
            iteron_agents::PlannerDecision::Unknown
        ),
        CoreSlot::Scheduler => !matches!(
            serde_json::from_value::<iteron_sched::SchedulerSlotDecision>(value.clone())
                .map_err(|_| ())?,
            iteron_sched::SchedulerSlotDecision::Unknown
        ),
        CoreSlot::Verifier => !matches!(
            serde_json::from_value::<iteron_verify::VerifierSlotDecision>(value.clone())
                .map_err(|_| ())?,
            iteron_verify::VerifierSlotDecision::Unknown
        ),
        CoreSlot::ModelRouter => !matches!(
            serde_json::from_value::<iteron_provider::catalog::ModelRouterDecision>(value.clone())
                .map_err(|_| ())?,
            iteron_provider::catalog::ModelRouterDecision::Unknown
        ),
        CoreSlot::Router => !matches!(
            serde_json::from_value::<iteron_agents::RouterSlotDecision>(value.clone())
                .map_err(|_| ())?,
            iteron_agents::RouterSlotDecision::Unknown
        ),
        CoreSlot::Collaboration => !matches!(
            serde_json::from_value::<iteron_workflow::CollaborationDecision>(value.clone())
                .map_err(|_| ())?,
            iteron_workflow::CollaborationDecision::Unknown
        ),
    };
    known.then_some(()).ok_or(())
}

fn rejected_outcome(slot: CoreSlot) -> SlotOutcome {
    let decision = match slot {
        CoreSlot::Context => serde_json::to_value(iteron_ctx::ContextSlotDecision::Unknown),
        CoreSlot::ToolPolicy => serde_json::to_value(iteron_tools::ToolPolicyDecision::Unknown),
        CoreSlot::Memory => serde_json::to_value(iteron_ctx::MemorySlotDecision::Unknown),
        CoreSlot::Planner => serde_json::to_value(iteron_agents::PlannerDecision::Unknown),
        CoreSlot::Scheduler => serde_json::to_value(iteron_sched::SchedulerSlotDecision::Unknown),
        CoreSlot::Verifier => serde_json::to_value(iteron_verify::VerifierSlotDecision::Unknown),
        CoreSlot::ModelRouter => {
            serde_json::to_value(iteron_provider::catalog::ModelRouterDecision::Unknown)
        }
        CoreSlot::Router | CoreSlot::Collaboration => Ok(serde_json::json!({"kind": "unknown"})),
    }
    .unwrap_or_else(|_| serde_json::json!({"kind": "unknown"}));
    SlotOutcome {
        admitted: CapabilitySet::none(),
        decision,
    }
}

#[cfg(test)]
pub(super) fn module_has_production_consumer(module: ModuleId) -> bool {
    let port = module_port_for(module);
    port.module == module && CoreSlot::ALL.contains(&port.core_slot)
}
