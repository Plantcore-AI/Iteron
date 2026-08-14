//! Production hot-swap executor backed by registry-minted process launch plans.

use super::{
    HotSwapBlockKind, HotSwapExecutor, HotSwapGeneration, HotSwapPhase, HotSwapRequest,
    HotSwapStageError,
};
use crate::{
    IMPLEMENTATION_PROCESS_PROTOCOL_VERSION, ImplementationObservationEnvelope,
    ImplementationRuntime, ImplementationRuntimeError, ImplementationState, ProcessLaunchPlan,
    RuntimeState,
};
use iteron_tunables::ModuleId;
use sha2::Digest as _;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

struct ActiveRuntimeGeneration {
    generation: HotSwapGeneration,
    runtime: ImplementationRuntime,
}

struct ActiveCell {
    active: ActiveRuntimeGeneration,
    /// While present, consumer calls fail closed. The executor alone may touch either process.
    transition: Option<String>,
}

/// The single host-owned routing handle for one module. Every consumer operation holds the same
/// mutex as an atomic generation switch, so an observation can belong to the old or new runtime,
/// never both. Consumers receive a typed transition error while state is being moved.
#[derive(Clone)]
pub struct ActiveImplementationHandle {
    inner: Arc<Mutex<ActiveCell>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeGenerationError {
    #[error("implementation generation identity does not match its launch plan")]
    Identity,
    #[error("implementation generation is reserved by transaction {0}")]
    TransitionInProgress(String),
    #[error("implementation generation mutex is poisoned")]
    Poisoned,
    #[error("implementation authority digest serialization failed: {0}")]
    AuthorityDigest(String),
    #[error(transparent)]
    Runtime(#[from] ImplementationRuntimeError),
}

impl ActiveImplementationHandle {
    pub fn new(
        runtime: ImplementationRuntime,
        generation: HotSwapGeneration,
    ) -> Result<Self, RuntimeGenerationError> {
        validate_runtime_identity(&runtime, &generation)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(ActiveCell {
                active: ActiveRuntimeGeneration {
                    generation,
                    runtime,
                },
                transition: None,
            })),
        })
    }

    pub fn current_generation(&self) -> Result<HotSwapGeneration, RuntimeGenerationError> {
        Ok(self.lock()?.active.generation.clone())
    }

    pub fn state(&self) -> Result<RuntimeState, RuntimeGenerationError> {
        Ok(self.lock()?.active.runtime.state())
    }

    pub fn start(
        &self,
        run_id: impl Into<String>,
        candidate_sha256: impl Into<String>,
        input: serde_json::Value,
        deadline_ms: u64,
    ) -> Result<(), RuntimeGenerationError> {
        let mut cell = self.consumer_lock()?;
        cell.active
            .runtime
            .start(run_id, candidate_sha256, input, deadline_ms)?;
        Ok(())
    }

    pub fn next_observation(
        &self,
        deadline: Duration,
    ) -> Result<ImplementationObservationEnvelope, RuntimeGenerationError> {
        let mut cell = self.consumer_lock()?;
        Ok(cell.active.runtime.next_observation(deadline)?)
    }

    pub fn cancel(
        &self,
        run_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(), RuntimeGenerationError> {
        let mut cell = self.consumer_lock()?;
        cell.active.runtime.cancel(run_id, reason)?;
        Ok(())
    }

    fn consumer_lock(&self) -> Result<MutexGuard<'_, ActiveCell>, RuntimeGenerationError> {
        let cell = self.lock()?;
        if let Some(transaction) = &cell.transition {
            return Err(RuntimeGenerationError::TransitionInProgress(
                transaction.clone(),
            ));
        }
        Ok(cell)
    }

    fn lock(&self) -> Result<MutexGuard<'_, ActiveCell>, RuntimeGenerationError> {
        self.inner
            .lock()
            .map_err(|_| RuntimeGenerationError::Poisoned)
    }
}

/// SHA-256 over the canonical serialized admitted capability set of the prospective generation.
/// This binds the ledger's authority digest to the registry-intersected plan, not the manifest's
/// untrusted request.
pub fn implementation_authority_sha256(
    plan: &ProcessLaunchPlan,
) -> Result<String, RuntimeGenerationError> {
    let bytes = serde_json::to_vec(&plan.admitted_capabilities())
        .map_err(|error| RuntimeGenerationError::AuthorityDigest(error.to_string()))?;
    Ok(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(bytes))
    ))
}

/// Real process implementation of every hot-swap phase.
///
/// Construction requires a previously durable exact old-generation state. That state is the
/// rollback anchor if the old process dies during snapshot or has already been reaped by Drain.
/// Without such an anchor, post-drain rollback is impossible and construction is rejected.
pub struct RuntimeHotSwapExecutor {
    active: ActiveImplementationHandle,
    old_plan: ProcessLaunchPlan,
    shadow_plan: ProcessLaunchPlan,
    rollback_state: ImplementationState,
    verified_request: Option<HotSwapRequest>,
    next_phase: HotSwapPhase,
    shadow: Option<ImplementationRuntime>,
    old_after_switch: Option<ImplementationRuntime>,
    switched: bool,
}

impl RuntimeHotSwapExecutor {
    pub fn new(
        active: ActiveImplementationHandle,
        shadow_plan: ProcessLaunchPlan,
        rollback_state: ImplementationState,
    ) -> Result<Self, RuntimeGenerationError> {
        rollback_state
            .validate()
            .map_err(ImplementationRuntimeError::from)?;
        let cell = active.lock()?;
        validate_runtime_identity(&cell.active.runtime, &cell.active.generation)?;
        if !state_matches_generation(
            &rollback_state,
            cell.active.runtime.launch_plan().module(),
            &cell.active.generation,
        ) {
            return Err(RuntimeGenerationError::Identity);
        }
        let old_plan = cell.active.runtime.launch_plan().clone();
        drop(cell);
        Ok(Self {
            active,
            old_plan,
            shadow_plan,
            rollback_state,
            verified_request: None,
            next_phase: HotSwapPhase::Verify,
            shadow: None,
            old_after_switch: None,
            switched: false,
        })
    }

    #[must_use]
    pub fn active_handle(&self) -> ActiveImplementationHandle {
        self.active.clone()
    }

    fn expect(
        &self,
        phase: HotSwapPhase,
        request: &HotSwapRequest,
    ) -> Result<(), HotSwapStageError> {
        if self.next_phase != phase
            || self
                .verified_request
                .as_ref()
                .is_some_and(|verified| verified != request)
        {
            return Err(stage(
                HotSwapBlockKind::Validation,
                phase,
                "phase or transaction correlation mismatch",
            ));
        }
        Ok(())
    }

    fn advance(&mut self, phase: HotSwapPhase) {
        self.next_phase = phase;
    }

    fn remaining(
        &self,
        phase: HotSwapPhase,
        end: Instant,
        ceiling_ms: u64,
    ) -> Result<u64, HotSwapStageError> {
        remaining_ms(phase, end, ceiling_ms)
    }

    fn rebuild_old(
        &self,
        request: &HotSwapRequest,
    ) -> Result<ImplementationRuntime, HotSwapStageError> {
        let end = Instant::now()
            + Duration::from_millis(request.deadline_ms.min(self.old_plan.runtime_deadline_ms()));
        let mut runtime = ImplementationRuntime::launch(self.old_plan.clone())
            .map_err(|error| runtime_stage(HotSwapPhase::RolledBack, error))?;
        let load_ms = remaining_ms(
            HotSwapPhase::RolledBack,
            end,
            self.old_plan.runtime_deadline_ms(),
        )?;
        runtime
            .load_with_deadline(load_ms)
            .map_err(|error| runtime_stage(HotSwapPhase::RolledBack, error))?;
        let restore_ms = remaining_ms(
            HotSwapPhase::RolledBack,
            end,
            self.old_plan.runtime_deadline_ms(),
        )?;
        runtime
            .restore(&self.rollback_state, restore_ms)
            .map_err(|error| runtime_stage(HotSwapPhase::RolledBack, error))?;
        let readiness_ms = remaining_ms(
            HotSwapPhase::RolledBack,
            end,
            self.old_plan.runtime_deadline_ms(),
        )?;
        runtime
            .readiness(&self.rollback_state, readiness_ms)
            .map_err(|error| runtime_stage(HotSwapPhase::RolledBack, error))?;
        Ok(runtime)
    }

    fn stop_runtime(
        runtime: &mut ImplementationRuntime,
        plan: &ProcessLaunchPlan,
        phase: HotSwapPhase,
        end: Instant,
    ) -> Result<(), HotSwapStageError> {
        if runtime.is_reaped() {
            return Ok(());
        }
        if !matches!(
            runtime.state(),
            RuntimeState::Loaded | RuntimeState::Running
        ) {
            return Err(stage(
                HotSwapBlockKind::Provider,
                phase,
                "runtime is neither stoppable nor reaped",
            ));
        }
        let deadline_ms = remaining_ms(phase, end, plan.cancellation_deadline_ms())?;
        match runtime.stop_with_deadline("hot swap process retirement", deadline_ms) {
            Ok(()) => Ok(()),
            Err(_) if runtime.is_reaped() => Err(stage(
                HotSwapBlockKind::Provider,
                phase,
                "provider stop failed; host killed and reaped it",
            )),
            Err(error) => Err(runtime_stage(phase, error)),
        }
    }
}

impl HotSwapExecutor for RuntimeHotSwapExecutor {
    fn protocol_version(&self) -> u16 {
        self.shadow_plan.protocol_version()
    }

    fn verify(&mut self, request: &HotSwapRequest, _end: Instant) -> Result<(), HotSwapStageError> {
        self.expect(HotSwapPhase::Verify, request)?;
        let authority_sha256 = implementation_authority_sha256(&self.shadow_plan)
            .map_err(|error| generation_stage(HotSwapPhase::Verify, error))?;
        let mut cell = self
            .active
            .lock()
            .map_err(|error| generation_stage(HotSwapPhase::Verify, error))?;
        if cell.transition.is_some()
            || cell.active.runtime.state() != RuntimeState::Loaded
            || cell.active.generation != request.old
            || !plan_matches(&self.old_plan, request.module, &request.old)
            || !plan_matches(&self.shadow_plan, request.module, &request.new)
            || self.old_plan.protocol_version() != IMPLEMENTATION_PROCESS_PROTOCOL_VERSION
            || self.shadow_plan.protocol_version() != IMPLEMENTATION_PROCESS_PROTOCOL_VERSION
            || authority_sha256 != request.authority_sha256
            || !state_matches_generation(&self.rollback_state, request.module, &request.old)
        {
            return Err(stage(
                HotSwapBlockKind::Validation,
                HotSwapPhase::Verify,
                "runtime, plan, state, authority, or safe-boundary identity mismatch",
            ));
        }
        cell.transition = Some(request.transaction_id.clone());
        drop(cell);
        self.verified_request = Some(request.clone());
        self.advance(HotSwapPhase::ShadowLoad);
        Ok(())
    }

    fn shadow_load(
        &mut self,
        request: &HotSwapRequest,
        end: Instant,
    ) -> Result<(), HotSwapStageError> {
        self.expect(HotSwapPhase::ShadowLoad, request)?;
        let mut runtime = ImplementationRuntime::launch(self.shadow_plan.clone())
            .map_err(|error| runtime_stage(HotSwapPhase::ShadowLoad, error))?;
        let deadline_ms = self.remaining(
            HotSwapPhase::ShadowLoad,
            end,
            self.shadow_plan.runtime_deadline_ms(),
        )?;
        runtime
            .load_with_deadline(deadline_ms)
            .map_err(|error| runtime_stage(HotSwapPhase::ShadowLoad, error))?;
        self.shadow = Some(runtime);
        self.advance(HotSwapPhase::Quiesce);
        Ok(())
    }

    fn quiesce(
        &mut self,
        request: &HotSwapRequest,
        _end: Instant,
    ) -> Result<(), HotSwapStageError> {
        self.expect(HotSwapPhase::Quiesce, request)?;
        let cell = self
            .active
            .lock()
            .map_err(|error| generation_stage(HotSwapPhase::Quiesce, error))?;
        if cell.transition.as_deref() != Some(request.transaction_id.as_str())
            || cell.active.generation != request.old
            || cell.active.runtime.state() != RuntimeState::Loaded
        {
            return Err(stage(
                HotSwapBlockKind::Dependency,
                HotSwapPhase::Quiesce,
                "old runtime left its reserved quiescent boundary",
            ));
        }
        drop(cell);
        self.advance(HotSwapPhase::Snapshot);
        Ok(())
    }

    fn snapshot(
        &mut self,
        request: &HotSwapRequest,
        end: Instant,
    ) -> Result<ImplementationState, HotSwapStageError> {
        self.expect(HotSwapPhase::Snapshot, request)?;
        let deadline_ms = self.remaining(
            HotSwapPhase::Snapshot,
            end,
            self.old_plan.runtime_deadline_ms(),
        )?;
        let mut cell = self
            .active
            .lock()
            .map_err(|error| generation_stage(HotSwapPhase::Snapshot, error))?;
        let state = cell
            .active
            .runtime
            .snapshot(
                self.rollback_state.run_id.clone(),
                request.old.generation,
                deadline_ms,
            )
            .map_err(|error| runtime_stage(HotSwapPhase::Snapshot, error))?;
        if !state_matches_generation(&state, request.module, &request.old)
            || state.run_id != self.rollback_state.run_id
            || state.state_schema != self.rollback_state.state_schema
        {
            return Err(stage(
                HotSwapBlockKind::Validation,
                HotSwapPhase::Snapshot,
                "snapshot does not match the durable rollback anchor",
            ));
        }
        drop(cell);
        self.rollback_state = state.clone();
        self.advance(HotSwapPhase::Migrate);
        Ok(state)
    }

    fn migrate(
        &mut self,
        request: &HotSwapRequest,
        snapshot: &ImplementationState,
        end: Instant,
    ) -> Result<ImplementationState, HotSwapStageError> {
        self.expect(HotSwapPhase::Migrate, request)?;
        let deadline_ms = self.remaining(
            HotSwapPhase::Migrate,
            end,
            self.shadow_plan.runtime_deadline_ms(),
        )?;
        let shadow = self.shadow.as_mut().ok_or_else(|| {
            stage(
                HotSwapBlockKind::Dependency,
                HotSwapPhase::Migrate,
                "shadow runtime is missing",
            )
        })?;
        let migrated = shadow
            .migrate(snapshot, request.new.generation, deadline_ms)
            .map_err(|error| runtime_stage(HotSwapPhase::Migrate, error))?;
        self.advance(HotSwapPhase::Restore);
        Ok(migrated)
    }

    fn restore(
        &mut self,
        request: &HotSwapRequest,
        migrated: &ImplementationState,
        end: Instant,
    ) -> Result<(), HotSwapStageError> {
        self.expect(HotSwapPhase::Restore, request)?;
        let deadline_ms = self.remaining(
            HotSwapPhase::Restore,
            end,
            self.shadow_plan.runtime_deadline_ms(),
        )?;
        self.shadow
            .as_mut()
            .ok_or_else(|| {
                stage(
                    HotSwapBlockKind::Dependency,
                    HotSwapPhase::Restore,
                    "shadow runtime is missing",
                )
            })?
            .restore(migrated, deadline_ms)
            .map_err(|error| runtime_stage(HotSwapPhase::Restore, error))?;
        self.advance(HotSwapPhase::Readiness);
        Ok(())
    }

    fn readiness(
        &mut self,
        request: &HotSwapRequest,
        migrated: &ImplementationState,
        end: Instant,
    ) -> Result<(), HotSwapStageError> {
        self.expect(HotSwapPhase::Readiness, request)?;
        let deadline_ms = self.remaining(
            HotSwapPhase::Readiness,
            end,
            self.shadow_plan.runtime_deadline_ms(),
        )?;
        self.shadow
            .as_mut()
            .ok_or_else(|| {
                stage(
                    HotSwapBlockKind::Dependency,
                    HotSwapPhase::Readiness,
                    "shadow runtime is missing",
                )
            })?
            .readiness(migrated, deadline_ms)
            .map_err(|error| runtime_stage(HotSwapPhase::Readiness, error))?;
        self.advance(HotSwapPhase::AtomicSwitch);
        Ok(())
    }

    fn atomic_switch(
        &mut self,
        request: &HotSwapRequest,
        _end: Instant,
    ) -> Result<(), HotSwapStageError> {
        self.expect(HotSwapPhase::AtomicSwitch, request)?;
        let shadow = self.shadow.take().ok_or_else(|| {
            stage(
                HotSwapBlockKind::Dependency,
                HotSwapPhase::AtomicSwitch,
                "ready shadow runtime is missing",
            )
        })?;
        if shadow.state() != RuntimeState::Loaded {
            return Err(stage(
                HotSwapBlockKind::Provider,
                HotSwapPhase::AtomicSwitch,
                "ready shadow runtime is not loaded",
            ));
        }
        let mut cell = self
            .active
            .lock()
            .map_err(|error| generation_stage(HotSwapPhase::AtomicSwitch, error))?;
        if cell.transition.as_deref() != Some(request.transaction_id.as_str())
            || cell.active.generation != request.old
        {
            return Err(stage(
                HotSwapBlockKind::Dependency,
                HotSwapPhase::AtomicSwitch,
                "active generation changed before switch",
            ));
        }
        let old = std::mem::replace(
            &mut cell.active,
            ActiveRuntimeGeneration {
                generation: request.new.clone(),
                runtime: shadow,
            },
        );
        self.old_after_switch = Some(old.runtime);
        self.switched = true;
        drop(cell);
        self.advance(HotSwapPhase::Drain);
        Ok(())
    }

    fn drain(&mut self, request: &HotSwapRequest, end: Instant) -> Result<(), HotSwapStageError> {
        self.expect(HotSwapPhase::Drain, request)?;
        let old = self.old_after_switch.as_mut().ok_or_else(|| {
            stage(
                HotSwapBlockKind::Dependency,
                HotSwapPhase::Drain,
                "old runtime is missing after switch",
            )
        })?;
        Self::stop_runtime(old, &self.old_plan, HotSwapPhase::Drain, end)?;
        self.advance(HotSwapPhase::Committed);
        Ok(())
    }

    fn rollback(&mut self, request: &HotSwapRequest) -> Result<(), HotSwapStageError> {
        if self
            .verified_request
            .as_ref()
            .is_some_and(|verified| verified != request)
        {
            return Err(stage(
                HotSwapBlockKind::Validation,
                HotSwapPhase::RolledBack,
                "rollback transaction correlation mismatch",
            ));
        }
        if self.switched {
            let old = match self.old_after_switch.take() {
                Some(runtime) if runtime.state() == RuntimeState::Loaded => runtime,
                _ => self.rebuild_old(request)?,
            };
            let mut cell = self
                .active
                .lock()
                .map_err(|error| generation_stage(HotSwapPhase::RolledBack, error))?;
            if cell.transition.as_deref() != Some(request.transaction_id.as_str())
                || cell.active.generation != request.new
            {
                return Err(stage(
                    HotSwapBlockKind::Dependency,
                    HotSwapPhase::RolledBack,
                    "new generation is not the reserved active runtime",
                ));
            }
            let mut new = std::mem::replace(
                &mut cell.active,
                ActiveRuntimeGeneration {
                    generation: request.old.clone(),
                    runtime: old,
                },
            );
            cell.transition = None;
            drop(cell);
            let cleanup_end = Instant::now()
                + Duration::from_millis(new.runtime.launch_plan().cancellation_deadline_ms());
            let new_plan = new.runtime.launch_plan().clone();
            let cleanup = Self::stop_runtime(
                &mut new.runtime,
                &new_plan,
                HotSwapPhase::RolledBack,
                cleanup_end,
            );
            self.switched = false;
            cleanup?;
        } else {
            if let Some(mut shadow) = self.shadow.take() {
                let cleanup_end = Instant::now()
                    + Duration::from_millis(self.shadow_plan.cancellation_deadline_ms());
                Self::stop_runtime(
                    &mut shadow,
                    &self.shadow_plan,
                    HotSwapPhase::RolledBack,
                    cleanup_end,
                )?;
            }
            let mut cell = self
                .active
                .lock()
                .map_err(|error| generation_stage(HotSwapPhase::RolledBack, error))?;
            if cell.active.generation != request.old {
                return Err(stage(
                    HotSwapBlockKind::Dependency,
                    HotSwapPhase::RolledBack,
                    "old generation is no longer active",
                ));
            }
            if !matches!(
                cell.active.runtime.state(),
                RuntimeState::Loaded | RuntimeState::Running
            ) {
                drop(cell);
                let recovered = self.rebuild_old(request)?;
                cell = self
                    .active
                    .lock()
                    .map_err(|error| generation_stage(HotSwapPhase::RolledBack, error))?;
                cell.active.runtime = recovered;
            }
            cell.transition = None;
        }
        self.next_phase = HotSwapPhase::RolledBack;
        Ok(())
    }

    fn committed(&mut self, request: &HotSwapRequest) -> Result<(), HotSwapStageError> {
        self.expect(HotSwapPhase::Committed, request)?;
        let mut cell = self
            .active
            .lock()
            .map_err(|error| generation_stage(HotSwapPhase::Committed, error))?;
        if cell.transition.as_deref() != Some(request.transaction_id.as_str())
            || cell.active.generation != request.new
            || cell.active.runtime.state() != RuntimeState::Loaded
        {
            return Err(stage(
                HotSwapBlockKind::Dependency,
                HotSwapPhase::Committed,
                "committed generation handle is inconsistent",
            ));
        }
        cell.transition = None;
        drop(cell);
        self.next_phase = HotSwapPhase::Committed;
        Ok(())
    }
}

fn validate_runtime_identity(
    runtime: &ImplementationRuntime,
    generation: &HotSwapGeneration,
) -> Result<(), RuntimeGenerationError> {
    if runtime.launch_plan().protocol_version() != IMPLEMENTATION_PROCESS_PROTOCOL_VERSION
        || !plan_matches(
            runtime.launch_plan(),
            runtime.launch_plan().module(),
            generation,
        )
    {
        return Err(RuntimeGenerationError::Identity);
    }
    Ok(())
}

fn plan_matches(
    plan: &ProcessLaunchPlan,
    module: ModuleId,
    generation: &HotSwapGeneration,
) -> bool {
    plan.module() == module
        && plan.implementation_id() == generation.implementation_id
        && prefixed_digest(plan.artifact_sha256()) == generation.artifact_sha256
}

fn state_matches_generation(
    state: &ImplementationState,
    module: ModuleId,
    generation: &HotSwapGeneration,
) -> bool {
    state.validate().is_ok()
        && state.module == module
        && state.implementation_id == generation.implementation_id
        && state.generation == generation.generation
        && state.state_sha256 == generation.state_sha256
}

fn prefixed_digest(digest: &str) -> String {
    if digest.starts_with("sha256:") {
        digest.to_owned()
    } else {
        format!("sha256:{digest}")
    }
}

fn remaining_ms(
    phase: HotSwapPhase,
    end: Instant,
    ceiling_ms: u64,
) -> Result<u64, HotSwapStageError> {
    let remaining = end.checked_duration_since(Instant::now()).ok_or_else(|| {
        stage(
            HotSwapBlockKind::Deadline,
            phase,
            "transaction deadline elapsed",
        )
    })?;
    let nanos = remaining.as_nanos();
    let rounded = nanos.saturating_add(999_999) / 1_000_000;
    let millis = u64::try_from(rounded).unwrap_or(u64::MAX).min(ceiling_ms);
    if millis == 0 {
        Err(stage(
            HotSwapBlockKind::Deadline,
            phase,
            "transaction deadline elapsed",
        ))
    } else {
        Ok(millis)
    }
}

fn runtime_stage(phase: HotSwapPhase, error: ImplementationRuntimeError) -> HotSwapStageError {
    stage(HotSwapBlockKind::Provider, phase, error.to_string())
}

fn generation_stage(phase: HotSwapPhase, error: RuntimeGenerationError) -> HotSwapStageError {
    stage(HotSwapBlockKind::Dependency, phase, error.to_string())
}

fn stage(
    kind: HotSwapBlockKind,
    phase: HotSwapPhase,
    reason: impl std::fmt::Display,
) -> HotSwapStageError {
    HotSwapStageError::new(kind, format!("{phase:?}: {reason}"))
}
