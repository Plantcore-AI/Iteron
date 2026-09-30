//! Same-controller cold fork attachment. The original root and every descendant reservation
//! remain unchanged; only the authenticated host can admit another physical Main journal.
use super::{
    AgentController, AgentControllerJournal, AgentControllerSnapshot, AgentIdV1, AgentStateV1,
    ControllerError, next_revision,
};
use iteron_protocol::agent_cohort::{
    AgentCohortMainRunV1, AgentCohortOriginV1, MAX_COHORT_MAIN_RUNS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CohortBindings {
    origin: Option<AgentCohortOriginV1>,
    main_runs: BTreeMap<String, AgentCohortMainRunV1>,
}

impl CohortBindings {
    pub(super) fn is_empty(&self) -> bool {
        self.origin.is_none() && self.main_runs.is_empty()
    }
}

impl AgentControllerSnapshot {
    pub fn cohort_origin(&self) -> Option<&AgentCohortOriginV1> {
        self.cohort_bindings.origin.as_ref()
    }
    pub fn cohort_main_runs(&self) -> Vec<AgentCohortMainRunV1> {
        self.cohort_bindings.main_runs.values().cloned().collect()
    }
    pub(super) fn cohort_root_scope(&self, scope: &str) -> bool {
        self.cohort_bindings.main_runs.contains_key(scope)
    }
    pub fn cohort_config_sha256(&self) -> Result<String, ControllerError> {
        config_sha(&self.config)
    }
}
fn config_sha(config: &super::AgentControllerConfig) -> Result<String, ControllerError> {
    let bytes = serde_json::to_vec(config)
        .map_err(|_| ControllerError::Invalid("cohort configuration cannot be encoded"))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}
impl<J: AgentControllerJournal> AgentController<J> {
    /// Called only after the exact primary financial baseline is durably installed.
    pub fn bind_cohort_origin(
        &mut self,
        origin: AgentCohortOriginV1,
    ) -> Result<(), ControllerError> {
        self.check_live()?;
        origin.validate().map_err(ControllerError::Invalid)?;
        if let Some(existing) = self.snapshot.cohort_origin() {
            return if existing == &origin {
                Ok(())
            } else {
                Err(ControllerError::RequestConflict)
            };
        }
        if origin.config_sha256 != self.snapshot.cohort_config_sha256()?
            || self
                .provider_budget_baseline(&origin.provider_scope())?
                .is_none()
        {
            return Err(ControllerError::RequestConflict);
        }
        let mut next = self.snapshot.clone();
        next.cohort_bindings.origin = Some(origin);
        next.revision = next_revision(next.revision)?;
        self.commit(next)
    }

    /// Adds no Agent, budget or epoch. Replaying this exact host admission is idempotent; changing
    /// its identity is forbidden. A closed/active/unknown cohort cannot acquire a new physical run.
    pub fn attach_cohort_main_run(
        &mut self,
        run: AgentCohortMainRunV1,
    ) -> Result<(), ControllerError> {
        self.check_live()?;
        run.validate().map_err(ControllerError::Invalid)?;
        let origin = self
            .snapshot
            .cohort_origin()
            .ok_or(ControllerError::RecoveryRequired)?;
        if run.tenant != origin.tenant || run.run_id == origin.run_id {
            return Err(ControllerError::RequestConflict);
        }
        if let Some(existing) = self
            .snapshot
            .cohort_bindings
            .main_runs
            .get(&run.scope_sha256)
        {
            return if existing == &run {
                Ok(())
            } else {
                Err(ControllerError::RequestConflict)
            };
        }
        if self.provider_budget_recovery_required()
            || self.snapshot.agents.values().any(|agent| {
                matches!(
                    agent.view.state,
                    AgentStateV1::RecoveryRequired { .. }
                        | AgentStateV1::Running { .. }
                        | AgentStateV1::Interrupting { .. }
                        | AgentStateV1::Closing { .. }
                )
            })
        {
            return Err(ControllerError::RecoveryRequired);
        }
        self.check_open(self.root_id())?;
        if self.snapshot.cohort_bindings.main_runs.len() >= MAX_COHORT_MAIN_RUNS - 1
            || self
                .provider_budget_scope_owner(&run.scope_sha256)
                .is_some()
        {
            return Err(ControllerError::Capacity);
        }
        let mut next = self.snapshot.clone();
        next.cohort_bindings
            .main_runs
            .insert(run.scope_sha256.clone(), run);
        next.revision = next_revision(next.revision)?;
        self.commit(next)
    }
}

pub(super) fn validate(snapshot: &AgentControllerSnapshot) -> Result<(), ControllerError> {
    let bindings = &snapshot.cohort_bindings;
    if bindings.main_runs.len() >= MAX_COHORT_MAIN_RUNS {
        return Err(ControllerError::Capacity);
    }
    let Some(origin) = &bindings.origin else {
        return if bindings.main_runs.is_empty() {
            Ok(())
        } else {
            Err(ControllerError::Invalid(
                "cohort physical bindings lack their origin",
            ))
        };
    };
    origin.validate().map_err(ControllerError::Invalid)?;
    if origin.config_sha256 != snapshot.cohort_config_sha256()?
        || snapshot
            .provider_budget_baseline(&origin.provider_scope())?
            .is_none()
    {
        return Err(ControllerError::Invalid(
            "cohort origin differs from durable financial genesis",
        ));
    }
    for (scope, run) in &bindings.main_runs {
        run.validate().map_err(ControllerError::Invalid)?;
        if scope != &run.scope_sha256
            || run.tenant != origin.tenant
            || run.run_id == origin.run_id
            || snapshot.primary_provider_scope_owner(scope).is_some()
        {
            return Err(ControllerError::Invalid(
                "invalid cohort fork physical scope ownership",
            ));
        }
    }
    // Root identity remains the single authenticated Main runtime; ordinary child bindings stay
    // exact and cannot use these scopes to acquire either root money or execution authority.
    if !snapshot.agents.contains_key(&AgentIdV1(1)) {
        return Err(ControllerError::UnknownAgent);
    }
    Ok(())
}
