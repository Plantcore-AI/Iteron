//! Verified cohort locator and immutable physical-run admission. No filesystem path, actor or
//! recovery assertion comes from a client/model envelope.
use super::{Agent, KernelError, replay_scoped_rollout};
use iteron_agents::ControllerError;
use iteron_protocol::agent_cohort::{
    AgentCohortInstallationV1, AgentCohortMainRunV1, AgentCohortOriginV1,
};
use iteron_protocol::{EventKind, RunId, TenantId, TurnId};
use iteron_record::ScopedEvent;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(super) struct CohortReplay {
    pub installation: Option<AgentCohortInstallationV1>,
    pub forked: bool,
    rows: Vec<ScopedEvent>,
}
impl CohortReplay {
    pub(super) fn load(path: &Path, tenant: &TenantId, run: &RunId) -> Result<Self, KernelError> {
        let rows = replay_scoped_rollout(path)?;
        let installation = installation_from_rows(&rows, tenant)?;
        let forked = rows.iter().any(|row| {
            row.run_id != *run
                || matches!(
                    &row.event.kind,
                    EventKind::RunStart {
                        parent_run: Some(_),
                        ..
                    }
                )
        });
        Ok(Self {
            installation,
            forked,
            rows,
        })
    }
    /// A brand new fork may join only before it has any physical provider history. Already
    /// admitted runs validate the original exact prefix rather than minting a new baseline.
    pub(super) fn main_admission(
        &self,
        tenant: &TenantId,
        run: &RunId,
        existing: Option<&AgentCohortMainRunV1>,
    ) -> Result<AgentCohortMainRunV1, KernelError> {
        let through = existing
            .map(|existing| existing.admitted_through_sequence)
            .unwrap_or_else(|| {
                self.rows
                    .iter()
                    .filter(|row| row.tenant == *tenant && row.run_id == *run)
                    .map(|row| row.event.seq.0)
                    .max()
                    .unwrap_or(0)
            });
        let mut hash = Sha256::new();
        hash.update(b"iteron-cohort-main-admission-v1\0");
        let mut seen = 0usize;
        let mut exact_tail = false;
        for row in self
            .rows
            .iter()
            .filter(|row| row.tenant == *tenant && row.run_id == *run && row.event.seq.0 <= through)
        {
            // There is no fresh-budget import for a fork that already performed unbound IO.
            if existing.is_none() && provider_event(&row.event.kind) {
                return Err(invalid("fork provider history predates cohort admission"));
            }
            let bytes = serde_json::to_vec(&(tenant, run, &row.event))
                .map_err(|_| invalid("cohort admission cannot be encoded"))?;
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
            seen += 1;
            exact_tail |= row.event.seq.0 == through;
        }
        if seen == 0 || !exact_tail {
            return Err(invalid("cohort admission prefix is unavailable"));
        }
        let admission = AgentCohortMainRunV1 {
            tenant: tenant.clone(),
            run_id: run.clone(),
            scope_sha256: iteron_protocol::agent_cohort::provider_scope(tenant, run),
            admitted_through_sequence: through,
            admission_sha256: format!("sha256:{:x}", hash.finalize()),
        };
        admission
            .validate()
            .map_err(|reason| KernelError::AgentControl(ControllerError::Invalid(reason)))?;
        if existing.is_some_and(|existing| existing != &admission) {
            return Err(invalid("cohort admission prefix commitment differs"));
        }
        Ok(admission)
    }
}
fn provider_event(kind: &EventKind) -> bool {
    match kind {
        EventKind::EffectIntent { tool, .. }
        | EventKind::EffectDone { tool, .. }
        | EventKind::EffectFailed { tool, .. }
        | EventKind::EffectUnknown { tool, .. } => tool == "provider",
        EventKind::TurnEnd { usage, .. } => *usage != iteron_protocol::Usage::default(),
        _ => false,
    }
}
pub(super) fn installation_from_rows(
    rows: &[ScopedEvent],
    tenant: &TenantId,
) -> Result<Option<AgentCohortInstallationV1>, KernelError> {
    let mut found: Option<AgentCohortInstallationV1> = None;
    for row in rows {
        let EventKind::AgentCohortInstalledV1 { installation } = &row.event.kind else {
            continue;
        };
        installation
            .validate()
            .map_err(|reason| KernelError::AgentControl(ControllerError::Invalid(reason)))?;
        if row.tenant != *tenant
            || installation.origin.tenant != row.tenant
            || installation.installed_run != row.run_id
            || found
                .as_ref()
                .is_some_and(|old| old.origin != installation.origin)
        {
            return Err(invalid("cohort installation scope or origin conflicts"));
        }
        found = Some(installation.clone());
    }
    Ok(found)
}

impl Agent {
    /// Actual verified owning run plus current canonical workspace. Public enable cannot choose
    /// an ancestry/path; the ordinary first-install hash retains its existing exact wire value.
    pub(crate) fn persistent_agent_workspace_scope(&self) -> Result<String, KernelError> {
        let recovered;
        let installation = match &self.cohort_installation {
            Some(installed) => Some(installed),
            None => {
                recovered = self.capture_cohort_replay()?;
                recovered.installation.as_ref()
            }
        };
        let run = installation.map_or(self.rollout.run_id(), |installed| &installed.origin.run_id);
        let workspace = self
            .workspace
            .canonicalize()
            .map_err(|_| invalid("agent workspace identity unavailable"))?;
        let identity = serde_json::to_vec(&(self.rollout.tenant(), run, workspace))
            .map_err(|_| invalid("agent workspace identity cannot be serialized"))?;
        Ok(format!("workspace-{:x}", Sha256::digest(identity)))
    }

    pub(super) fn require_installed_cohort(&mut self) -> Result<(), KernelError> {
        // Agent::new can receive an existing writer without set_resume. Check that actual cold
        // journal once before any Main lease or provider IO, then retain the typed guard.
        if !self.cohort_replay_checked {
            self.cohort_installation = CohortReplay::load(
                self.rollout.path(),
                self.rollout.tenant(),
                self.rollout.run_id(),
            )?
            .installation;
            self.cohort_replay_checked = true;
        }
        if self.cohort_installation.is_some() && self.persistent_agents.is_none() {
            return Err(invalid(
                "this run inherits a persistent cohort; reopen its existing controller before continuing",
            ));
        }
        Ok(())
    }
    pub(super) fn capture_cohort_replay(&self) -> Result<CohortReplay, KernelError> {
        if self.rollout.path().parent() != Some(self.runtime_state_dir.as_path()) {
            return Err(invalid(
                "cohort runtime-state root differs from the actual rollout root",
            ));
        }
        CohortReplay::load(
            self.rollout.path(),
            self.rollout.tenant(),
            self.rollout.run_id(),
        )
    }
    pub(super) fn publish_cohort_installation(
        &mut self,
        origin: AgentCohortOriginV1,
    ) -> Result<(), KernelError> {
        let installation = AgentCohortInstallationV1 {
            origin,
            installed_run: self.rollout.run_id().clone(),
        };
        installation
            .validate()
            .map_err(|reason| KernelError::AgentControl(ControllerError::Invalid(reason)))?;
        // A failed append permanently closes the ordinary path in this process as well.
        self.cohort_installation = Some(installation.clone());
        self.cohort_replay_checked = true;
        self.emit_durable(
            TurnId(self.seq_turn),
            EventKind::AgentCohortInstalledV1 { installation },
        )?;
        Ok(())
    }
}
pub(super) fn main_rollout_path(state: &Path, run: &RunId) -> PathBuf {
    // This helper only receives a validated durable origin/main-run identity.
    state.join(format!("{}.jsonl", run.0))
}
fn invalid(reason: &'static str) -> KernelError {
    KernelError::AgentControl(ControllerError::Invalid(reason))
}

#[cfg(test)]
#[path = "cold_cohort_tests.rs"]
mod tests;
