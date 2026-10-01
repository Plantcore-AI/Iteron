//! Durable, content-free execution binding minted only by an authenticated native host.
use super::{AgentIdV1, ControllerError};
use iteron_protocol::Effort;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEngineParentSource {
    pub tenant: String,
    pub run: String,
    pub provider_scope_sha256: String,
}
impl AgentEngineParentSource {
    pub fn validate(&self) -> Result<(), ControllerError> {
        for value in [&self.tenant, &self.run] {
            if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
                return Err(ControllerError::Invalid(
                    "invalid engine physical parent identity",
                ));
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"iteron-persistent-provider-run-v1\0");
        for value in [&self.tenant, &self.run] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        if self.provider_scope_sha256 != format!("sha256:{:x}", hash.finalize()) {
            return Err(ControllerError::RequestConflict);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentEngineOrigin {
    DirectSubagent {
        parent: AgentEngineParentSource,
    },
    WorkflowChild {
        parent: AgentEngineParentSource,
        workflow_id: String,
        task_id: u32,
    },
}
impl AgentEngineOrigin {
    pub fn parent(&self) -> &AgentEngineParentSource {
        match self {
            Self::DirectSubagent { parent } | Self::WorkflowChild { parent, .. } => parent,
        }
    }
    pub fn validate(&self) -> Result<(), ControllerError> {
        self.parent().validate()?;
        if let Self::WorkflowChild {
            workflow_id,
            task_id,
            ..
        } = self
            && (workflow_id.is_empty()
                || workflow_id.len() > 128
                || workflow_id.chars().any(char::is_control)
                || *task_id == 0)
        {
            return Err(ControllerError::Invalid(
                "invalid engine workflow cost origin",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEngineExecution {
    pub profile: String,
    pub profile_digest: String,
    pub provider_id: String,
    pub model_id: String,
    pub catalog_digest: String,
    pub capability_digest: String,
    pub effort: Effort,
    pub origin: AgentEngineOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_context: Option<iteron_protocol::native_child_context::NativeChildContextRefV1>,
}
impl AgentEngineExecution {
    pub fn validate(&self) -> Result<(), ControllerError> {
        self.origin.validate()?;
        if let Some(reference) = &self.native_context {
            reference.validate().map_err(ControllerError::Invalid)?;
            if reference.tenant != self.origin.parent().tenant
                || reference.run != self.origin.parent().run
            {
                return Err(ControllerError::RequestConflict);
            }
        }
        if self.profile.is_empty()
            || self.profile.len() > 128
            || !self
                .profile
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
            || !valid_digest(&self.profile_digest)
        {
            return Err(ControllerError::Invalid("invalid engine profile identity"));
        }
        for value in [&self.provider_id, &self.model_id] {
            if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
                return Err(ControllerError::Invalid(
                    "invalid engine native route identity",
                ));
            }
        }
        // Native route evidence may use the historical empty identity for an uncatalogued model.
        for value in [&self.catalog_digest, &self.capability_digest] {
            if !value.is_empty() && !valid_digest(value) {
                return Err(ControllerError::Invalid("invalid engine route evidence"));
            }
        }
        Ok(())
    }
}
fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

impl<J: super::AgentControllerJournal> super::AgentController<J> {
    pub fn validate_engine_origin(
        &self,
        actor: super::AgentActor,
        origin: &AgentEngineOrigin,
    ) -> Result<(), ControllerError> {
        self.check_live()?;
        self.check_actor(actor)?;
        origin.validate()?;
        let super::AgentActor::Agent(parent) = actor else {
            return Err(ControllerError::Permission);
        };
        if self.provider_budget_scope_owner(&origin.parent().provider_scope_sha256) != Some(parent)
        {
            return Err(ControllerError::Permission);
        }
        self.check_open(parent)
    }
    pub fn runtime_engine_execution(
        &self,
        id: AgentIdV1,
        epoch: super::AgentEpochV1,
    ) -> Result<Option<AgentEngineExecution>, ControllerError> {
        self.check_live()?;
        if self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?
            .view
            .state
            .epoch()
            != Some(epoch)
        {
            return Err(ControllerError::StaleEpoch);
        }
        let mut bindings = self
            .snapshot
            .workflow_claims
            .values()
            .filter(|receipt| receipt.claim.assigned_agent == id)
            .filter_map(|receipt| receipt.claim.execution.as_ref());
        let binding = bindings.next().cloned().or_else(|| {
            self.snapshot
                .agents
                .get(&id)
                .and_then(|record| record.native_execution.clone())
        });
        if bindings.any(|other| Some(other) != binding.as_ref()) {
            return Err(ControllerError::RecoveryRequired);
        }
        Ok(binding)
    }
}
