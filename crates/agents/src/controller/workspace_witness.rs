//! Durable host-only evidence for bounded isolated writer continuation.
use super::{AgentController, AgentControllerJournal, ControllerError};
use iteron_protocol::Capability;
use serde::{Deserialize, Serialize};

/// Host-minted exact Git tree evidence for serialized isolated writer transactions. It grants
/// no new capability and cannot be supplied through the model or public control protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWorkspaceWitness {
    pub workspace_identity: String,
    pub base_head: String,
    pub parent_index_tree: String,
    pub working_tree: String,
}
impl AgentWorkspaceWitness {
    pub fn validate(&self) -> Result<(), ControllerError> {
        let valid = |id: &str| {
            (id.len() == 40 || id.len() == 64) && id.bytes().all(|byte| byte.is_ascii_hexdigit())
        };
        let identity: Vec<_> = self.workspace_identity.split(':').collect();
        if identity.len() != 3
            || identity[0] != "unix"
            || identity[1..]
                .iter()
                .any(|part| part.parse::<u64>().is_err())
        {
            return Err(ControllerError::Invalid(
                "invalid isolated writer workspace identity",
            ));
        }
        if !valid(&self.base_head)
            || !valid(&self.parent_index_tree)
            || !valid(&self.working_tree)
            || self.base_head.len() != self.parent_index_tree.len()
            || self.base_head.len() != self.working_tree.len()
        {
            return Err(ControllerError::Invalid(
                "invalid isolated writer tree witness",
            ));
        }
        Ok(())
    }
}

impl<J: AgentControllerJournal> AgentController<J> {
    pub fn workspace_witness(&self) -> Result<Option<AgentWorkspaceWitness>, ControllerError> {
        self.check_live()?;
        Ok(self.snapshot.workspace_witness.clone())
    }
    pub fn record_workspace_witness(
        &mut self,
        expected: Option<&AgentWorkspaceWitness>,
        witness: AgentWorkspaceWitness,
    ) -> Result<(), ControllerError> {
        self.check_live()?;
        witness.validate()?;
        if !self
            .snapshot
            .config
            .root_capabilities
            .contains(Capability::ReversibleLocal)
        {
            return Err(ControllerError::Permission);
        }
        if self.snapshot.workspace_witness.as_ref() != expected {
            return Err(ControllerError::RequestConflict);
        }
        if let Some(prior) = expected
            && (prior.workspace_identity != witness.workspace_identity
                || prior.base_head != witness.base_head
                || prior.parent_index_tree != witness.parent_index_tree)
        {
            return Err(ControllerError::Invalid(
                "isolated writer changed its immutable repository baseline",
            ));
        }
        if expected == Some(&witness) {
            return Ok(());
        }
        let mut next = self.snapshot.clone();
        next.workspace_witness = Some(witness);
        self.commit(next)
    }
}
