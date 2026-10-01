//! Main/child safe-point composition of current durable native context evidence.
use super::approval_wait::ApprovalJournal;
use super::persistent_agents::AgentControlPort;
use super::workflow_spawner::native_context;
use super::{Agent, KernelError};
use iteron_agents::{AgentActor, AgentEngineParentSource};
use iteron_protocol::native_child_context::NativeChildContextRefV1;
use iteron_protocol::{EventKind, TurnId};
use std::sync::Arc;

impl Agent {
    pub(crate) fn refresh_persistent_native_context(
        &mut self,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        let Some(control) = self.persistent_agents.clone() else {
            return Ok(());
        };
        let parent = if let Some(mailbox) = &self.persistent_mailbox {
            mailbox
                .child_controller()
                .map_err(KernelError::AgentControl)?
                .1
        } else {
            control
                .host_limits()
                .map_err(KernelError::AgentControl)?
                .root
                .agent_id
        };
        self.publish_current_native_context(&control, parent, turn)
    }
    pub(super) fn publish_current_native_context(
        &mut self,
        control: &Arc<dyn AgentControlPort>,
        parent: iteron_protocol::agent_control::AgentIdV1,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        self.provider_selection
            .validate_live(&self.provider, &self.model)?;
        let route = self
            .provider_selection
            .selected()
            .ok_or(KernelError::InvalidRoute(
                "child context requires an actual durable provider selection",
            ))?
            .route
            .clone();
        let source = AgentEngineParentSource {
            tenant: self.rollout.tenant().0.clone(),
            run: self.rollout.run_id().0.clone(),
            provider_scope_sha256: self.provider_scope(),
        };
        let context = self.kernel_spawner_context(&route, "persistent-agents");
        let actor = AgentActor::Agent(parent);
        let reference = control
            .native_context_reference(actor, &source, &context)
            .map_err(KernelError::AgentControl)?;
        let publication = native_context::capture(
            &context,
            &source,
            reference.as_ref().map_or_else(
                || self.rollout.next_sequence().0,
                |reference| reference.sequence,
            ),
        )
        .map_err(KernelError::AgentControl)?;
        let reference = match reference {
            Some(reference) => reference,
            None => {
                let sequence = ApprovalJournal {
                    rollout: &mut self.rollout,
                    ledger: &mut self.ledger,
                    record_failed: &mut self.record_failed,
                    diagnostics: &self.diagnostics,
                    #[cfg(test)]
                    fault: &mut self.fail_next_durable_append,
                }
                .append_receipt(
                    turn,
                    EventKind::NativeChildContextCapturedV1 {
                        context: publication.clone(),
                    },
                )?;
                if sequence.0 != publication.publication_sequence {
                    return Err(KernelError::ContextResolution(
                        "native context publication sequence differs".into(),
                    ));
                }
                NativeChildContextRefV1 {
                    generation_sha256: publication.generation_sha256.clone(),
                    tenant: source.tenant.clone(),
                    run: source.run.clone(),
                    sequence: sequence.0,
                }
            }
        };
        control
            .install_native_context(actor, source, context, publication, reference)
            .map_err(KernelError::AgentControl)
    }
}
