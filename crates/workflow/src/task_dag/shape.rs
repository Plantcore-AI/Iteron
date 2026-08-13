use super::DagError;
use super::reducer::TaskDag;
use super::types::{Command, MAX_LABEL_BYTES, max_message_bytes, max_reason_bytes};

impl TaskDag {
    pub(super) fn validate_command_shape(&self, command: &Command) -> Result<(), DagError> {
        match command {
            Command::CreateTask { spec, .. } => {
                if spec.dependencies.len() > self.config.limits.max_edges {
                    return Err(DagError::Capacity { kind: "edge" });
                }
                if spec.label.len()
                    > iteron_tunables::param_integer(
                        "workflow.task_dag.types.max_label_bytes",
                        MAX_LABEL_BYTES,
                    )
                {
                    return Err(DagError::Invalid("task label is over its byte limit"));
                }
                spec.budget.validate().map_err(DagError::Budget)
            }
            Command::SendMessage { message, .. } => {
                if message.payload.len() > max_message_bytes() {
                    return Err(DagError::Invalid("message is over its byte limit"));
                }
                Ok(())
            }
            Command::RegisterJoin { join, .. } => {
                if join.members.len() > self.config.limits.max_tasks {
                    return Err(DagError::Capacity {
                        kind: "join member",
                    });
                }
                Ok(())
            }
            Command::RequestCancel { reason, .. } => {
                if reason.len() > max_reason_bytes() {
                    return Err(DagError::Invalid("cancel reason is over its byte limit"));
                }
                Ok(())
            }
            Command::CompleteTask {
                result_digest,
                code,
                detail,
                ..
            } => {
                if result_digest.as_ref().is_some_and(|value| value.len() > 64) {
                    return Err(DagError::Invalid("result digest is over its byte limit"));
                }
                if code.as_ref().is_some_and(|value| value.len() > 128) {
                    return Err(DagError::Invalid("completion code is over its byte limit"));
                }
                if detail
                    .as_ref()
                    .is_some_and(|value| value.len() > max_reason_bytes())
                {
                    return Err(DagError::Invalid(
                        "completion detail is over its byte limit",
                    ));
                }
                Ok(())
            }
            Command::RegisterAttempt { attempt, .. } => {
                if attempt.input_digest.len() > 64 {
                    return Err(DagError::Invalid(
                        "attempt input digest is over its byte limit",
                    ));
                }
                if attempt
                    .prior_evidence_digest
                    .as_ref()
                    .is_some_and(|value| value.len() > 64)
                {
                    return Err(DagError::Invalid(
                        "attempt predecessor evidence digest is over its byte limit",
                    ));
                }
                Ok(())
            }
            Command::StartTask { .. }
            | Command::StartAttempt { .. }
            | Command::ChargeBudget { .. }
            | Command::AcknowledgeMessage { .. } => Ok(()),
            Command::CompleteAttempt {
                result_digest,
                code,
                detail,
                ..
            } => {
                if result_digest.as_ref().is_some_and(|value| value.len() > 64) {
                    return Err(DagError::Invalid(
                        "attempt result digest is over its byte limit",
                    ));
                }
                if code.as_ref().is_some_and(|value| value.len() > 128) {
                    return Err(DagError::Invalid(
                        "attempt completion code is over its byte limit",
                    ));
                }
                if detail
                    .as_ref()
                    .is_some_and(|value| value.len() > max_reason_bytes())
                {
                    return Err(DagError::Invalid(
                        "attempt completion detail is over its byte limit",
                    ));
                }
                Ok(())
            }
        }
    }
}
