//! Default compatibility refusal: no replay map, queue endpoints, flags, lease or task.
use super::control::PlantcoreCommand;
use crate::runtime::ResumeActivation;
use serde_json::{Value, json};
pub(super) struct PlantcoreCommands;
pub(super) struct PreparedPlantcoreReply {
    pub(super) value: Value,
    pub(super) resume_activation: Option<ResumeActivation>,
}
impl PlantcoreCommands {
    pub(super) fn disabled() -> Self {
        Self
    }
    pub(super) async fn submit(
        &self,
        command_id: String,
        _command: PlantcoreCommand,
    ) -> PreparedPlantcoreReply {
        PreparedPlantcoreReply {
            value: json!({ "type":"plantcore_command_reply_v1", "command_id":command_id, "status":"rejected", "reason":"unsupported" }),
            resume_activation: None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{PlantcoreCommand, PlantcoreCommands};
    #[tokio::test]
    async fn old_command_shape_is_readable_but_never_admitted_or_replayed() {
        assert_eq!(std::mem::size_of::<PlantcoreCommands>(), 0);
        let owner = PlantcoreCommands::disabled();
        for command in [
            PlantcoreCommand::Interrupt,
            PlantcoreCommand::Drain,
            PlantcoreCommand::PauseDispatchAfterSafePoint,
            PlantcoreCommand::ResumeDispatch,
            PlantcoreCommand::Steer {
                text: "must not enter SQ".into(),
            },
        ] {
            let reply = owner.submit("old-id".into(), command).await;
            assert_eq!(reply.value["reason"], "unsupported");
            assert!(reply.resume_activation.is_none());
        }
    }
}
