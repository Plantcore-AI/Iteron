//! Optional model-maintained task plans. These records grant no execution or completion authority.
use crate::Seq;
use serde::{Deserialize, Serialize};

pub const MAX_PLAN_STEPS: usize = 32;
pub const MAX_PLAN_OBLIGATIONS: usize = 32;
pub const MAX_PLAN_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStepStatusV1 {
    Pending,
    InProgress,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStepV1 {
    pub description: String,
    pub status: PlanStepStatusV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskPlanSnapshotV1 {
    pub version: u32,
    pub revision: u64,
    pub based_on_submission_seq: Seq,
    pub steps: Vec<PlanStepV1>,
    pub obligations: Vec<String>,
}
impl TaskPlanSnapshotV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || self.revision == 0
            || self.based_on_submission_seq == Seq::ZERO
            || self.steps.is_empty()
            || self.steps.len() > MAX_PLAN_STEPS
            || self.obligations.len() > MAX_PLAN_OBLIGATIONS
            || self
                .steps
                .iter()
                .filter(|step| step.status == PlanStepStatusV1::InProgress)
                .count()
                > 1
            || self
                .steps
                .iter()
                .any(|step| !bounded_text(&step.description))
            || self.obligations.iter().any(|text| !bounded_text(text))
            || serde_json::to_vec(self).map_or(true, |bytes| bytes.len() > MAX_PLAN_BYTES)
        {
            return Err("task plan exceeds its version or content bounds");
        }
        Ok(())
    }
}
fn bounded_text(text: &str) -> bool {
    !text.trim().is_empty()
        && text.len() <= 512
        && !text
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t'))
}
