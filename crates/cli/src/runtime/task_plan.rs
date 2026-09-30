//! Sole mutable optional task-plan owner. Only actual WAL receipts publish replacement state.
use iteron_protocol::{Event, EventKind, Role, Seq, task_plan::TaskPlanSnapshotV1};
use serde::Deserialize;
#[cfg(test)]
#[path = "task_plan_tests.rs"]
mod tests;

pub(super) struct TaskPlanOwner {
    snapshot: Option<TaskPlanSnapshotV1>,
    latest_submission: Seq,
    publication: Seq,
    needs_review: bool,
}
impl Default for TaskPlanOwner {
    fn default() -> Self {
        Self {
            snapshot: None,
            latest_submission: Seq::ZERO,
            publication: Seq::ZERO,
            needs_review: false,
        }
    }
}
pub(super) struct PreparedTaskPlan {
    snapshot: TaskPlanSnapshotV1,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum TaskPlanInput {
    Inspect,
    Replace {
        expected_revision: u64,
        observed_submission_seq: Seq,
        steps: Vec<iteron_protocol::task_plan::PlanStepV1>,
        obligations: Vec<String>,
    },
}
impl TaskPlanOwner {
    pub(super) fn observe_submission(&mut self, receipt: Seq) {
        if receipt > self.latest_submission {
            self.latest_submission = receipt;
            self.needs_review |= self.is_active();
        }
    }
    fn is_active(&self) -> bool {
        self.snapshot.as_ref().is_some_and(|plan| {
            !plan.obligations.is_empty()
                || plan.steps.iter().any(|step| {
                    step.status != iteron_protocol::task_plan::PlanStepStatusV1::Completed
                })
        })
    }
    pub(super) fn append_context(&self, system: &mut String) {
        if !self.is_active() {
            return;
        }
        system.push_str("\n\n[Model-maintained task plan: reference data, no execution or completion authority]\n");
        system.push_str(&self.inspect().to_string());
        if self.needs_review {
            system.push_str("\nNewly admitted input changed the context after this plan. Review steps and unresolved obligations against that input before continuing the long task.");
        }
    }
    pub(super) fn inspect(&self) -> serde_json::Value {
        serde_json::json!({"kind":"model_task_plan_v1", "plan":self.snapshot,
            "revision":self.snapshot.as_ref().map_or(0, |plan| plan.revision),
            "observed_submission_seq":self.latest_submission, "needs_review":self.needs_review,
            "authority":"model_maintained_reference"})
    }
    pub(super) fn prepare(&self, input: TaskPlanInput) -> Result<PreparedTaskPlan, &'static str> {
        let TaskPlanInput::Replace {
            expected_revision,
            observed_submission_seq,
            mut steps,
            mut obligations,
        } = input
        else {
            return Err("inspect does not replace a task plan");
        };
        let revision = self.snapshot.as_ref().map_or(0, |plan| plan.revision);
        if expected_revision != revision || observed_submission_seq != self.latest_submission {
            return Err("task scope or revision changed; inspect and revise the plan");
        }
        for step in &mut steps {
            step.description = iteron_record::redact::scrub(&step.description);
        }
        for obligation in &mut obligations {
            *obligation = iteron_record::redact::scrub(obligation);
        }
        let snapshot = TaskPlanSnapshotV1 {
            version: 1,
            revision: revision.checked_add(1).ok_or("plan revision exhausted")?,
            based_on_submission_seq: observed_submission_seq,
            steps,
            obligations,
        };
        snapshot.validate()?;
        Ok(PreparedTaskPlan { snapshot })
    }
    pub(super) fn publish(
        &mut self,
        prepared: PreparedTaskPlan,
        receipt: Seq,
    ) -> Result<(), &'static str> {
        if receipt <= self.latest_submission
            || receipt <= self.publication
            || prepared.snapshot.based_on_submission_seq != self.latest_submission
        {
            return Err("task plan has no current durable publication receipt");
        }
        self.snapshot = Some(prepared.snapshot);
        self.publication = receipt;
        self.needs_review = false;
        Ok(())
    }
    pub(super) fn recover<'a>(
        events: impl IntoIterator<Item = &'a Event>,
    ) -> Result<Self, &'static str> {
        let mut owner = Self::default();
        for event in events {
            match &event.kind {
                EventKind::Message { message } if message.role == Role::User => {
                    owner.observe_submission(event.seq)
                }
                EventKind::TaskPlanUpdatedV1 { plan } => {
                    plan.validate()?;
                    let next = match owner.snapshot.as_ref() {
                        Some(prior) => prior
                            .revision
                            .checked_add(1)
                            .ok_or("task plan revision exhausted")?,
                        None => 1,
                    };
                    if plan.revision != next {
                        return Err("task plan journal revisions are inconsistent");
                    }
                    owner.publish(
                        PreparedTaskPlan {
                            snapshot: plan.clone(),
                        },
                        event.seq,
                    )?;
                }
                _ => {}
            }
        }
        Ok(owner)
    }
}
impl PreparedTaskPlan {
    pub(super) fn event(&self) -> EventKind {
        EventKind::TaskPlanUpdatedV1 {
            plan: self.snapshot.clone(),
        }
    }
}
impl super::Agent {
    pub(crate) fn task_plan_snapshot(&self) -> serde_json::Value {
        self.task_plan.inspect()
    }
    pub(super) fn execute_task_plan(
        &mut self,
        turn: iteron_protocol::TurnId,
        call: &iteron_protocol::ToolUse,
    ) -> Result<iteron_protocol::ToolResult, super::KernelError> {
        let input = serde_json::from_value::<TaskPlanInput>(call.input.clone());
        let content = match input {
            Ok(TaskPlanInput::Inspect) => Ok(self.task_plan_snapshot().to_string()),
            Ok(input) => match self.task_plan.prepare(input) {
                Ok(prepared) => {
                    let receipt = self.emit_durable_seq(turn, prepared.event())?;
                    self.task_plan
                        .publish(prepared, receipt)
                        .map_err(|reason| super::KernelError::ContextResolution(reason.into()))?;
                    Ok(self.task_plan.inspect().to_string())
                }
                Err(reason) => Err(reason),
            },
            Err(_) => Err("invalid bounded task-plan command"),
        };
        let is_error = content.is_err();
        Ok(iteron_protocol::ToolResult {
            tool_use_id: call.id.clone(),
            content: content.unwrap_or_else(str::to_owned),
            is_error,
            trust: iteron_protocol::Trust::Untrusted,
            latency_ms: 0,
        })
    }
}
