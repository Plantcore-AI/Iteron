//! Sole mutable optional task-plan owner. Only actual WAL receipts publish replacement state.
use iteron_protocol::{Block, Event, EventKind, Role, Seq, task_plan::TaskPlanSnapshotV1};
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
    pub(super) fn captured_reference(
        &self,
        tenant: &iteron_protocol::TenantId,
        run: &iteron_protocol::RunId,
    ) -> Option<iteron_ctx::context_provenance::CapturedContextMaterial> {
        use sha2::{Digest, Sha256};
        if !self.is_active() || self.publication == Seq::ZERO {
            return None;
        }
        let snapshot = self.snapshot.as_ref()?;
        // Recovery supplies only verified events for this writer's current physical run. This
        // snapshot is the frozen admitted event, not current disk state or a guessed file version.
        let record = serde_json::to_string(&EventKind::TaskPlanUpdatedV1 {
            plan: snapshot.clone(),
        })
        .ok()?;
        let scope = hex::encode(Sha256::digest(serde_json::to_vec(&(tenant, run)).ok()?));
        let mut rendered = String::new();
        self.append_context(&mut rendered);
        Some(
            iteron_ctx::context_provenance::CapturedContextMaterial::journal_record(
                iteron_ctx::ContextSourceClass::TaskPlanReference,
                &scope,
                self.publication.0,
                snapshot.revision,
                &record,
                &rendered,
                iteron_protocol::Trust::Untrusted,
            )
            .with_journal_observation(self.latest_submission.0),
        )
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
        if steps.len() > iteron_protocol::task_plan::MAX_PLAN_STEPS
            || obligations.len() > iteron_protocol::task_plan::MAX_PLAN_OBLIGATIONS
            || steps.iter().any(|step| step.description.len() > 512)
            || obligations.iter().any(|text| text.len() > 512)
            || !bounded_json(&(&steps, &obligations))
        {
            return Err("task plan input exceeds bounded owner admission");
        }
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
                EventKind::Message { message }
                    if message.role == Role::User
                        && !message.content.iter().any(|block| {
                            matches!(block, Block::ToolResult(_) | Block::ToolImage(_))
                        }) =>
                {
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
        let mut journal = super::kernel_dispatch_journal::KernelDispatchJournal {
            workspace: &self.workspace,
            rollout: &mut self.rollout,
            ledger: &mut self.ledger,
            effects: &mut self.effect_journal,
            record_failed: &mut self.record_failed,
            diagnostics: &self.diagnostics,
            money: self.usd_budget.clone(),
            policy: &mut self.policy_evidence,
            bootstrap: None,
            #[cfg(test)]
            fault: &mut self.fail_next_durable_append,
        };
        super::task_plan_execution::TaskPlanExecution {
            owner: &mut self.task_plan,
            journal: &mut journal,
        }
        .execute(turn, call)
    }
}

pub(super) fn bounded_input(value: &serde_json::Value) -> bool {
    use serde_json::Value;
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() > 5 {
        return false;
    }
    match object.get("operation").and_then(Value::as_str) {
        Some("inspect") => return object.len() == 1,
        Some("replace") if object.len() == 5 => {}
        _ => return false,
    }
    if object
        .get("expected_revision")
        .and_then(Value::as_u64)
        .is_none()
        || object
            .get("observed_submission_seq")
            .and_then(Value::as_u64)
            .is_none_or(|seq| seq == 0)
    {
        return false;
    }
    let Some(steps) = object.get("steps").and_then(Value::as_array) else {
        return false;
    };
    let Some(obligations) = object.get("obligations").and_then(Value::as_array) else {
        return false;
    };
    if steps.is_empty()
        || steps.len() > iteron_protocol::task_plan::MAX_PLAN_STEPS
        || obligations.len() > iteron_protocol::task_plan::MAX_PLAN_OBLIGATIONS
    {
        return false;
    }
    for step in steps {
        let Some(fields) = step.as_object() else {
            return false;
        };
        if fields.len() != 2
            || fields
                .get("description")
                .and_then(Value::as_str)
                .is_none_or(|text| text.len() > 512)
            || !matches!(
                fields.get("status").and_then(Value::as_str),
                Some("pending" | "in_progress" | "completed")
            )
        {
            return false;
        }
    }
    if obligations
        .iter()
        .any(|item| item.as_str().is_none_or(|text| text.len() > 512))
    {
        return false;
    }
    bounded_json(value)
}

fn bounded_json(value: &impl serde::Serialize) -> bool {
    struct ByteCount(usize);
    impl std::io::Write for ByteCount {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|total| *total <= iteron_protocol::task_plan::MAX_PLAN_BYTES)
                .ok_or_else(|| std::io::Error::other("bounded plan input exceeded"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(ByteCount(0), value).is_ok()
}
