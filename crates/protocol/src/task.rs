//! `TaskEnvelope` — a task entering the runtime, with its acceptance contract and authority.
//!
//! # Why this is constructed from `Op`, not added to it
//!
//! `Op` is an internally-tagged enum on the submission queue, matched exhaustively in three places
//! in `crates/kernel`. A blast-radius review found that adding an `Op::Task` variant would not only
//! break those matches but do something worse: the natural arm for a new variant pushes into
//! `pending_steers`, which would reclassify a whole envelope — acceptance contract, budget,
//! authority ceiling — as steering *text*.
//!
//! So the envelope is a separate type built **from** `Op::UserInput`. The submission queue keeps
//! its exact shape and bytes; the envelope is what the runtime carries once a submission has been
//! admitted.
//!
//! # What is deliberately not here
//!
//! An adversarial review of the W1 freeze found that the acceptance contract, as specified, could
//! not express what its own dependents need: issue #32 requires two differently-quantified oracle
//! sets (FAIL_TO_PASS must flip, PASS_TO_PASS must hold), against a single-oracle shape. Rather
//! than freeze a single oracle and force `Option` fields onto it later, [`Acceptance`] carries a
//! *set* of named checks with an explicit quantifier. One check is the degenerate case.

use crate::Op;
use crate::capability_set::CapabilitySet;
use crate::ids::SubmissionId;
use crate::wire::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};

/// Upper bound on a task's text payload.
pub const MAX_TASK_TEXT_BYTES: usize = 1_048_576;
/// Upper bound on the number of acceptance checks one task may declare.
pub const MAX_ACCEPTANCE_CHECKS: usize = 256;

/// How an acceptance check's result is read.
///
/// This exists because "did it pass" is not one question. A regression suite must *keep* passing;
/// a bug fix's test must *start* passing. Collapsing both into one boolean is what forced #32 to
/// invent its own shape outside the ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quantifier {
    /// Must pass after the change. Says nothing about before.
    MustPass,
    /// Must fail before the change and pass after. The check proves the change did something.
    MustFlipToPass,
    /// Must pass before and after. The check proves the change broke nothing.
    MustStayPassing,
}

/// One named, machine-runnable acceptance check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceCheck {
    /// Stable identity of the check within the task. Not a display name.
    pub id: String,
    /// How to read the result.
    pub quantifier: Quantifier,
}

/// What "done" means for a task, as a set of checks rather than a single verdict.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Acceptance {
    pub checks: Vec<AcceptanceCheck>,
}

impl Acceptance {
    /// The degenerate single-check case.
    pub fn single(id: impl Into<String>, quantifier: Quantifier) -> Self {
        Self {
            checks: vec![AcceptanceCheck {
                id: id.into(),
                quantifier,
            }],
        }
    }

    /// An empty acceptance set means "no machine-checkable definition of done was supplied".
    /// It is not the same as "passed", and callers must not treat it as one.
    pub fn is_unspecified(&self) -> bool {
        self.checks.is_empty()
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.checks.len() > MAX_ACCEPTANCE_CHECKS {
            return Err("too many acceptance checks");
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.checks.len());
        for check in &self.checks {
            if check.id.is_empty() {
                return Err("acceptance check id must not be empty");
            }
            if seen.contains(&check.id.as_str()) {
                return Err("acceptance check ids must be unique within a task");
            }
            seen.push(&check.id);
        }
        Ok(())
    }
}

/// A task entering the runtime.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskEnvelope {
    /// The submission this envelope was admitted from.
    pub task_id: SubmissionId,
    /// The protocol version the submission arrived under. Pinned for the whole run.
    pub protocol_version: u32,
    /// The operator's request.
    pub text: String,
    /// What counts as done.
    pub acceptance: Acceptance,
    /// The authority ceiling for the whole task. A set: nothing in the task may be admitted
    /// outside it, and it can only ever be narrowed.
    pub ceiling: CapabilitySet,
}

impl TaskEnvelope {
    /// Build an envelope from an admitted `Op::UserInput`.
    ///
    /// Returns `None` for any other submission kind: approvals, steering and interrupts are not
    /// tasks, and quietly turning one into a task is the reclassification bug this type avoids.
    pub fn from_user_input(task_id: SubmissionId, op: &Op, ceiling: CapabilitySet) -> Option<Self> {
        let text = match op {
            Op::UserInput { text } => text,
            _ => return None,
        };
        Some(Self {
            task_id,
            protocol_version: PROTOCOL_VERSION,
            text: text.to_owned(),
            acceptance: Acceptance::default(),
            ceiling,
        })
    }

    /// Attach a machine-checkable definition of done.
    pub fn with_acceptance(mut self, acceptance: Acceptance) -> Self {
        self.acceptance = acceptance;
        self
    }

    /// Validate bounds and internal consistency. Pure.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.text.len() > MAX_TASK_TEXT_BYTES {
            return Err("task text exceeds its declared bound");
        }
        if self.ceiling.is_empty() {
            return Err("a task with an empty authority ceiling can admit nothing");
        }
        self.acceptance.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::{Acceptance, Quantifier, TaskEnvelope};
    use crate::Op;
    use crate::capability_set::CapabilitySet;
    use crate::ids::SubmissionId;
    use crate::tool::Capability;

    fn ceiling() -> CapabilitySet {
        CapabilitySet::from_iter_capabilities([Capability::ReadOnly, Capability::ReversibleLocal])
    }

    #[test]
    fn only_a_user_input_becomes_a_task() {
        let input = Op::UserInput {
            text: "fix the parser".into(),
        };
        assert!(TaskEnvelope::from_user_input(SubmissionId(1), &input, ceiling()).is_some());

        // Steering is not a task. Turning it into one would smuggle a whole envelope's
        // authority in through a text channel.
        let steer = Op::Steer {
            text: "actually, also do X".into(),
        };
        assert!(TaskEnvelope::from_user_input(SubmissionId(2), &steer, ceiling()).is_none());
    }

    #[test]
    fn the_submission_queue_shape_is_untouched_by_the_envelope_existing() {
        let input = Op::UserInput {
            text: "fix the parser".into(),
        };
        let before = serde_json::to_string(&input).expect("Op serialises");
        let _ = TaskEnvelope::from_user_input(SubmissionId(1), &input, ceiling());
        assert_eq!(
            serde_json::to_string(&input).expect("re-serialises"),
            before,
            "Op is matched exhaustively in the kernel and pinned by fixtures; it must not move"
        );
    }

    #[test]
    fn acceptance_distinguishes_must_flip_from_must_stay() {
        let acceptance = Acceptance {
            checks: vec![
                super::AcceptanceCheck {
                    id: "test_parses_nested_braces".into(),
                    quantifier: Quantifier::MustFlipToPass,
                },
                super::AcceptanceCheck {
                    id: "suite::regression".into(),
                    quantifier: Quantifier::MustStayPassing,
                },
            ],
        };
        let envelope = TaskEnvelope::from_user_input(
            SubmissionId(1),
            &Op::UserInput { text: "fix".into() },
            ceiling(),
        )
        .expect("envelope")
        .with_acceptance(acceptance);
        assert!(envelope.validate().is_ok());
        assert!(!envelope.acceptance.is_unspecified());
    }

    #[test]
    fn an_empty_acceptance_set_is_unspecified_not_passed() {
        let envelope = TaskEnvelope::from_user_input(
            SubmissionId(1),
            &Op::UserInput { text: "fix".into() },
            ceiling(),
        )
        .expect("envelope");
        assert!(envelope.acceptance.is_unspecified());
        assert!(
            envelope.validate().is_ok(),
            "unspecified is legal, but it is not a pass"
        );
    }

    #[test]
    fn duplicate_check_ids_and_empty_ceilings_are_rejected() {
        let dup = Acceptance {
            checks: vec![
                super::AcceptanceCheck {
                    id: "same".into(),
                    quantifier: Quantifier::MustPass,
                },
                super::AcceptanceCheck {
                    id: "same".into(),
                    quantifier: Quantifier::MustStayPassing,
                },
            ],
        };
        let envelope = TaskEnvelope::from_user_input(
            SubmissionId(1),
            &Op::UserInput { text: "fix".into() },
            ceiling(),
        )
        .expect("envelope")
        .with_acceptance(dup);
        assert!(envelope.validate().is_err());

        let no_authority = TaskEnvelope::from_user_input(
            SubmissionId(1),
            &Op::UserInput { text: "fix".into() },
            CapabilitySet::none(),
        )
        .expect("envelope");
        assert!(no_authority.validate().is_err());
    }

    #[test]
    fn single_is_the_degenerate_case_of_a_set() {
        let one = Acceptance::single("cargo test", Quantifier::MustPass);
        assert_eq!(one.checks.len(), 1);
        assert!(!one.is_unspecified());
    }
}
