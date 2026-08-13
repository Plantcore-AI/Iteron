//! Immutable, independently owned evaluation-suite content for the evolution verifier.

use crate::verifier::VerifierError;
use crate::verifier_crypto::digest_serialized;
use crate::{
    MAX_GOVERNED_DATASET_BYTES, MAX_SHORT_STRING_BYTES, validate_digest, validate_nonempty_string,
};
use serde::Serialize;

pub const MAX_EVALUATION_TASKS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvaluationTask {
    pub task_id: String,
    pub fixture_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvaluationSuite {
    owner_id: String,
    version: String,
    pub(crate) tasks: Vec<EvaluationTask>,
    pub(crate) digest: String,
}

impl EvaluationSuite {
    pub fn new(
        owner_id: impl Into<String>,
        version: impl Into<String>,
        mut tasks: Vec<EvaluationTask>,
    ) -> Result<Self, VerifierError> {
        let owner_id = owner_id.into();
        let version = version.into();
        validate_nonempty_string("evaluation.owner_id", &owner_id, MAX_SHORT_STRING_BYTES)
            .map_err(VerifierError::InvalidContract)?;
        validate_nonempty_string("evaluation.version", &version, MAX_SHORT_STRING_BYTES)
            .map_err(VerifierError::InvalidContract)?;
        if tasks.is_empty()
            || tasks.len()
                > iteron_tunables::param_integer(
                    "evolve.verifier_eval.max_evaluation_tasks",
                    MAX_EVALUATION_TASKS,
                )
        {
            return Err(VerifierError::InvalidEvaluationTaskCount {
                max: iteron_tunables::param_integer(
                    "evolve.verifier_eval.max_evaluation_tasks",
                    MAX_EVALUATION_TASKS,
                ),
                actual: tasks.len(),
            });
        }
        tasks.sort_by(|left, right| left.task_id.cmp(&right.task_id));
        let mut previous: Option<&str> = None;
        for task in &tasks {
            validate_nonempty_string("evaluation.task_id", &task.task_id, MAX_SHORT_STRING_BYTES)
                .map_err(VerifierError::InvalidContract)?;
            validate_digest(&task.fixture_digest).map_err(VerifierError::InvalidContract)?;
            if previous == Some(task.task_id.as_str()) {
                return Err(VerifierError::DuplicateEvaluationTask(task.task_id.clone()));
            }
            previous = Some(&task.task_id);
        }
        #[derive(Serialize)]
        struct SuiteContent<'a> {
            owner_id: &'a str,
            version: &'a str,
            tasks: &'a [EvaluationTask],
        }
        let digest = digest_serialized(
            &SuiteContent {
                owner_id: &owner_id,
                version: &version,
                tasks: &tasks,
            },
            MAX_GOVERNED_DATASET_BYTES,
        )?;
        Ok(Self {
            owner_id,
            version,
            tasks,
            digest,
        })
    }

    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn tasks(&self) -> &[EvaluationTask] {
        &self.tasks
    }
}
