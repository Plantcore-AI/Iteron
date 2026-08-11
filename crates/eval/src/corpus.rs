//! Strict, external evaluation-corpus manifests with provenance and contamination guards.

use crate::types::{BenchmarkReference, EvaluationPurpose, Partition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::Path;

pub const CORPUS_SCHEMA_VERSION: u32 = 2;
pub const CORPUS_PREVIOUS_SCHEMA_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TASKS: usize = 10_000;
const MAX_TESTS_PER_SET: usize = 50_000;
const MAX_TEST_COMMANDS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source: String,
    pub task_id: String,
    pub license: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkBinding {
    #[serde(flatten)]
    pub reference: BenchmarkReference,
    /// Hidden benchmark regression tests, applied only after the candidate diff is captured.
    pub test_patch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusTask {
    pub id: String,
    pub repo_url: String,
    /// Full, immutable Git object id. Branches and tags are deliberately rejected.
    pub commit: String,
    pub prompt: String,
    /// Legacy candidate-side verification command. Kept through the N-1 migration so a schema-v1
    /// corpus does not lose its original bytes or behavior.
    pub verify_command: String,
    /// Legacy hidden ground-truth command. Native v2 tasks use `test_cmd` plus the two explicit
    /// oracle sets, but retaining this field keeps v1 fixtures reproducible.
    pub ground_truth_command: String,
    /// Official prebuilt environment reference. For SWE-bench Pro this is the repository plus the
    /// dataset's per-instance `dockerhub_tag`; callers may additionally pin a registry digest.
    pub dockerhub_tag: Option<String>,
    /// Tests that must change from red before the candidate patch to green afterwards.
    pub fail_to_pass: Vec<String>,
    /// Tests that must be green both before and after the candidate patch.
    pub pass_to_pass: Vec<String>,
    /// Per-language command used to execute the named test sets. Commands receive
    /// `CORE_EVAL_TEST_SET` and `CORE_EVAL_TEST_IDS_JSON` in their confined shell environment.
    pub test_cmd: BTreeMap<String, String>,
    pub partition: Partition,
    pub provenance: Provenance,
    pub benchmark: Option<BenchmarkBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusManifest {
    pub schema_version: u32,
    pub corpus_version: String,
    /// `sha256:<hex>` over the canonical JSON serialization of `tasks`.
    pub dataset_digest: String,
    pub tasks: Vec<CorpusTask>,
}

#[derive(Debug, Deserialize)]
struct SchemaProbe {
    schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusTaskV1 {
    id: String,
    repo_url: String,
    commit: String,
    prompt: String,
    verify_command: String,
    ground_truth_command: String,
    partition: Partition,
    provenance: Provenance,
    benchmark: Option<BenchmarkBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusManifestV1 {
    schema_version: u32,
    corpus_version: String,
    dataset_digest: String,
    tasks: Vec<CorpusTaskV1>,
}

#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    #[error("cannot read corpus manifest `{path}`: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("corpus manifest exceeds {MAX_MANIFEST_BYTES} bytes")]
    TooLarge,
    #[error("invalid corpus JSON: {0}")]
    Json(serde_json::Error),
    #[error("unsupported corpus schema_version {actual}; expected {expected}")]
    Schema { actual: u32, expected: u32 },
    #[error("corpus_version must be non-empty")]
    EmptyVersion,
    #[error("corpus must contain between 1 and {MAX_TASKS} tasks")]
    TaskCount,
    #[error("duplicate corpus task id `{0}`")]
    DuplicateTask(String),
    #[error("task `{task}` has invalid field `{field}`: {reason}")]
    InvalidTask {
        task: String,
        field: &'static str,
        reason: String,
    },
    #[error("dataset digest mismatch: manifest has `{actual}`, computed `{expected}`")]
    DigestMismatch { actual: String, expected: String },
    #[error("no {partition:?} tasks are available for evaluation purpose {purpose:?}")]
    NoEligibleTasks {
        purpose: EvaluationPurpose,
        partition: Partition,
    },
    #[error("task `{task}` is {actual:?}; purpose {purpose:?} requires {required:?}")]
    Contamination {
        task: String,
        purpose: EvaluationPurpose,
        actual: Partition,
        required: Partition,
    },
}

impl CorpusManifest {
    pub fn load(path: &Path) -> Result<Self, CorpusError> {
        let file = std::fs::File::open(path).map_err(|source| CorpusError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let mut bytes = Vec::new();
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| CorpusError::Read {
                path: path.display().to_string(),
                source,
            })?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(CorpusError::TooLarge);
        }
        let probe: SchemaProbe = serde_json::from_slice(&bytes).map_err(CorpusError::Json)?;
        match probe.schema_version {
            CORPUS_SCHEMA_VERSION => {
                let manifest: Self = serde_json::from_slice(&bytes).map_err(CorpusError::Json)?;
                manifest.validate()?;
                Ok(manifest)
            }
            CORPUS_PREVIOUS_SCHEMA_VERSION => migrate_v1(&bytes),
            actual => Err(CorpusError::Schema {
                actual,
                expected: CORPUS_SCHEMA_VERSION,
            }),
        }
    }

    pub fn validate(&self) -> Result<(), CorpusError> {
        if self.schema_version != CORPUS_SCHEMA_VERSION {
            return Err(CorpusError::Schema {
                actual: self.schema_version,
                expected: CORPUS_SCHEMA_VERSION,
            });
        }
        if self.corpus_version.trim().is_empty() {
            return Err(CorpusError::EmptyVersion);
        }
        if self.tasks.is_empty() || self.tasks.len() > MAX_TASKS {
            return Err(CorpusError::TaskCount);
        }

        let mut ids = HashSet::new();
        for task in &self.tasks {
            if !ids.insert(&task.id) {
                return Err(CorpusError::DuplicateTask(task.id.clone()));
            }
            validate_task(task)?;
        }

        let expected = digest_tasks(&self.tasks)?;
        if self.dataset_digest != expected {
            return Err(CorpusError::DigestMismatch {
                actual: self.dataset_digest.clone(),
                expected,
            });
        }
        Ok(())
    }

    pub fn tasks_for(&self, purpose: EvaluationPurpose) -> Result<Vec<&CorpusTask>, CorpusError> {
        let required = purpose.required_partition();
        let tasks: Vec<_> = self
            .tasks
            .iter()
            .filter(|task| task.partition == required)
            .collect();
        if tasks.is_empty() {
            return Err(CorpusError::NoEligibleTasks {
                purpose,
                partition: required,
            });
        }
        Ok(tasks)
    }

    pub fn task_for(
        &self,
        task_id: &str,
        purpose: EvaluationPurpose,
    ) -> Result<Option<&CorpusTask>, CorpusError> {
        let Some(task) = self.tasks.iter().find(|task| task.id == task_id) else {
            return Ok(None);
        };
        let required = purpose.required_partition();
        if task.partition != required {
            return Err(CorpusError::Contamination {
                task: task.id.clone(),
                purpose,
                actual: task.partition,
                required,
            });
        }
        Ok(Some(task))
    }
}

pub fn digest_tasks(tasks: &[CorpusTask]) -> Result<String, CorpusError> {
    let canonical = serde_json::to_vec(tasks).map_err(CorpusError::Json)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(canonical))))
}

fn migrate_v1(bytes: &[u8]) -> Result<CorpusManifest, CorpusError> {
    let legacy: CorpusManifestV1 = serde_json::from_slice(bytes).map_err(CorpusError::Json)?;
    if legacy.schema_version != CORPUS_PREVIOUS_SCHEMA_VERSION {
        return Err(CorpusError::Schema {
            actual: legacy.schema_version,
            expected: CORPUS_SCHEMA_VERSION,
        });
    }
    let expected = digest_serializable(&legacy.tasks)?;
    if legacy.dataset_digest != expected {
        return Err(CorpusError::DigestMismatch {
            actual: legacy.dataset_digest,
            expected,
        });
    }

    let tasks = legacy
        .tasks
        .into_iter()
        .map(|task| {
            let mut test_cmd = BTreeMap::new();
            test_cmd.insert("legacy".to_owned(), task.ground_truth_command.clone());
            CorpusTask {
                id: task.id,
                repo_url: task.repo_url,
                commit: task.commit,
                prompt: task.prompt,
                fail_to_pass: vec![task.verify_command.clone()],
                pass_to_pass: Vec::new(),
                test_cmd,
                verify_command: task.verify_command,
                ground_truth_command: task.ground_truth_command,
                dockerhub_tag: task
                    .benchmark
                    .as_ref()
                    .and_then(|binding| binding.reference.environment_image.clone()),
                partition: task.partition,
                provenance: task.provenance,
                benchmark: task.benchmark,
            }
        })
        .collect::<Vec<_>>();
    let manifest = CorpusManifest {
        schema_version: CORPUS_SCHEMA_VERSION,
        corpus_version: legacy.corpus_version,
        dataset_digest: digest_tasks(&tasks)?,
        tasks,
    };
    manifest.validate()?;
    Ok(manifest)
}

fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<String, CorpusError> {
    let canonical = serde_json::to_vec(value).map_err(CorpusError::Json)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(canonical))))
}

fn validate_task(task: &CorpusTask) -> Result<(), CorpusError> {
    let invalid = |field, reason: &str| CorpusError::InvalidTask {
        task: task.id.clone(),
        field,
        reason: reason.to_owned(),
    };
    if task.id.trim().is_empty() || task.id.len() > 256 {
        return Err(invalid("id", "must contain 1..=256 bytes"));
    }
    if !is_lower_hex_sha(&task.commit, false) {
        return Err(invalid("commit", "must be a lowercase 40-hex Git SHA-1"));
    }
    let url = url::Url::parse(&task.repo_url)
        .map_err(|error| invalid("repo_url", &format!("invalid absolute URL: {error}")))?;
    if !matches!(url.scheme(), "https" | "file") {
        return Err(invalid("repo_url", "only https and file URLs are accepted"));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "repo_url",
            "credentials, query strings, and fragments are not allowed in corpus URLs",
        ));
    }
    for (field, value, limit) in [
        ("prompt", task.prompt.as_str(), 256 * 1024),
        ("verify_command", task.verify_command.as_str(), 16 * 1024),
        (
            "ground_truth_command",
            task.ground_truth_command.as_str(),
            16 * 1024,
        ),
        (
            "provenance.source",
            task.provenance.source.as_str(),
            4 * 1024,
        ),
        (
            "provenance.task_id",
            task.provenance.task_id.as_str(),
            4 * 1024,
        ),
    ] {
        if value.trim().is_empty() || value.len() > limit {
            return Err(invalid(field, &format!("must contain 1..={limit} bytes")));
        }
    }
    if let Some(image) = &task.dockerhub_tag
        && (image.trim().is_empty()
            || image.len() > 1_024
            || image.contains(char::is_whitespace)
            || image.ends_with(":latest"))
    {
        return Err(invalid(
            "dockerhub_tag",
            "must be a bounded, non-latest image reference without whitespace",
        ));
    }
    validate_test_set(task, "fail_to_pass", &task.fail_to_pass, true)?;
    validate_test_set(task, "pass_to_pass", &task.pass_to_pass, false)?;
    let mut tests = HashSet::new();
    for test in &task.fail_to_pass {
        tests.insert(test);
    }
    if task.pass_to_pass.iter().any(|test| !tests.insert(test)) {
        return Err(invalid(
            "pass_to_pass",
            "must not overlap FAIL_TO_PASS or contain duplicates",
        ));
    }
    if task.test_cmd.is_empty() || task.test_cmd.len() > MAX_TEST_COMMANDS {
        return Err(invalid(
            "test_cmd",
            &format!("must contain 1..={MAX_TEST_COMMANDS} language commands"),
        ));
    }
    for (language, command) in &task.test_cmd {
        if language.is_empty()
            || language.len() > 32
            || !language
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(invalid(
                "test_cmd",
                "language keys must be 1..=32 lowercase ASCII identifier bytes",
            ));
        }
        if command.trim().is_empty() || command.len() > 64 * 1024 {
            return Err(invalid("test_cmd", "commands must contain 1..=65536 bytes"));
        }
    }
    if let Some(binding) = &task.benchmark {
        validate_benchmark(task, binding)?;
    }
    Ok(())
}

fn validate_test_set(
    task: &CorpusTask,
    field: &'static str,
    tests: &[String],
    required: bool,
) -> Result<(), CorpusError> {
    let invalid = |reason: &str| CorpusError::InvalidTask {
        task: task.id.clone(),
        field,
        reason: reason.to_owned(),
    };
    if (required && tests.is_empty()) || tests.len() > MAX_TESTS_PER_SET {
        return Err(invalid(&format!(
            "must contain {}..={MAX_TESTS_PER_SET} tests",
            usize::from(required)
        )));
    }
    let mut unique = HashSet::new();
    for test in tests {
        if test.trim().is_empty() || test.len() > 16 * 1024 {
            return Err(invalid("each test id must contain 1..=16384 bytes"));
        }
        if !unique.insert(test) {
            return Err(invalid("must not contain duplicate test ids"));
        }
    }
    Ok(())
}

fn validate_benchmark(task: &CorpusTask, binding: &BenchmarkBinding) -> Result<(), CorpusError> {
    let invalid = |field, reason: &str| CorpusError::InvalidTask {
        task: task.id.clone(),
        field,
        reason: reason.to_owned(),
    };
    let reference = &binding.reference;
    for (field, value, limit) in [
        ("benchmark.name", reference.name.as_str(), 256),
        ("benchmark.instance_id", reference.instance_id.as_str(), 512),
        (
            "benchmark.dataset_revision",
            reference.dataset_revision.as_str(),
            256,
        ),
    ] {
        if value.trim().is_empty() || value.len() > limit {
            return Err(invalid(field, &format!("must contain 1..={limit} bytes")));
        }
    }
    if !is_lower_hex_sha(&reference.dataset_revision, true) {
        return Err(invalid(
            "benchmark.dataset_revision",
            "must be a lowercase 40- or 64-hex immutable revision",
        ));
    }
    if !task.provenance.source.contains(&reference.dataset_revision) {
        return Err(invalid(
            "provenance.source",
            "must bind the benchmark dataset revision",
        ));
    }
    if !is_lower_hex_sha(&reference.environment_setup_commit, false) {
        return Err(invalid(
            "benchmark.environment_setup_commit",
            "must be a lowercase 40-hex Git SHA-1",
        ));
    }
    if binding.test_patch.is_empty() || binding.test_patch.len() > 2 * 1024 * 1024 {
        return Err(invalid(
            "benchmark.test_patch",
            "must contain 1..=2097152 bytes",
        ));
    }
    let expected = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(binding.test_patch.as_bytes()))
    );
    if reference.test_patch_sha256 != expected {
        return Err(invalid(
            "benchmark.test_patch_sha256",
            &format!(
                "digest mismatch: manifest has `{}`, computed `{expected}`",
                reference.test_patch_sha256
            ),
        ));
    }
    if reference.environment_image.as_ref().is_some_and(|image| {
        image.trim().is_empty() || image.len() > 1_024 || image.contains(['\r', '\n'])
    }) {
        return Err(invalid(
            "benchmark.environment_image",
            "must be one non-empty line of at most 1024 bytes",
        ));
    }
    Ok(())
}

fn is_lower_hex_sha(value: &str, allow_sha256: bool) -> bool {
    (value.len() == 40 || (allow_sha256 && value.len() == 64))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BenchmarkReference;

    fn task(id: &str, partition: Partition) -> CorpusTask {
        CorpusTask {
            id: id.into(),
            repo_url: "https://github.com/example/repo.git".into(),
            commit: "0123456789abcdef0123456789abcdef01234567".into(),
            prompt: "fix the bug".into(),
            verify_command: "cargo test --locked".into(),
            ground_truth_command: "cargo test --locked".into(),
            dockerhub_tag: None,
            fail_to_pass: vec!["legacy::cargo-test".into()],
            pass_to_pass: Vec::new(),
            test_cmd: BTreeMap::from([("rust".into(), "cargo test --locked".into())]),
            partition,
            provenance: Provenance {
                source: "benchmark-v1".into(),
                task_id: id.into(),
                license: Some("MIT".into()),
            },
            benchmark: None,
        }
    }

    fn manifest(tasks: Vec<CorpusTask>) -> CorpusManifest {
        CorpusManifest {
            schema_version: CORPUS_SCHEMA_VERSION,
            corpus_version: "fixture-v2".into(),
            dataset_digest: digest_tasks(&tasks).unwrap(),
            tasks,
        }
    }

    fn benchmark_binding() -> BenchmarkBinding {
        let patch = "diff --git a/test.txt b/test.txt\nnew file mode 100644\n--- /dev/null\n+++ b/test.txt\n@@ -0,0 +1 @@\n+regression\n";
        BenchmarkBinding {
            reference: BenchmarkReference {
                name: "SWE-bench_Lite".into(),
                instance_id: "example__repo-1".into(),
                dataset_revision: "2".repeat(40),
                environment_setup_commit: "3".repeat(40),
                environment_image: Some("swebench/example@sha256:fixture".into()),
                test_patch_sha256: format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(patch.as_bytes()))
                ),
            },
            test_patch: patch.into(),
        }
    }

    static NEXT_TEMP_FILE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// A path no other test in this binary can also produce.
    ///
    /// The nanosecond timestamp this replaces is not a unique value: `SystemTime::now()` is
    /// microsecond-granular on macOS, and consecutive calls on this machine return byte-identical
    /// nanos. Four tests here share one prefix, so two running concurrently could land on the same
    /// path -- and because each writes a *different* corpus and then reads it back, the loser reads
    /// the winner's file. That is not a lost temp file; it is one test asserting against another
    /// test's data, which is how `v3_and_unknown_fields_are_rejected_before_task_data_is_used`
    /// reached `.unwrap_err()` on a manifest that had legitimately loaded.
    ///
    /// A process-wide counter cannot collide with itself, which is the same reason
    /// `crates/tools/src/schema_tests.rs` and `write_file_tests.rs` already use one.
    fn temp_file() -> std::path::PathBuf {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "iteron-eval-corpus-{}-{sequence}.json",
            std::process::id()
        ))
    }

    #[test]
    fn external_manifest_loads_and_round_trips_without_source_changes() {
        let path = temp_file();
        let expected = manifest(vec![
            task("one", Partition::Train),
            task("two", Partition::HeldOut),
        ]);
        std::fs::write(&path, serde_json::to_vec_pretty(&expected).unwrap()).unwrap();
        let loaded = CorpusManifest::load(&path).unwrap();
        assert_eq!(loaded, expected);
        assert_eq!(
            loaded.tasks_for(EvaluationPurpose::Score).unwrap()[0].id,
            "two"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn v1_manifest_migrates_without_changing_prompt_or_hidden_patch_bytes() {
        let mut legacy_task = CorpusTaskV1 {
            id: "legacy".into(),
            repo_url: "https://github.com/example/repo.git".into(),
            commit: "0123456789abcdef0123456789abcdef01234567".into(),
            prompt: "preserve me byte-for-byte\n".into(),
            verify_command: "cargo test legacy::f2p".into(),
            ground_truth_command: "cargo test --all".into(),
            partition: Partition::HeldOut,
            provenance: Provenance {
                source: "legacy-v1".into(),
                task_id: "legacy".into(),
                license: Some("MIT".into()),
            },
            benchmark: None,
        };
        let patch = "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new with spaces  \n";
        legacy_task.benchmark = Some(BenchmarkBinding {
            reference: BenchmarkReference {
                name: "legacy".into(),
                instance_id: "legacy".into(),
                dataset_revision: "2".repeat(40),
                environment_setup_commit: "3".repeat(40),
                environment_image: Some("example/image:pinned".into()),
                test_patch_sha256: format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(patch.as_bytes()))
                ),
            },
            test_patch: patch.into(),
        });
        legacy_task.provenance.source = format!(
            "https://example.invalid/dataset/tree/{}",
            legacy_task
                .benchmark
                .as_ref()
                .unwrap()
                .reference
                .dataset_revision
        );
        let legacy = CorpusManifestV1 {
            schema_version: CORPUS_PREVIOUS_SCHEMA_VERSION,
            corpus_version: "fixture-v1".into(),
            dataset_digest: digest_serializable(std::slice::from_ref(&legacy_task)).unwrap(),
            tasks: vec![legacy_task.clone()],
        };
        let path = temp_file();
        std::fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        let loaded = CorpusManifest::load(&path).unwrap();
        assert_eq!(loaded.schema_version, CORPUS_SCHEMA_VERSION);
        assert_eq!(loaded.tasks[0].prompt, legacy_task.prompt);
        assert_eq!(
            loaded.tasks[0].benchmark.as_ref().unwrap().test_patch,
            legacy_task.benchmark.as_ref().unwrap().test_patch
        );
        assert_eq!(
            loaded.tasks[0].fail_to_pass,
            vec![legacy_task.verify_command]
        );
        assert_eq!(
            loaded.tasks[0].ground_truth_command,
            legacy_task.ground_truth_command
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn v3_and_unknown_fields_are_rejected_before_task_data_is_used() {
        let mut corpus = manifest(vec![task("task", Partition::HeldOut)]);
        corpus.schema_version = 3;
        let path = temp_file();
        std::fs::write(&path, serde_json::to_vec(&corpus).unwrap()).unwrap();
        let error = CorpusManifest::load(&path).unwrap_err();
        assert!(
            matches!(
                error,
                CorpusError::Schema {
                    actual: 3,
                    expected: CORPUS_SCHEMA_VERSION
                }
            ),
            "unexpected error: {error:?}"
        );

        let mut value =
            serde_json::to_value(manifest(vec![task("task", Partition::HeldOut)])).unwrap();
        value["tasks"][0]["unknown"] = serde_json::Value::Bool(true);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            CorpusManifest::load(&path),
            Err(CorpusError::Json(_))
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn scoring_a_training_task_is_refused() {
        let corpus = manifest(vec![task("train", Partition::Train)]);
        assert!(matches!(
            corpus.task_for("train", EvaluationPurpose::Score),
            Err(CorpusError::Contamination { .. })
        ));
        assert!(matches!(
            corpus.tasks_for(EvaluationPurpose::Score),
            Err(CorpusError::NoEligibleTasks { .. })
        ));

        let corpus = manifest(vec![task("held-out", Partition::HeldOut)]);
        assert!(matches!(
            corpus.task_for("held-out", EvaluationPurpose::Tune),
            Err(CorpusError::Contamination { .. })
        ));
        assert!(matches!(
            corpus.tasks_for(EvaluationPurpose::Tune),
            Err(CorpusError::NoEligibleTasks { .. })
        ));
    }

    #[test]
    fn branch_names_and_tampered_dataset_are_rejected() {
        let mut corpus = manifest(vec![task("task", Partition::HeldOut)]);
        corpus.tasks[0].commit = "main".into();
        assert!(matches!(
            corpus.validate(),
            Err(CorpusError::InvalidTask {
                field: "commit",
                ..
            })
        ));

        let mut corpus = manifest(vec![task("task", Partition::HeldOut)]);
        corpus.tasks[0].prompt.push('!');
        assert!(matches!(
            corpus.validate(),
            Err(CorpusError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn benchmark_binding_round_trips_and_rejects_a_tampered_test_patch() {
        let mut bound_task = task("benchmark", Partition::HeldOut);
        let binding = benchmark_binding();
        bound_task.provenance.source = format!(
            "https://example.invalid/dataset/tree/{}",
            binding.reference.dataset_revision
        );
        bound_task.benchmark = Some(binding);
        let corpus = manifest(vec![bound_task]);
        corpus.validate().unwrap();
        let encoded = serde_json::to_vec(&corpus).unwrap();
        let decoded: CorpusManifest = serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();

        let mut tampered = decoded;
        tampered.tasks[0]
            .benchmark
            .as_mut()
            .unwrap()
            .test_patch
            .push_str("tampered");
        assert!(matches!(
            tampered.validate(),
            Err(CorpusError::InvalidTask {
                field: "benchmark.test_patch_sha256",
                ..
            })
        ));
    }

    #[test]
    fn benchmark_revision_must_be_pinned_and_bound_by_provenance() {
        let mut bound_task = task("benchmark", Partition::HeldOut);
        let binding = benchmark_binding();
        bound_task.provenance.source = format!(
            "https://example.invalid/dataset/tree/{}",
            binding.reference.dataset_revision
        );
        bound_task.benchmark = Some(binding);

        let mut unpinned = manifest(vec![bound_task.clone()]);
        unpinned.tasks[0]
            .benchmark
            .as_mut()
            .unwrap()
            .reference
            .dataset_revision = "main".into();
        assert!(matches!(
            unpinned.validate(),
            Err(CorpusError::InvalidTask {
                field: "benchmark.dataset_revision",
                ..
            })
        ));

        bound_task.provenance.source = "https://example.invalid/dataset/tree/main".into();
        let unbound = manifest(vec![bound_task]);
        assert!(matches!(
            unbound.validate(),
            Err(CorpusError::InvalidTask {
                field: "provenance.source",
                ..
            })
        ));
    }
}
