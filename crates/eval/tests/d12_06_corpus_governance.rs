use core_eval::{CorpusError, CorpusManifest, EvaluationPurpose, Partition};
use serde_json::Value;
use std::path::{Path, PathBuf};

const MAX_SCAN_DEPTH: usize = 3;
const MAX_DIRECTORIES: usize = 32;
const MAX_ENTRIES_PER_DIRECTORY: usize = 256;
const MAX_JSON_DOCUMENTS: usize = 128;

fn json_documents(root: &Path) -> Vec<(PathBuf, Value)> {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut directories = 0_usize;
    let mut documents = Vec::new();

    while let Some((directory, depth)) = pending.pop() {
        directories += 1;
        assert!(
            directories <= MAX_DIRECTORIES,
            "governed corpus scan exceeded {MAX_DIRECTORIES} directories"
        );
        let mut entries = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("read governed corpus directory {directory:?}: {error}"))
            .map(|entry| entry.expect("read governed corpus directory entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        assert!(
            entries.len() <= MAX_ENTRIES_PER_DIRECTORY,
            "governed corpus directory {directory:?} exceeded {MAX_ENTRIES_PER_DIRECTORY} entries"
        );

        for path in entries {
            if path.is_dir() && depth < MAX_SCAN_DEPTH {
                pending.push((path, depth + 1));
            } else if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("read governed JSON {path:?}: {error}"));
                let value = serde_json::from_slice(&bytes)
                    .unwrap_or_else(|error| panic!("parse governed JSON {path:?}: {error}"));
                documents.push((path, value));
                assert!(
                    documents.len() <= MAX_JSON_DOCUMENTS,
                    "governed corpus scan exceeded {MAX_JSON_DOCUMENTS} JSON documents"
                );
            }
        }
    }

    documents.sort_by(|left, right| left.0.cmp(&right.0));
    documents
}

fn recognized_benchmark(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("swe-bench")
}

fn is_pinned_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn has_recorded_benchmark_outcome(documents: &[(PathBuf, Value)], corpus: &CorpusManifest) -> bool {
    documents.iter().any(|(_, document)| {
        document.get("corpus_version").and_then(Value::as_str)
            == Some(corpus.corpus_version.as_str())
            && document.get("dataset_digest").and_then(Value::as_str)
                == Some(corpus.dataset_digest.as_str())
            && document
                .get("cells")
                .and_then(Value::as_array)
                .is_some_and(|cells| {
                    cells.iter().any(|cell| {
                        let Some(task_id) = cell.get("task").and_then(Value::as_str) else {
                            return false;
                        };
                        let Some(task) = corpus.tasks.iter().find(|task| task.id == task_id) else {
                            return false;
                        };
                        let Some(expected_benchmark) = task.benchmark.as_ref() else {
                            return false;
                        };
                        let Some(recorded_benchmark) = cell.get("benchmark") else {
                            return false;
                        };

                        task.partition == Partition::HeldOut
                            && cell.get("partition").and_then(Value::as_str) == Some("held_out")
                            && cell.get("run_status").and_then(Value::as_str) == Some("completed")
                            && cell.get("resolved").is_some_and(Value::is_boolean)
                            && recorded_benchmark.get("name").and_then(Value::as_str)
                                == Some(expected_benchmark.reference.name.as_str())
                            && recorded_benchmark
                                .get("instance_id")
                                .and_then(Value::as_str)
                                == Some(expected_benchmark.reference.instance_id.as_str())
                    })
                })
    })
}

#[test]
fn d12_06_governed_corpus_has_split_and_recorded_held_out_benchmark() {
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpora");
    let documents = json_documents(&corpus_root);
    assert!(
        !documents.is_empty(),
        "the evaluator must ship at least one external governed corpus manifest"
    );

    let corpora = documents
        .iter()
        .filter_map(|(path, _)| {
            CorpusManifest::load(path)
                .ok()
                .map(|manifest| (path, manifest))
        })
        .collect::<Vec<_>>();
    assert!(
        !corpora.is_empty(),
        "no checked-in JSON document loads through the production CorpusManifest loader"
    );

    let split_benchmark_corpora = corpora
        .iter()
        .filter(|(_, corpus)| {
            corpus
                .tasks
                .iter()
                .any(|task| task.partition == Partition::Train)
                && corpus.tasks.iter().any(|task| {
                    task.partition == Partition::HeldOut
                        && task
                            .benchmark
                            .as_ref()
                            .is_some_and(|binding| recognized_benchmark(&binding.reference.name))
                })
        })
        .collect::<Vec<_>>();
    let inventory = corpora
        .iter()
        .map(|(path, corpus)| {
            let train = corpus
                .tasks
                .iter()
                .filter(|task| task.partition == Partition::Train)
                .count();
            let held_out = corpus.tasks.len() - train;
            format!("{}: train={train}, held_out={held_out}", path.display())
        })
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        !split_benchmark_corpora.is_empty(),
        "no governed external corpus declares a real train/held-out split with a held-out \
         recognized benchmark task; inventory: {inventory}"
    );

    let (_, corpus) = split_benchmark_corpora
        .into_iter()
        .find(|(_, corpus)| has_recorded_benchmark_outcome(&documents, corpus))
        .unwrap_or_else(|| {
            panic!(
                "a recognized held-out benchmark is bound, but no checked-in evaluation record \
                 links its corpus_version and dataset_digest to a completed boolean pass/fail"
            )
        });

    for task in &corpus.tasks {
        assert!(
            is_pinned_sha(&task.commit),
            "task {} is not pinned to an immutable repository SHA",
            task.id
        );
        assert!(
            !task.provenance.source.trim().is_empty() && !task.provenance.task_id.trim().is_empty(),
            "task {} lacks per-task provenance",
            task.id
        );
        if let Some(binding) = &task.benchmark {
            assert!(
                is_pinned_sha(&binding.reference.dataset_revision),
                "benchmark task {} has an unpinned dataset revision",
                task.id
            );
            assert!(
                task.provenance
                    .source
                    .contains(&binding.reference.dataset_revision),
                "benchmark task {} provenance does not bind its dataset revision",
                task.id
            );
        }
    }

    let tuning_tasks = corpus
        .tasks_for(EvaluationPurpose::Tune)
        .expect("the governed split must expose training tasks for tuning");
    assert!(
        tuning_tasks
            .iter()
            .all(|task| task.partition == Partition::Train),
        "a held-out task reached the tuning task set"
    );
    let scoring_tasks = corpus
        .tasks_for(EvaluationPurpose::Score)
        .expect("the governed split must expose held-out tasks for scoring");
    assert!(
        scoring_tasks
            .iter()
            .all(|task| task.partition == Partition::HeldOut),
        "a training task reached the held-out scoring task set"
    );

    for task in &corpus.tasks {
        let forbidden_purpose = match task.partition {
            Partition::Train => EvaluationPurpose::Score,
            Partition::HeldOut => EvaluationPurpose::Tune,
        };
        assert!(
            matches!(
                corpus.task_for(&task.id, forbidden_purpose),
                Err(CorpusError::Contamination { .. })
            ),
            "task {} was selectable through its forbidden {:?} path",
            task.id,
            forbidden_purpose
        );
    }
}
