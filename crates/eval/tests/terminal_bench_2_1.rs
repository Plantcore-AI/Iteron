use iteron_eval::{
    ArtifactReference, BenchmarkPin, ExternalHarnessResult, ProfileIdentity, ResourceBounds,
    ResourceUsage, RunEvidence, TaskIdentity, TerminalBenchAdapterError, TerminalBenchRequest,
    TerminalOutcome, TimingEvidence, parse_external_harness_result, parse_terminal_bench_request,
};

fn request() -> TerminalBenchRequest {
    TerminalBenchRequest {
        schema_version: 1,
        benchmark: BenchmarkPin {
            id: "terminal-bench".into(),
            version: "2.1".into(),
        },
        task: TaskIdentity {
            task_id: "compile-linux-kernel".into(),
            trial_id: "trial-0001".into(),
            dataset_revision: "5c8eadf1f393183288fa08b8f73ca9a469cc5e00".into(),
        },
        profile: ProfileIdentity {
            profile_sha256: "a".repeat(64),
            registry_sha256: "b".repeat(64),
            param_registry_sha256: "c".repeat(64),
        },
        iteron_revision: "d".repeat(40),
        binary_path: "/opt/iteron/bin/iteron".into(),
        workspace_path: "/workspace/task".into(),
        profile_path: "/artifacts/candidate.json".into(),
        effective_profile_path: "/artifacts/effective.json".into(),
        result_path: "/artifacts/result.json".into(),
        runs_dir: "/artifacts/runs".into(),
        task_prompt: "Complete the benchmark task.".into(),
        credential_env_names: vec!["ANTHROPIC_API_KEY".into(), "OPENAI_API_KEY".into()],
        resources: ResourceBounds {
            max_wall_secs: 7_200,
            max_turns: 250,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
            max_evidence_bytes: 64 * 1024 * 1024,
            max_memory_bytes: 1024 * 1024 * 1024,
        },
    }
}

fn artifact(path: &str, digest: char) -> ArtifactReference {
    ArtifactReference {
        path: path.into(),
        bytes: 128,
        sha256: digest.to_string().repeat(64),
    }
}

fn result(request: &TerminalBenchRequest) -> ExternalHarnessResult {
    ExternalHarnessResult {
        schema_version: 1,
        benchmark: request.benchmark.clone(),
        task: request.task.clone(),
        profile: request.profile.clone(),
        iteron_revision: request.iteron_revision.clone(),
        run_id: "run-123".into(),
        outcome: TerminalOutcome::Completed,
        success: true,
        exit_code: Some(0),
        score_micros: Some(1_000_000),
        evidence: RunEvidence {
            effective_profile: artifact(
                &request.effective_profile_path,
                request.profile.profile_sha256.chars().next().unwrap(),
            ),
            iteron_result: artifact(&request.result_path, 'e'),
            run_record: artifact("/artifacts/runs/run-123.jsonl", 'f'),
            score_evidence: Some(artifact("/artifacts/score.json", '1')),
        },
        timing: TimingEvidence {
            started_unix_ms: 1_787_000_000_000,
            elapsed_ms: 12_000,
        },
        resources: ResourceUsage {
            stdout_bytes: 128,
            stderr_bytes: 0,
            evidence_bytes: 512,
            peak_memory_bytes: Some(256 * 1024 * 1024),
        },
    }
}

#[test]
fn exact_terminal_bench_2_1_pin_is_required() {
    request().validate().unwrap();
    for (id, version) in [
        ("terminal-bench", "2.0"),
        ("terminal-bench", "2.1.0"),
        ("", "2.1"),
    ] {
        let mut invalid = request();
        invalid.benchmark.id = id.into();
        invalid.benchmark.version = version.into();
        assert_eq!(
            invalid.validate(),
            Err(TerminalBenchAdapterError::BenchmarkPin)
        );
    }

    let mut value = serde_json::to_value(request()).unwrap();
    value["benchmark"]
        .as_object_mut()
        .unwrap()
        .remove("version");
    assert!(parse_terminal_bench_request(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn request_and_result_bounds_are_enforced() {
    let mut invalid = request();
    invalid.resources.max_wall_secs = 86_401;
    assert_eq!(
        invalid.validate(),
        Err(TerminalBenchAdapterError::Field("resources"))
    );

    let request = request();
    let mut invalid_result = result(&request);
    invalid_result.resources.stdout_bytes = request.resources.max_stdout_bytes + 1;
    assert!(invalid_result.validate_against(&request).is_err());
}

#[test]
fn command_is_deterministic_and_never_contains_credential_values() {
    let request = request();
    let first = request.command().unwrap();
    let second = request.command().unwrap();
    assert_eq!(first, second);
    assert!(first.clear_environment);
    assert_eq!(
        first.inherit_environment,
        ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
    );
    assert_eq!(first.environment.get("TZ").map(String::as_str), Some("UTC"));
    let serialized = serde_json::to_string(&first).unwrap();
    assert!(!serialized.contains("sk-test-secret"));
    assert!(
        !first
            .environment
            .keys()
            .any(|name| name.ends_with("API_KEY"))
    );
}

#[test]
fn credential_names_are_allowlisted_sorted_and_value_free() {
    let mut invalid = request();
    invalid.credential_env_names = vec!["OPENAI_API_KEY=secret".into()];
    assert!(invalid.validate().is_err());
    invalid.credential_env_names = vec!["OPENAI_API_KEY".into(), "ANTHROPIC_API_KEY".into()];
    assert!(invalid.validate().is_err());
}

#[test]
fn profile_and_result_identity_roundtrip() {
    let request = request();
    let result = result(&request);
    let bytes = serde_json::to_vec(&result).unwrap();
    assert_eq!(
        parse_external_harness_result(&bytes, &request).unwrap(),
        result
    );

    let mut wrong = result;
    wrong.profile.profile_sha256 = "9".repeat(64);
    let bytes = serde_json::to_vec(&wrong).unwrap();
    assert_eq!(
        parse_external_harness_result(&bytes, &request),
        Err(TerminalBenchAdapterError::IdentityMismatch)
    );
}
