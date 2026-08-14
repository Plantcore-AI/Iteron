use iteron_eval::{
    AdapterOperation, AdapterPin, ArtifactReference, BenchmarkAdapterRegistry, BenchmarkPin,
    CandidateImplementation, CliRunSpec, DryRunState, ExternalHarnessResult, ITERON_CLI_ID,
    ITERON_CLI_VERSION, ProfileIdentity, RESEARCH_PROTOCOL, ResearchProtocolError, ResearchRequest,
    ResearchRequestEnvelope, ResearchResponse, ResearchResponseEnvelope, ResearchRunState,
    ResearchSession, ResourceBounds, ResourceUsage, RunEvidence, RunSpec, TaskIdentity,
    TerminalBenchRequest, TerminalOutcome, TimingEvidence, TunerCandidate, parse_research_request,
    parse_research_response,
};
use iteron_tunables::ProfileDocument;
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, ChildStdin, Command, Stdio};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn cli_pin() -> AdapterPin {
    AdapterPin {
        benchmark_id: ITERON_CLI_ID.into(),
        benchmark_version: ITERON_CLI_VERSION.into(),
    }
}

fn profile() -> ProfileDocument {
    ProfileDocument {
        schema_version: iteron_tunables::PROFILE_DOCUMENT_SCHEMA_VERSION,
        profile_id: "research/candidate-1".into(),
        registry_revision: iteron_tunables::REGISTRY_REVISION,
        registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
        param_registry_digest: Some(iteron_tunables::param_registry_digest_sha256()),
        module_scope: None,
        values: Vec::new(),
        params: Vec::new(),
        artifacts: Vec::new(),
    }
}

fn candidate() -> TunerCandidate {
    let mut document = profile();
    document.artifacts.push(iteron_tunables::ArtifactOverride {
        artifact: "prompt/system@v1".into(),
        text: "research fixture".into(),
    });
    TunerCandidate {
        schema_version: iteron_eval::UNIVERSAL_CANDIDATE_SCHEMA_VERSION,
        id: "research/candidate-1".into(),
        values: BTreeMap::new(),
        profile: Some(document),
        implementations: Vec::new(),
    }
}

fn candidate_digests(candidate: &TunerCandidate) -> (String, String) {
    let candidate_sha256 = candidate.digest_sha256().unwrap();
    let (_, profile_sha256) = candidate.rendered_profile().unwrap();
    (candidate_sha256, profile_sha256)
}

fn envelope(request_id: &str, payload: ResearchRequest) -> ResearchRequestEnvelope {
    ResearchRequestEnvelope {
        protocol: RESEARCH_PROTOCOL.into(),
        request_id: request_id.into(),
        payload,
    }
}

fn assert_correlated_error(
    response: ResearchResponseEnvelope,
    request_id: &str,
    expected_code: &str,
) {
    assert_eq!(response.protocol, RESEARCH_PROTOCOL);
    assert_eq!(response.request_id, request_id);
    assert!(matches!(
        response.payload,
        ResearchResponse::Error { code, .. } if code == expected_code
    ));
}

fn run_spec() -> CliRunSpec {
    CliRunSpec {
        binary_path: "/opt/iteron/bin/iteron".into(),
        workspace_path: "/workspace/task".into(),
        profile_path: "/artifacts/candidate.json".into(),
        effective_profile_path: "/artifacts/effective.json".into(),
        result_path: "/artifacts/result.json".into(),
        runs_dir: "/artifacts/runs".into(),
        profile_sha256: "a".repeat(64),
        registry_sha256: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
        param_registry_sha256: iteron_tunables::param_registry_digest_sha256(),
        iteron_revision: "b".repeat(40),
        task_prompt: "Complete the task.".into(),
        implementation_candidate_path: None,
        implementation_candidate_digest: None,
        credential_env_names: vec!["ANTHROPIC_API_KEY".into(), "OPENAI_API_KEY".into()],
        max_wall_secs: 7_200,
        max_turns: 250,
        max_stdout_bytes: 1024 * 1024,
        max_stderr_bytes: 1024 * 1024,
        max_evidence_bytes: 64 * 1024 * 1024,
        max_memory_bytes: 1024 * 1024 * 1024,
    }
}

#[test]
fn exact_protocol_and_adapter_versions_are_pinned() {
    let registry = BenchmarkAdapterRegistry::builtin();
    registry.resolve(&cli_pin(), AdapterOperation::Run).unwrap();
    registry
        .resolve(
            &AdapterPin {
                benchmark_id: "terminal-bench".into(),
                benchmark_version: "2.1".into(),
            },
            AdapterOperation::Run,
        )
        .unwrap();
    for pin in [
        AdapterPin {
            benchmark_id: "iteron-cli".into(),
            benchmark_version: "2".into(),
        },
        AdapterPin {
            benchmark_id: "terminal-bench".into(),
            benchmark_version: "2.1.0".into(),
        },
        AdapterPin {
            benchmark_id: "terminal-bench".into(),
            benchmark_version: "".into(),
        },
    ] {
        assert!(registry.resolve(&pin, AdapterOperation::Run).is_err());
    }

    let mut wrong = envelope("req-1", ResearchRequest::Surface { adapter: cli_pin() });
    wrong.protocol = "iteron-research/2".into();
    assert_eq!(wrong.validate(), Err(ResearchProtocolError::Protocol));

    let wrong_version = envelope(
        "wrong-version",
        ResearchRequest::Surface {
            adapter: AdapterPin {
                benchmark_id: "terminal-bench".into(),
                benchmark_version: "2.0".into(),
            },
        },
    );
    let decoded = parse_research_request(&serde_json::to_vec(&wrong_version).unwrap()).unwrap();
    let refused = ResearchSession::new().handle(decoded);
    assert_eq!(refused.request_id, "wrong-version");
    assert!(matches!(
        refused.payload,
        ResearchResponse::Error { code, .. } if code == "unknown_adapter"
    ));
}

#[test]
fn duplicate_keys_unknown_fields_and_bounds_fail_closed() {
    let duplicated = br#"{
      "protocol":"iteron-research/1",
      "request_id":"req-1",
      "request_id":"req-2",
      "payload":{"operation":"surface","adapter":{"benchmark_id":"iteron-cli","benchmark_version":"1"}}
    }"#;
    assert!(matches!(
        parse_research_request(duplicated),
        Err(ResearchProtocolError::Json(error)) if error.contains("duplicate")
    ));

    let mut value = serde_json::to_value(envelope(
        "req-1",
        ResearchRequest::Surface { adapter: cli_pin() },
    ))
    .unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("surprise".into(), true.into());
    assert!(parse_research_request(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut invalid = run_spec();
    invalid.max_wall_secs = 86_401;
    assert!(invalid.validate().is_err());
    invalid = run_spec();
    invalid.credential_env_names = vec!["OPENAI_API_KEY=value".into()];
    assert!(invalid.validate().is_err());

    let bare_candidate_digest = envelope(
        "bare-candidate-digest",
        ResearchRequest::CandidateValidate {
            adapter: cli_pin(),
            candidate_sha256: "a".repeat(64),
            candidate: candidate(),
            implementation_candidate_path: None,
        },
    );
    assert!(bare_candidate_digest.validate().is_err());
}

#[test]
fn request_response_correlation_is_exact() {
    let request = envelope(
        "req-correlated",
        ResearchRequest::Surface { adapter: cli_pin() },
    );
    let mut response = ResearchSession::new().handle(request.clone());
    response.validate_against(&request).unwrap();
    response.request_id = "other".into();
    assert_eq!(
        response.validate_against(&request),
        Err(ResearchProtocolError::Correlation)
    );

    let bytes = serde_json::to_vec(&ResearchResponseEnvelope {
        protocol: RESEARCH_PROTOCOL.into(),
        request_id: "other".into(),
        payload: ResearchResponse::Surface {
            registry_digest_sha256: "a".repeat(64),
            adapters: Vec::new(),
            surface: serde_json::json!({}),
        },
    })
    .unwrap();
    assert_eq!(
        parse_research_response(&bytes, &request),
        Err(ResearchProtocolError::Correlation)
    );
}

#[test]
fn stale_registry_identity_and_response_operation_fail_closed() {
    let request = envelope(
        "surface-stale",
        ResearchRequest::Surface { adapter: cli_pin() },
    );
    let mut response = ResearchSession::new().handle(request.clone());
    if let ResearchResponse::Surface {
        registry_digest_sha256,
        ..
    } = &mut response.payload
    {
        *registry_digest_sha256 = "0".repeat(64);
    } else {
        panic!("surface request returned a non-surface response");
    }
    assert!(matches!(
        response.validate_against(&request),
        Err(ResearchProtocolError::InvalidField(_))
    ));

    response.payload = ResearchResponse::CandidateValidate {
        candidate_id: "research/candidate-1".into(),
        candidate_sha256: format!("sha256:{}", "a".repeat(64)),
        profile_sha256: "a".repeat(64),
        rendered_bytes: 1,
        implementation_count: 1,
        implementation_activation_sha256: Some("b".repeat(64)),
        implementation_activation_bytes: 1,
    };
    assert_eq!(
        response.validate_against(&request),
        Err(ResearchProtocolError::Correlation)
    );
}

#[test]
fn candidate_validation_uses_the_canonical_profile_digest() {
    let accepted_candidate = candidate();
    let (candidate_sha256, profile_sha256) = candidate_digests(&accepted_candidate);
    let request = envelope(
        "candidate-request",
        ResearchRequest::CandidateValidate {
            adapter: cli_pin(),
            candidate_sha256: candidate_sha256.clone(),
            candidate: accepted_candidate,
            implementation_candidate_path: None,
        },
    );
    let response = ResearchSession::new().handle(request.clone());
    let mut mismatched_count = response.clone();
    if let ResearchResponse::CandidateValidate {
        implementation_count,
        implementation_activation_sha256,
        implementation_activation_bytes,
        ..
    } = &mut mismatched_count.payload
    {
        *implementation_count = 1;
        *implementation_activation_sha256 = Some("d".repeat(64));
        *implementation_activation_bytes = 1;
    }
    assert_eq!(
        mismatched_count.validate_against(&request),
        Err(ResearchProtocolError::Correlation)
    );
    assert!(matches!(
        response.payload,
        ResearchResponse::CandidateValidate {
            candidate_id,
            candidate_sha256: response_candidate_sha256,
            profile_sha256: response_profile_sha256,
            implementation_count: 0,
            ..
        } if candidate_id == "research/candidate-1"
            && response_candidate_sha256 == candidate_sha256
            && response_profile_sha256 == profile_sha256
    ));
}

#[test]
fn registry_builds_a_deterministic_credential_value_free_command() {
    let registry = BenchmarkAdapterRegistry::builtin();
    let run = RunSpec::IteronCli { spec: run_spec() };
    let first = registry.command(&cli_pin(), &run).unwrap();
    let second = registry.command(&cli_pin(), &run).unwrap();
    assert_eq!(first, second);
    assert!(first.clear_environment);
    assert!(
        !first
            .environment
            .keys()
            .any(|name| name.ends_with("API_KEY"))
    );
    assert_eq!(
        first.inherit_environment,
        ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
    );
    assert!(!first.argv.iter().any(|arg| arg.contains("secret")));
    assert!(!first.argv.iter().any(|arg| arg == "--harness-profile"));
}

#[test]
fn persistent_state_machine_covers_run_result_evidence_and_cancel_without_execution() {
    let mut session = ResearchSession::new();
    let accepted_candidate = candidate();
    let (candidate_sha256, profile_sha256) = candidate_digests(&accepted_candidate);
    let validated = session.handle(envelope(
        "candidate-before-run",
        ResearchRequest::CandidateValidate {
            adapter: cli_pin(),
            candidate_sha256: candidate_sha256.clone(),
            candidate: accepted_candidate,
            implementation_candidate_path: None,
        },
    ));
    assert!(matches!(
        validated.payload,
        ResearchResponse::CandidateValidate { .. }
    ));
    let mut spec = run_spec();
    spec.profile_sha256 = profile_sha256.clone();
    let run = envelope(
        "run-request",
        ResearchRequest::Run {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.clone(),
            profile_sha256: profile_sha256.clone(),
            implementation_activation_sha256: None,
            run_id: "run-1".into(),
            run: Box::new(RunSpec::IteronCli { spec }),
        },
    );
    assert!(matches!(
        session.handle(run).payload,
        ResearchResponse::Run {
            execution_mode,
            state: DryRunState::Planned,
            ..
        } if execution_mode == "dry_run"
    ));
    for payload in [
        ResearchRequest::Result {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.clone(),
            profile_sha256: profile_sha256.clone(),
            implementation_activation_sha256: None,
            run_id: "run-1".into(),
        },
        ResearchRequest::Evidence {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.clone(),
            profile_sha256: profile_sha256.clone(),
            implementation_activation_sha256: None,
            run_id: "run-1".into(),
        },
    ] {
        let response = session.handle(envelope("query", payload));
        match response.payload {
            ResearchResponse::Result {
                terminal_result_available,
                ..
            } => assert!(!terminal_result_available),
            ResearchResponse::Evidence {
                evidence_available,
                artifacts,
                ..
            } => {
                assert!(!evidence_available);
                assert!(artifacts.is_empty());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
    let cancelled = session.handle(envelope(
        "cancel",
        ResearchRequest::Cancel {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256: None,
            run_id: "run-1".into(),
        },
    ));
    assert!(matches!(
        cancelled.payload,
        ResearchResponse::Cancel {
            state: DryRunState::Cancelled,
            ..
        }
    ));
}

#[test]
fn stale_candidate_and_run_identities_are_refused_with_exact_correlation() {
    let mut session = ResearchSession::new();
    let accepted_candidate = candidate();
    let (candidate_sha256, profile_sha256) = candidate_digests(&accepted_candidate);
    let mut spec = run_spec();
    spec.profile_sha256 = profile_sha256.clone();
    let run = envelope(
        "run-before-validation",
        ResearchRequest::Run {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.clone(),
            profile_sha256: profile_sha256.clone(),
            implementation_activation_sha256: None,
            run_id: "run-1".into(),
            run: Box::new(RunSpec::IteronCli { spec: spec.clone() }),
        },
    );
    assert_correlated_error(
        session.handle(run),
        "run-before-validation",
        "unknown_candidate",
    );

    session.handle(envelope(
        "validate-candidate",
        ResearchRequest::CandidateValidate {
            adapter: cli_pin(),
            candidate_sha256: candidate_sha256.clone(),
            candidate: accepted_candidate,
            implementation_candidate_path: None,
        },
    ));

    let mut replacement = candidate();
    replacement.implementations.push(CandidateImplementation {
        module: iteron_tunables::ModuleId::VerificationQuorum,
        implementation_id: "research-verifier".into(),
        protocol: "iteron-implementation/1".into(),
        catalog_path: "/opt/iteron/marketplace/catalog.json".into(),
        artifact_root: "/opt/iteron/marketplace/artifacts/verifier".into(),
        manifest_sha256: format!("sha256:{}", "d".repeat(64)),
        artifact_sha256: format!("sha256:{}", "f".repeat(64)),
    });
    let replacement_digest = replacement.digest_sha256().unwrap();
    let (_, replacement_profile_sha256) = replacement.rendered_profile().unwrap();
    assert_eq!(replacement_profile_sha256, profile_sha256);
    assert_ne!(replacement_digest, candidate_sha256);
    assert_correlated_error(
        session.handle(envelope(
            "replace-candidate",
            ResearchRequest::CandidateValidate {
                adapter: cli_pin(),
                candidate_sha256: replacement_digest.clone(),
                candidate: replacement,
                implementation_candidate_path: Some("/tmp/unused-activation.json".into()),
            },
        )),
        "replace-candidate",
        "candidate_identity_mismatch",
    );

    let run = envelope(
        "plan-run",
        ResearchRequest::Run {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.clone(),
            profile_sha256: profile_sha256.clone(),
            implementation_activation_sha256: None,
            run_id: "run-1".into(),
            run: Box::new(RunSpec::IteronCli { spec }),
        },
    );
    assert!(matches!(
        session.handle(run.clone()).payload,
        ResearchResponse::Run {
            state: DryRunState::Planned,
            ..
        }
    ));
    let mut duplicate = run;
    duplicate.request_id = "duplicate-run".into();
    assert_correlated_error(session.handle(duplicate), "duplicate-run", "duplicate_run");

    assert_correlated_error(
        session.handle(envelope(
            "stale-implementation-set",
            ResearchRequest::Result {
                adapter: cli_pin(),
                candidate_id: "research/candidate-1".into(),
                candidate_sha256: replacement_digest,
                profile_sha256: profile_sha256.clone(),
                implementation_activation_sha256: None,
                run_id: "run-1".into(),
            },
        )),
        "stale-implementation-set",
        "run_identity_mismatch",
    );
    assert_correlated_error(
        session.handle(envelope(
            "stale-profile",
            ResearchRequest::Result {
                adapter: cli_pin(),
                candidate_id: "research/candidate-1".into(),
                candidate_sha256: candidate_sha256.clone(),
                profile_sha256: "0".repeat(64),
                implementation_activation_sha256: None,
                run_id: "run-1".into(),
            },
        )),
        "stale-profile",
        "run_identity_mismatch",
    );
    assert_correlated_error(
        session.handle(envelope(
            "unknown-run",
            ResearchRequest::Evidence {
                adapter: cli_pin(),
                candidate_id: "research/candidate-1".into(),
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256: None,
                run_id: "run-missing".into(),
            },
        )),
        "unknown-run",
        "unknown_run",
    );
}

#[test]
fn terminal_bench_2_1_registry_wrapper_preserves_the_exact_adapter_command() {
    let request = TerminalBenchRequest {
        schema_version: 1,
        benchmark: BenchmarkPin {
            id: "terminal-bench".into(),
            version: "2.1".into(),
        },
        task: TaskIdentity {
            task_id: "task-1".into(),
            trial_id: "trial-1".into(),
            dataset_revision: "revision-1".into(),
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
        task_prompt: "Complete the task.".into(),
        credential_env_names: vec!["OPENAI_API_KEY".into()],
        resources: ResourceBounds {
            max_wall_secs: 3_600,
            max_turns: 250,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
            max_evidence_bytes: 64 * 1024 * 1024,
            max_memory_bytes: 1024 * 1024 * 1024,
        },
    };
    let expected = request.command().unwrap();
    let actual = BenchmarkAdapterRegistry::builtin()
        .command(
            &AdapterPin {
                benchmark_id: "terminal-bench".into(),
                benchmark_version: "2.1".into(),
            },
            &RunSpec::TerminalBench21 {
                request,
                implementation_candidate: None,
            },
        )
        .unwrap();
    assert_eq!(actual, expected);
}

#[cfg(unix)]
struct ExecuteLayout {
    root: PathBuf,
    workspace: PathBuf,
    profile: PathBuf,
    effective: PathBuf,
    result: PathBuf,
    runs: PathBuf,
    script: PathBuf,
    pid_file: PathBuf,
}

#[cfg(unix)]
impl ExecuteLayout {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "iteron-research-{label}-{}-{nonce}",
            std::process::id()
        ));
        let workspace = root.join("workspace");
        let runs = root.join("runs");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&runs).unwrap();
        let root = root.canonicalize().unwrap();
        let workspace = root.join("workspace");
        let runs = root.join("runs");
        Self {
            profile: root.join("candidate.json"),
            effective: root.join("effective.json"),
            result: root.join("result.json"),
            script: root.join("fake-iteron"),
            pid_file: root.join("child.pid"),
            root,
            workspace,
            runs,
        }
    }

    fn write_script(&self, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&self.script, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&self.script).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&self.script, permissions).unwrap();
    }

    fn cli_spec(&self, profile_sha256: &str) -> CliRunSpec {
        CliRunSpec {
            binary_path: self.script.to_string_lossy().into_owned(),
            workspace_path: self.workspace.to_string_lossy().into_owned(),
            profile_path: self.profile.to_string_lossy().into_owned(),
            effective_profile_path: self.effective.to_string_lossy().into_owned(),
            result_path: self.result.to_string_lossy().into_owned(),
            runs_dir: self.runs.to_string_lossy().into_owned(),
            profile_sha256: profile_sha256.into(),
            registry_sha256: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
            param_registry_sha256: iteron_tunables::param_registry_digest_sha256(),
            iteron_revision: "b".repeat(40),
            task_prompt: "execute-fixture".into(),
            implementation_candidate_path: None,
            implementation_candidate_digest: None,
            credential_env_names: Vec::new(),
            max_wall_secs: 10,
            max_turns: 2,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
            max_evidence_bytes: 1024 * 1024,
            // macOS counts dyld shared-cache mappings against RLIMIT_AS, so a realistic
            // executable ceiling must leave room for those immutable mappings.
            max_memory_bytes: 64 * 1024 * 1024 * 1024,
        }
    }
}

#[cfg(unix)]
impl Drop for ExecuteLayout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
struct ExecuteHarness {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<std::process::ChildStdout>,
}

#[cfg(unix)]
impl ExecuteHarness {
    fn start(iteron_cli: &Path, environment: &[(&str, &str)]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_iteron-harness"));
        command
            .args(["serve", "--execute", "--iteron-cli"])
            .arg(iteron_cli)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("NO_COLOR", "1")
            .env("TZ", "UTC");
        for (name, value) in environment {
            command.env(name, value);
        }
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input: Some(input),
            output,
        }
    }

    fn request(&mut self, request: &ResearchRequestEnvelope) -> ResearchResponseEnvelope {
        let encoded = serde_json::to_vec(request).unwrap();
        let input = self.input.as_mut().unwrap();
        input.write_all(&encoded).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
        let mut response = Vec::new();
        self.output.read_until(b'\n', &mut response).unwrap();
        assert!(!response.is_empty());
        parse_research_response(&response, request).unwrap()
    }
}

#[cfg(unix)]
impl Drop for ExecuteHarness {
    fn drop(&mut self) {
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
    }
}

#[cfg(unix)]
fn validate_for_execute(harness: &mut ExecuteHarness, pin: AdapterPin) -> (String, String) {
    let accepted = candidate();
    let (candidate_sha256, profile_sha256) = candidate_digests(&accepted);
    let response = harness.request(&envelope(
        "execute-candidate",
        ResearchRequest::CandidateValidate {
            adapter: pin,
            candidate_sha256: candidate_sha256.clone(),
            candidate: accepted,
            implementation_candidate_path: None,
        },
    ));
    assert!(matches!(
        response.payload,
        ResearchResponse::CandidateValidate { .. }
    ));
    (candidate_sha256, profile_sha256)
}

#[cfg(unix)]
fn execute_run_request(
    pin: AdapterPin,
    candidate_sha256: &str,
    profile_sha256: &str,
    run_id: &str,
    run: RunSpec,
) -> ResearchRequestEnvelope {
    envelope(
        &format!("start-{run_id}"),
        ResearchRequest::Run {
            adapter: pin,
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.into(),
            profile_sha256: profile_sha256.into(),
            implementation_activation_sha256: None,
            run_id: run_id.into(),
            run: Box::new(run),
        },
    )
}

#[cfg(unix)]
fn wait_for_result(
    harness: &mut ExecuteHarness,
    pin: AdapterPin,
    candidate_sha256: &str,
    profile_sha256: &str,
    run_id: &str,
) -> ResearchResponseEnvelope {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ordinal = 0_u32;
    loop {
        ordinal += 1;
        let response = harness.request(&envelope(
            &format!("result-{run_id}-{ordinal}"),
            ResearchRequest::Result {
                adapter: pin.clone(),
                candidate_id: "research/candidate-1".into(),
                candidate_sha256: candidate_sha256.into(),
                profile_sha256: profile_sha256.into(),
                implementation_activation_sha256: None,
                run_id: run_id.into(),
            },
        ));
        if !matches!(
            response.payload,
            ResearchResponse::Result {
                state: ResearchRunState::Running,
                ..
            }
        ) {
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "execute-mode run did not terminate"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !path.exists() {
        assert!(Instant::now() < deadline, "fixture file was not created");
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn process_exists(pid: i32) -> bool {
    // SAFETY: signal zero performs a read-only liveness probe for one fixture pid.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(unix)]
fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(unix)]
const CLI_RESULT: &str = r#"{"schema_version":4,"type":"result","outcome":"done","reason":null,"success":true,"assistant_text":"done","run_id":"fixture-runtime-run","cost_usd":null,"cost_status":"unknown","cost_reason":"no_verified_rate_card","turns":1,"exit_code":0,"error":null}"#;

#[cfg(unix)]
fn implementation_candidate_fixture(layout: &ExecuteLayout) -> (TunerCandidate, PathBuf) {
    use iteron_marketplace::{
        EvidenceLimits, ImplementationCatalog, ImplementationFailurePolicy, ImplementationManifest,
        Version,
    };
    use iteron_protocol::capability_set::CapabilitySet;
    use std::os::unix::fs::PermissionsExt;

    let artifact_root = layout.root.join("implementation-artifact");
    fs::create_dir(&artifact_root).unwrap();
    let executable = artifact_root.join("fixture-implementation");
    let artifact_bytes = b"#!/bin/sh\nexit 0\n";
    fs::write(&executable, artifact_bytes).unwrap();
    let mut permissions = fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&executable, permissions).unwrap();
    let artifact_sha256 = digest(artifact_bytes);
    let manifest = ImplementationManifest {
        implementation_id: "fixture-verifier".into(),
        implementation_version: Version(1, 0, 0),
        module: iteron_tunables::ModuleId::VerificationQuorum,
        artifact_sha256: artifact_sha256.clone(),
        executable: "fixture-implementation".into(),
        argv: Vec::new(),
        protocol_version: 1,
        requested_capabilities: CapabilitySet::only(iteron_protocol::Capability::CodeExecuting),
        dependencies: Vec::new(),
        runtime_deadline_ms: 1_000,
        cancellation_deadline_ms: 1_000,
        evidence_limits: EvidenceLimits {
            stdout_bytes: 1024,
            stderr_bytes: 1024,
            observations: 16,
        },
        failure_policy: ImplementationFailurePolicy::FailClosed,
    };
    let manifest_sha256 = digest(&serde_json::to_vec(&manifest).unwrap());
    let catalog = ImplementationCatalog {
        schema_version: 1,
        implementations: vec![manifest],
    };
    let catalog_path = layout.root.join("implementation-catalog.json");
    fs::write(&catalog_path, serde_json::to_vec(&catalog).unwrap()).unwrap();
    let candidate = TunerCandidate {
        schema_version: iteron_eval::UNIVERSAL_CANDIDATE_SCHEMA_VERSION,
        id: "research/candidate-1".into(),
        values: BTreeMap::new(),
        profile: Some(profile()),
        implementations: vec![CandidateImplementation {
            module: iteron_tunables::ModuleId::VerificationQuorum,
            implementation_id: "fixture-verifier".into(),
            protocol: "iteron-implementation/1".into(),
            catalog_path: catalog_path.to_string_lossy().into_owned(),
            artifact_root: artifact_root.to_string_lossy().into_owned(),
            manifest_sha256: format!("sha256:{manifest_sha256}"),
            artifact_sha256: format!("sha256:{artifact_sha256}"),
        }],
    };
    (
        candidate,
        layout.root.join("implementation-activation.json"),
    )
}

#[cfg(unix)]
#[test]
fn implementation_activation_is_verified_and_forged_consumption_cannot_complete() {
    let layout = ExecuteLayout::new("implementation-activation");
    layout.write_script("exit 0");
    let (accepted, activation_path) = implementation_candidate_fixture(&layout);
    let (candidate_sha256, profile_sha256) = candidate_digests(&accepted);
    let mut session = ResearchSession::with_pinned_iteron_cli(&layout.script).unwrap();
    let validated = session.handle(envelope(
        "implementation-candidate",
        ResearchRequest::CandidateValidate {
            adapter: cli_pin(),
            candidate_sha256: candidate_sha256.clone(),
            candidate: accepted.clone(),
            implementation_candidate_path: Some(activation_path.to_string_lossy().into_owned()),
        },
    ));
    let activation_sha256 = match validated.payload {
        ResearchResponse::CandidateValidate {
            implementation_activation_sha256: Some(digest),
            implementation_activation_bytes,
            implementation_count: 1,
            ..
        } if implementation_activation_bytes > 0 => digest,
        other => panic!("unexpected activation response: {other:?}"),
    };

    let mut missing_spec = layout.cli_spec(&profile_sha256);
    missing_spec.implementation_candidate_path = None;
    missing_spec.implementation_candidate_digest = None;
    let missing = session.handle(envelope(
        "implementation-run-missing-activation",
        ResearchRequest::Run {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.clone(),
            profile_sha256: profile_sha256.clone(),
            implementation_activation_sha256: None,
            run_id: "implementation-missing".into(),
            run: Box::new(RunSpec::IteronCli { spec: missing_spec }),
        },
    ));
    assert_correlated_error(
        missing,
        "implementation-run-missing-activation",
        "candidate_identity_mismatch",
    );

    let stale_digest = "f".repeat(64);
    let mut stale_spec = layout.cli_spec(&profile_sha256);
    stale_spec.implementation_candidate_path = Some(activation_path.to_string_lossy().into_owned());
    stale_spec.implementation_candidate_digest = Some(stale_digest.clone());
    let stale = session.handle(envelope(
        "implementation-run-stale-activation",
        ResearchRequest::Run {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.clone(),
            profile_sha256: profile_sha256.clone(),
            implementation_activation_sha256: Some(stale_digest),
            run_id: "implementation-stale".into(),
            run: Box::new(RunSpec::IteronCli { spec: stale_spec }),
        },
    ));
    assert_correlated_error(
        stale,
        "implementation-run-stale-activation",
        "candidate_identity_mismatch",
    );

    let mut wrong = accepted.clone();
    wrong.implementations[0].artifact_sha256 = format!("sha256:{}", "0".repeat(64));
    let wrong_sha256 = wrong.digest_sha256().unwrap();
    let mut wrong_session = ResearchSession::new();
    let wrong_response = wrong_session.handle(envelope(
        "implementation-wrong-artifact",
        ResearchRequest::CandidateValidate {
            adapter: cli_pin(),
            candidate_sha256: wrong_sha256,
            candidate: wrong,
            implementation_candidate_path: Some(
                layout
                    .root
                    .join("wrong-activation.json")
                    .to_string_lossy()
                    .into_owned(),
            ),
        },
    ));
    assert_correlated_error(
        wrong_response,
        "implementation-wrong-artifact",
        "invalid_field",
    );

    let terminal_pin = AdapterPin {
        benchmark_id: "terminal-bench".into(),
        benchmark_version: "2.1".into(),
    };
    let terminal_activation = layout.root.join("terminal-activation.json");
    let mut terminal_session = ResearchSession::new();
    let terminal_validated = terminal_session.handle(envelope(
        "terminal-implementation-candidate",
        ResearchRequest::CandidateValidate {
            adapter: terminal_pin.clone(),
            candidate_sha256: candidate_sha256.clone(),
            candidate: accepted,
            implementation_candidate_path: Some(terminal_activation.to_string_lossy().into_owned()),
        },
    ));
    let terminal_digest = match terminal_validated.payload {
        ResearchResponse::CandidateValidate {
            implementation_activation_sha256: Some(digest),
            ..
        } => digest,
        other => panic!("unexpected terminal activation response: {other:?}"),
    };
    let mut terminal_spec = layout.cli_spec(&profile_sha256);
    terminal_spec.implementation_candidate_path =
        Some(terminal_activation.to_string_lossy().into_owned());
    terminal_spec.implementation_candidate_digest = Some(terminal_digest.clone());
    let unsupported = terminal_session.handle(envelope(
        "terminal-implementation-run",
        ResearchRequest::Run {
            adapter: terminal_pin,
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.clone(),
            profile_sha256: profile_sha256.clone(),
            implementation_activation_sha256: Some(terminal_digest),
            run_id: "terminal-implementation".into(),
            run: Box::new(RunSpec::IteronCli {
                spec: terminal_spec,
            }),
        },
    ));
    assert_correlated_error(
        unsupported,
        "terminal-implementation-run",
        "unsupported_implementation_activation",
    );

    let receipt_path = layout.runs.join(format!(
        ".iteron-implementation-{activation_sha256}-consumption.json"
    ));
    let receipt = serde_json::json!({
        "schema_id": "iteron-implementation-consumption/1",
        "candidate_sha256": candidate_sha256,
        "activation_sha256": activation_sha256,
        "cli_run_id": "fixture-runtime-run",
        "implementations": [{
            "module": "verification_quorum",
            "implementation_id": "fixture-verifier",
            "loaded": true,
            "started": true,
            "terminal": true,
            "stopped": true
        }]
    });
    layout.write_script(&format!(
        r#"candidate_path=
candidate_digest=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --implementation-candidate) candidate_path="$2"; shift 2 ;;
    --implementation-candidate-digest) candidate_digest="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ "$candidate_path" = '{}' ] || exit 71
[ "$candidate_digest" = '{}' ] || exit 72
printf '%s' '{{}}' > '{}'
printf '%s' 'run-record' > '{}/run-record.json'
printf '%s' '{}' > '{}'
printf '%s' '{}'"#,
        activation_path.display(),
        activation_sha256,
        layout.effective.display(),
        layout.runs.display(),
        serde_json::to_string(&receipt).unwrap(),
        receipt_path.display(),
        CLI_RESULT,
    ));
    let mut spec = layout.cli_spec(&profile_sha256);
    spec.implementation_candidate_path = Some(activation_path.to_string_lossy().into_owned());
    spec.implementation_candidate_digest = Some(activation_sha256.clone());
    let run = envelope(
        "implementation-run",
        ResearchRequest::Run {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.clone(),
            profile_sha256: profile_sha256.clone(),
            implementation_activation_sha256: Some(activation_sha256.clone()),
            run_id: "implementation-run".into(),
            run: Box::new(RunSpec::IteronCli { spec }),
        },
    );
    let refused = session.handle(run);
    assert_correlated_error(
        refused,
        "implementation-run",
        "executable_identity_mismatch",
    );
    assert!(
        !receipt_path.exists(),
        "the swapped executable must be rejected before it can forge consumption evidence"
    );
}

#[cfg(unix)]
#[test]
fn execute_server_runs_exact_command_and_returns_value_free_result_and_evidence() {
    let layout = ExecuteLayout::new("success");
    layout.write_script(&format!(
        r#"if [ "${{UNRELATED_SECRET+x}}" = x ]; then exit 41; fi
if [ "$OPENAI_API_KEY" != "allowed-credential" ]; then exit 42; fi
if [ "${{ANTHROPIC_API_KEY+x}}" = x ]; then exit 43; fi
printf '%s' '{{}}' > '{}'
printf '%s' 'run-record' > '{}/run-record.json'
printf '%s' '{}'"#,
        layout.effective.display(),
        layout.runs.display(),
        CLI_RESULT
    ));
    let mut harness = ExecuteHarness::start(
        &layout.script,
        &[
            ("OPENAI_API_KEY", "allowed-credential"),
            ("ANTHROPIC_API_KEY", "not-requested"),
            ("UNRELATED_SECRET", "must-not-cross"),
        ],
    );
    let (candidate_sha256, profile_sha256) = validate_for_execute(&mut harness, cli_pin());
    let mut spec = layout.cli_spec(&profile_sha256);
    spec.credential_env_names = vec!["OPENAI_API_KEY".into()];
    let run = harness.request(&execute_run_request(
        cli_pin(),
        &candidate_sha256,
        &profile_sha256,
        "execute-success",
        RunSpec::IteronCli { spec },
    ));
    assert!(matches!(
        run.payload,
        ResearchResponse::Run { ref execution_mode, .. } if execution_mode == "execute"
    ));
    let result = wait_for_result(
        &mut harness,
        cli_pin(),
        &candidate_sha256,
        &profile_sha256,
        "execute-success",
    );
    assert!(
        matches!(
            result.payload,
            ResearchResponse::Result {
                state: ResearchRunState::Completed,
                terminal_result_available: true,
                ..
            }
        ),
        "unexpected execute result: {result:?}"
    );
    let evidence = harness.request(&envelope(
        "execute-evidence",
        ResearchRequest::Evidence {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: candidate_sha256.clone(),
            profile_sha256: profile_sha256.clone(),
            implementation_activation_sha256: None,
            run_id: "execute-success".into(),
        },
    ));
    assert!(matches!(
        evidence.payload,
        ResearchResponse::Evidence {
            evidence_available: true,
            ref artifacts,
            ..
        } if artifacts.len() >= 3
    ));
    let serialized = serde_json::to_string(&(run, result, evidence)).unwrap();
    for secret in ["allowed-credential", "not-requested", "must-not-cross"] {
        assert!(!serialized.contains(secret));
    }

    let stale = harness.request(&envelope(
        "execute-stale",
        ResearchRequest::Result {
            adapter: cli_pin(),
            candidate_id: "research/candidate-1".into(),
            candidate_sha256: format!("sha256:{}", "f".repeat(64)),
            profile_sha256,
            implementation_activation_sha256: None,
            run_id: "execute-success".into(),
        },
    ));
    assert!(matches!(
        stale.payload,
        ResearchResponse::Error { ref code, .. } if code == "run_identity_mismatch"
    ));
}

#[cfg(unix)]
#[test]
fn execute_cancel_and_server_drop_kill_and_reap_the_child() {
    for cancel_explicitly in [true, false] {
        let layout = ExecuteLayout::new(if cancel_explicitly { "cancel" } else { "drop" });
        layout.write_script(&format!(
            "printf '%s' \"$$\" > '{}'\nwhile :; do :; done",
            layout.pid_file.display()
        ));
        let mut harness = ExecuteHarness::start(&layout.script, &[]);
        let (candidate_sha256, profile_sha256) = validate_for_execute(&mut harness, cli_pin());
        let spec = layout.cli_spec(&profile_sha256);
        harness.request(&execute_run_request(
            cli_pin(),
            &candidate_sha256,
            &profile_sha256,
            "cancel-or-drop",
            RunSpec::IteronCli { spec },
        ));
        wait_for_file(&layout.pid_file);
        let pid: i32 = fs::read_to_string(&layout.pid_file)
            .unwrap()
            .parse()
            .unwrap();
        assert!(process_exists(pid));
        if cancel_explicitly {
            let cancelled = harness.request(&envelope(
                "cancel-running",
                ResearchRequest::Cancel {
                    adapter: cli_pin(),
                    candidate_id: "research/candidate-1".into(),
                    candidate_sha256,
                    profile_sha256,
                    implementation_activation_sha256: None,
                    run_id: "cancel-or-drop".into(),
                },
            ));
            assert!(matches!(
                cancelled.payload,
                ResearchResponse::Cancel {
                    state: ResearchRunState::Cancelled,
                    ..
                }
            ));
        }
        drop(harness);
        assert!(!process_exists(pid), "child survived cancel/drop and reap");
    }
}

#[cfg(unix)]
#[test]
fn execute_timeout_output_and_evidence_bounds_have_truthful_terminal_states() {
    let cases = [
        (
            "timeout",
            "while :; do :; done".to_string(),
            ResearchRunState::TimedOut,
        ),
        (
            "stdout",
            "i=0; while [ $i -lt 4096 ]; do printf x; i=$((i+1)); done".to_string(),
            ResearchRunState::StdoutLimit,
        ),
        (
            "stderr",
            "i=0; while [ $i -lt 4096 ]; do printf x >&2; i=$((i+1)); done".to_string(),
            ResearchRunState::StderrLimit,
        ),
    ];
    for (label, body, expected) in cases {
        let layout = ExecuteLayout::new(label);
        layout.write_script(&body);
        let mut harness = ExecuteHarness::start(&layout.script, &[]);
        let (candidate_sha256, profile_sha256) = validate_for_execute(&mut harness, cli_pin());
        let mut spec = layout.cli_spec(&profile_sha256);
        if label == "timeout" {
            spec.max_wall_secs = 1;
        } else if label == "stdout" {
            spec.max_stdout_bytes = 64;
        } else {
            spec.max_stderr_bytes = 64;
        }
        harness.request(&execute_run_request(
            cli_pin(),
            &candidate_sha256,
            &profile_sha256,
            label,
            RunSpec::IteronCli { spec },
        ));
        let result = wait_for_result(
            &mut harness,
            cli_pin(),
            &candidate_sha256,
            &profile_sha256,
            label,
        );
        assert!(matches!(
            result.payload,
            ResearchResponse::Result { state, terminal_result_available: false, .. }
                if state == expected
        ));
    }

    let layout = ExecuteLayout::new("evidence");
    let oversized = "x".repeat(512);
    layout.write_script(&format!(
        "printf '%s' '{}' > '{}'\nprintf '%s' '{}'",
        oversized,
        layout.effective.display(),
        CLI_RESULT
    ));
    let mut harness = ExecuteHarness::start(&layout.script, &[]);
    let (candidate_sha256, profile_sha256) = validate_for_execute(&mut harness, cli_pin());
    let mut spec = layout.cli_spec(&profile_sha256);
    spec.max_evidence_bytes = 128;
    harness.request(&execute_run_request(
        cli_pin(),
        &candidate_sha256,
        &profile_sha256,
        "evidence",
        RunSpec::IteronCli { spec },
    ));
    let result = wait_for_result(
        &mut harness,
        cli_pin(),
        &candidate_sha256,
        &profile_sha256,
        "evidence",
    );
    assert!(matches!(
        result.payload,
        ResearchResponse::Result {
            state: ResearchRunState::EvidenceLimit,
            terminal_result_available: false,
            ..
        }
    ));

    #[cfg(target_os = "macos")]
    {
        let layout = ExecuteLayout::new("memory");
        layout.write_script("while :; do :; done");
        let mut harness = ExecuteHarness::start(&layout.script, &[]);
        let (candidate_sha256, profile_sha256) = validate_for_execute(&mut harness, cli_pin());
        let mut spec = layout.cli_spec(&profile_sha256);
        spec.max_memory_bytes = 1;
        harness.request(&execute_run_request(
            cli_pin(),
            &candidate_sha256,
            &profile_sha256,
            "memory",
            RunSpec::IteronCli { spec },
        ));
        let result = wait_for_result(
            &mut harness,
            cli_pin(),
            &candidate_sha256,
            &profile_sha256,
            "memory",
        );
        assert!(matches!(
            result.payload,
            ResearchResponse::Result {
                state: ResearchRunState::Failed,
                terminal_result_available: false,
                detail: Some(ref detail),
                ..
            } if detail.contains("memory byte bound reached")
        ));
    }
}

#[cfg(unix)]
#[test]
fn execute_terminal_bench_parses_external_result_and_verifies_real_artifacts() {
    let layout = ExecuteLayout::new("terminal-bench");
    layout.write_script(&format!("printf '%s' '{}'", CLI_RESULT));
    fs::write(&layout.effective, b"{}").unwrap();
    let run_record_path = layout.runs.join("run-record.json");
    fs::write(&run_record_path, b"run-record").unwrap();
    let stdout = CLI_RESULT.as_bytes();
    let effective = fs::read(&layout.effective).unwrap();
    let run_record = fs::read(&run_record_path).unwrap();

    let mut harness = ExecuteHarness::start(&layout.script, &[]);
    let pin = AdapterPin {
        benchmark_id: "terminal-bench".into(),
        benchmark_version: "2.1".into(),
    };
    let (candidate_sha256, profile_sha256) = validate_for_execute(&mut harness, pin.clone());
    let request = TerminalBenchRequest {
        schema_version: 1,
        benchmark: BenchmarkPin {
            id: "terminal-bench".into(),
            version: "2.1".into(),
        },
        task: TaskIdentity {
            task_id: "task-execute".into(),
            trial_id: "trial-1".into(),
            dataset_revision: "fixture-revision".into(),
        },
        profile: ProfileIdentity {
            profile_sha256: profile_sha256.clone(),
            registry_sha256: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
            param_registry_sha256: iteron_tunables::param_registry_digest_sha256(),
        },
        iteron_revision: "d".repeat(40),
        binary_path: layout.script.to_string_lossy().into_owned(),
        workspace_path: layout.workspace.to_string_lossy().into_owned(),
        profile_path: layout.profile.to_string_lossy().into_owned(),
        effective_profile_path: layout.effective.to_string_lossy().into_owned(),
        result_path: layout.result.to_string_lossy().into_owned(),
        runs_dir: layout.runs.to_string_lossy().into_owned(),
        task_prompt: "terminal-bench execute fixture".into(),
        credential_env_names: Vec::new(),
        resources: ResourceBounds {
            max_wall_secs: 10,
            max_turns: 2,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
            max_evidence_bytes: 1024 * 1024,
            max_memory_bytes: 64 * 1024 * 1024 * 1024,
        },
    };
    let adapter_result_path = layout
        .runs
        .join(".iteron-research-task-execute-trial-1-result.json");
    let evidence_bytes = (stdout.len() + effective.len() + run_record.len()) as u64;
    let external_result = ExternalHarnessResult {
        schema_version: 1,
        benchmark: request.benchmark.clone(),
        task: request.task.clone(),
        profile: request.profile.clone(),
        iteron_revision: request.iteron_revision.clone(),
        run_id: "terminal-bench-runtime-run".into(),
        outcome: TerminalOutcome::Completed,
        success: true,
        exit_code: Some(0),
        score_micros: None,
        evidence: RunEvidence {
            effective_profile: ArtifactReference {
                path: layout.effective.to_string_lossy().into_owned(),
                bytes: effective.len() as u64,
                sha256: digest(&effective),
            },
            iteron_result: ArtifactReference {
                path: layout.result.to_string_lossy().into_owned(),
                bytes: stdout.len() as u64,
                sha256: digest(stdout),
            },
            run_record: ArtifactReference {
                path: run_record_path.to_string_lossy().into_owned(),
                bytes: run_record.len() as u64,
                sha256: digest(&run_record),
            },
            score_evidence: None,
        },
        timing: TimingEvidence {
            started_unix_ms: 1,
            elapsed_ms: 1,
        },
        resources: ResourceUsage {
            stdout_bytes: stdout.len() as u64,
            stderr_bytes: 0,
            evidence_bytes,
            peak_memory_bytes: Some(1024),
        },
    };
    fs::write(
        &adapter_result_path,
        serde_json::to_vec(&external_result).unwrap(),
    )
    .unwrap();

    let run = harness.request(&execute_run_request(
        pin.clone(),
        &candidate_sha256,
        &profile_sha256,
        "tb-execute",
        RunSpec::TerminalBench21 {
            request: request.clone(),
            implementation_candidate: None,
        },
    ));
    assert!(matches!(
        run.payload,
        ResearchResponse::Run {
            ref adapter_result_path,
            ..
        } if adapter_result_path.as_deref()
            == Some(layout.runs.join(".iteron-research-task-execute-trial-1-result.json").to_string_lossy().as_ref())
    ));
    let result = wait_for_result(
        &mut harness,
        pin.clone(),
        &candidate_sha256,
        &profile_sha256,
        "tb-execute",
    );
    assert!(matches!(
        result.payload,
        ResearchResponse::Result {
            state: ResearchRunState::Completed,
            terminal_result: Some(ref terminal),
            ..
        } if terminal.schema_id == "iteron-eval/terminal-bench-result/1"
            && terminal.run_id == "terminal-bench-runtime-run"
    ));
    let evidence = harness.request(&envelope(
        "tb-evidence",
        ResearchRequest::Evidence {
            adapter: pin,
            candidate_id: "research/candidate-1".into(),
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256: None,
            run_id: "tb-execute".into(),
        },
    ));
    assert!(matches!(
        evidence.payload,
        ResearchResponse::Evidence {
            evidence_available: true,
            ref artifacts,
            ..
        } if artifacts.len() == 3
    ));
}
