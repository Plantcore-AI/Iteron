//! Provider-free CLI adapter for the deterministic tunables resolver.
//!
//! This command consumes an explicit frozen request. It is a simulation surface until the runtime
//! binding and run-genesis contracts land; it never claims to describe the current process.

use clap::{Subcommand, ValueEnum};
use serde::Serialize;
use std::io::Read as _;
use std::path::{Path, PathBuf};

// One 1 MiB normalized root may appear in requested/effective, three adjustment pairs, and a
// shadowed value, plus the fixed 160-entry audit metadata. Keep a hard 16 MiB complete-report cap.
const MAX_RESOLUTION_OUTPUT_BYTES: usize = 16 * 1_048_576;
const MAX_RESOLUTION_STDERR_BYTES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum Action {
    /// Resolve a frozen request and print one machine-readable simulation report.
    Resolve {
        /// Request JSON file, or `-` for stdin. Input is capped at 1 MiB.
        request: PathBuf,
    },
    /// Explain a frozen request. Text covers all 160 families; JSON selects one family.
    Explain {
        /// Request JSON file, or `-` for stdin. Input is capped at 1 MiB.
        request: PathBuf,
        /// Machine output requires one canonical ID, semantic key, or registered alias.
        #[arg(long)]
        family: Option<String>,
        /// Human text or one-family JSON.
        #[arg(long, value_enum, default_value_t = ExplainFormat::Text)]
        format: ExplainFormat,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ExplainFormat {
    Text,
    Json,
}

#[derive(Serialize)]
struct SimulationDocument<T> {
    schema_version: u16,
    kind: &'static str,
    simulation: bool,
    runtime_bound: bool,
    status: &'static str,
    exit_code: u8,
    result: T,
}

#[derive(Serialize)]
struct ResolutionFailureDocument<'a> {
    schema_version: u16,
    kind: &'static str,
    simulation: bool,
    runtime_bound: bool,
    status: &'static str,
    exit_code: u8,
    failure: &'a iteron_tunables::ResolutionFailureReport,
}

#[derive(Serialize)]
struct FailureSummary<'a> {
    code: iteron_tunables::FailureCode,
    detail: &'a str,
    failures: &'a [iteron_tunables::FamilyFailure],
}

#[derive(Serialize)]
struct ExplainFailureDocument<'a, T> {
    schema_version: u16,
    kind: &'static str,
    simulation: bool,
    runtime_bound: bool,
    status: &'static str,
    exit_code: u8,
    failure: FailureSummary<'a>,
    result: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderedOutput {
    exit_code: u8,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl RenderedOutput {
    fn emit(self) -> anyhow::Result<u8> {
        use std::io::Write as _;
        std::io::stdout().lock().write_all(&self.stdout)?;
        std::io::stderr().lock().write_all(&self.stderr)?;
        Ok(self.exit_code)
    }
}

pub(crate) fn run(action: &Action) -> anyhow::Result<u8> {
    match action {
        Action::Resolve { request } => resolve(request),
        Action::Explain {
            request,
            family,
            format,
        } => explain(request, family.as_deref(), *format),
    }
}

fn resolve(request: &Path) -> anyhow::Result<u8> {
    let bytes = read_request(request)?;
    render_resolve(&bytes)?.emit()
}

fn explain(request: &Path, family: Option<&str>, format: ExplainFormat) -> anyhow::Result<u8> {
    let bytes = read_request(request)?;
    render_explain(&bytes, family, format)?.emit()
}

fn render_resolve(bytes: &[u8]) -> anyhow::Result<RenderedOutput> {
    match iteron_tunables::resolve_json(bytes) {
        Ok(resolved) => json_output(
            &SimulationDocument {
                schema_version: 1,
                kind: "tunables_resolution_simulation",
                simulation: true,
                runtime_bound: false,
                status: "resolved",
                exit_code: crate::output::EXIT_SUCCESS,
                result: resolved.report(),
            },
            crate::output::EXIT_SUCCESS,
        ),
        Err(failure) => render_resolution_failure(&failure),
    }
}

fn render_resolution_failure(
    failure: &iteron_tunables::ResolutionFailureReport,
) -> anyhow::Result<RenderedOutput> {
    if failure.code == iteron_tunables::FailureCode::ActiveResolutionFailed
        && failure.report.is_none()
    {
        anyhow::bail!("tunables active-resolution failure omitted its audit report")
    }
    let status = match failure.code {
        iteron_tunables::FailureCode::InvalidInput => "invalid_input",
        iteron_tunables::FailureCode::ActiveResolutionFailed => "active_resolution_failed",
    };
    json_output(
        &ResolutionFailureDocument {
            schema_version: 1,
            kind: "tunables_resolution_simulation",
            simulation: true,
            runtime_bound: false,
            status,
            exit_code: crate::output::EXIT_HARNESS,
            failure,
        },
        crate::output::EXIT_HARNESS,
    )
}

fn render_explain(
    bytes: &[u8],
    family: Option<&str>,
    format: ExplainFormat,
) -> anyhow::Result<RenderedOutput> {
    validate_explain_request(family, format)?;
    match iteron_tunables::resolve_json(bytes) {
        Ok(resolved) => render_explain_report(resolved.report(), None, family, format),
        Err(failure) if failure.code == iteron_tunables::FailureCode::ActiveResolutionFailed => {
            let report = failure.report.as_ref().ok_or_else(|| {
                anyhow::anyhow!("active-resolution failure omitted its audit report")
            })?;
            render_explain_report(report, Some(&failure), family, format)
        }
        Err(failure) => render_invalid_explain(&failure, format),
    }
}

fn render_invalid_explain(
    failure: &iteron_tunables::ResolutionFailureReport,
    format: ExplainFormat,
) -> anyhow::Result<RenderedOutput> {
    if failure.code != iteron_tunables::FailureCode::InvalidInput || failure.report.is_some() {
        anyhow::bail!("tunables invalid-input failure violated its report contract")
    }
    match format {
        ExplainFormat::Text => text_output(
            format!(
                "SIMULATION ONLY (runtime_bound=false) status=invalid_input exit_code={}\n{}",
                crate::output::EXIT_HARNESS,
                failure.detail
            ),
            crate::output::EXIT_HARNESS,
        ),
        ExplainFormat::Json => json_output(
            &ResolutionFailureDocument {
                schema_version: 1,
                kind: "tunables_explain_simulation",
                simulation: true,
                runtime_bound: false,
                status: "invalid_input",
                exit_code: crate::output::EXIT_HARNESS,
                failure,
            },
            crate::output::EXIT_HARNESS,
        ),
    }
}

fn validate_explain_request(family: Option<&str>, format: ExplainFormat) -> anyhow::Result<()> {
    match (format, family) {
        (ExplainFormat::Text, Some(_)) => {
            anyhow::bail!("--family is supported only with --format json")
        }
        (ExplainFormat::Json, None) => {
            anyhow::bail!("--format json requires --family <ID|SEMANTIC_KEY|ALIAS>")
        }
        (ExplainFormat::Text, None) | (ExplainFormat::Json, Some(_)) => Ok(()),
    }
}

fn render_explain_report(
    report: &iteron_tunables::ResolutionReport,
    failure: Option<&iteron_tunables::ResolutionFailureReport>,
    family: Option<&str>,
    format: ExplainFormat,
) -> anyhow::Result<RenderedOutput> {
    let exit_code = failure.map_or(crate::output::EXIT_SUCCESS, |_| crate::output::EXIT_HARNESS);
    match (format, family) {
        (ExplainFormat::Text, None) => {
            let explanation = iteron_tunables::explain_text(report)?;
            let status = if failure.is_some() {
                "active_resolution_failed"
            } else {
                "resolved"
            };
            let failures = failure.map_or(0, |failure| failure.failures.len());
            text_output(
                format!(
                    "SIMULATION ONLY (runtime_bound=false) status={status} exit_code={exit_code} failures={failures}\n{explanation}"
                ),
                exit_code,
            )
        }
        (ExplainFormat::Json, Some(selector)) => {
            let entry = iteron_tunables::explain_entry_json(report, selector)?;
            let entry: serde_json::Value = serde_json::from_str(&entry)?;
            if let Some(failure) = failure {
                json_output(
                    &ExplainFailureDocument {
                        schema_version: 1,
                        kind: "tunables_explain_simulation",
                        simulation: true,
                        runtime_bound: false,
                        status: "active_resolution_failed",
                        exit_code,
                        failure: FailureSummary {
                            code: failure.code,
                            detail: &failure.detail,
                            failures: &failure.failures,
                        },
                        result: entry,
                    },
                    exit_code,
                )
            } else {
                json_output(
                    &SimulationDocument {
                        schema_version: 1,
                        kind: "tunables_explain_simulation",
                        simulation: true,
                        runtime_bound: false,
                        status: "resolved",
                        exit_code,
                        result: entry,
                    },
                    exit_code,
                )
            }
        }
        (ExplainFormat::Text, Some(_)) | (ExplainFormat::Json, None) => {
            anyhow::bail!("explain arguments violate the validated output contract")
        }
    }
}

fn read_request(path: &Path) -> anyhow::Result<Vec<u8>> {
    if path == Path::new("-") {
        return read_bounded(std::io::stdin().lock());
    }
    let file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("cannot open tunables request file: {error}"))?;
    read_bounded(file)
}

fn read_bounded(mut reader: impl std::io::Read) -> anyhow::Result<Vec<u8>> {
    let limit = u64::try_from(iteron_tunables::RESOLUTION_INPUT_MAX_BYTES)
        .map_err(|_| anyhow::anyhow!("tunables request bound exceeds the platform read limit"))?;
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("cannot read tunables request: {error}"))?;
    Ok(bytes)
}

fn json_output(value: &impl Serialize, exit_code: u8) -> anyhow::Result<RenderedOutput> {
    let mut stdout = serde_json::to_vec_pretty(value)?;
    stdout.push(b'\n');
    bounded_output(stdout, Vec::new(), exit_code)
}

fn text_output(mut value: String, exit_code: u8) -> anyhow::Result<RenderedOutput> {
    if !value.ends_with('\n') {
        value.push('\n');
    }
    bounded_output(value.into_bytes(), Vec::new(), exit_code)
}

fn bounded_output(
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: u8,
) -> anyhow::Result<RenderedOutput> {
    if stdout.len() > MAX_RESOLUTION_OUTPUT_BYTES {
        anyhow::bail!(
            "tunables simulation output exceeds the {MAX_RESOLUTION_OUTPUT_BYTES}-byte bound"
        );
    }
    if stderr.len() > MAX_RESOLUTION_STDERR_BYTES {
        anyhow::bail!(
            "tunables simulation stderr exceeds the {MAX_RESOLUTION_STDERR_BYTES}-byte bound"
        );
    }
    Ok(RenderedOutput {
        exit_code,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ExplainFormat, MAX_RESOLUTION_OUTPUT_BYTES, SimulationDocument, bounded_output,
        json_output, read_bounded, render_explain, render_resolve,
    };

    /// A request that is *valid* but resolves nothing.
    ///
    /// Input validation now requires activation evidence for every runtime-derived family, so a
    /// request that omits it is rejected as `invalid_input` and never reaches the stage this test
    /// is about. The evidence is therefore complete while the declared values stay empty: the
    /// request gets past the door and then fails closed on the families themselves, which is the
    /// distinction between `invalid_input` and `active_resolution_failed` that these tests pin.
    fn unresolved_request_json() -> Vec<u8> {
        let activation: Vec<_> = iteron_tunables::families()
            .iter()
            .filter_map(|family| match family.activation.predicate {
                iteron_tunables::ActivationPredicate::RuntimeDerived { seam } => {
                    Some(serde_json::json!({
                        "family": family.id,
                        "seam": seam,
                        "subject_digest_sha256": "a".repeat(64),
                        "evidence_digest_sha256": "b".repeat(64),
                        "active": true,
                    }))
                }
                _ => None,
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "schema_version": iteron_tunables::RESOLUTION_SCHEMA_VERSION,
            "registry_id": iteron_tunables::REGISTRY_ID,
            "registry_revision": iteron_tunables::REGISTRY_REVISION,
            "registry_digest": iteron_tunables::REGISTRY_DIGEST_SHA256,
            "activation_evidence": activation,
        }))
        .unwrap()
    }

    #[test]
    fn request_reader_preserves_one_extra_byte_for_typed_core_rejection() {
        let exact = vec![b' '; iteron_tunables::RESOLUTION_INPUT_MAX_BYTES];
        assert_eq!(read_bounded(exact.as_slice()).unwrap().len(), exact.len());

        let oversized = vec![b' '; iteron_tunables::RESOLUTION_INPUT_MAX_BYTES + 1];
        assert_eq!(
            read_bounded(oversized.as_slice()).unwrap().len(),
            oversized.len()
        );
        let rendered = render_resolve(&oversized).unwrap();
        assert_eq!(rendered.exit_code, crate::output::EXIT_HARNESS);
        assert!(rendered.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&rendered.stdout).unwrap();
        assert_eq!(value["status"], "invalid_input");
        assert_eq!(value["failure"]["code"], "invalid_input");
    }

    #[test]
    fn resolve_machine_failure_keeps_the_complete_report_and_nonzero_status() {
        let request = unresolved_request_json();
        let first = render_resolve(&request).unwrap();
        let second = render_resolve(&request).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.exit_code, crate::output::EXIT_HARNESS);
        assert!(first.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
        assert_eq!(value["kind"], "tunables_resolution_simulation");
        assert_eq!(value["status"], "active_resolution_failed");
        assert_eq!(value["exit_code"], crate::output::EXIT_HARNESS);
        assert_eq!(value["failure"]["code"], "active_resolution_failed");
        assert_eq!(
            value["failure"]["report"]["entries"]
                .as_array()
                .unwrap()
                .len(),
            iteron_tunables::EXPECTED_FAMILY_COUNT
        );
    }

    #[test]
    fn explain_uses_active_failure_report_for_human_and_machine_output() {
        let request = unresolved_request_json();
        let human = render_explain(&request, None, ExplainFormat::Text).unwrap();
        assert_eq!(human.exit_code, crate::output::EXIT_HARNESS);
        assert!(human.stderr.is_empty());
        let human = String::from_utf8(human.stdout).unwrap();
        assert!(human.contains("status=active_resolution_failed"));
        assert!(human.contains("unresolved.external_constraint_missing"));

        let machine = render_explain(&request, Some("provider"), ExplainFormat::Json).unwrap();
        assert_eq!(machine.exit_code, crate::output::EXIT_HARNESS);
        assert!(machine.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
        assert_eq!(value["status"], "active_resolution_failed");
        assert_eq!(value["failure"]["code"], "active_resolution_failed");
        assert_eq!(value["result"]["entry"]["family_id"], "provider");
        assert_eq!(value["result"]["entry"]["state"], "inactive");
    }

    #[test]
    fn invalid_input_uses_typed_bounded_channels_without_a_forged_report() {
        let resolve = render_resolve(b"{}").unwrap();
        assert_eq!(resolve.exit_code, crate::output::EXIT_HARNESS);
        assert!(resolve.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&resolve.stdout).unwrap();
        assert_eq!(value["status"], "invalid_input");
        assert_eq!(value["failure"]["code"], "invalid_input");
        assert!(value["failure"]["report"].is_null());

        let machine = render_explain(b"{}", Some("provider"), ExplainFormat::Json).unwrap();
        assert_eq!(machine.exit_code, crate::output::EXIT_HARNESS);
        assert!(machine.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
        assert_eq!(value["status"], "invalid_input");
        assert!(value.get("result").is_none());
        assert!(value["failure"]["report"].is_null());

        let human = render_explain(b"{}", None, ExplainFormat::Text).unwrap();
        assert_eq!(human.exit_code, crate::output::EXIT_HARNESS);
        assert!(human.stderr.is_empty());
        assert!(human.stdout.len() < 256);
        assert!(
            String::from_utf8(human.stdout)
                .unwrap()
                .contains("status=invalid_input")
        );
    }

    #[test]
    fn success_envelope_uses_stdout_only_and_zero_exit() {
        let output = json_output(
            &SimulationDocument {
                schema_version: 1,
                kind: "tunables_resolution_simulation",
                simulation: true,
                runtime_bound: false,
                status: "resolved",
                exit_code: crate::output::EXIT_SUCCESS,
                result: serde_json::json!({"entries": 160}),
            },
            crate::output::EXIT_SUCCESS,
        )
        .unwrap();
        assert_eq!(output.exit_code, crate::output::EXIT_SUCCESS);
        assert!(output.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["status"], "resolved");
        assert_eq!(value["exit_code"], 0);
    }

    #[test]
    fn complete_report_output_bound_remains_hard() {
        assert!(
            bounded_output(
                vec![b'x'; MAX_RESOLUTION_OUTPUT_BYTES],
                Vec::new(),
                crate::output::EXIT_SUCCESS,
            )
            .is_ok()
        );
        assert!(
            bounded_output(
                vec![b'x'; MAX_RESOLUTION_OUTPUT_BYTES + 1],
                Vec::new(),
                crate::output::EXIT_SUCCESS,
            )
            .is_err()
        );
    }
}
