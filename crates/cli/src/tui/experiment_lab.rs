//! Offline experiment request and signed-evidence TUI surface.

use super::*;
use iteron_eval::VerifiedEvidenceBundle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

mod storage;

use storage::*;

const MAX_VALUE_BYTES: usize = 32 * 1024;
const MAX_REQUEST_BYTES: u64 = 128 * 1024;
const MAX_LISTED_REQUESTS: usize = 80;
const MAX_LISTED_BUNDLES: usize = 40;
/// Characters a JSON value may occupy on one request row. A wider value wraps and breaks the
/// column alignment the row shares with every other listed request; longer values are elided, and
/// the ellipsis that replaces the tail costs one of these characters.
const ONE_LINE_VALUE_MAX_CHARS: usize = 120;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateRequest {
    family: String,
    family_semantic_digest: String,
    value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionBoundary {
    mode: String,
    self_promotion: bool,
    runtime_activation: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExperimentRequest {
    schema_version: u8,
    request_type: String,
    request_id: String,
    status: String,
    evaluation_purpose: String,
    allowed_partition: String,
    tunables_registry_digest: String,
    candidate: CandidateRequest,
    promotion: PromotionBoundary,
}

#[derive(Debug, Clone)]
struct RequestReceipt {
    request: ExperimentRequest,
    relative_path: PathBuf,
    reused: bool,
}

#[derive(Debug, thiserror::Error)]
enum LabError {
    #[error("usage: /lab [list|request <family> <json>|compare <bundle> <trusted-key>|promote]")]
    Usage,
    #[error("experiment lab path is unsafe: {0}")]
    UnsafePath(String),
    #[error("experiment request is invalid: {0}")]
    InvalidRequest(String),
    #[error("experiment lab I/O failed: {0}")]
    Io(String),
    #[error("signed evidence verification failed: {0}")]
    Evidence(String),
}

pub(super) fn handle(app: &mut App, session: &Session, arg: &str) {
    let input = arg.trim();
    let outcome = if input.is_empty() || input == "list" {
        list(app, session.workspace())
    } else if let Some(rest) = input.strip_prefix("request ") {
        request(app, session.workspace(), rest)
    } else if let Some(rest) = input.strip_prefix("compare ") {
        compare(app, session.workspace(), rest)
    } else if input == "promote" || input.starts_with("promote ") {
        app.panel(
            "◇",
            "experiment lab · promotion boundary",
            vec![
                kv("status", "blocked by design"),
                kv("authority", "external human-owned PromotionAuthority"),
                kv("runtime activation", "unavailable from /lab"),
                block::PanelRow::Note(
                    "The lab can request train-only experiments and verify evidence. It cannot sign, promote, activate, or roll back policy.".into(),
                ),
            ],
        );
        Ok(())
    } else {
        Err(LabError::Usage)
    };
    if let Err(error) = outcome {
        app.note(block::NoticeLevel::Err, error.to_string());
    }
}

fn request(app: &mut App, workspace: &Path, input: &str) -> Result<(), LabError> {
    let Some((family, value)) = split_once_whitespace(input) else {
        return Err(LabError::Usage);
    };
    let receipt = create_request(workspace, family, value)?;
    render_request(app, &receipt);
    Ok(())
}

fn compare(app: &mut App, workspace: &Path, input: &str) -> Result<(), LabError> {
    let mut words = input.split_whitespace();
    let bundle_id = words.next().ok_or(LabError::Usage)?;
    let trusted_key = words.next().ok_or(LabError::Usage)?;
    if words.next().is_some() || !safe_component(bundle_id) {
        return Err(LabError::Usage);
    }
    let evidence_root =
        secure_subdir(workspace, &[".iteron", "experiments", "evidence"], false)?
            .ok_or_else(|| LabError::Evidence("no local evidence directory exists".into()))?;
    let bundle = evidence_root.join(bundle_id);
    let metadata = std::fs::symlink_metadata(&bundle)
        .map_err(|error| LabError::Evidence(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LabError::UnsafePath(
            "evidence bundle must be a regular directory".into(),
        ));
    }
    let canonical = bundle
        .canonicalize()
        .map_err(|error| LabError::Evidence(error.to_string()))?;
    if !canonical.starts_with(&evidence_root) {
        return Err(LabError::UnsafePath(
            "evidence bundle escapes the experiment root".into(),
        ));
    }
    let verified = iteron_eval::verify_evidence_bundle(&canonical, trusted_key)
        .map_err(|error| LabError::Evidence(error.to_string()))?;
    render_comparison(app, bundle_id, &verified);
    Ok(())
}

fn list(app: &mut App, workspace: &Path) -> Result<(), LabError> {
    let Some(root) = secure_subdir(workspace, &[".iteron", "experiments"], false)? else {
        app.panel(
            "◇",
            "experiment lab",
            vec![
                kv("status", "ready · no local experiments"),
                kv("scope", "offline · train-only"),
                kv("registry", iteron_tunables::REGISTRY_DIGEST_SHA256),
                kv("promotion", "external human authority only"),
                block::PanelRow::Note(
                    "Start with `/lab request <family> <json-value>`. No runtime setting changes when a request is created.".into(),
                ),
            ],
        );
        return Ok(());
    };
    let requests = list_requests(&root.join("requests"))?;
    let bundles = list_bundles(&root.join("evidence"))?;
    let mut rows = vec![
        kv("status", "offline · evidence-gated"),
        kv("registry", iteron_tunables::REGISTRY_DIGEST_SHA256),
        kv("requests", &requests.len().to_string()),
        kv("signed bundles", &bundles.len().to_string()),
    ];
    rows.extend(requests.iter().map(|request| {
        item(
            "◇",
            &format!("{} · {}", request.request_id, request.status),
            &format!(
                "{} = {}",
                request.candidate.family,
                one_line_value(&request.candidate.value)
            ),
        )
    }));
    rows.extend(bundles.iter().map(|bundle| {
        item(
            "◆",
            bundle,
            "signed evidence · `/lab compare ID TRUSTED_KEY`",
        )
    }));
    rows.push(block::PanelRow::Note(
        "No experiment can self-promote; /lab has no activation credential or promotion key."
            .into(),
    ));
    app.panel("◇", "experiment lab", rows);
    Ok(())
}

fn create_request(
    workspace: &Path,
    family_id: &str,
    raw_value: &str,
) -> Result<RequestReceipt, LabError> {
    if raw_value.len()
        > iteron_tunables::param_integer("cli.tui.experiment_lab.max_value_bytes", MAX_VALUE_BYTES)
    {
        return Err(LabError::InvalidRequest("value exceeds 32 KiB".into()));
    }
    let family = iteron_tunables::families()
        .iter()
        .find(|family| family.id == family_id)
        .ok_or_else(|| LabError::InvalidRequest(format!("unknown family `{family_id}`")))?;
    if family.optimization.class == iteron_tunables::OptimizationClass::Pin {
        return Err(LabError::InvalidRequest(format!(
            "`{family_id}` is a security/durability pin, not a search choice"
        )));
    }
    if family.implementation_status != iteron_tunables::ImplementationStatus::Full {
        return Err(LabError::InvalidRequest(format!(
            "`{family_id}` has no complete production binding"
        )));
    }
    let value = serde_json::from_str(raw_value)
        .unwrap_or_else(|_| serde_json::Value::String(raw_value.to_owned()));
    if value.is_null() {
        return Err(LabError::InvalidRequest(
            "null is not a candidate value; omit inactive conditional families".into(),
        ));
    }
    let candidate = CandidateRequest {
        family: family.id.into(),
        family_semantic_digest: iteron_tunables::family_semantic_digest(family)
            .map_err(|error| LabError::InvalidRequest(error.to_string()))?
            .value,
        value,
    };
    let payload = serde_json::to_vec(&candidate)
        .map_err(|error| LabError::InvalidRequest(error.to_string()))?;
    let digest = hex::encode(Sha256::digest(payload));
    let request_id = format!("req-{}", &digest[..20]);
    let request = ExperimentRequest {
        schema_version: 1,
        request_type: "offline_tuner_request".into(),
        request_id: request_id.clone(),
        status: "requested".into(),
        evaluation_purpose: "tune".into(),
        allowed_partition: "train".into(),
        tunables_registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
        candidate,
        promotion: PromotionBoundary {
            mode: "external_human_authority_only".into(),
            self_promotion: false,
            runtime_activation: false,
        },
    };
    let directory = secure_subdir(workspace, &[".iteron", "experiments", "requests"], true)?
        .expect("create=true always returns a directory");
    let destination = directory.join(format!("{request_id}.json"));
    let mut bytes = serde_json::to_vec_pretty(&request)
        .map_err(|error| LabError::InvalidRequest(error.to_string()))?;
    bytes.push(b'\n');
    let reused = destination.exists();
    if reused && read_bounded(&destination)? != bytes {
        return Err(LabError::InvalidRequest(
            "content-addressed request id collision".into(),
        ));
    }
    if !reused {
        write_atomic(&directory, &destination, &bytes)?;
    }
    Ok(RequestReceipt {
        request,
        relative_path: PathBuf::from(".iteron/experiments/requests")
            .join(format!("{request_id}.json")),
        reused,
    })
}

fn render_request(app: &mut App, receipt: &RequestReceipt) {
    app.panel(
        "◇",
        "experiment request",
        vec![
            kv("status", if receipt.reused { "requested · existing" } else { "requested · new" }),
            kv("request", &receipt.request.request_id),
            kv("family", &receipt.request.candidate.family),
            kv("value", &one_line_value(&receipt.request.candidate.value)),
            kv("evaluation", "tune · train partition only"),
            kv("runtime activation", "none"),
            kv("promotion", "external human authority only"),
            kv("artifact", &receipt.relative_path.display().to_string()),
            block::PanelRow::Note(
                "Request recorded. An offline runner/tuner may consume it; this TUI did not change the active policy.".into(),
            ),
        ],
    );
}

fn render_comparison(app: &mut App, bundle_id: &str, verified: &VerifiedEvidenceBundle) {
    let comparison = &verified.paired.comparison;
    let mut rows = vec![
        kv("trust", "verified · signed bytes + recomputed reports"),
        kv("bundle", bundle_id),
        kv(
            "baseline",
            &format!(
                "{} · {:.1}% resolved",
                comparison.baseline.name,
                comparison.baseline.resolved_rate * 100.0
            ),
        ),
        kv(
            "candidate",
            &format!(
                "{} · {:.1}% resolved",
                comparison.treatment.name,
                comparison.treatment.resolved_rate * 100.0
            ),
        ),
        kv(
            "quality Δ",
            &format!(
                "{:+.1} pp · CI95 [{:+.1}, {:+.1}]",
                comparison.resolved_rate_delta * 100.0,
                comparison.paired_ci95[0] * 100.0,
                comparison.paired_ci95[1] * 100.0
            ),
        ),
        kv(
            "paired observations",
            &format!(
                "{} / {} minimum",
                comparison.matched_pairs, comparison.minimum_pairs
            ),
        ),
        kv("conclusion", &comparison.statistical_conclusion.to_string()),
        kv("signer", &format!("{}…", &verified.index.public_key[..12])),
    ];
    rows.push(kv(
        "cost Δ",
        &comparison
            .cost_delta_usd
            .map(|delta| format!("${delta:+.6}"))
            .unwrap_or_else(|| "unknown · not promotion-ready".into()),
    ));
    for point in &verified.pareto.points {
        rows.push(item(
            "◆",
            &format!(
                "{} · {:.1}% · ${:.4}",
                point.candidate_id,
                point.resolved_rate * 100.0,
                point.average_cost_usd
            ),
            &format!(
                "{:.0} ms · {} failed",
                point.average_latency_ms, point.failed_runs
            ),
        ));
    }
    rows.push(kv("Pareto frontier", &verified.pareto.frontier.join(" · ")));
    rows.push(block::PanelRow::Note(
        "Evidence comparison is read-only. Promotion still requires the separate human-owned authority and held-out gate.".into(),
    ));
    app.panel("◆", "experiment evidence", rows);
}

fn split_once_whitespace(value: &str) -> Option<(&str, &str)> {
    let offset = value.find(char::is_whitespace)?;
    let (left, right) = value.split_at(offset);
    let right = right.trim_start();
    (!left.is_empty() && !right.is_empty()).then_some((left, right))
}

fn one_line_value(value: &serde_json::Value) -> String {
    let mut text = value.to_string().replace(['\n', '\r'], " ");
    if text.chars().count()
        > iteron_tunables::param_integer(
            "cli.tui.experiment_lab.one_line_value_max_chars",
            ONE_LINE_VALUE_MAX_CHARS,
        )
    {
        text = format!(
            "{}…",
            text.chars()
                .take(
                    iteron_tunables::param_integer(
                        "cli.tui.experiment_lab.one_line_value_max_chars",
                        ONE_LINE_VALUE_MAX_CHARS
                    ) - 1
                )
                .collect::<String>()
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_workspace(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iteron-cli-lab-{label}-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn full_search_family() -> &'static str {
        iteron_tunables::families()
            .iter()
            .find(|family| {
                family.implementation_status == iteron_tunables::ImplementationStatus::Full
                    && family.optimization.class != iteron_tunables::OptimizationClass::Pin
            })
            .unwrap()
            .id
    }

    #[test]
    fn request_is_content_addressed_train_only_and_has_no_activation_surface() {
        let workspace = temp_workspace("request");
        let first = create_request(&workspace, full_search_family(), "true").unwrap();
        let second = create_request(&workspace, full_search_family(), "true").unwrap();
        assert_eq!(first.request.request_id, second.request.request_id);
        assert!(!first.reused);
        assert!(second.reused);
        assert_eq!(first.request.evaluation_purpose, "tune");
        assert_eq!(first.request.allowed_partition, "train");
        assert!(!first.request.promotion.self_promotion);
        assert!(!first.request.promotion.runtime_activation);
        let mut app = App::new();
        render_request(&mut app, &first);
        let block::BlockKind::Panel { title, rows } = &app.transcript.last().unwrap().kind else {
            panic!("request must render as a semantic panel");
        };
        assert_eq!(title, "experiment request");
        assert!(rows.iter().any(|row| matches!(
            row,
            block::PanelRow::KeyValue { key, value }
                if key == "evaluation" && value.contains("train partition only")
        )));
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn pin_and_symlinked_lab_root_are_refused() {
        let workspace = temp_workspace("refusal");
        let pinned = iteron_tunables::families()
            .iter()
            .find(|family| family.optimization.class == iteron_tunables::OptimizationClass::Pin)
            .unwrap();
        assert!(create_request(&workspace, pinned.id, "true").is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(std::env::temp_dir(), workspace.join(".iteron")).unwrap();
            assert!(create_request(&workspace, full_search_family(), "true").is_err());
        }
        let _ = std::fs::remove_dir_all(workspace);
    }
}
