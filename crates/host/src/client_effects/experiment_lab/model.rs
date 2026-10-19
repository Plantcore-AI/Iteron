use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const MAX_VALUE_BYTES: usize = 32 * 1024;
const ONE_LINE_VALUE_MAX_CHARS: usize = 120;
fn max_value_bytes() -> usize {
    iteron_tunables::param_integer("cli.tui.experiment_lab.max_value_bytes", MAX_VALUE_BYTES)
        .min(MAX_VALUE_BYTES)
}
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum LabActionV1 {
    List,
    Request {
        family: String,
        value: String,
    },
    Compare {
        bundle_id: String,
        trusted_public_key: String,
    },
}
impl LabActionV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::List => Ok(()),
            Self::Request { family, value }
                if !family.is_empty()
                    && family.len() <= 128
                    && !value.trim().is_empty()
                    && value.len() <= max_value_bytes() =>
            {
                Ok(())
            }
            Self::Compare {
                bundle_id,
                trusted_public_key,
            } if super::super::workspace_storage::leaf(bundle_id).is_ok()
                && trusted_public_key.len() == 64
                && trusted_public_key.bytes().all(|n| n.is_ascii_hexdigit()) =>
            {
                Ok(())
            }
            _ => Err("invalid bounded lab action"),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatusV1 {
    Created,
    Existing,
    NotPublished,
    PublicationUnknown,
}
#[derive(Debug, Serialize)]
pub struct RequestViewV1 {
    pub request_id: String,
    pub family: String,
    pub value: String,
    pub relative_path: String,
    pub status: RequestStatusV1,
}
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LabFactsV1 {
    Inventory {
        requests: Vec<RequestViewV1>,
        bundles: Vec<String>,
        incomplete: bool,
    },
    Request {
        receipt: RequestViewV1,
    },
    Comparison {
        view: ComparisonViewV1,
    },
}
#[derive(Debug, Serialize)]
pub struct ComparisonViewV1 {
    pub bundle: String,
    pub synthetic: bool,
    pub baseline: String,
    pub candidate: String,
    pub baseline_rate: f64,
    pub candidate_rate: f64,
    pub rate_delta: f64,
    pub ci95: [f64; 2],
    pub matched: u64,
    pub minimum: u64,
    pub conclusion: String,
    pub signer_display: String,
    pub cost_delta_usd: Option<f64>,
    pub total_rows: usize,
    pub success: usize,
    pub task_failure: usize,
    pub infrastructure_failure: usize,
    pub censored: usize,
    pub held_out: usize,
    pub pareto: Vec<ParetoViewV1>,
    pub frontier: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct ParetoViewV1 {
    pub candidate: String,
    pub resolved_rate: f64,
    pub average_cost_usd: f64,
    pub average_latency_ms: f64,
    pub failed: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateRequest {
    family: String,
    family_semantic_digest: String,
    value: serde_json::Value,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PromotionMode {
    ExternalHumanAuthorityOnly,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Denied;
impl Serialize for Denied {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bool(false)
    }
}
impl<'de> Deserialize<'de> for Denied {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if bool::deserialize(d)? {
            return Err(serde::de::Error::custom(
                "lab cannot activate or promote runtime policy",
            ));
        }
        Ok(Self)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionBoundary {
    mode: PromotionMode,
    self_promotion: Denied,
    runtime_activation: Denied,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExperimentRequest {
    schema_version: u8,
    request_type: String,
    pub(super) request_id: String,
    status: String,
    evaluation_purpose: String,
    allowed_partition: String,
    tunables_registry_digest: String,
    candidate: CandidateRequest,
    promotion: PromotionBoundary,
}
fn candidate(family_id: &str, value: serde_json::Value) -> Result<CandidateRequest, &'static str> {
    let family = iteron_tunables::families()
        .iter()
        .find(|family| family.id == family_id)
        .ok_or("unknown lab family")?;
    if family.optimization.class == iteron_tunables::OptimizationClass::Pin {
        return Err("security and durability pins cannot be experiment candidates");
    }
    if family.implementation_status != iteron_tunables::ImplementationStatus::Full
        || value.is_null()
        || serde_json::to_vec(&value)
            .map_err(|_| "invalid candidate value")?
            .len()
            > max_value_bytes()
    {
        return Err("candidate has no complete binding or violates value bounds");
    }
    Ok(CandidateRequest {
        family: family.id.into(),
        family_semantic_digest: iteron_tunables::family_semantic_digest(family)
            .map_err(|_| "family identity unavailable")?
            .value,
        value,
    })
}
fn request_id(candidate: &CandidateRequest) -> Result<String, &'static str> {
    let bytes = serde_json::to_vec(candidate).map_err(|_| "candidate encoding unavailable")?;
    let digest = hex::encode(Sha256::digest(bytes));
    Ok(format!("req-{}", &digest[..20]))
}
pub(super) fn prepare_request(
    family: &str,
    raw: &str,
) -> Result<(ExperimentRequest, Vec<u8>), &'static str> {
    if raw.len() > max_value_bytes() {
        return Err("candidate value exceeds the configured byte limit");
    }
    let candidate = candidate(
        family,
        serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.into())),
    )?;
    let request = ExperimentRequest {
        schema_version: 1,
        request_type: "offline_tuner_request".into(),
        request_id: request_id(&candidate)?,
        status: "requested".into(),
        evaluation_purpose: "tune".into(),
        allowed_partition: "train".into(),
        tunables_registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
        candidate,
        promotion: PromotionBoundary {
            mode: PromotionMode::ExternalHumanAuthorityOnly,
            self_promotion: Denied,
            runtime_activation: Denied,
        },
    };
    let mut bytes =
        serde_json::to_vec_pretty(&request).map_err(|_| "request encoding unavailable")?;
    bytes.push(b'\n');
    if bytes.len() > super::max_request_bytes() {
        return Err("request exceeds bounded storage");
    }
    Ok((request, bytes))
}
impl ExperimentRequest {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.request_type != "offline_tuner_request"
            || self.status != "requested"
            || self.evaluation_purpose != "tune"
            || self.allowed_partition != "train"
            || self.tunables_registry_digest != iteron_tunables::REGISTRY_DIGEST_SHA256
            || self.request_id != request_id(&self.candidate)?
        {
            return Err("stored lab request identity is invalid");
        }
        let expected = candidate(&self.candidate.family, self.candidate.value.clone())?;
        if self.candidate != expected {
            return Err("stored family binding differs from this registry");
        }
        Ok(())
    }
}
pub(super) fn display(value: &str) -> String {
    let safe = iteron_record::redact::scrub(value);
    crate::semantic_text::ui_safe_text(&safe)
        .chars()
        .take(512)
        .collect()
}
fn one_line_value(value: &str) -> String {
    let text = display(value).replace(['\n', '\r'], " ");
    let limit = iteron_tunables::param_integer(
        "cli.tui.experiment_lab.one_line_value_max_chars",
        ONE_LINE_VALUE_MAX_CHARS,
    )
    .min(ONE_LINE_VALUE_MAX_CHARS);
    if text.chars().count() <= limit {
        text
    } else if limit == 0 {
        String::new()
    } else {
        format!("{}…", text.chars().take(limit - 1).collect::<String>())
    }
}
pub(super) fn project_request(
    request: &ExperimentRequest,
    status: RequestStatusV1,
) -> RequestViewV1 {
    RequestViewV1 {
        request_id: request.request_id.clone(),
        family: request.candidate.family.clone(),
        value: one_line_value(&request.candidate.value.to_string()),
        relative_path: format!(".iteron/experiments/requests/{}.json", request.request_id),
        status,
    }
}
