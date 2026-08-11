use crate::resolution_types::{EntryState, ResolutionReport, ResolvedEntry};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[derive(Serialize)]
struct EffectiveEntry<'a> {
    ordinal: u16,
    family_id: &'static str,
    state: EntryState,
    effective: &'a Option<crate::ResolutionValue>,
}

#[derive(Serialize)]
struct EffectivePayload<'a> {
    canonicalization: &'static str,
    registry_id: &'static str,
    registry_revision: u16,
    registry_digest: &'static str,
    entries: Vec<EffectiveEntry<'a>>,
}

#[derive(Serialize)]
struct ResolutionPayload<'a> {
    canonicalization: &'static str,
    schema_version: u16,
    registry_id: &'static str,
    registry_revision: u16,
    registry_digest: &'static str,
    input_digest_sha256: &'a str,
    effective_digest_sha256: &'a str,
    profile_digest_sha256: &'a Option<String>,
    entries: &'a [ResolvedEntry],
}

pub(crate) fn effective_digest(entries: &[ResolvedEntry]) -> Result<String, String> {
    let entries = entries
        .iter()
        .map(|entry| EffectiveEntry {
            ordinal: entry.ordinal,
            family_id: entry.family_id,
            state: entry.outcome.state(),
            effective: &entry.effective,
        })
        .collect();
    digest_json(&EffectivePayload {
        canonicalization: "iteron-tunables-effective-json-v1",
        registry_id: crate::REGISTRY_ID,
        registry_revision: crate::REGISTRY_REVISION,
        registry_digest: crate::REGISTRY_DIGEST_SHA256,
        entries,
    })
}

pub(crate) fn resolution_digest(report: &ResolutionReport) -> Result<String, String> {
    digest_json(&ResolutionPayload {
        canonicalization: "iteron-tunables-resolution-json-v1",
        schema_version: report.schema_version,
        registry_id: report.registry_id,
        registry_revision: report.registry_revision,
        registry_digest: report.registry_digest,
        input_digest_sha256: &report.input_digest_sha256,
        effective_digest_sha256: &report.effective_digest_sha256,
        profile_digest_sha256: &report.profile_digest_sha256,
        entries: &report.entries,
    })
}

fn digest_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|_| "resolution digest encoding failed".to_owned())
}
