use super::{
    AgentMemoryMode, ChildToolDisposition, ExtensionFactError, McpTransport, MessagingTopology,
    OAuthLifecycleMode, ReplayOwnerObservation, SessionIsolationProfile,
};
use iteron_tunables::{ConstraintValue, ExternalCeiling, ResolutionValue, RuntimeResolutionBuilder};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn boolv(value: bool) -> ResolutionValue {
    ResolutionValue::Boolean { value }
}

pub(super) fn int(value: i64) -> ResolutionValue {
    ResolutionValue::Integer { value }
}

pub(super) fn text(value: &str) -> ResolutionValue {
    ResolutionValue::Text {
        value: value.to_owned(),
    }
}

pub(super) fn en(value: &str) -> ResolutionValue {
    ResolutionValue::Enum {
        value: value.to_owned(),
    }
}

pub(super) fn list(values: impl IntoIterator<Item = ResolutionValue>) -> ResolutionValue {
    ResolutionValue::List {
        items: values.into_iter().collect(),
    }
}

pub(super) fn map(values: impl IntoIterator<Item = (String, ResolutionValue)>) -> ResolutionValue {
    ResolutionValue::Map {
        entries: values.into_iter().collect(),
    }
}

pub(super) fn object<const N: usize>(values: [(&str, ResolutionValue); N]) -> ResolutionValue {
    ResolutionValue::Object {
        fields: values
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    }
}

pub(super) fn tool_profile(profile: &BTreeMap<String, ChildToolDisposition>) -> ResolutionValue {
    map(profile.iter().map(|(name, disposition)| {
        (
            name.clone(),
            en(match disposition {
                ChildToolDisposition::Allow => "allow",
                ChildToolDisposition::Ask => "ask",
                ChildToolDisposition::Deny => "deny",
            }),
        )
    }))
}

pub(super) const fn memory_mode(mode: AgentMemoryMode) -> &'static str {
    match mode {
        AgentMemoryMode::Isolated => "isolated",
        AgentMemoryMode::SharedRead => "shared_read",
        AgentMemoryMode::SharedReadWrite => "shared_read_write",
    }
}

pub(super) const fn transport(value: McpTransport) -> &'static str {
    match value {
        McpTransport::Stdio => "stdio",
        McpTransport::Http => "http",
    }
}

pub(super) const fn messaging(value: MessagingTopology) -> &'static str {
    match value {
        MessagingTopology::ParentMediated => "parent_mediated",
        MessagingTopology::Peer => "peer",
        MessagingTopology::Broadcast => "broadcast",
    }
}

pub(super) const fn oauth_mode(value: OAuthLifecycleMode) -> &'static str {
    match value {
        OAuthLifecycleMode::Disabled => "disabled",
        OAuthLifecycleMode::Bearer => "bearer",
        OAuthLifecycleMode::RefreshToken => "refresh_token",
        OAuthLifecycleMode::Mixed => "mixed",
    }
}

pub(super) const fn session_profile(value: SessionIsolationProfile) -> &'static str {
    match value {
        SessionIsolationProfile::Hermetic => "hermetic",
        SessionIsolationProfile::Durable => "durable",
        SessionIsolationProfile::Interactive => "interactive",
    }
}

pub(super) fn replay_policy(value: ReplayOwnerObservation) -> ResolutionValue {
    object([
        ("verify_hash_chain", boolv(value.verify_hash_chain)),
        ("verify_identity_scope", boolv(value.verify_identity_scope)),
        (
            "verify_effect_terminals",
            boolv(value.verify_effect_terminals),
        ),
        ("on_divergence", en("fail_closed")),
    ])
}

pub(super) fn upper(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), ExtensionFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::UpperBound { value },
    )?;
    Ok(())
}

pub(super) fn domain(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    allowed: impl IntoIterator<Item = ResolutionValue>,
) -> Result<(), ExtensionFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::Domain {
            minimum: None,
            maximum: None,
            allowed_values: Some(allowed.into_iter().collect::<BTreeSet<_>>()),
            required_values: None,
            preferred: None,
        },
    )?;
    Ok(())
}

pub(super) fn lower(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), ExtensionFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::Domain {
            minimum: Some(value),
            maximum: None,
            allowed_values: None,
            required_values: None,
            preferred: None,
        },
    )?;
    Ok(())
}

pub(super) fn exact(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), ExtensionFactError> {
    builder.constrain(family, field, ceiling, ConstraintValue::Exact { value })?;
    Ok(())
}

pub(super) fn i64u(value: usize, family: &'static str) -> Result<i64, ExtensionFactError> {
    i64::try_from(value).map_err(|_| ExtensionFactError::IntegerOverflow(family))
}

pub(super) fn i64v(value: u64, family: &'static str) -> Result<i64, ExtensionFactError> {
    i64::try_from(value).map_err(|_| ExtensionFactError::IntegerOverflow(family))
}

pub(super) fn owner_digest(
    domain: &'static str,
    value: &impl Serialize,
) -> Result<String, ExtensionFactError> {
    let encoded =
        serde_json::to_vec(&(domain, value)).map_err(|_| ExtensionFactError::EvidenceEncoding)?;
    Ok(hex::encode(Sha256::digest(encoded)))
}
