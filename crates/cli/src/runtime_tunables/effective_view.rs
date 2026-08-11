//! Version-neutral runtime projection of one immutable tunables truth.

use iteron_record::TunablesCheckpoint;
use iteron_tunables::{EntryOutcome, ResolutionValue, ResolvedTunableSet};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(crate) struct EffectiveTunablesView {
    effective_digest_sha256: String,
    profile_digest_sha256: Option<String>,
    values: BTreeMap<String, ResolutionValue>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum EffectiveViewError {
    #[error("historical V1 tunables checkpoints contain identity only and cannot drive runtime")]
    HistoricalIdentityOnly,
    #[error("effective tunables contain a duplicate family `{0}`")]
    DuplicateFamily(String),
    #[error("effective tunable `{0}` is absent or inactive")]
    NotEffective(String),
    #[error("effective tunable `{family}` has the wrong type; expected {expected}")]
    WrongType {
        family: String,
        expected: &'static str,
    },
    #[error("effective tunable `{0}` could not be decoded from its immutable checkpoint")]
    Decode(String),
    #[error("immutable tunables checkpoint has no recognized named runtime profile")]
    UnknownProfile,
}

impl EffectiveTunablesView {
    pub(crate) fn from_resolved(resolved: &ResolvedTunableSet) -> Result<Self, EffectiveViewError> {
        let mut values = BTreeMap::new();
        for entry in &resolved.report().entries {
            if !matches!(entry.outcome, EntryOutcome::Effective) {
                continue;
            }
            let value = entry
                .effective
                .clone()
                .ok_or_else(|| EffectiveViewError::NotEffective(entry.family_id.to_owned()))?;
            if values.insert(entry.family_id.to_owned(), value).is_some() {
                return Err(EffectiveViewError::DuplicateFamily(
                    entry.family_id.to_owned(),
                ));
            }
        }
        Ok(Self {
            effective_digest_sha256: resolved.report().effective_digest_sha256.clone(),
            profile_digest_sha256: resolved.report().profile_digest_sha256.clone(),
            values,
        })
    }

    pub(crate) fn from_checkpoint(
        checkpoint: &TunablesCheckpoint,
    ) -> Result<Self, EffectiveViewError> {
        let TunablesCheckpoint::V2(snapshot) = checkpoint else {
            return Err(EffectiveViewError::HistoricalIdentityOnly);
        };
        iteron_record::validate_tunables_snapshot_v2(snapshot)
            .map_err(|_| EffectiveViewError::Decode("checkpoint".into()))?;
        let mut values = BTreeMap::new();
        for entry in &snapshot.entries {
            let Some(encoded) = &entry.effective_value else {
                continue;
            };
            let value = serde_json::from_value(encoded.clone())
                .map_err(|_| EffectiveViewError::Decode(entry.family_id.clone()))?;
            if values.insert(entry.family_id.clone(), value).is_some() {
                return Err(EffectiveViewError::DuplicateFamily(entry.family_id.clone()));
            }
        }
        Ok(Self {
            effective_digest_sha256: snapshot.effective_digest_sha256.clone(),
            profile_digest_sha256: snapshot.profile_digest_sha256.clone(),
            values,
        })
    }

    pub(crate) fn effective_digest_sha256(&self) -> &str {
        &self.effective_digest_sha256
    }

    pub(crate) fn runtime_profile(
        &self,
    ) -> Result<iteron_tunables::RuntimeProfile, EffectiveViewError> {
        let digest = self
            .profile_digest_sha256
            .as_deref()
            .ok_or(EffectiveViewError::UnknownProfile)?;
        for profile in iteron_tunables::RuntimeProfile::ALL {
            let candidate = iteron_tunables::runtime_profile_digest(profile)
                .map_err(|_| EffectiveViewError::Decode("runtime_profile".into()))?;
            if candidate == digest {
                return Ok(profile);
            }
        }
        Err(EffectiveViewError::UnknownProfile)
    }

    pub(crate) fn value(&self, family: &str) -> Result<&ResolutionValue, EffectiveViewError> {
        self.values
            .get(family)
            .ok_or_else(|| EffectiveViewError::NotEffective(family.to_owned()))
    }

    pub(crate) fn optional_value(&self, family: &str) -> Option<&ResolutionValue> {
        self.values.get(family)
    }

    pub(crate) fn boolean(&self, family: &str) -> Result<bool, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Boolean { value } => Ok(*value),
            _ => Err(wrong_type(family, "boolean")),
        }
    }

    pub(crate) fn integer(&self, family: &str) -> Result<i64, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Integer { value } => Ok(*value),
            _ => Err(wrong_type(family, "integer")),
        }
    }

    pub(crate) fn decimal(
        &self,
        family: &str,
    ) -> Result<iteron_tunables::DecimalValue, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Decimal { value } => Ok(*value),
            _ => Err(wrong_type(family, "decimal")),
        }
    }

    pub(crate) fn text(&self, family: &str) -> Result<&str, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Text { value } => Ok(value),
            _ => Err(wrong_type(family, "text")),
        }
    }

    pub(crate) fn enumeration(&self, family: &str) -> Result<&str, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Enum { value } => Ok(value),
            _ => Err(wrong_type(family, "enum")),
        }
    }

    pub(crate) fn object(
        &self,
        family: &str,
    ) -> Result<&BTreeMap<String, ResolutionValue>, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Object { fields } => Ok(fields),
            _ => Err(wrong_type(family, "object")),
        }
    }

    pub(crate) fn map(
        &self,
        family: &str,
    ) -> Result<&BTreeMap<String, ResolutionValue>, EffectiveViewError> {
        match self.value(family)? {
            ResolutionValue::Map { entries } => Ok(entries),
            _ => Err(wrong_type(family, "map")),
        }
    }
}

fn wrong_type(family: &str, expected: &'static str) -> EffectiveViewError {
    EffectiveViewError::WrongType {
        family: family.to_owned(),
        expected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{RunGenesisTunablesSnapshot, RunGenesisTunablesVersion};

    #[test]
    fn v1_identity_is_never_misrepresented_as_runtime_values() {
        let checkpoint = TunablesCheckpoint::V1(RunGenesisTunablesSnapshot {
            version: RunGenesisTunablesVersion::V1,
            canonicalization: "fixture".into(),
            resolution_schema_version: 1,
            registry_id: "fixture".into(),
            registry_schema_version: 1,
            family_schema_version: 1,
            registry_revision: 1,
            registry_digest_sha256: "a".repeat(64),
            input_digest_sha256: "b".repeat(64),
            effective_digest_sha256: "c".repeat(64),
            resolution_digest_sha256: "d".repeat(64),
            profile_digest_sha256: None,
            entries: Vec::new(),
            snapshot_digest_sha256: "e".repeat(64),
        });
        assert_eq!(
            EffectiveTunablesView::from_checkpoint(&checkpoint).unwrap_err(),
            EffectiveViewError::HistoricalIdentityOnly
        );
    }
}
