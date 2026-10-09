//! Route-scoped policy disclosures. These describe source declarations, not enforced guarantees.
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataPolicyDeclaration {
    #[serde(default)]
    pub retention: DataRetention,
    #[serde(default)]
    pub training_use: DataTrainingUse,
    #[serde(default)]
    pub processing: DataProcessing,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DataRetention {
    #[default]
    #[serde(deserialize_with = "deserialize_empty_declaration")]
    Unknown,
    #[serde(deserialize_with = "deserialize_empty_declaration")]
    NoRetention,
    Days {
        maximum_days: NonZeroU16,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataTrainingUse {
    #[default]
    Unknown,
    NotUsed,
    MayBeUsed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DataProcessing {
    #[default]
    #[serde(deserialize_with = "deserialize_empty_declaration")]
    Unknown,
    #[serde(deserialize_with = "deserialize_empty_declaration")]
    Global,
    Regional {
        jurisdictions: Vec<String>,
    },
}

fn deserialize_empty_declaration<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Internally tagged unit variants otherwise discard their residual map. Keep the public
    // unit shape while refusing aspirational guarantees or misspelled policy fields.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    Empty::deserialize(deserializer).map(|_| ())
}

impl DataPolicyDeclaration {
    /// Jurisdiction identifiers are bounded source declarations, not inferred country facts.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let DataProcessing::Regional { jurisdictions } = &self.processing {
            if jurisdictions.is_empty() || jurisdictions.len() > 32 {
                return Err("data-policy regional declaration exceeds its cardinality bound");
            }
            let mut seen = std::collections::BTreeSet::new();
            for jurisdiction in jurisdictions {
                if jurisdiction.len() != 2
                    || !jurisdiction.bytes().all(|byte| byte.is_ascii_uppercase())
                    || !seen.insert(jurisdiction)
                {
                    return Err("data-policy jurisdiction must be a unique two-letter identifier");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataPolicyProvenance {
    OperatorDeclaration,
    MetadataSnapshot,
}

/// The host captures this with one exact route. It never grants a permission or changes wire IO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DataPolicyObservation {
    pub declaration: DataPolicyDeclaration,
    pub provenance: DataPolicyProvenance,
    pub version: String,
    pub source: String,
    pub captured_at_unix_secs: Option<u64>,
}
