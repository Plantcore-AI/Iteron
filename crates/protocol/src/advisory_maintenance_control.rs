//! Thread-bound readonly access to the independent advisory journal; never a job mutation API.
use crate::advisory_maintenance::MaintenanceObservationV1;
use crate::{RunId, SessionId};
use serde::{Deserialize, Deserializer, Serialize, de};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MaintenanceReadV1 {
    Read {
        thread_id: SessionId,
        after_revision: u64,
        limit: u16,
    },
    Subscribe {
        thread_id: SessionId,
    },
}
impl MaintenanceReadV1 {
    pub fn thread_id(&self) -> &SessionId {
        match self {
            Self::Read { thread_id, .. } | Self::Subscribe { thread_id } => thread_id,
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        let id = &self.thread_id().0;
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err("invalid maintenance thread identity");
        }
        if let Self::Read { limit, .. } = self
            && !(1..=64).contains(limit)
        {
            return Err("maintenance snapshot limit must be 1..64");
        }
        Ok(())
    }
}
impl<'de> Deserialize<'de> for MaintenanceReadV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Read {
                thread_id: SessionId,
                #[serde(default)]
                after_revision: u64,
                #[serde(default = "default_limit")]
                limit: u16,
            },
            Subscribe {
                thread_id: SessionId,
            },
        }
        let value = match Wire::deserialize(deserializer)? {
            Wire::Read {
                thread_id,
                after_revision,
                limit,
            } => Self::Read {
                thread_id,
                after_revision,
                limit,
            },
            Wire::Subscribe { thread_id } => Self::Subscribe { thread_id },
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}
fn default_limit() -> u16 {
    64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceEventV1 {
    pub thread_id: SessionId,
    pub run_id: RunId,
    pub observation: MaintenanceObservationV1,
}
impl MaintenanceEventV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        MaintenanceReadV1::Subscribe {
            thread_id: self.thread_id.clone(),
        }
        .validate()?;
        let value = &self.observation;
        if self.run_id.0.is_empty()
            || self.run_id.0.len() > 200
            || self.run_id.0.chars().any(char::is_control)
            || value.version != 1
            || value.journal_revision == 0
            || value.jobs.len() > 64
            || !hash(&value.scope_sha256)
            || !hash(&value.journal_sha256)
            || value.jobs.iter().any(|job| {
                job.job_id.0 == 0
                    || job.last_revision == 0
                    || job.last_revision > value.journal_revision
                    || !hash(&job.input_sha256)
                    || job
                        .reason_code
                        .as_ref()
                        .is_some_and(|code| code.len() > 128 || code.chars().any(char::is_control))
            })
            || value
                .jobs
                .windows(2)
                .any(|pair| pair[0].job_id >= pair[1].job_id)
        {
            return Err("invalid bounded maintenance journal observation");
        }
        Ok(())
    }
}
fn hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceAvailabilityCodeV1 {
    Unavailable,
    ReconciliationNeeded,
    InvalidObservation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceAvailabilityV1 {
    pub thread_id: SessionId,
    pub run_id: RunId,
    pub code: MaintenanceAvailabilityCodeV1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory_maintenance::{
        MaintenanceEvidenceSourceV1, MaintenanceJobIdV1, MaintenanceJobV1, MaintenanceKindV1,
        MaintenanceStateV1,
    };
    fn event() -> MaintenanceEventV1 {
        MaintenanceEventV1 {
            thread_id: SessionId("session-r".into()),
            run_id: RunId("r".into()),
            observation: MaintenanceObservationV1 {
                version: 1,
                scope_sha256: format!("sha256:{}", "a".repeat(64)),
                journal_revision: 3,
                journal_sha256: format!("sha256:{}", "b".repeat(64)),
                evidence_source: MaintenanceEvidenceSourceV1::MaintenanceJournal,
                jobs: vec![MaintenanceJobV1 {
                    job_id: MaintenanceJobIdV1(1),
                    kind: MaintenanceKindV1::TokenCalibration,
                    turn: 0,
                    state: MaintenanceStateV1::ReconciliationNeeded,
                    input_sha256: format!("sha256:{}", "c".repeat(64)),
                    queued_unix_ms: 1,
                    started_unix_ms: Some(2),
                    finished_unix_ms: Some(3),
                    last_revision: 3,
                    reason_code: Some("cache_publication_unknown".into()),
                }],
                dropped_jobs: 0,
                omitted_jobs: 0,
            },
        }
    }
    #[test]
    fn readonly_control_cannot_mint_state_or_locator_and_bounds_latest_snapshot() {
        for wire in [
            r#"{"type":"read","thread_id":"s","limit":65}"#,
            r#"{"type":"read","thread_id":"s","limit":0}"#,
            r#"{"type":"subscribe","thread_id":"s","path":"/other/journal"}"#,
            r#"{"type":"read","thread_id":"s","state":"completed"}"#,
            r#"{"type":"read","thread_id":""}"#,
        ] {
            assert!(serde_json::from_str::<MaintenanceReadV1>(wire).is_err());
        }
        let command: MaintenanceReadV1 =
            serde_json::from_str(r#"{"type":"read","thread_id":"s"}"#).unwrap();
        assert!(matches!(
            command,
            MaintenanceReadV1::Read {
                limit: 64,
                after_revision: 0,
                ..
            }
        ));
    }
    #[test]
    fn journal_identity_bounds_and_unknown_state_remain_explicit() {
        let mut value = event();
        value.validate().unwrap();
        let encoded = serde_json::to_value(&value).unwrap();
        assert_eq!(
            encoded["observation"]["jobs"][0]["state"],
            "reconciliation_needed"
        );
        assert_eq!(encoded["observation"]["jobs"][0]["turn"], 0);
        value.observation.journal_sha256 = "b".repeat(64);
        assert!(value.validate().is_err());
        value = event();
        value.observation.jobs[0].last_revision = 4;
        assert!(value.validate().is_err());
        value = event();
        value.observation.jobs = vec![value.observation.jobs[0].clone(); 65];
        assert!(value.validate().is_err());
        let availability = MaintenanceAvailabilityV1 {
            thread_id: SessionId("s".into()),
            run_id: RunId("r".into()),
            code: MaintenanceAvailabilityCodeV1::ReconciliationNeeded,
        };
        let encoded = serde_json::to_value(availability).unwrap();
        assert!(encoded.get("journal_revision").is_none());
        assert!(encoded.get("jobs").is_none());
    }
}
