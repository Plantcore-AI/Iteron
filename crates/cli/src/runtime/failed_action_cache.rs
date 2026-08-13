//! Bounded run-scoped memory for exact failed-effect deduplication.
//!
//! The previous `HashMap<String, String>` retained arbitrary tool-input and error bytes for the
//! whole run. Besides making the `failed_action_dedup` tunable untrue, a long-running agent could
//! grow it without a ceiling. Keys are now fixed-size content digests and values are bounded error
//! tails; FIFO eviction is deterministic and affects only the optional short-circuit optimization.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};

pub(crate) const MAX_IDENTITIES: usize = 4_096;
const MAX_PRIOR_ERROR_BYTES: usize = 4 * 1_024;

#[derive(Debug, Default)]
pub(crate) struct FailedActionCache {
    entries: HashMap<[u8; 32], String>,
    order: VecDeque<[u8; 32]>,
}

impl FailedActionCache {
    pub(crate) fn get(&self, signature: &str) -> Option<&String> {
        self.entries.get(&digest(signature))
    }

    pub(crate) fn contains_key(&self, signature: &str) -> bool {
        self.entries.contains_key(&digest(signature))
    }

    pub(crate) fn insert(&mut self, signature: String, error: String) -> Option<String> {
        let key = digest(&signature);
        let error = bounded_tail(
            &error,
            iteron_tunables::param_integer(
                "cli.runtime.failed_action_cache.max_prior_error_bytes",
                MAX_PRIOR_ERROR_BYTES,
            ),
        );
        if let Some(existing) = self.entries.get_mut(&key) {
            return Some(std::mem::replace(existing, error));
        }
        if self.entries.len()
            == iteron_tunables::param_integer(
                "cli.runtime.failed_action_cache.max_identities",
                MAX_IDENTITIES,
            )
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        self.order.push_back(key);
        self.entries.insert(key, error)
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Exact production value supplied to the trusted tunables composition root.
    pub(crate) fn tunable_value() -> iteron_tunables::ResolutionValue {
        iteron_tunables::ResolutionValue::Object {
            fields: std::collections::BTreeMap::from([
                (
                    "failed_only".to_owned(),
                    iteron_tunables::ResolutionValue::Boolean { value: true },
                ),
                (
                    "max_identities".to_owned(),
                    iteron_tunables::ResolutionValue::Integer {
                        value: iteron_tunables::param_integer(
                            "cli.runtime.failed_action_cache.max_identities",
                            MAX_IDENTITIES,
                        ) as i64,
                    },
                ),
                (
                    "scope".to_owned(),
                    iteron_tunables::ResolutionValue::Enum {
                        value: "run".to_owned(),
                    },
                ),
            ]),
        }
    }
}

fn digest(signature: &str) -> [u8; 32] {
    Sha256::digest(signature.as_bytes()).into()
}

fn bounded_tail(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    const MARKER: &str = "… (truncated)\n";
    let retained = max_bytes.saturating_sub(MARKER.len());
    let mut start = value.len().saturating_sub(retained);
    while start < value.len() && !value.is_char_boundary(start) {
        start += 1;
    }
    format!("{MARKER}{}", &value[start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_is_bounded_and_fifo() {
        let mut cache = FailedActionCache::default();
        for index in 0..=MAX_IDENTITIES {
            cache.insert(format!("tool::{index}"), format!("error-{index}"));
        }
        assert_eq!(cache.entries.len(), MAX_IDENTITIES);
        assert!(cache.get("tool::0").is_none());
        assert_eq!(cache.get("tool::1").map(String::as_str), Some("error-1"));
    }

    #[test]
    fn retained_error_and_tunable_projection_are_exactly_bounded() {
        let mut cache = FailedActionCache::default();
        cache.insert("tool::input".into(), "x".repeat(MAX_PRIOR_ERROR_BYTES + 1));
        assert_eq!(
            cache.get("tool::input").map(String::len),
            Some(MAX_PRIOR_ERROR_BYTES)
        );
        let iteron_tunables::ResolutionValue::Object { fields } =
            FailedActionCache::tunable_value()
        else {
            panic!("policy must be an object");
        };
        assert_eq!(
            fields.get("max_identities"),
            Some(&iteron_tunables::ResolutionValue::Integer {
                value: MAX_IDENTITIES as i64
            })
        );
    }
}
