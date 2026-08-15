//! Exact identities for content-bearing fixed authorities.
//!
//! A catalog reference in a checkpoint is evidence of what the resolver selected, not evidence
//! that the process is about to use the same physical catalog. New production compositions keep
//! these families inactive. Production resume supplies no identities and therefore rejects a
//! historical effective entry before any consumer is admitted. The private test insertion below
//! exercises the equality gate without pretending that a live materializer is registered.

use iteron_tunables::{FixedAuthorityId, ResolutionValue, RuntimeBindingSpec, RuntimeGetterId};
use std::collections::BTreeMap;

const GOVERNED_CATALOG_FAMILIES: &[&str] = &[
    "builtin_prompt_corpus",
    "instruction_bundle",
    "memory_corpus",
    "skill_catalog",
    "provider_model_capability_catalog",
    "mcp_topology_tool_catalog",
    "tool_action_space",
    "rate_card_catalog",
    "router_lexicons",
    "web_search_backend_catalog",
    "failure_classification_taxonomy",
];

/// Fixed families whose executable policy is reconstructed solely from the immutable V2 value.
/// Every other non-content fixed family must be re-sampled from a sealed live owner on resume.
const CHECKPOINT_RECONSTRUCTED_FIXED_FAMILIES: &[&str] = &[
    "request_output_cap",
    "compaction_adaptive",
    "compaction_keep_recent",
    "token_estimator",
    "bm25",
    "skill_listing_budget",
    "max_consecutive_tool_errors",
    "verifier_timeout",
    "route_topology",
    "decomposition_profile",
    "fan_breadth",
    "admission",
    "writer_fan_turn_split",
    "wall_split",
    "worker_min_turns",
    "fan_concurrency",
    "subagent_effort_inheritance",
    "child_ceiling",
    "report_budget",
    "join_reduce",
    "environment_snapshot",
    "provider_connect_tls_timeout",
    "provider_request_total_deadline",
    "stream_idle_watchdog",
    "spawn_depth_control",
    "task_priority_scheduling",
    "per_server_startup_deadline",
    "per_tool_mcp_deadline",
    "http_pool_keepalive_idle_policy",
];

#[derive(Debug, Clone, Default)]
pub(crate) struct FixedArtifactReceipts {
    observed: BTreeMap<&'static str, ResolutionValue>,
}

/// Exact values re-sampled from fixed process owners during resume admission. A V2 entry cannot
/// populate this map; only the sealed owner adapters below may do so.
#[derive(Debug, Clone, Default)]
pub(crate) struct FixedAuthorityReceipts {
    observed: BTreeMap<&'static str, ResolutionValue>,
}

#[derive(Debug, Clone)]
pub(crate) struct FixedAuthoritySample {
    pub family: &'static str,
    pub authority: FixedAuthorityId,
    pub value: ResolutionValue,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum FixedArtifactError {
    #[error("fixed artifact `{0}` could not be materialized from its physical owner")]
    Materialization(&'static str),
    #[error("fixed authority group `{0}` could not be sampled from its physical owners")]
    AuthoritySampling(&'static str),
    #[error("live fixed-authority sample `{0}` is not registered for process revalidation")]
    UnexpectedAuthoritySample(&'static str),
    #[error("live fixed-authority sample `{0}` names the wrong authority")]
    WrongAuthoritySample(&'static str),
    #[error("live fixed-authority sample `{0}` was registered more than once")]
    DuplicateAuthoritySample(&'static str),
}

impl FixedArtifactReceipts {
    /// Sample the small set of fixed artifacts that have an actual in-process materializer.
    /// Configured content catalogs are intentionally absent until their private materializer
    /// supplies an exact identity; a checkpoint cannot insert itself into this receipt set.
    pub(crate) fn production() -> Result<Self, FixedArtifactError> {
        let mut receipts = Self::default();
        let taxonomy = super::provider_process_facts::failure_classification_catalog_value()
            .map_err(|_| FixedArtifactError::Materialization("failure_classification_taxonomy"))?;
        receipts
            .observed
            .insert("failure_classification_taxonomy", taxonomy);
        Ok(receipts)
    }

    pub(crate) fn matches(&self, family: &str, expected: &ResolutionValue) -> bool {
        self.observed.get(family) == Some(expected)
    }

    pub(crate) fn contains(&self, family: &str) -> bool {
        self.observed.contains_key(family)
    }

    #[cfg(test)]
    pub(crate) fn remove(&mut self, family: &str) {
        self.observed.remove(family);
    }

    #[cfg(test)]
    pub(crate) fn observe_checkpoint_value(
        &mut self,
        family: &'static str,
        value: ResolutionValue,
    ) {
        self.observed.insert(family, value);
    }
}

impl FixedAuthorityReceipts {
    pub(crate) fn production() -> Result<Self, FixedArtifactError> {
        let mut receipts = Self::default();
        receipts.observe(FixedAuthoritySample {
            family: "provider_discovery_account_probe_cache_policy",
            authority: FixedAuthorityId::ProviderDiscoveryBootstrap,
            value: provider_discovery_owner_value(),
        })?;
        for sample in super::core_facts::live_fixed_authority_samples() {
            receipts.observe(sample)?;
        }
        for sample in super::execution_facts::live_fixed_authority_samples()
            .map_err(|_| FixedArtifactError::AuthoritySampling("execution_facts"))?
        {
            receipts.observe(sample)?;
        }
        for sample in super::provider_process_facts::live_fixed_authority_samples()
            .map_err(|_| FixedArtifactError::AuthoritySampling("provider_process_facts"))?
        {
            receipts.observe(sample)?;
        }
        for sample in super::extension_facts::live_fixed_authority_samples() {
            receipts.observe(sample)?;
        }
        Ok(receipts)
    }

    pub(crate) fn observe(
        &mut self,
        sample: FixedAuthoritySample,
    ) -> Result<(), FixedArtifactError> {
        let Some(family) = iteron_tunables::families()
            .iter()
            .find(|family| family.id == sample.family)
        else {
            return Err(FixedArtifactError::UnexpectedAuthoritySample(sample.family));
        };
        // Adapters retain their exact live sample while a formerly fixed non-Pin family migrates
        // to the external profile plane. Effective families are validated by owner/getter
        // receipts instead, so the fixed receipt set intentionally ignores that legacy sample.
        if matches!(family.runtime_binding, RuntimeBindingSpec::Effective { .. }) {
            return Ok(());
        }
        let RuntimeBindingSpec::Fixed { authority, .. } = family.runtime_binding else {
            return Err(FixedArtifactError::UnexpectedAuthoritySample(sample.family));
        };
        if !requires_live_authority_resample(sample.family) {
            return Err(FixedArtifactError::UnexpectedAuthoritySample(sample.family));
        }
        if authority != sample.authority {
            return Err(FixedArtifactError::WrongAuthoritySample(sample.family));
        }
        if self.observed.contains_key(sample.family) {
            return Err(FixedArtifactError::DuplicateAuthoritySample(sample.family));
        }
        self.observed.insert(sample.family, sample.value);
        Ok(())
    }

    pub(crate) fn matches(&self, family: &str, expected: &ResolutionValue) -> bool {
        self.observed.get(family) == Some(expected)
    }

    pub(crate) fn contains(&self, family: &str) -> bool {
        self.observed.contains_key(family)
    }

    #[cfg(test)]
    pub(crate) fn remove(&mut self, family: &str) {
        self.observed.remove(family);
    }

    #[cfg(test)]
    pub(crate) fn replace_for_test(&mut self, family: &'static str, value: ResolutionValue) {
        self.observed.insert(family, value);
    }
}

pub(crate) fn requires_live_receipt(family: &str) -> bool {
    family == "operator_prompt_stream" || GOVERNED_CATALOG_FAMILIES.contains(&family)
}

pub(crate) fn requires_live_authority_resample(family: &str) -> bool {
    !requires_live_receipt(family) && !CHECKPOINT_RECONSTRUCTED_FIXED_FAMILIES.contains(&family)
}

/// Typed checkpoint decoder that reconstructs each context-dependent fixed policy. This is not a
/// runtime getter in registry metadata: it is a bounded consumer receipt used only for the B
/// class, whose physical value is defined by the immutable checkpoint rather than a process-wide
/// singleton.
pub(crate) fn checkpoint_fixed_consumer(family: &str) -> Option<RuntimeGetterId> {
    match family {
        "request_output_cap"
        | "compaction_adaptive"
        | "compaction_keep_recent"
        | "token_estimator"
        | "bm25"
        | "skill_listing_budget"
        | "max_consecutive_tool_errors"
        | "verifier_timeout" => Some(RuntimeGetterId::EffectiveCore),
        "route_topology"
        | "decomposition_profile"
        | "fan_breadth"
        | "admission"
        | "writer_fan_turn_split"
        | "wall_split"
        | "fan_concurrency"
        | "worker_min_turns"
        | "subagent_effort_inheritance"
        | "child_ceiling"
        | "report_budget"
        | "join_reduce"
        | "spawn_depth_control"
        | "task_priority_scheduling" => Some(RuntimeGetterId::EffectiveExecution),
        "provider_connect_tls_timeout"
        | "provider_request_total_deadline"
        | "stream_idle_watchdog"
        | "http_pool_keepalive_idle_policy" => Some(RuntimeGetterId::EffectiveProvider),
        "per_server_startup_deadline" | "per_tool_mcp_deadline" => {
            Some(RuntimeGetterId::EffectiveMcp)
        }
        "environment_snapshot" => Some(RuntimeGetterId::EffectiveContent),
        _ => None,
    }
}

pub(crate) fn configured_absence_reason(value: &serde_json::Value) -> bool {
    value
        == &serde_json::json!({
            "type": "activation",
            "reason": "configuration_absent"
        })
}

/// Re-sample the actual bootstrap cache owner.  Family 70 is fixed-hidden because discovery must
/// run before the general resolver, but its V2 value still has to equal the policy that performed
/// that bootstrap work; object shape alone is not evidence of equality.
pub(crate) fn provider_discovery_owner_value() -> ResolutionValue {
    let owner = crate::providers::ProviderDiscoveryPolicy::owner();
    ResolutionValue::Object {
        fields: [
            (
                "eager_budget_milliseconds".to_owned(),
                ResolutionValue::Integer {
                    value: owner.eager_budget_milliseconds() as i64,
                },
            ),
            (
                "positive_ttl_seconds".to_owned(),
                ResolutionValue::Integer {
                    value: owner.positive_ttl_seconds() as i64,
                },
            ),
            (
                "failure_backoff_base_seconds".to_owned(),
                ResolutionValue::Integer {
                    value: owner.failure_backoff_base_seconds() as i64,
                },
            ),
            (
                "failure_backoff_cap_seconds".to_owned(),
                ResolutionValue::Integer {
                    value: owner.failure_backoff_cap_seconds() as i64,
                },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_authority_classes_are_closed_and_checkpoint_consumers_are_bijective() {
        let fixed = iteron_tunables::families()
            .iter()
            .filter(|family| matches!(family.runtime_binding, RuntimeBindingSpec::Fixed { .. }))
            .collect::<Vec<_>>();
        assert_eq!(fixed.len(), 23, "the closed FixedHidden inventory drifted");
        for family in fixed {
            let checkpoint = CHECKPOINT_RECONSTRUCTED_FIXED_FAMILIES.contains(&family.id);
            let content = requires_live_receipt(family.id);
            let live = requires_live_authority_resample(family.id);
            assert_eq!(
                usize::from(checkpoint) + usize::from(content) + usize::from(live),
                1,
                "{} must belong to exactly one fixed-authority class",
                family.id
            );
            assert_eq!(
                checkpoint_fixed_consumer(family.id).is_some(),
                checkpoint,
                "{} checkpoint classification and consumer registry disagree",
                family.id
            );
        }
    }

    #[test]
    fn live_receipt_registry_rejects_wrong_duplicate_and_checkpoint_samples() {
        let mut receipts = FixedAuthorityReceipts::default();
        receipts
            .observe(FixedAuthoritySample {
                family: "provider_discovery_account_probe_cache_policy",
                authority: FixedAuthorityId::ProviderDiscoveryBootstrap,
                value: provider_discovery_owner_value(),
            })
            .expect("registered live owner sample");
        assert!(matches!(
            receipts.observe(FixedAuthoritySample {
                family: "provider_discovery_account_probe_cache_policy",
                authority: FixedAuthorityId::ProviderDiscoveryBootstrap,
                value: provider_discovery_owner_value(),
            }),
            Err(FixedArtifactError::DuplicateAuthoritySample(
                "provider_discovery_account_probe_cache_policy"
            ))
        ));

        let mut wrong = FixedAuthorityReceipts::default();
        assert!(matches!(
            wrong.observe(FixedAuthoritySample {
                family: "provider_discovery_account_probe_cache_policy",
                authority: FixedAuthorityId::RuntimeInvariant,
                value: provider_discovery_owner_value(),
            }),
            Err(FixedArtifactError::WrongAuthoritySample(
                "provider_discovery_account_probe_cache_policy"
            ))
        ));
        assert!(matches!(
            wrong.observe(FixedAuthoritySample {
                family: "join_reduce",
                authority: FixedAuthorityId::RuntimeInvariant,
                value: ResolutionValue::Integer { value: 1 },
            }),
            Err(FixedArtifactError::UnexpectedAuthoritySample("join_reduce"))
        ));
    }
}
