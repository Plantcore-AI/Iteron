//! Trusted retry-policy resolution for the CLI composition root.
//!
//! A repository config is parsed strictly but cannot increase, decrease, or otherwise steer paid
//! provider retries. Only numeric environment overrides and the operator-owned user config enter
//! the effective policy. This module contains no credential-shaped fields.

use iteron_sched::BackoffPolicy;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;

const MAX_RETRY_BASE_MS: u64 = 30_000;
const MAX_RETRY_CAP_MS: u64 = 60_000;
const MAX_RETRY_ATTEMPTS: u32 = 10;

const ENV_BASE_MS: &str = "ITERON_RETRY_BASE_MS";
const ENV_CAP_MS: &str = "ITERON_RETRY_CAP_MS";
const ENV_MAX_ATTEMPTS: &str = "ITERON_RETRY_MAX_ATTEMPTS";

/// Optional per-field overlay on [`BackoffPolicy`]. `max_attempts` includes the first request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct RetryConfig {
    pub(crate) base_ms: Option<u64>,
    pub(crate) cap_ms: Option<u64>,
    pub(crate) max_attempts: Option<u32>,
}

impl RetryConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_policy(self.apply(BackoffPolicy::default()))
    }

    fn apply(self, mut policy: BackoffPolicy) -> BackoffPolicy {
        if let Some(base_ms) = self.base_ms {
            policy.base_ms = base_ms;
        }
        if let Some(cap_ms) = self.cap_ms {
            policy.cap_ms = cap_ms;
        }
        if let Some(max_attempts) = self.max_attempts {
            policy.max_attempts = max_attempts;
        }
        policy
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.base_ms.is_none() && self.cap_ms.is_none() && self.max_attempts.is_none()
    }
}

/// Result of trust-aware policy resolution. Project presence is surfaced so the CLI can explain
/// that the repository value was ignored instead of silently pretending it took effect.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RetryResolution {
    pub(crate) policy: BackoffPolicy,
    pub(crate) project_ignored: bool,
    pub(crate) trusted_override_present: bool,
}

/// Resolve `environment > trusted user config > built-in`, ignoring repository policy by design.
pub(crate) fn resolve_retry_policy(
    environment: RetryConfig,
    trusted_user: Option<&RetryConfig>,
    untrusted_project: Option<&RetryConfig>,
) -> Result<RetryResolution, String> {
    let user = trusted_user.copied().unwrap_or_default();
    let policy = environment.apply(user.apply(BackoffPolicy::default()));
    validate_policy(policy)?;
    Ok(RetryResolution {
        policy,
        project_ignored: untrusted_project.is_some_and(|retry| !retry.is_empty()),
        trusted_override_present: !environment.is_empty() || !user.is_empty(),
    })
}

pub(crate) fn load_retry_environment() -> Result<RetryConfig, String> {
    retry_environment_from(|key| std::env::var_os(key))
}

fn retry_environment_from(
    mut get: impl FnMut(&str) -> Option<OsString>,
) -> Result<RetryConfig, String> {
    Ok(RetryConfig {
        base_ms: parse_numeric_env(ENV_BASE_MS, get(ENV_BASE_MS))?,
        cap_ms: parse_numeric_env(ENV_CAP_MS, get(ENV_CAP_MS))?,
        max_attempts: parse_numeric_env(ENV_MAX_ATTEMPTS, get(ENV_MAX_ATTEMPTS))?,
    })
}

fn parse_numeric_env<T>(key: &str, value: Option<OsString>) -> Result<Option<T>, String>
where
    T: std::str::FromStr,
{
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| format!("{key} must be valid Unicode decimal digits"))?;
    value
        .parse()
        .map(Some)
        .map_err(|_| format!("{key} must be a base-10 non-negative integer"))
}

fn validate_policy(policy: BackoffPolicy) -> Result<(), String> {
    if !(1..=MAX_RETRY_BASE_MS).contains(&policy.base_ms) {
        return Err(format!(
            "retry.base_ms must be in 1..={MAX_RETRY_BASE_MS}, got {}",
            policy.base_ms
        ));
    }
    if !(policy.base_ms..=MAX_RETRY_CAP_MS).contains(&policy.cap_ms) {
        return Err(format!(
            "retry.cap_ms must be in base_ms..={MAX_RETRY_CAP_MS}, got {} with base_ms {}",
            policy.cap_ms, policy.base_ms
        ));
    }
    if !(1..=MAX_RETRY_ATTEMPTS).contains(&policy.max_attempts) {
        return Err(format!(
            "retry.max_attempts must be in 1..={MAX_RETRY_ATTEMPTS}, got {}",
            policy.max_attempts
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileConfig;
    use async_trait::async_trait;
    use iteron_protocol::{ReasoningEffort, StopReason};
    use iteron_provider::{
        AccountAvailability, AdapterKind, ApiResponseError, AvailabilityTransition, ErrorProfile,
        ErrorScope, NormalizedFailure, Provider, ProviderError, RetryDisposition, StreamItem,
        TurnRequest, TurnResult, UsageReport,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    #[test]
    fn defaults_bounds_and_trust_precedence_are_preserved() {
        let defaults = resolve_retry_policy(RetryConfig::default(), None, None).unwrap();
        assert_eq!(defaults.policy.base_ms, 500);
        assert_eq!(defaults.policy.cap_ms, 30_000);
        assert_eq!(defaults.policy.max_attempts, 6);

        let project = RetryConfig {
            base_ms: Some(1),
            cap_ms: Some(1),
            max_attempts: Some(1),
        };
        let user = RetryConfig {
            base_ms: Some(25),
            cap_ms: Some(100),
            max_attempts: Some(4),
        };
        let environment = RetryConfig {
            cap_ms: Some(40),
            ..RetryConfig::default()
        };
        let resolved = resolve_retry_policy(environment, Some(&user), Some(&project)).unwrap();
        assert_eq!(resolved.policy.base_ms, 25);
        assert_eq!(resolved.policy.cap_ms, 40);
        assert_eq!(resolved.policy.max_attempts, 4);
        assert!(resolved.project_ignored);
        assert!(resolved.trusted_override_present);

        for invalid in [
            RetryConfig {
                base_ms: Some(0),
                ..RetryConfig::default()
            },
            RetryConfig {
                base_ms: Some(1_000),
                cap_ms: Some(999),
                ..RetryConfig::default()
            },
            RetryConfig {
                max_attempts: Some(11),
                ..RetryConfig::default()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }

    #[test]
    fn numeric_environment_is_strict_and_layered() {
        let values = BTreeMap::from([
            (ENV_BASE_MS, OsString::from("20")),
            (ENV_CAP_MS, OsString::from("80")),
            (ENV_MAX_ATTEMPTS, OsString::from("3")),
        ]);
        let parsed = retry_environment_from(|key| values.get(key).cloned()).unwrap();
        assert_eq!(parsed.base_ms, Some(20));
        assert_eq!(parsed.cap_ms, Some(80));
        assert_eq!(parsed.max_attempts, Some(3));

        let error =
            retry_environment_from(|key| (key == ENV_MAX_ATTEMPTS).then(|| OsString::from("many")))
                .unwrap_err();
        assert!(error.contains(ENV_MAX_ATTEMPTS));
    }

    #[test]
    fn retry_schema_has_no_credential_surface() {
        let error =
            FileConfig::parse(r#"{"schema_version":2,"retry":{"base_ms":20,"api_key":null}}"#)
                .expect_err("credential-shaped fields must stay outside retry policy");
        assert!(error.to_string().contains("unknown field `api_key`"));
    }

    struct HintedFailures {
        calls: Arc<AtomicU32>,
    }

    #[async_trait]
    impl Provider for HintedFailures {
        async fn turn(
            &self,
            _request: &TurnRequest,
            _on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            let attempt = self.calls.fetch_add(1, Ordering::SeqCst);
            if attempt >= 2 {
                return Ok(TurnResult {
                    blocks: Vec::new(),
                    stop_reason: StopReason::EndTurn,
                    usage: UsageReport::complete(Default::default()),
                });
            }
            let hint = if attempt == 0 { 25 } else { 40 };
            Err(ProviderError::ApiResponse(ApiResponseError {
                status: 429,
                body: "fixture rate limit".into(),
                body_truncated: false,
                retry_after: Some(Duration::from_millis(hint)),
                normalized: Box::new(NormalizedFailure {
                    adapter: AdapterKind::OpenAiCompatibleChat,
                    error_profile: ErrorProfile::OpenAi,
                    code: Some("rate_limit_error".into()),
                    public_message: "provider rate limit reached",
                    scope: ErrorScope::Account,
                    availability: AvailabilityTransition::Account(AccountAvailability::RateLimited),
                    retry: RetryDisposition::Transient,
                    request_id: None,
                }),
            }))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn d2_19_configured_policy_reaches_retry_provider_and_drives_exact_schedule() {
        let trusted = FileConfig::parse(
            r#"{"schema_version":2,"retry":{"base_ms":25,"cap_ms":40,"max_attempts":3}}"#,
        )
        .expect("trusted user config should parse");
        let policy = resolve_retry_policy(RetryConfig::default(), trusted.retry.as_ref(), None)
            .unwrap()
            .policy;
        assert_eq!(policy.base_ms, 25);
        assert_eq!(policy.cap_ms, 40);
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(
            iteron_sched::full_jitter(&policy, 0, 1.0),
            Duration::from_millis(25),
            "the configured base must reach the scheduler's first backoff ceiling"
        );
        assert_eq!(
            iteron_sched::full_jitter(&policy, 1, 1.0),
            Duration::from_millis(40),
            "the configured exponential base must then clamp at the configured cap"
        );
        let calls = Arc::new(AtomicU32::new(0));
        let provider = iteron_sched::RetryProvider::new(
            Box::new(HintedFailures {
                calls: Arc::clone(&calls),
            }),
            policy,
        );
        let task = tokio::spawn(async move {
            let request = TurnRequest {
                model: "fixture".into(),
                system: "system".into(),
                messages: Vec::new(),
                input_images: Vec::new(),
                tools: Vec::new(),
                max_tokens: 16,
                cache_system: false,
                thinking_budget: 0,
                reasoning_effort: ReasoningEffort::Low,
            };
            provider.turn(&request, &mut |_| {}).await
        });

        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(24)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_millis(39)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(task.await.unwrap().is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
