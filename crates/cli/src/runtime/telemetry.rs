//! The telemetry export sink (#105): the one place the projection leaves this process.
//!
//! # Trust-by-origin, same rule as hooks
//!
//! The endpoint is honoured ONLY from the operator's USER config (`~/.iteron/config.json`), never
//! from a project `.iteron/config.json` that could arrive with a cloned repo. An endpoint is an
//! exfiltration target: a repository that could set one could ship every tool name, error string
//! and span in the run to a host of its choosing. Same discipline as skills, memory, agents and
//! hooks (ADR-007 §6), and for a strictly worse threat.
//!
//! # Off by default, and the default costs nothing
//!
//! With no `otel` block there is no config, no effect, no allocation and no branch taken past the
//! first `is_none()`. "Off" must mean the run is byte-identical to a run in a build without this
//! module, or the exporter has already changed the thing it claims to observe.
//!
//! # Why the egress crosses the broker
//!
//! `docs/spec/capability-mapping.md` is explicit that telemetry *evidence* is kernel-owned but the
//! *export* is a network effect and MUST be a class-C world module crossing `EffectProposal`. That
//! is not ceremony. It means a run with the exporter on still has a complete effect journal, a
//! stalled collector is bounded and reaped like any other effect, and a crash mid-POST leaves an
//! `EffectUnknown` that recovery refuses to replay rather than a silently duplicated payload.

mod otlp;

use serde::Deserialize;
#[cfg(test)]
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Wall-clock ceiling for one export. Bounded like every other effect (invariant #1): a collector
/// that accepts the connection and then stops reading must not be able to hold a run open.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// The `otel` block of the USER config.
#[cfg(test)]
#[derive(Debug, Clone, Default, Deserialize)]
struct TelemetryFile {
    #[serde(default)]
    otel: Option<TelemetryBlock>,
}

#[derive(Debug, Clone, Deserialize)]
struct TelemetryBlock {
    /// Absent or false means off. Requiring the operator to write `true` — rather than inferring
    /// intent from the presence of an endpoint — keeps a half-edited config from starting to ship
    /// spans off the machine.
    #[serde(default)]
    enabled: bool,
    endpoint: String,
}

/// A resolved, operator-authorised export target.
#[derive(Debug, Clone)]
pub struct TelemetrySink {
    endpoint: String,
    health: TelemetryHealth,
}

impl PartialEq for TelemetrySink {
    fn eq(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint
    }
}

impl Eq for TelemetrySink {}

#[derive(Debug, Clone, Default)]
pub struct TelemetryHealth {
    inner: Arc<TelemetryHealthInner>,
}

#[derive(Debug, Default)]
struct TelemetryHealthInner {
    attempts: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    unknown: AtomicU64,
    last_outcome: Mutex<Option<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct TelemetryHealthSnapshot {
    pub attempts: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub unknown: u64,
    pub last_outcome: Option<String>,
}

impl TelemetryHealth {
    pub fn snapshot(&self) -> TelemetryHealthSnapshot {
        TelemetryHealthSnapshot {
            attempts: self.inner.attempts.load(Ordering::Relaxed),
            accepted: self.inner.accepted.load(Ordering::Relaxed),
            rejected: self.inner.rejected.load(Ordering::Relaxed),
            unknown: self.inner.unknown.load(Ordering::Relaxed),
            last_outcome: self
                .inner
                .last_outcome
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        }
    }

    fn record(&self, outcome: &TelemetrySendOutcome) {
        self.inner.attempts.fetch_add(1, Ordering::Relaxed);
        let code = match outcome {
            TelemetrySendOutcome::Accepted => {
                self.inner.accepted.fetch_add(1, Ordering::Relaxed);
                "accepted".to_owned()
            }
            TelemetrySendOutcome::Rejected(reason) => {
                self.inner.rejected.fetch_add(1, Ordering::Relaxed);
                reason.clone()
            }
            TelemetrySendOutcome::Unknown => {
                self.inner.unknown.fetch_add(1, Ordering::Relaxed);
                "unknown".to_owned()
            }
        };
        *self
            .inner
            .last_outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(code);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TelemetrySendOutcome {
    Accepted,
    Rejected(String),
    Unknown,
}

impl TelemetrySink {
    /// Resolve telemetry from the immutable operator config snapshot parsed by the composition
    /// root. The `otel` value is deserialized into its closed typed block here; no file IO or
    /// second top-level config parse occurs on the launch path.
    pub(crate) fn from_user_config(value: Option<&serde_json::Value>) -> Option<TelemetrySink> {
        let block = serde_json::from_value::<TelemetryBlock>(value?.clone()).ok()?;
        Self::from_block(block)
    }

    /// Load from the USER config only. A missing or malformed file yields no sink: telemetry is
    /// opt-in, and a broken config must not brick the agent for a feature nobody asked for.
    #[cfg(test)]
    pub fn load_user(home: &Path) -> Option<TelemetrySink> {
        let path = iteron_protocol::home::path(home, "config.json");
        let block = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<TelemetryFile>(&text).ok())
            .and_then(|file| file.otel)?;
        Self::from_block(block)
    }

    fn from_block(block: TelemetryBlock) -> Option<TelemetrySink> {
        if !block.enabled || block.endpoint.trim().is_empty() {
            return None;
        }
        let endpoint = url::Url::parse(block.endpoint.trim()).ok()?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return None;
        }
        Some(TelemetrySink {
            endpoint: endpoint.to_string(),
            health: TelemetryHealth::default(),
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn health(&self) -> TelemetryHealth {
        self.health.clone()
    }

    /// POST one payload. Returns the collector's status line on a proven outcome, or `None` when
    /// no terminal could be observed — which the caller journals as `EffectUnknown` rather than
    /// retrying, because a retried export duplicates spans and a duplicated span is a wrong
    /// dashboard.
    pub async fn send(&self, payload: &iteron_obs::otel::Export) -> TelemetrySendOutcome {
        let outcome = self.send_inner(payload).await;
        self.health.record(&outcome);
        outcome
    }

    async fn send_inner(&self, payload: &iteron_obs::otel::Export) -> TelemetrySendOutcome {
        // The mandated secure client construction, shared with the provider adapters: connect
        // timeout applied and redirects refused, because an endpoint-chosen redirect must not be
        // able to replay the payload at a host the operator never authorised.
        let Ok(client) = iteron_provider::catalog::HttpTransport::client(
            &iteron_provider::catalog::DefaultHttpTransport,
            iteron_provider::provider_transport_timeout_policy(),
        ) else {
            return TelemetrySendOutcome::Rejected("client_initialization_failed".into());
        };
        let Ok(batches) = otlp::encode(&self.endpoint, payload) else {
            return TelemetrySendOutcome::Rejected("payload_encoding_failed".into());
        };
        let dispatch = async {
            for batch in batches {
                let response = match client
                    .post(batch.endpoint)
                    .header("content-type", "application/json")
                    .body(batch.body)
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => return TelemetrySendOutcome::Unknown,
                };
                if !response.status().is_success() {
                    return TelemetrySendOutcome::Rejected(format!(
                        "collector_http_{}",
                        response.status().as_u16()
                    ));
                }
            }
            TelemetrySendOutcome::Accepted
        };
        tokio::time::timeout(
            iteron_tunables::param_duration("cli.runtime.telemetry.export_timeout", EXPORT_TIMEOUT),
            dispatch,
        )
        .await
        .unwrap_or(TelemetrySendOutcome::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home_with(config: &str, tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("core-otel-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(dir.join(".iteron")).unwrap();
        std::fs::write(dir.join(".iteron").join("config.json"), config).unwrap();
        dir
    }

    /// The default. No block, no sink, and therefore no effect will ever be admitted.
    #[test]
    fn absent_config_yields_no_sink() {
        let home = home_with("{}", "absent");
        assert_eq!(TelemetrySink::load_user(&home), None);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// An endpoint alone is not consent. The operator has to say `true`, so a half-edited config
    /// cannot start shipping spans off the machine.
    #[test]
    fn an_endpoint_without_enabled_is_still_off() {
        let home = home_with(
            r#"{"otel":{"endpoint":"http://127.0.0.1:4318/v1/traces"}}"#,
            "notenabled",
        );
        assert_eq!(TelemetrySink::load_user(&home), None);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn an_enabled_endpoint_in_the_user_config_is_honoured() {
        let home = home_with(
            r#"{"otel":{"enabled":true,"endpoint":"http://127.0.0.1:4318/v1/traces"}}"#,
            "enabled",
        );
        let sink = TelemetrySink::load_user(&home).expect("sink");
        assert_eq!(sink.endpoint(), "http://127.0.0.1:4318/v1/traces");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A malformed config is not a brick. Telemetry is opt-in; a typo in it must not stop the
    /// agent from running.
    #[test]
    fn a_malformed_config_does_not_brick_the_agent() {
        let home = home_with("{not json", "malformed");
        assert_eq!(TelemetrySink::load_user(&home), None);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The trust boundary, stated as a test rather than a comment: this loader is given the HOME
    /// path and reads `<home>/.iteron/config.json`. A project-local `.iteron/config.json` is a
    /// different file that this function never opens, so a cloned repo cannot introduce an
    /// endpoint however it is written.
    #[test]
    fn a_project_local_config_is_never_read() {
        let home = home_with("{}", "origin");
        let project = home.join("workspace");
        std::fs::create_dir_all(project.join(".iteron")).unwrap();
        std::fs::write(
            project.join(".iteron").join("config.json"),
            r#"{"otel":{"enabled":true,"endpoint":"http://attacker.example/v1/traces"}}"#,
        )
        .unwrap();
        assert_eq!(
            TelemetrySink::load_user(&home),
            None,
            "a repo-supplied endpoint must never become an export target"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}
