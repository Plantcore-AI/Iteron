//! Typed, content-free diagnostics emitted by the kernel through an injected evidence port.
//!
//! Diagnostics deliberately carry no free-form strings. Provider, filesystem, record, and model
//! errors can contain paths, credentials, or transcript fragments; those values must stay on their
//! typed error paths and never enter an embedding's diagnostic stream. The emitter is shared by a
//! parent and all descendants so fan-out cannot multiply the fixed run-wide bound.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

/// Maximum number of diagnostic records emitted across one agent and all of its descendants.
pub const MAX_KERNEL_DIAGNOSTICS_PER_RUN: u32 = 64;
/// Schema version used by machine frontends when they envelope a [`KernelDiagnostic`].
pub const KERNEL_DIAGNOSTIC_SCHEMA_VERSION: u8 = 1;
/// Exact closed diagnostic-code inventory carried by schema version 1.
pub const KERNEL_DIAGNOSTIC_CODES: [&str; 2] =
    ["record_append_failed", "resume_redaction_degraded"];

/// Secret-safe diagnostic vocabulary exported by `core-kernel`.
///
/// This enum is intentionally closed and contains only bounded numeric or enum fields. Adding a
/// string field is a security-sensitive public-contract change because record errors and resumed
/// transcript content are not safe diagnostic payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum KernelDiagnostic {
    /// An append/fsync at the durable record boundary failed. The underlying error is omitted.
    RecordAppendFailed {},
    /// Masked tool output was reconstructed from a record, so the resumed model context differs
    /// from the original live context.
    ResumeRedactionDegraded {
        redacted_tool_results: u32,
        count_saturated: bool,
    },
}

impl KernelDiagnostic {
    /// Stable code used by corpus checks and content-free consumers.
    pub const fn code(self) -> &'static str {
        match self {
            Self::RecordAppendFailed {} => "record_append_failed",
            Self::ResumeRedactionDegraded { .. } => "resume_redaction_degraded",
        }
    }
}

/// Closed machine envelope used by frontends when exporting a kernel diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelDiagnosticEnvelope {
    pub schema_version: u8,
    #[serde(rename = "type")]
    pub record_type: KernelDiagnosticRecordType,
    pub diagnostic: KernelDiagnostic,
}

impl KernelDiagnosticEnvelope {
    pub fn current(diagnostic: KernelDiagnostic) -> Self {
        Self {
            schema_version: KERNEL_DIAGNOSTIC_SCHEMA_VERSION,
            record_type: KernelDiagnosticRecordType::KernelDiagnostic,
            diagnostic,
        }
    }
}

/// Fixed discriminator for the diagnostic machine stream; never free-form text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelDiagnosticRecordType {
    KernelDiagnostic,
}

/// Concrete, non-blocking evidence-plane port. The kernel can only `try_send` into its fixed-size
/// channel; it never invokes embedding code or performs diagnostic IO on a state-machine path.
#[derive(Clone)]
pub struct DiagnosticPort {
    sender: SyncSender<KernelDiagnostic>,
}

/// Create the sole admitted diagnostic transport. Its capacity equals the shared emission bound,
/// so a receiver that drains only after a run still observes every admitted diagnostic.
pub fn bounded_channel() -> (DiagnosticPort, Receiver<KernelDiagnostic>) {
    let (sender, receiver) = sync_channel(MAX_KERNEL_DIAGNOSTICS_PER_RUN as usize);
    (DiagnosticPort { sender }, receiver)
}

impl DiagnosticPort {
    fn try_emit(&self, diagnostic: KernelDiagnostic) {
        let _ = self.sender.try_send(diagnostic);
    }
}

/// Internal bounded emitter cloned into every descendant agent.
#[derive(Clone)]
pub(crate) struct DiagnosticEmitter {
    port: Option<DiagnosticPort>,
    emitted: Arc<AtomicU32>,
}

impl Default for DiagnosticEmitter {
    fn default() -> Self {
        Self {
            port: None,
            emitted: Arc::new(AtomicU32::new(0)),
        }
    }
}

impl DiagnosticEmitter {
    #[cfg(test)]
    pub(crate) fn new(port: DiagnosticPort) -> Self {
        Self {
            port: Some(port),
            emitted: Arc::new(AtomicU32::new(0)),
        }
    }

    pub(crate) fn with_port(&self, port: DiagnosticPort) -> Self {
        Self {
            port: Some(port),
            emitted: self.emitted.clone(),
        }
    }

    pub(crate) fn emit(&self, diagnostic: KernelDiagnostic) {
        let admitted = self
            .emitted
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |emitted| {
                (emitted < MAX_KERNEL_DIAGNOSTICS_PER_RUN).then_some(emitted.saturating_add(1))
            });
        if admitted.is_ok()
            && let Some(port) = &self.port
        {
            port.try_emit(diagnostic);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_typed_matches_current_projection(
        original: &serde_json::Value,
        canonical: &serde_json::Value,
        surface: &serde_json::Value,
        fixture: &serde_json::Value,
        label: &str,
    ) {
        let raw = original.as_object().expect("fixture object");
        let mut target = raw.clone();
        let mut shims = surface["compatibility_shims"]
            .as_array()
            .expect("compatibility shims is an array")
            .iter()
            .collect::<Vec<_>>();
        shims.sort_by(|left, right| {
            (
                left["target_version"]
                    .as_u64()
                    .expect("shim target version"),
                left["old_field"].as_str().expect("shim old field"),
            )
                .cmp(&(
                    right["target_version"]
                        .as_u64()
                        .expect("shim target version"),
                    right["old_field"].as_str().expect("shim old field"),
                ))
        });
        for shim in shims {
            let old_field = shim["old_field"].as_str().expect("shim old field");
            let Some(old) = target.remove(old_field) else {
                continue;
            };
            if raw.contains_key(old_field) {
                let relative = fixture["path"].as_str().expect("fixture path");
                assert!(
                    shim["fixtures"]
                        .as_array()
                        .expect("shim fixtures")
                        .iter()
                        .any(|path| path.as_str() == Some(relative)),
                    "{label} uses `{old_field}` without declaring the fixture on its shim"
                );
            }
            if let Some(replacement) = shim["replacement"].as_str() {
                assert!(
                    !target.contains_key(replacement),
                    "{label} migration would overwrite replacement field `{replacement}`"
                );
                target.insert(replacement.to_owned(), old);
            }
            if let Some(version_field) = surface["version_field"].as_str() {
                target.insert(
                    version_field.to_owned(),
                    serde_json::Value::from(
                        shim["target_version"]
                            .as_u64()
                            .expect("shim target version"),
                    ),
                );
            }
        }
        if let Some(version_field) = surface["version_field"].as_str() {
            target.insert(
                version_field.to_owned(),
                serde_json::Value::from(
                    surface["current_version"]
                        .as_u64()
                        .expect("surface current version"),
                ),
            );
        }
        let active_fields = surface["fields"]
            .as_array()
            .expect("surface fields")
            .iter()
            .map(|field| field["name"].as_str().expect("field name"))
            .collect::<std::collections::BTreeSet<_>>();
        let target_fields = target
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            target_fields.is_subset(&active_fields),
            "{label} migration retained stale or undeclared fields"
        );
        let encoded = canonical.as_object().expect("typed encoding object");
        let encoded_fields = encoded
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            encoded_fields.is_subset(&active_fields),
            "{label} typed encoding emitted undeclared fields"
        );
        for (field, value) in target {
            assert_eq!(
                encoded.get(&field),
                Some(&value),
                "{label} typed current serialization changed traceable field `{field}`"
            );
        }
        if fixture["schema_version"] == surface["current_version"] {
            assert_eq!(
                canonical, original,
                "{label} current-version wire shape changed"
            );
        }
    }

    #[test]
    fn shared_descendant_emitter_has_one_hard_bound() {
        let (port, receiver) = bounded_channel();
        let parent = DiagnosticEmitter::new(port);
        let child = parent.clone();
        for index in 0..MAX_KERNEL_DIAGNOSTICS_PER_RUN.saturating_mul(2) {
            let emitter = if index % 2 == 0 { &parent } else { &child };
            emitter.emit(KernelDiagnostic::RecordAppendFailed {});
        }
        assert_eq!(
            receiver.try_iter().count(),
            MAX_KERNEL_DIAGNOSTICS_PER_RUN as usize
        );
    }

    #[test]
    fn serialized_vocabulary_has_no_open_text_field() {
        let diagnostic = KernelDiagnostic::ResumeRedactionDegraded {
            redacted_tool_results: u32::MAX,
            count_saturated: true,
        };
        let value = serde_json::to_value(diagnostic).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "code": "resume_redaction_degraded",
                "redacted_tool_results": u32::MAX,
                "count_saturated": true
            })
        );
        assert_eq!(
            serde_json::from_value::<KernelDiagnostic>(value).unwrap(),
            diagnostic
        );
    }

    #[test]
    fn frozen_machine_envelope_round_trips_without_shape_drift() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repository root exists");
        let contract: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("governance/schema-compatibility.json"))
                .expect("compatibility contract is readable"),
        )
        .expect("compatibility contract is JSON");
        let surface = contract["surfaces"]
            .as_array()
            .expect("surfaces is an array")
            .iter()
            .find(|surface| surface["id"] == "kernel.diagnostic")
            .expect("kernel diagnostic surface is declared");
        assert_eq!(
            surface["current_version"], KERNEL_DIAGNOSTIC_SCHEMA_VERSION,
            "the durable contract must track the current diagnostic producer"
        );
        let mut fixture_codes = std::collections::BTreeSet::new();
        let mut fixture_diagnostics = std::collections::BTreeSet::new();
        for fixture in surface["fixtures"]
            .as_array()
            .expect("fixtures is an array")
        {
            let relative = fixture["path"].as_str().expect("fixture path is a string");
            let original: serde_json::Value = serde_json::from_slice(
                &std::fs::read(root.join(relative)).expect("diagnostic fixture is readable"),
            )
            .expect("diagnostic fixture is JSON");
            let envelope: KernelDiagnosticEnvelope =
                serde_json::from_value(original.clone()).unwrap();
            assert!(
                fixture_codes.insert(envelope.diagnostic.code()),
                "diagnostic code `{}` has more than one frozen fixture",
                envelope.diagnostic.code()
            );
            fixture_diagnostics.insert(
                serde_json::to_string(&serde_json::to_value(envelope.diagnostic).unwrap()).unwrap(),
            );
            assert_eq!(
                u64::from(envelope.schema_version),
                fixture["schema_version"]
                    .as_u64()
                    .expect("fixture schema version is numeric"),
                "{relative}"
            );
            let canonical = serde_json::to_value(envelope).unwrap();
            let reparsed: KernelDiagnosticEnvelope =
                serde_json::from_value(canonical.clone()).unwrap();
            assert_eq!(
                serde_json::to_value(reparsed).unwrap(),
                canonical,
                "{relative}"
            );
            assert_typed_matches_current_projection(
                &original, &canonical, surface, fixture, relative,
            );
        }
        let expected_codes = KERNEL_DIAGNOSTIC_CODES
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            expected_codes.len(),
            KERNEL_DIAGNOSTIC_CODES.len(),
            "the diagnostic-code inventory cannot contain duplicates"
        );
        assert!(
            KERNEL_DIAGNOSTIC_CODES
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "the diagnostic-code inventory must remain strictly sorted"
        );
        assert_eq!(
            fixture_codes, expected_codes,
            "the frozen diagnostic corpus must contain every code exactly once"
        );
        assert_eq!(
            fixture_diagnostics,
            [
                serde_json::json!({"code": "record_append_failed"}),
                serde_json::json!({
                    "code": "resume_redaction_degraded",
                    "redacted_tool_results": 1,
                    "count_saturated": false,
                }),
            ]
            .into_iter()
            .map(|value| serde_json::to_string(&value).unwrap())
            .collect(),
            "the schema-v1 corpus values changed without an explicit fixture review"
        );
        assert!(
            serde_json::from_value::<KernelDiagnostic>(serde_json::json!({
                "code": "record_append_failed",
                "unexpected": true,
            }))
            .is_err(),
            "nested diagnostic fields must fail closed"
        );
    }

    #[test]
    fn replacing_a_port_does_not_reset_the_shared_run_bound() {
        let (first_port, first_receiver) = bounded_channel();
        let emitter = DiagnosticEmitter::new(first_port);
        for _ in 0..MAX_KERNEL_DIAGNOSTICS_PER_RUN {
            emitter.emit(KernelDiagnostic::RecordAppendFailed {});
        }
        let (second_port, second_receiver) = bounded_channel();
        let replaced = emitter.with_port(second_port);
        replaced.emit(KernelDiagnostic::RecordAppendFailed {});
        assert_eq!(
            first_receiver.try_iter().count(),
            MAX_KERNEL_DIAGNOSTICS_PER_RUN as usize
        );
        assert_eq!(second_receiver.try_iter().count(), 0);
    }

    #[test]
    fn disconnected_receiver_cannot_affect_kernel_control_flow() {
        let (port, receiver) = bounded_channel();
        drop(receiver);
        let emitter = DiagnosticEmitter::new(port);
        emitter.emit(KernelDiagnostic::RecordAppendFailed {});
    }
}
