//! Canonical PlantCore schema-v7 projection from typed runtime facts.

use iteron_protocol::{PlantcoreTerminalOutcome, ProductResult, TurnUsage, UsageUnavailableReason};
use serde_json::{Map, Value, json};
use sha2::Digest;
use std::io;

pub(super) const MAX_EVENT_BYTES: usize = 65_536;

pub(crate) struct AssistantStream {
    message_number: u64,
    next_ordinal: u32,
    text: String,
    scrubber: super::StreamingScrubber,
}

impl Default for AssistantStream {
    fn default() -> Self {
        Self {
            message_number: 1,
            next_ordinal: 0,
            text: String::new(),
            scrubber: super::StreamingScrubber::default(),
        }
    }
}

impl AssistantStream {
    pub(crate) fn push(&mut self, delta: &str) -> io::Result<Option<Value>> {
        let Some(delta) = self.scrubber.push(delta) else {
            return Ok(None);
        };
        self.push_scrubbed(delta).map(Some)
    }

    pub(crate) fn flush(&mut self) -> io::Result<Option<Value>> {
        let Some(delta) = self.scrubber.finish() else {
            return Ok(None);
        };
        self.push_scrubbed(delta).map(Some)
    }

    pub(crate) fn finish_run(
        &mut self,
        done: bool,
        expected_assistant_text: Option<&str>,
    ) -> io::Result<Vec<Value>> {
        let mut values = Vec::with_capacity(3);
        if let Some(delta) = self.flush()? {
            values.push(delta);
        }
        if done {
            if self.next_ordinal == 0 {
                values.push(self.push_scrubbed(String::new())?);
            }
            let expected = expected_assistant_text
                .map(iteron_record::redact::scrub)
                .ok_or_else(|| invalid("done assistant stream requires terminal text"))?;
            if expected != self.text {
                return Err(invalid(
                    "done terminal assistant text differs from the assistant stream",
                ));
            }
            let message_id = self.message_id();
            let assistant_text_sha256 =
                prefixed_sha256(&sha2::Sha256::digest(self.text.as_bytes()));
            values.push(validate_value(json!({
                "schema_version": 7,
                "type": "assistant_completed",
                "message_id": message_id,
                "final_ordinal": self.next_ordinal - 1,
                "assistant_text_sha256": assistant_text_sha256,
            }))?);
        }
        self.reset()?;
        Ok(values)
    }

    fn push_scrubbed(&mut self, delta: String) -> io::Result<Value> {
        if self.text.len().saturating_add(delta.len()) > MAX_EVENT_BYTES {
            return Err(invalid("assistant stream exceeds 65,536 UTF-8 bytes"));
        }
        let ordinal = self.next_ordinal;
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .ok_or_else(|| invalid("assistant stream ordinal exhausted"))?;
        self.text.push_str(&delta);
        let message_id = self.message_id();
        let text_sha256 = prefixed_sha256(&sha2::Sha256::digest(delta.as_bytes()));
        validate_value(json!({
            "schema_version": 7,
            "type": "assistant_delta",
            "message_id": message_id,
            "ordinal": ordinal,
            "text_utf8": delta,
            "text_sha256": text_sha256,
        }))
    }

    fn message_id(&self) -> String {
        format!("assistant-{}", self.message_number)
    }

    fn reset(&mut self) -> io::Result<()> {
        self.message_number = self
            .message_number
            .checked_add(1)
            .ok_or_else(|| invalid("assistant message identity exhausted"))?;
        self.next_ordinal = 0;
        self.text.clear();
        self.scrubber = super::StreamingScrubber::default();
        Ok(())
    }
}

pub(super) fn usage_value(usage: &TurnUsage) -> io::Result<Value> {
    let value = match usage {
        TurnUsage::Complete {
            turn,
            dispatched_attempt_count,
            counters,
            cumulative_metering,
        } => {
            counters.validate().map_err(invalid)?;
            let mut fields = Map::new();
            fields.insert("schema_version".into(), Value::from(7));
            fields.insert("type".into(), Value::from("usage"));
            fields.insert("turn".into(), Value::from(*turn));
            fields.insert("status".into(), Value::from("complete"));
            fields.insert(
                "dispatched_attempt_count".into(),
                Value::from(*dispatched_attempt_count),
            );
            fields.insert("input_tokens".into(), Value::from(counters.input_tokens));
            fields.insert("output_tokens".into(), Value::from(counters.output_tokens));
            fields.insert(
                "cache_creation_tokens".into(),
                Value::from(counters.cache_creation_tokens),
            );
            fields.insert(
                "cache_read_tokens".into(),
                Value::from(counters.cache_read_tokens),
            );
            fields.insert(
                "thinking_tokens".into(),
                Value::from(counters.thinking_tokens),
            );
            fields.insert(
                "total_tokens".into(),
                Value::from(
                    counters
                        .total_tokens()
                        .ok_or_else(|| invalid("five-class token total overflowed"))?,
                ),
            );
            if let Some(metering) = cumulative_metering {
                fields.insert(
                    "metering".into(),
                    json!({
                        "policy_version": metering.policy_version,
                        "policy_digest_sha256": prefixed_sha256(&metering.policy_digest_sha256),
                        "calculator_contract_version": metering.calculator_contract_version,
                        "unit": "USD_MICRO",
                        "cumulative_amount": metering.cumulative_amount,
                    }),
                );
            }
            Value::Object(fields)
        }
        TurnUsage::Unavailable {
            turn,
            dispatched_attempt_count,
            reasons,
        } => {
            if reasons.is_empty() || reasons.len() > 4 {
                return Err(invalid(
                    "unavailable usage requires one through four reasons",
                ));
            }
            let mut ordered = reasons.clone();
            ordered.sort_unstable();
            ordered.dedup();
            if ordered.len() != reasons.len() {
                return Err(invalid("unavailable usage reasons must be unique"));
            }
            json!({
                "schema_version": 7,
                "type": "usage",
                "turn": turn,
                "status": "unavailable",
                "dispatched_attempt_count": dispatched_attempt_count,
                "reasons": ordered.into_iter().map(reason_name).collect::<Vec<_>>(),
            })
        }
    };
    validate_value(value)
}

pub(super) fn result_value(outcome: &PlantcoreTerminalOutcome) -> io::Result<Value> {
    let mut fields = Map::new();
    fields.insert("schema_version".into(), Value::from(7));
    fields.insert("type".into(), Value::from("result"));
    fields.insert("outcome".into(), Value::from(outcome_name(outcome)));
    match outcome {
        PlantcoreTerminalOutcome::Done(product) => {
            fields.insert("product_result_candidate".into(), product_value(product));
        }
        PlantcoreTerminalOutcome::BudgetExhausted(limit) => {
            fields.insert("budget_limit".into(), Value::from(limit.as_str()));
        }
        PlantcoreTerminalOutcome::Drained
        | PlantcoreTerminalOutcome::Interrupted
        | PlantcoreTerminalOutcome::Stuck
        | PlantcoreTerminalOutcome::HarnessError
        | PlantcoreTerminalOutcome::UsageUnavailable => {}
    }
    validate_value(Value::Object(fields))
}

pub(super) fn opaque_value(mut value: Value) -> io::Result<Value> {
    let fields = value
        .as_object_mut()
        .ok_or_else(|| invalid("v7 event must be a JSON object"))?;
    let event_type = fields
        .get("type")
        .and_then(Value::as_str)
        .filter(|event_type| !event_type.is_empty())
        .ok_or_else(|| invalid("v7 event type must be a non-empty string"))?
        .to_owned();
    if event_type.len() > 64 {
        return Err(invalid("v7 event type must contain at most 64 UTF-8 bytes"));
    }
    fields.insert("schema_version".into(), Value::from(7));
    match event_type.as_str() {
        "turn_end" => {
            fields.remove("cost_usd");
            fields.remove("cumulative_cost_usd");
            fields.remove("cache_hit");
        }
        // Tool arguments are model/provider payload, not a stable engine fact. Omitting them from
        // the opaque v7 diagnostic event keeps arbitrary valid JSON numbers and secrets out of the
        // portable no-float recording while v4-v6 retain their frozen projection.
        "tool_start" => {
            fields.remove("args");
        }
        "approval_request" => {
            fields.remove("arguments");
        }
        _ => {}
    }
    validate_value(value)
}

pub(super) fn canonical_bytes(value: &Value) -> io::Result<Vec<u8>> {
    reject_floats(value)?;
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(invalid("canonical v7 event exceeds 65,536 bytes"));
    }
    if bytes.ends_with(b"\n") || bytes.ends_with(b"\r") {
        return Err(invalid("canonical v7 event has trailing line ending"));
    }
    Ok(bytes)
}

fn validate_value(value: Value) -> io::Result<Value> {
    let _ = canonical_bytes(&value)?;
    Ok(value)
}

fn product_value(product: &ProductResult) -> Value {
    let (status, assistant_text, question, artifacts) = match product {
        ProductResult::Completed {
            assistant_text,
            artifacts,
        } => ("completed", assistant_text, None, artifacts),
        ProductResult::NeedsInput {
            assistant_text,
            question,
            artifacts,
        } => ("needs_input", assistant_text, Some(question), artifacts),
    };
    let assistant_text = iteron_record::redact::scrub(assistant_text);
    let mut fields = Map::new();
    fields.insert("status".into(), Value::from(status));
    fields.insert(
        "assistant_text_utf8".into(),
        Value::from(assistant_text.clone()),
    );
    fields.insert(
        "assistant_text_sha256".into(),
        Value::from(prefixed_sha256(&sha2::Sha256::digest(
            assistant_text.as_bytes(),
        ))),
    );
    fields.insert(
        "artifacts".into(),
        Value::Array(
            artifacts
                .iter()
                .map(|artifact| {
                    json!({
                        "logical_name": artifact.logical_name,
                        "relative_path": artifact.relative_path,
                        "media_type": artifact.media_type,
                        "size_bytes": artifact.size_bytes,
                        "content_sha256": prefixed_sha256(&artifact.content_sha256),
                    })
                })
                .collect(),
        ),
    );
    if let Some(question) = question {
        let prompt_utf8 = iteron_record::redact::scrub(&question.prompt_utf8);
        fields.insert(
            "question".into(),
            json!({
                "question_id": question.question_id,
                "prompt_utf8": prompt_utf8.clone(),
                "prompt_sha256": prefixed_sha256(&sha2::Sha256::digest(prompt_utf8.as_bytes())),
            }),
        );
    }
    Value::Object(fields)
}

fn outcome_name(outcome: &PlantcoreTerminalOutcome) -> &'static str {
    match outcome {
        PlantcoreTerminalOutcome::Done(_) => "done",
        PlantcoreTerminalOutcome::Drained => "drained",
        PlantcoreTerminalOutcome::BudgetExhausted(_) => "budget_exhausted",
        PlantcoreTerminalOutcome::Interrupted => "interrupted",
        PlantcoreTerminalOutcome::Stuck => "stuck",
        PlantcoreTerminalOutcome::HarnessError => "harness_error",
        PlantcoreTerminalOutcome::UsageUnavailable => "usage_unavailable",
    }
}

fn reason_name(reason: UsageUnavailableReason) -> &'static str {
    match reason {
        UsageUnavailableReason::ProviderOmitted => "provider_omitted",
        UsageUnavailableReason::CacheCreationUnreported => "cache_creation_unreported",
        UsageUnavailableReason::ProvenFailureWithoutUsage => "proven_failure_without_usage",
        UsageUnavailableReason::OutcomeUnobservable => "outcome_unobservable",
    }
}

fn reject_floats(value: &Value) -> io::Result<()> {
    match value {
        Value::Number(number) if number.is_f64() => {
            Err(invalid("canonical v7 events forbid floating-point numbers"))
        }
        Value::Array(values) => values.iter().try_for_each(reject_floats),
        Value::Object(values) => values.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
}

fn prefixed_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{
        FiveClassUsage, Metering, Outcome, PlantcoreBudgetLimit, Question, TurnUsage,
    };

    fn target_schema() -> jsonschema::Validator {
        let schema = serde_json::from_slice(include_bytes!(
            "../../../../contracts/plantcore/iteron-output-v7.schema.json"
        ))
        .unwrap();
        jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .build(&schema)
            .unwrap()
    }

    #[test]
    fn assistant_stream_has_stable_identity_contiguous_ordinals_and_completion_digest() {
        let mut stream = AssistantStream::default();
        let first = stream.push("answer ").unwrap().unwrap();
        assert_eq!(first["message_id"], "assistant-1");
        assert_eq!(first["ordinal"], 0);
        assert_eq!(first["text_utf8"], "answer ");
        assert!(stream.push("done").unwrap().is_none());
        let second = stream.flush().unwrap().unwrap();
        assert_eq!(second["type"], "assistant_delta");
        assert_eq!(second["message_id"], "assistant-1");
        assert_eq!(second["ordinal"], 1);
        assert_eq!(second["text_utf8"], "done");
        assert_eq!(stream.text, iteron_record::redact::scrub("answer done"));
        let finished = stream.finish_run(true, Some("answer done")).unwrap();
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0]["type"], "assistant_completed");
        assert_eq!(finished[0]["message_id"], "assistant-1");
        assert_eq!(finished[0]["final_ordinal"], 1);
        assert_eq!(
            finished[0]["assistant_text_sha256"],
            prefixed_sha256(&sha2::Sha256::digest(b"answer done"))
        );
        for value in [&first, &second, &finished[0]] {
            target_schema().validate(value).unwrap();
        }
    }

    #[test]
    fn empty_done_and_partial_failure_have_distinct_lifecycles() {
        let mut empty = AssistantStream::default();
        let finished = empty.finish_run(true, Some("")).unwrap();
        assert_eq!(finished.len(), 2);
        assert_eq!(finished[0]["type"], "assistant_delta");
        assert_eq!(finished[0]["text_utf8"], "");
        assert_eq!(finished[1]["type"], "assistant_completed");

        let mut partial = AssistantStream::default();
        assert!(partial.push("partial").unwrap().is_none());
        let failed = partial.finish_run(false, None).unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0]["type"], "assistant_delta");
        assert_eq!(failed[0]["text_utf8"], "partial");
        assert!(
            failed
                .iter()
                .all(|value| value["type"] != "assistant_completed")
        );
    }

    #[test]
    fn usage_total_does_not_double_count_thinking() {
        let value = usage_value(&TurnUsage::Complete {
            turn: 1,
            dispatched_attempt_count: 1,
            counters: FiveClassUsage {
                input_tokens: 5,
                output_tokens: 7,
                cache_creation_tokens: 2,
                cache_read_tokens: 3,
                thinking_tokens: 4,
            },
            cumulative_metering: None,
        })
        .unwrap();
        assert_eq!(value["total_tokens"], 17);
        assert!(canonical_bytes(&value).unwrap().len() <= MAX_EVENT_BYTES);
    }

    #[test]
    fn admitted_profile_digest_is_a_bounded_opaque_v7_event() {
        let digest = iteron_protocol::HexSha256::digest(b"profile");
        let value = super::super::v7_plantcore_run_admitted(digest).unwrap();
        assert_eq!(value["schema_version"], 7);
        assert_eq!(value["type"], "plantcore_run_admitted");
        assert_eq!(value["profile_digest_sha256"], format!("sha256:{digest}"));
        assert!(canonical_bytes(&value).unwrap().len() <= MAX_EVENT_BYTES);
    }

    #[test]
    fn opaque_v7_events_require_a_nonempty_string_type() {
        assert!(opaque_value(serde_json::json!({})).is_err());
        assert!(opaque_value(serde_json::json!({"type": ""})).is_err());
        assert!(opaque_value(serde_json::json!({"type": 7})).is_err());
        assert_eq!(
            opaque_value(serde_json::json!({"type": "thinking"})).unwrap(),
            serde_json::json!({"schema_version": 7, "type": "thinking"}),
        );
        assert_eq!(
            opaque_value(serde_json::json!({
                "type": "tool_start",
                "tool_use_id": "tool-1",
                "name": "gateway_call",
                "args": {"temperature": 0.7}
            }))
            .unwrap(),
            serde_json::json!({
                "schema_version": 7,
                "type": "tool_start",
                "tool_use_id": "tool-1",
                "name": "gateway_call"
            }),
            "v7 keeps the opaque tool lifecycle without recording arbitrary argument payloads"
        );
    }

    #[test]
    fn terminal_truth_table_has_exact_fields() {
        let completed = ProductResult::Completed {
            assistant_text: "answer".into(),
            artifacts: Vec::new(),
        };
        let cases = [
            (
                PlantcoreTerminalOutcome::Done(completed.clone()),
                &[
                    "outcome",
                    "product_result_candidate",
                    "schema_version",
                    "type",
                ][..],
            ),
            (
                PlantcoreTerminalOutcome::Drained,
                &["outcome", "schema_version", "type"],
            ),
            (
                PlantcoreTerminalOutcome::Interrupted,
                &["outcome", "schema_version", "type"],
            ),
            (
                PlantcoreTerminalOutcome::Stuck,
                &["outcome", "schema_version", "type"],
            ),
            (
                PlantcoreTerminalOutcome::HarnessError,
                &["outcome", "schema_version", "type"],
            ),
            (
                PlantcoreTerminalOutcome::UsageUnavailable,
                &["outcome", "schema_version", "type"],
            ),
            (
                PlantcoreTerminalOutcome::BudgetExhausted(PlantcoreBudgetLimit::MaxTokens),
                &["budget_limit", "outcome", "schema_version", "type"],
            ),
        ];
        for (outcome, expected_keys) in cases {
            let value = result_value(&outcome).unwrap();
            let mut keys = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            keys.sort_unstable();
            assert_eq!(keys, expected_keys);
        }
        assert!(PlantcoreTerminalOutcome::from_runtime(Outcome::Done, None).is_err());
        assert!(PlantcoreTerminalOutcome::from_runtime(Outcome::Drained, Some(completed)).is_err());
        assert!(
            PlantcoreTerminalOutcome::from_runtime(Outcome::BudgetExhausted("future"), None)
                .is_err()
        );
    }

    #[test]
    fn product_projection_hashes_exact_text_and_prompt_bytes() {
        let prompt = "which target?".to_owned();
        let product = ProductResult::NeedsInput {
            assistant_text: "context only".into(),
            question: Question {
                question_id: "iteron-question-test".into(),
                prompt_sha256: sha2::Sha256::digest(prompt.as_bytes()).into(),
                prompt_utf8: prompt.clone(),
            },
            artifacts: Vec::new(),
        };
        let value = result_value(&PlantcoreTerminalOutcome::Done(product)).unwrap();
        let candidate = &value["product_result_candidate"];
        assert_eq!(candidate["assistant_text_utf8"], "context only");
        assert_eq!(candidate["question"]["prompt_utf8"], prompt);
        assert_eq!(
            candidate["assistant_text_sha256"],
            prefixed_sha256(&sha2::Sha256::digest(b"context only"))
        );
        assert_eq!(
            candidate["question"]["prompt_sha256"],
            prefixed_sha256(&sha2::Sha256::digest(b"which target?"))
        );
        assert!(candidate.get("usage_receipt").is_none());
        assert!(candidate.get("artifact_id").is_none());
    }

    #[test]
    fn product_projection_scrubs_free_text_before_hashing_emitted_bytes() {
        let secret = concat!("sk-ant-api03-", "AbCdEfGhIjKlMnOpQrStUvWx");
        let product = ProductResult::NeedsInput {
            assistant_text: format!("answer {secret}"),
            question: Question {
                question_id: "iteron-question-redaction".into(),
                prompt_sha256: sha2::Sha256::digest(format!("confirm {secret}").as_bytes()).into(),
                prompt_utf8: format!("confirm {secret}"),
            },
            artifacts: Vec::new(),
        };
        let value = result_value(&PlantcoreTerminalOutcome::Done(product)).unwrap();
        let candidate = &value["product_result_candidate"];
        let assistant = candidate["assistant_text_utf8"].as_str().unwrap();
        let prompt = candidate["question"]["prompt_utf8"].as_str().unwrap();
        assert!(!assistant.contains(secret));
        assert!(!prompt.contains(secret));
        assert_eq!(
            candidate["assistant_text_sha256"],
            prefixed_sha256(&sha2::Sha256::digest(assistant.as_bytes()))
        );
        assert_eq!(
            candidate["question"]["prompt_sha256"],
            prefixed_sha256(&sha2::Sha256::digest(prompt.as_bytes()))
        );
    }

    #[test]
    fn typed_usage_and_terminal_projections_match_the_pinned_platform_schema() {
        let validator = target_schema();
        let digest = [7; 32];
        let complete = usage_value(&TurnUsage::Complete {
            turn: 1,
            dispatched_attempt_count: 2,
            counters: FiveClassUsage {
                input_tokens: 5,
                output_tokens: 7,
                cache_creation_tokens: 2,
                cache_read_tokens: 3,
                thinking_tokens: 4,
            },
            cumulative_metering: Some(Metering {
                policy_version: "policy-v1".into(),
                policy_digest_sha256: digest,
                calculator_contract_version: "plantcore.metering.five-class-ceil.v1".into(),
                cumulative_amount: 11,
            }),
        })
        .unwrap();
        let unavailable = usage_value(&TurnUsage::Unavailable {
            turn: 2,
            dispatched_attempt_count: 1,
            reasons: vec![UsageUnavailableReason::OutcomeUnobservable],
        })
        .unwrap();
        let completed = ProductResult::Completed {
            assistant_text: "answer".into(),
            artifacts: Vec::new(),
        };
        for value in [
            complete,
            unavailable,
            result_value(&PlantcoreTerminalOutcome::Done(completed.clone())).unwrap(),
            result_value(&PlantcoreTerminalOutcome::BudgetExhausted(
                PlantcoreBudgetLimit::MaxWallSecs,
            ))
            .unwrap(),
            super::super::v7_plantcore_run_admitted(iteron_protocol::HexSha256::digest(b"profile"))
                .unwrap(),
        ] {
            if let Err(error) = validator.validate(&value) {
                panic!("generated v7 event violates pinned Platform schema: {error}");
            }
        }

        let mut forbidden = result_value(&PlantcoreTerminalOutcome::Done(completed)).unwrap();
        forbidden["engine_seq"] = Value::from(1);
        assert!(validator.validate(&forbidden).is_err());
    }
}
