//! Secret redaction on the record path (ADR-008 §1, enterprise/compliance). Tool output can
//! contain a hardcoded key or a token; the durable, long-retained audit log must not become a
//! secret store. So known-secret *shapes* are masked in tool results **before they enter the
//! record**. The live model context keeps the real content (the agent needs it to work); only
//! the recorded copy is scrubbed.
//!
//! This is shape-based, not a guarantee: it catches the common credential formats, not every
//! possible secret. It is a real compliance reduction, not a solution — stated honestly. The
//! full ADR-008 design (content-addressed tombstonable blobs) is the stronger, later form.
//!
//! Zero-dependency: a small hand-rolled scanner, no regex crate.

use core_protocol::{Block, Event, EventKind, WorkflowEvent};

/// Redact tool-result content in an event before it enters the record (ADR-008 §1). Returns a
/// scrubbed clone; the caller's live copy is untouched. This is the single chokepoint applied by
/// `Rollout::append`, so every recorded event is scrubbed regardless of who emitted it.
pub fn redact_event(event: &Event) -> Event {
    let kind = match &event.kind {
        EventKind::ToolDone { result, effect_id } => {
            let mut r = result.clone();
            r.content = scrub(&r.content);
            EventKind::ToolDone {
                result: r,
                effect_id: effect_id.clone(),
            }
        }
        EventKind::EffectIntent {
            id,
            tool_use_id,
            tool,
            capability,
            arguments,
            workspace,
        } => EventKind::EffectIntent {
            // Correlation identifiers are structural. Changing one side but not ToolDone would
            // manufacture a dangling effect during recovery.
            id: id.clone(),
            tool_use_id: scrub(tool_use_id),
            tool: scrub(tool),
            capability: *capability,
            arguments: scrub_json(arguments),
            workspace: scrub(workspace),
        },
        EventKind::EffectUnknown { id, tool, reason } => EventKind::EffectUnknown {
            id: id.clone(),
            tool: scrub(tool),
            reason: scrub(reason),
        },
        EventKind::Message { message } => EventKind::Message {
            message: redact_message(message),
        },
        EventKind::Compaction { messages } => EventKind::Compaction {
            messages: messages.iter().map(redact_message).collect(),
        },
        // The injected context (memory + instructions) is written verbatim to the durable record
        // (REC-INJECT). A remembered fact could contain a credential, so scrub it too (code review:
        // this event previously fell through unscrubbed, leaking secrets into the audit log).
        EventKind::ContextInjection { text, trust } => EventKind::ContextInjection {
            text: scrub(text),
            trust: *trust,
        },
        // Route/provenance events are durable control-plane data. They deliberately contain no
        // credential field, but operator-defined ids are still strings and must not become a
        // backdoor secret store. Preserve content-address/digest-shaped identifiers because they
        // are legitimate routing/provenance values; scrub known credential shapes everywhere else.
        EventKind::RunStart {
            cwd,
            model,
            effort,
            created_at,
            parent_run,
            forked_at,
            parent_hash_at_seq,
            config_digest,
        } => EventKind::RunStart {
            // These are structural references, not free-form route metadata. Preserve them exactly
            // or a hash-shaped workspace/run name would become unresumable.
            cwd: cwd.clone(),
            model: scrub_route_identifier(model),
            effort: *effort,
            created_at: *created_at,
            parent_run: parent_run.clone(),
            forked_at: *forked_at,
            parent_hash_at_seq: parent_hash_at_seq.as_deref().map(scrub_route_digest),
            config_digest: scrub_route_digest(config_digest),
        },
        EventKind::ModelSelected {
            provider_id,
            model_id,
            catalog_digest,
            capability_digest,
        } => EventKind::ModelSelected {
            provider_id: scrub_route_identifier(provider_id),
            model_id: scrub_route_identifier(model_id),
            catalog_digest: scrub_route_digest(catalog_digest),
            capability_digest: scrub_route_digest(capability_digest),
        },
        EventKind::Approval {
            id,
            tool_use_id,
            tool,
            capability,
            arguments,
            workspace,
            verdict,
        } => EventKind::Approval {
            id: *id,
            tool_use_id: scrub(tool_use_id),
            tool: scrub(tool),
            capability: *capability,
            arguments: scrub_json(arguments),
            workspace: scrub(workspace),
            verdict: *verdict,
        },
        EventKind::Workflow {
            version,
            workflow_id,
            event,
        } => EventKind::Workflow {
            version: *version,
            workflow_id: scrub(workflow_id),
            event: redact_workflow_event(event),
        },
        EventKind::SubagentFinished {
            sub_run,
            outcome,
            metrics,
            error_code,
            error_detail,
            summary_digest,
            evidence_bytes,
        } => EventKind::SubagentFinished {
            sub_run: sub_run.clone(),
            outcome: *outcome,
            metrics: metrics.clone(),
            error_code: error_code.as_deref().map(scrub),
            error_detail: error_detail.as_deref().map(scrub),
            summary_digest: summary_digest.clone(),
            evidence_bytes: *evidence_bytes,
        },
        other => other.clone(),
    };
    Event {
        seq: event.seq,
        turn: event.turn,
        kind,
    }
}

fn redact_workflow_event(event: &WorkflowEvent) -> WorkflowEvent {
    match event {
        WorkflowEvent::Started { name, class } => WorkflowEvent::Started {
            name: scrub(name),
            class: scrub(class),
        },
        WorkflowEvent::Planned {
            mode,
            tasks,
            dropped,
            duplicates_removed,
            invalid_removed,
            fan_turn_budget,
            writer_turn_reserve,
            fan_wall_secs,
            writer_wall_reserve_secs,
        } => WorkflowEvent::Planned {
            mode: *mode,
            tasks: tasks
                .iter()
                .cloned()
                .map(|mut task| {
                    task.label = scrub(&task.label);
                    task
                })
                .collect(),
            dropped: *dropped,
            duplicates_removed: *duplicates_removed,
            invalid_removed: *invalid_removed,
            fan_turn_budget: *fan_turn_budget,
            writer_turn_reserve: *writer_turn_reserve,
            fan_wall_secs: *fan_wall_secs,
            writer_wall_reserve_secs: *writer_wall_reserve_secs,
        },
        WorkflowEvent::PhaseChanged { phase } => WorkflowEvent::PhaseChanged { phase: *phase },
        WorkflowEvent::ChildStarted {
            task_id,
            sub_run,
            spawn_seq,
            budget,
        } => WorkflowEvent::ChildStarted {
            task_id: *task_id,
            // Structural child link: changing it here would break the SubagentSpawned correlation.
            sub_run: sub_run.clone(),
            spawn_seq: *spawn_seq,
            budget: budget.clone(),
        },
        WorkflowEvent::ChildFinished {
            task_id,
            sub_run,
            outcome,
            metrics,
            error_code,
            error_detail,
            summary_digest,
            evidence_bytes,
        } => WorkflowEvent::ChildFinished {
            task_id: *task_id,
            sub_run: sub_run.clone(),
            outcome: *outcome,
            metrics: metrics.clone(),
            error_code: error_code.as_deref().map(scrub),
            error_detail: error_detail.as_deref().map(scrub),
            summary_digest: summary_digest.clone(),
            evidence_bytes: *evidence_bytes,
        },
        WorkflowEvent::Reduced {
            evidence_message_seq,
            done,
            failed,
            skipped,
            elapsed_ms,
        } => WorkflowEvent::Reduced {
            evidence_message_seq: *evidence_message_seq,
            done: *done,
            failed: *failed,
            skipped: *skipped,
            elapsed_ms: *elapsed_ms,
        },
        WorkflowEvent::Finished {
            outcome,
            metrics,
            elapsed_ms,
            error_code,
            error_detail,
        } => WorkflowEvent::Finished {
            outcome: *outcome,
            metrics: metrics.clone(),
            elapsed_ms: *elapsed_ms,
            error_code: error_code.as_deref().map(scrub),
            error_detail: error_detail.as_deref().map(scrub),
        },
    }
}

fn is_content_address(value: &str) -> bool {
    let hex = value.strip_prefix("sha256:").unwrap_or(value);
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Route identifiers may legitimately be content hashes (for example an operator-hosted model
/// addressed by SHA-256). Preserve that exact shape; otherwise apply the standard credential
/// scanner. Public for the kernel's write-ahead preflight so durable state cannot differ from the
/// in-memory provider/model pair.
pub fn scrub_route_identifier(value: &str) -> String {
    if is_content_address(value) {
        value.to_owned()
    } else {
        scrub(value)
    }
}

fn scrub_route_digest(value: &str) -> String {
    if value.is_empty() || is_content_address(value) {
        value.to_owned()
    } else {
        scrub(value)
    }
}

/// Recursively scrub secret shapes out of every string in a JSON value (tool-call arguments):
/// an `edit`/`bash` call can carry a hardcoded key in its `input`, which must not persist in the
/// record (code review: `ToolUse.input` fell through unscrubbed).
fn scrub_json(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::String(s) => Value::String(scrub(s)),
        Value::Array(a) => Value::Array(a.iter().map(scrub_json).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, val)| (k.clone(), scrub_json(val)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn redact_message(m: &core_protocol::Message) -> core_protocol::Message {
    let content = m
        .content
        .iter()
        .map(|b| match b {
            Block::ToolResult(r) => {
                let mut r = r.clone();
                r.content = scrub(&r.content);
                Block::ToolResult(r)
            }
            // Model/user free text, extended-thinking reasoning, and tool-call ARGUMENTS can each
            // carry a secret (code review + fix-verification: all fell through unscrubbed). Scrub
            // the text/thinking and every string in the tool input.
            Block::Text { text } => Block::Text { text: scrub(text) },
            Block::Thinking { thinking } => Block::Thinking {
                thinking: scrub(thinking),
            },
            // Opaque continuation state must remain byte-stable or the provider cannot verify its
            // encrypted payload on resume. It is never rendered or included in Debug output and
            // only the exact route+format may replay it. Portable display blocks are scrubbed.
            Block::ProviderState(state) => Block::ProviderState(state.clone()),
            Block::ToolUse(t) => {
                let mut t = t.clone();
                t.input = scrub_json(&t.input);
                Block::ToolUse(t)
            } // Exhaustive on purpose (no catch-all): a NEW Block variant must force an explicit
              // redaction decision here rather than silently persisting to the record unscrubbed.
        })
        .collect();
    core_protocol::Message {
        role: m.role,
        content,
    }
}

/// Mask known-secret shapes in `s`, returning the redacted string (unchanged if none found).
pub fn scrub(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    // Line-oriented for the multi-line PEM case; token-oriented within a line.
    let mut in_pem = false;
    for line in s.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.contains("BEGIN") && trimmed.contains("PRIVATE KEY") {
            in_pem = true;
            out.push_str("[REDACTED PRIVATE KEY]\n");
            continue;
        }
        if in_pem {
            if trimmed.contains("END") && trimmed.contains("PRIVATE KEY") {
                in_pem = false;
            }
            continue; // drop PEM body lines
        }
        out.push_str(&scrub_tokens_in_line(line));
    }
    out
}

fn scrub_tokens_in_line(line: &str) -> String {
    // Split on whitespace-ish boundaries but preserve the original separators by walking words.
    let mut out = String::with_capacity(line.len());
    let mut word = String::new();
    for ch in line.chars() {
        if ch.is_whitespace() || matches!(ch, '"' | '\'' | '=' | ':' | ',' | '(' | ')' | ';') {
            if !word.is_empty() {
                out.push_str(&mask_if_secret(&word));
                word.clear();
            }
            out.push(ch);
        } else {
            word.push(ch);
        }
    }
    if !word.is_empty() {
        out.push_str(&mask_if_secret(&word));
    }
    out
}

/// Return a masked placeholder if `w` looks like a credential, else `w` unchanged.
fn mask_if_secret(w: &str) -> String {
    let looks_secret =
        // provider key prefixes
        w.starts_with("sk-") && w.len() > 20
        || w.starts_with("sk-ant-")
        || w.starts_with("ghp_") || w.starts_with("gho_") || w.starts_with("ghs_") // GitHub
        || w.starts_with("xoxb-") || w.starts_with("xoxp-")                          // Slack
        || w.starts_with("AKIA") && w.len() >= 20                                    // AWS access key id
        || w.starts_with("AIza") && w.len() > 30                                     // Google API key
        || looks_like_jwt(w)                                                          // JWT
        || (w.len() >= 32 && looks_like_hex_or_b64_token(w));
    if looks_secret {
        // char-safe prefix (code review: &w[..4] panics on a multibyte char after the prefix).
        format!("[REDACTED:{}…]", w.chars().take(4).collect::<String>())
    } else {
        w.to_string()
    }
}

/// A JSON Web Token: three base64url segments joined by '.', starting with the `eyJ` header
/// ("{\"" base64url). A common leaked secret the shape-scanner otherwise misses.
fn looks_like_jwt(w: &str) -> bool {
    if !w.starts_with("eyJ") {
        return false;
    }
    let parts: Vec<&str> = w.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            p.len() >= 8
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
        })
}

/// A long run of hex/base64-ish chars with enough entropy to be a token, not prose. Conservative
/// so ordinary long identifiers (all-lowercase words, snake_case) are not masked — but a long
/// PURE-HEX run is masked regardless of case (code review: lowercase-hex git-sha-shaped secrets).
fn looks_like_hex_or_b64_token(w: &str) -> bool {
    if w.len() < 32 {
        return false;
    }
    let ok = w.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '_' || c == '-' || c == '='
    });
    if !ok {
        return false;
    }
    // A long pure-hex run is a token shape regardless of case (a 32+ hex string is a hash/key,
    // not prose). Masking it in the AUDIT RECORD is cheap even for a git sha (the live model
    // context is untouched), and it catches lowercase-hex secrets.
    let is_hex = w.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex {
        return true;
    }
    // Otherwise require an uppercase letter AND a digit (entropy): masks mixed-case-with-digit
    // tokens (typical API keys / base64) while leaving plain words / lowercase paths alone.
    let has_upper = w.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = w.chars().any(|c| c.is_ascii_digit());
    has_upper && has_digit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_provider_and_platform_keys() {
        assert!(
            scrub(
                "key = sk-\
ant-api03-AbCdEfGhIjKlMnOpQrStUvWx"
            )
            .contains("[REDACTED")
        );
        assert!(
            scrub(
                "token: ghp_\
AbCdEf12\
34567890AbCdEf1234567890"
            )
            .contains("[REDACTED")
        );
        assert!(
            scrub(
                "aws AKIA\
IOSFODNN7EXAMPLE here"
            )
            .contains("[REDACTED")
        );
    }

    #[test]
    fn drops_private_key_body() {
        let pem = "-----BEGIN RSA PRIVATE \
KEY-----\nMIIEpAIBAAKCAQEA...\nabc\n-----END RSA PRIVATE KEY-----\n";
        let r = scrub(pem);
        assert!(r.contains("[REDACTED PRIVATE KEY]"));
        assert!(!r.contains("MIIEpAIBAAKCAQEA"), "PEM body must be dropped");
    }

    #[test]
    fn leaves_ordinary_code_alone() {
        let code = "def multiply(a, b):\n    return a * b  # a normal function\n";
        assert_eq!(scrub(code), code, "ordinary code must be untouched");
        // long snake_case identifiers are not secrets
        let ident = "let some_very_long_but_ordinary_variable_name = 1;";
        assert_eq!(scrub(ident), ident);
    }

    #[test]
    fn masks_a_high_entropy_hex_token() {
        // a 40-char hex-ish token with mixed case + digits
        let s = "SECRET=A1b2C3d4\
E5f6A1b2\
C3d4E5f6A1b2C3d4E5f6A1b2";
        assert!(scrub(s).contains("[REDACTED"));
    }

    #[test]
    fn scrubs_context_injection_and_tool_use_arguments() {
        use core_protocol::{Block, Event, EventKind, Message, Role, Seq, ToolUse, TurnId};
        // A remembered fact carrying a secret, injected + recorded, must be scrubbed.
        let inj = Event {
            seq: Seq(1),
            turn: TurnId(0),
            kind: EventKind::ContextInjection {
                text: "remember: the key is sk-\
ant-api03-AbCdEfGhIjKlMnOpQrStUvWx"
                    .into(),
                trust: core_protocol::Trust::Workspace,
            },
        };
        match redact_event(&inj).kind {
            EventKind::ContextInjection { text, .. } => {
                assert!(text.contains("[REDACTED") && !text.contains("QrStUvWx"))
            }
            _ => panic!("kind changed"),
        }
        // A tool call whose arguments carry a secret (e.g. an edit writing a key) must be scrubbed.
        let msg = Event {
            seq: Seq(2),
            turn: TurnId(0),
            kind: EventKind::Message {
                message: Message {
                    role: Role::Assistant,
                    content: vec![Block::ToolUse(ToolUse {
                        id: "e".into(),
                        name: "edit".into(),
                        input: serde_json::json!({"path":"cfg.rs","new":"const K = \"ghp_\
AbCdEf12\
34567890AbCdEf1234567890\";"}),
                    })],
                },
            },
        };
        let out = serde_json::to_string(&redact_event(&msg)).unwrap();
        assert!(
            out.contains("[REDACTED"),
            "tool-call argument secret must be scrubbed"
        );
        assert!(
            !out.contains("ghp_AbCdEf1234567890"),
            "the raw token must not persist"
        );

        let intent = Event {
            seq: Seq(3),
            turn: TurnId(0),
            kind: EventKind::EffectIntent {
                id: core_protocol::EffectId("stable-correlation-id".into()),
                tool_use_id: "model-call-id".into(),
                tool: "edit".into(),
                capability: core_protocol::Capability::ReversibleLocal,
                arguments: serde_json::json!({
                    "path": "cfg.rs",
                    "new": "ghp_\
                AbCdEf12\
                34567890AbCdEf1234567890"
                }),
                workspace: "/repo".into(),
            },
        };
        match redact_event(&intent).kind {
            EventKind::EffectIntent { id, arguments, .. } => {
                assert_eq!(id.0, "stable-correlation-id");
                assert!(arguments["new"].as_str().unwrap().contains("[REDACTED"));
            }
            _ => panic!("kind changed"),
        }
    }

    #[test]
    fn masks_jwt_and_lowercase_hex_and_does_not_panic_on_multibyte() {
        // JWT (was a false negative)
        assert!(
            scrub(
                "auth eyJhbGciOiJIUzI1NiJ9.\
eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N end"
            )
            .contains("[REDACTED"),
            "JWT must be masked"
        );
        // lowercase hex secret / long sha-shaped token (was a false negative)
        assert!(
            scrub(
                "token=deadbeef\
cafebabe\
deadbeefcafebabedeadbeef end"
            )
            .contains("[REDACTED"),
            "lowercase hex token must be masked"
        );
        // multibyte char right after `sk-` must not panic the byte-slice (code review F1)
        let _ = scrub("key sk-übersecretübersecretübersecret end");
    }

    #[test]
    fn route_events_scrub_credentials_but_preserve_provenance_hashes() {
        let digest = "sha256:aaaaaaaa\
aaaaaaaa\
aaaaaaaa\
aaaaaaaa\
aaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaa";
        let event = Event {
            seq: core_protocol::Seq::ZERO,
            turn: core_protocol::TurnId(0),
            kind: EventKind::ModelSelected {
                provider_id: "sk-\
ant-api03-SuperSecretProviderToken12345"
                    .into(),
                model_id: "ghp_\
AbCdEf12\
34567890AbCdEf1234567890"
                    .into(),
                catalog_digest: digest.into(),
                capability_digest: "xoxb-SuperSecretCapabilityToken123456".into(),
            },
        };
        match redact_event(&event).kind {
            EventKind::ModelSelected {
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
            } => {
                assert!(provider_id.contains("[REDACTED"));
                assert!(model_id.contains("[REDACTED"));
                assert_eq!(catalog_digest, digest);
                assert!(capability_digest.contains("[REDACTED"));
            }
            _ => panic!("kind changed"),
        }

        let content_address = "bbbbbbbb\
bbbbbbbb\
bbbbbbbb\
bbbbbbbb\
bbbbbbbb\
bbbbbbbbbbbbbbbbbbbbbbbb";
        assert_eq!(scrub_route_identifier(content_address), content_address);

        let genesis = Event {
            seq: core_protocol::Seq::ZERO,
            turn: core_protocol::TurnId(0),
            kind: EventKind::RunStart {
                cwd: "/repo/ghp_\
AbCdEf12\
34567890AbCdEf1234567890"
                    .into(),
                model: "sk-\
ant-api03-SuperSecretGenesisModel12345"
                    .into(),
                effort: core_protocol::Effort::Medium,
                created_at: 7,
                parent_run: Some(
                    "run-ghp_\
AbCdEf12\
34567890AbCdEf1234567890"
                        .into(),
                ),
                forked_at: Some(3),
                parent_hash_at_seq: Some(content_address.into()),
                config_digest: digest.into(),
            },
        };
        match redact_event(&genesis).kind {
            EventKind::RunStart {
                cwd,
                model,
                parent_run,
                parent_hash_at_seq,
                config_digest,
                ..
            } => {
                assert_eq!(
                    cwd,
                    "/repo/ghp_\
AbCdEf12\
34567890AbCdEf1234567890"
                );
                assert!(model.contains("[REDACTED"));
                assert_eq!(
                    parent_run.as_deref(),
                    Some(
                        "run-ghp_\
AbCdEf12\
34567890AbCdEf1234567890"
                    )
                );
                assert_eq!(parent_hash_at_seq.as_deref(), Some(content_address));
                assert_eq!(config_digest, digest);
            }
            _ => panic!("kind changed"),
        }
    }

    #[test]
    fn workflow_labels_and_errors_cross_the_record_scrubber() {
        let secret = "sk-\
ant-api03-WorkflowSecretToken123456";
        let event = Event {
            seq: core_protocol::Seq::ZERO,
            turn: core_protocol::TurnId(2),
            kind: EventKind::Workflow {
                version: core_protocol::WorkflowEventVersion::V1,
                workflow_id: "workflow-2".into(),
                event: core_protocol::WorkflowEvent::ChildFinished {
                    task_id: 0,
                    sub_run: Some("fan-0".into()),
                    outcome: core_protocol::WorkflowChildOutcome::Failed,
                    metrics: core_protocol::WorkflowMetrics::default(),
                    error_code: Some("provider_error".into()),
                    error_detail: Some(format!("provider echoed {secret}")),
                    summary_digest: None,
                    evidence_bytes: 0,
                },
            },
        };
        let encoded = serde_json::to_string(&redact_event(&event)).unwrap();
        assert!(!encoded.contains(secret));
        assert!(encoded.contains("[REDACTED"));
    }
}
