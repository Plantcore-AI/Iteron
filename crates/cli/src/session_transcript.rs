//! Bounded verified history display keeps physical source identity and never re-executes a tool.
use iteron_protocol::session_navigation::{
    SessionTranscriptBlockV1, SessionTranscriptContentV1, SessionTranscriptV1,
};
use iteron_protocol::{Block, EventKind, Role, ToolResult};
use iteron_record::ScopedEvent;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
const MAX_ADOPTED_BLOCKS: usize = 120;
const MAX_ADOPTED_TOOL_OUTPUT_BYTES: usize = 4 * 1024;
const MAX_BYTES: usize = 512 * 1024;
fn text(value: &str, limit: usize) -> (String, bool) {
    let safe = iteron_record::redact::scrub(value);
    let mut end = safe.len().min(limit);
    while !safe.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = end < safe.len();
    (safe[..end].to_owned(), truncated)
}
fn args(value: &Value) -> Value {
    let mut pending = vec![(value, 0_usize)];
    let mut nodes = 0_usize;
    let mut bytes = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > 256 || depth > 16 || bytes > 16 * 1024 {
            return json!({"display":"arguments exceed the projection bound"});
        }
        match value {
            Value::String(value) => bytes = bytes.saturating_add(value.len()),
            Value::Array(values) => {
                if values.len() > 256 {
                    return json!({"display":"arguments exceed the projection bound"});
                }
                pending.extend(values.iter().map(|v| (v, depth + 1)));
            }
            Value::Object(values) => {
                if values.len() > 256 {
                    return json!({"display":"arguments exceed the projection bound"});
                }
                for (key, value) in values {
                    bytes = bytes.saturating_add(key.len());
                    pending.push((value, depth + 1));
                }
            }
            _ => bytes = bytes.saturating_add(32),
        }
    }
    if bytes > 16 * 1024 {
        return json!({"display":"arguments exceed the projection bound"});
    }
    scrub(value)
}
fn scrub(value: &Value) -> Value {
    match value {
        Value::String(value) => Value::String(iteron_record::redact::scrub(value)),
        Value::Array(values) => Value::Array(values.iter().map(scrub).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (iteron_record::redact::scrub(key), scrub(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}
pub(crate) fn project(events: &[ScopedEvent]) -> SessionTranscriptV1 {
    let max_blocks = iteron_tunables::param_integer(
        "cli.tui.session_adoption.max_adopted_blocks",
        MAX_ADOPTED_BLOCKS,
    )
    .min(MAX_ADOPTED_BLOCKS);
    let max_tool_output_bytes = iteron_tunables::param_integer(
        "cli.tui.session_adoption.max_adopted_tool_output_bytes",
        MAX_ADOPTED_TOOL_OUTPUT_BYTES,
    )
    .min(MAX_ADOPTED_TOOL_OUTPUT_BYTES);
    let mut selected = VecDeque::new();
    let mut total = 0_usize;
    for scoped in events {
        let (EventKind::Message { message } | EventKind::MessageV2 { message }) =
            &scoped.event.kind
        else {
            continue;
        };
        for block in &message.content {
            if matches!(block, Block::ToolUse(_))
                || matches!(block, Block::Text {text} if !text.trim().is_empty())
                || matches!(block, Block::Thinking {thinking} if !thinking.trim().is_empty())
            {
                total = total.saturating_add(1);
                if max_blocks == 0 {
                    continue;
                }
                if selected.len() == max_blocks {
                    selected.pop_front();
                }
                selected.push_back((scoped, message.role, block));
            }
        }
    }
    let needed = selected
        .iter()
        .filter_map(|(scoped, _, block)| match block {
            Block::ToolUse(call) => Some((
                scoped.run_id.0.as_str(),
                scoped.event.turn.0,
                call.id.as_str(),
            )),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut results: HashMap<(&str, u32, &str), Option<&ToolResult>> = HashMap::new();
    for scoped in events {
        let (EventKind::Message { message } | EventKind::MessageV2 { message }) =
            &scoped.event.kind
        else {
            continue;
        };
        for block in &message.content {
            if let Block::ToolResult(result) = block {
                let key = (
                    scoped.run_id.0.as_str(),
                    scoped.event.turn.0,
                    result.tool_use_id.as_str(),
                );
                if needed.contains(&key) {
                    results
                        .entry(key)
                        .and_modify(|old| {
                            if old.is_some_and(|old| {
                                old.content != result.content
                                    || old.is_error != result.is_error
                                    || old.latency_ms != result.latency_ms
                            }) {
                                *old = None;
                            }
                        })
                        .or_insert(Some(result));
                }
            }
        }
    }
    let mut blocks = VecDeque::new();
    let mut bytes = 0_usize;
    for (scoped, role, block) in selected {
        let (content, truncated) = match block {
            Block::Text { text: body } => {
                let (body, truncated) = text(body, 64 * 1024);
                (
                    match role {
                        Role::User => SessionTranscriptContentV1::User { text: body },
                        Role::Assistant => SessionTranscriptContentV1::Assistant { text: body },
                    },
                    truncated,
                )
            }
            Block::Thinking { thinking } => {
                let (body, truncated) = text(thinking, 64 * 1024);
                (
                    SessionTranscriptContentV1::Thinking { text: body },
                    truncated,
                )
            }
            Block::ToolUse(call) => {
                let recorded = results
                    .get(&(
                        scoped.run_id.0.as_str(),
                        scoped.event.turn.0,
                        call.id.as_str(),
                    ))
                    .and_then(|v| *v);
                let (output, truncated) = recorded
                    .map(|r| text(&r.content, max_tool_output_bytes))
                    .unwrap_or_else(|| {
                        (
                            "no unambiguous recorded result for this physical run and turn".into(),
                            false,
                        )
                    });
                (
                    SessionTranscriptContentV1::Tool {
                        name: text(&call.name, 128).0,
                        args: args(&call.input),
                        recorded_is_error: recorded.map(|r| r.is_error),
                        output,
                        latency_ms: recorded.map(|r| r.latency_ms),
                    },
                    truncated,
                )
            }
            _ => continue,
        };
        let view = SessionTranscriptBlockV1 {
            source_run_id: scoped.run_id.clone(),
            source_seq: scoped.event.seq,
            content_truncated: truncated,
            content,
        };
        let Ok(weight) = serde_json::to_vec(&view).map(|v| v.len()) else {
            continue;
        };
        if weight > MAX_BYTES {
            continue;
        }
        while bytes.saturating_add(weight) > MAX_BYTES {
            let Some((_, weight)) = blocks.pop_front() else {
                break;
            };
            bytes -= weight;
        }
        bytes += weight;
        blocks.push_back((view, weight));
    }
    let blocks = blocks.into_iter().map(|(view, _)| view).collect::<Vec<_>>();
    SessionTranscriptV1 {
        source: "verified_physical_message_projection".into(),
        total_blocks: total,
        omitted_blocks: total.saturating_sub(blocks.len()),
        blocks,
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_BYTES, project};
    use iteron_protocol::{
        Block, Event, EventKind, Message, Role, Seq, ToolResult, ToolUse, TurnId,
        session_navigation::SessionTranscriptContentV1,
    };
    fn append(rollout: &mut iteron_record::Rollout, role: Role, content: Vec<Block>) {
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message { role, content },
                },
            })
            .unwrap();
    }
    #[test]
    fn actual_forked_history_keeps_reused_tool_ids_in_their_physical_origin() {
        let root = std::env::temp_dir().join(format!(
            "iteron-transcript-origin-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut agent = crate::app_server::navigation_agent(&root);
        let parent = agent.rollout.run_id().clone();
        let tenant = agent.rollout.tenant().clone();
        let runs = root.join(".iteron/runs");
        append(
            &mut agent.rollout,
            Role::Assistant,
            vec![Block::ToolUse(ToolUse {
                id: "reused".into(),
                name: "read_file".into(),
                input: serde_json::json!({"path":"parent"}),
            })],
        );
        append(
            &mut agent.rollout,
            Role::User,
            vec![Block::ToolResult(ToolResult {
                tool_use_id: "reused".into(),
                content: "parent recorded output".into(),
                is_error: false,
                trust: iteron_protocol::Trust::Untrusted,
                latency_ms: 7,
            })],
        );
        let tail = iteron_record::replay(agent.rollout.path())
            .unwrap()
            .last()
            .unwrap()
            .seq;
        let (child, _) = iteron_record::session::fork_with_checkpoint(
            &runs,
            &parent,
            tail,
            &tenant,
            agent.tunables_checkpoint().unwrap(),
            iteron_record::LegacyTunablesPolicy::RejectUnpinned,
        )
        .unwrap();
        let mut child_writer =
            iteron_record::Rollout::open_existing(&runs, &child, tenant).unwrap();
        append(
            &mut child_writer,
            Role::Assistant,
            vec![Block::ToolUse(ToolUse {
                id: "reused".into(),
                name: "read_file".into(),
                input: serde_json::json!({"path":"child"}),
            })],
        );
        append(
            &mut child_writer,
            Role::User,
            vec![Block::ToolResult(ToolResult {
                tool_use_id: "reused".into(),
                content: "child recorded failure".into(),
                is_error: true,
                trust: iteron_protocol::Trust::Untrusted,
                latency_ms: 11,
            })],
        );
        let scoped = iteron_record::session::load_forked_scoped(&runs, &child).unwrap();
        let view = project(&scoped);
        let tools = view
            .blocks
            .iter()
            .filter_map(|row| match &row.content {
                SessionTranscriptContentV1::Tool {
                    output,
                    recorded_is_error,
                    latency_ms,
                    ..
                } => Some((&row.source_run_id, output, *recorded_is_error, *latency_ms)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(tools.len(), 2);
        assert_eq!(
            tools[0],
            (
                &parent,
                &"parent recorded output".to_owned(),
                Some(false),
                Some(7)
            )
        );
        assert_eq!(
            tools[1],
            (
                &child,
                &"child recorded failure".to_owned(),
                Some(true),
                Some(11)
            )
        );
        drop(child_writer);
        drop(agent);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn aggregate_display_byte_bound_and_scrubbed_argument_shape_are_honest() {
        let tenant = iteron_protocol::TenantId::default();
        let run = iteron_protocol::RunId("actual-origin".into());
        let events = (0..200)
            .map(|index| iteron_record::ScopedEvent {
                tenant: tenant.clone(),
                run_id: run.clone(),
                event: Event {
                    seq: Seq(index),
                    turn: TurnId(0),
                    kind: EventKind::Message {
                        message: Message {
                            role: Role::Assistant,
                            content: vec![Block::Text {
                                text: "界".repeat(30_000),
                            }],
                        },
                    },
                },
            })
            .collect::<Vec<_>>();
        let view = project(&events);
        assert!(view.omitted_blocks > 0);
        assert_eq!(view.total_blocks, 200);
        assert!(view.blocks.iter().all(|row| row.content_truncated));
        assert!(
            view.blocks
                .iter()
                .map(|row| serde_json::to_vec(row).unwrap().len())
                .sum::<usize>()
                <= MAX_BYTES
        );
        let mut hostile = serde_json::Value::String("safe".into());
        for _ in 0..30 {
            hostile = serde_json::json!([hostile]);
        }
        assert_eq!(
            super::args(&hostile),
            serde_json::json!({"display":"arguments exceed the projection bound"})
        );
    }
}
