//! Projection from the durable event stream to a provider-valid transcript.

use iteron_protocol::{Block, Event, EventKind, Message, Role, ToolResult, ToolUse, Trust};

/// Append a user message while preserving provider role alternation.
pub(super) fn merge_adjacent_user_message(messages: &mut Vec<Message>, mut message: Message) {
    if matches!(message.role, Role::User)
        && let Some(last) = messages.last_mut()
        && matches!(last.role, Role::User)
    {
        if !last.content.is_empty() && !message.content.is_empty() {
            last.content.push(Block::Text {
                text: "\n\n".into(),
            });
        }
        last.content.append(&mut message.content);
        return;
    }
    messages.push(message);
}

/// Project model messages from canonical events, recovering durable tool terminals after a crash.
#[cfg(test)]
pub(super) fn project_messages_from_events(mut events: Vec<Event>) -> Vec<Message> {
    super::tool_image_replay::remove_unverified_images(&mut events);
    project_verified_messages(events)
}

pub(super) fn project_messages_from_scoped_events(
    events: Vec<iteron_record::ScopedEvent>,
) -> Vec<Message> {
    project_verified_messages(super::tool_image_replay::verified_image_events(events))
}

fn project_verified_messages(events: Vec<Event>) -> Vec<Message> {
    let mut messages = Vec::new();
    let mut pending_turn = None;
    let mut terminal_results =
        std::collections::BTreeMap::<String, (iteron_protocol::Seq, ToolResult)>::new();
    let mut tool_images = std::collections::BTreeMap::<
        String,
        Vec<iteron_protocol::tool_image::ToolImageObservationV1>,
    >::new();
    let mut duplicate_terminal_id = false;

    for event in events {
        match event.kind {
            EventKind::Message { message } => {
                let has_tool_use = matches!(message.role, Role::Assistant)
                    && message
                        .content
                        .iter()
                        .any(|block| matches!(block, Block::ToolUse(_)));
                messages.push(message);
                terminal_results.clear();
                tool_images.clear();
                duplicate_terminal_id = false;
                pending_turn = has_tool_use.then_some(event.turn);
            }
            EventKind::Compaction {
                messages: compacted,
            } => {
                // The seed range is measured in reconciled projection coordinates. Reconcile
                // first so separately durable steers cannot shift that coordinate system.
                messages = iteron_ctx::replay_compaction(reconcile_transcript(messages), compacted);
                terminal_results.clear();
                tool_images.clear();
                duplicate_terminal_id = false;
                pending_turn = messages.last().and_then(|message| {
                    (matches!(message.role, Role::Assistant)
                        && message
                            .content
                            .iter()
                            .any(|block| matches!(block, Block::ToolUse(_))))
                    .then_some(event.turn)
                });
            }
            EventKind::ToolDone { result, .. } if pending_turn == Some(event.turn) => {
                duplicate_terminal_id |= terminal_results
                    .insert(result.tool_use_id.clone(), (event.seq, result))
                    .is_some();
            }
            EventKind::ToolImageObservedV1 { observation } if pending_turn == Some(event.turn) => {
                let matches = terminal_results.get(&observation.tool_use_id).is_some_and(
                    |(sequence, result)| *sequence == observation.terminal_seq && !result.is_error,
                );
                let images = tool_images
                    .entry(observation.tool_use_id.clone())
                    .or_default();
                if matches
                    && observation.validate().is_ok()
                    && images.len() < iteron_protocol::tool_image::MAX_TOOL_IMAGES_PER_MESSAGE
                {
                    images.push(observation);
                }
            }
            _ => {}
        }
    }

    if !duplicate_terminal_id
        && !terminal_results.is_empty()
        && let Some(assistant) = messages.last()
        && matches!(assistant.role, Role::Assistant)
    {
        let ordered_calls: Vec<&ToolUse> = assistant
            .content
            .iter()
            .filter_map(|block| match block {
                Block::ToolUse(tool) => Some(tool),
                _ => None,
            })
            .collect();
        if !ordered_calls.is_empty() {
            let mut images = Vec::new();
            let results = ordered_calls
                .into_iter()
                .map(|call| {
                    terminal_results
                        .remove(&call.id)
                        .map(|(_,result)| {if !result.is_error {let remaining=iteron_protocol::tool_image::MAX_TOOL_IMAGES_PER_MESSAGE.saturating_sub(images.len());images.extend(tool_images.remove(&call.id).unwrap_or_default().into_iter().take(remaining).map(Block::ToolImage));}result})
                        .unwrap_or_else(|| ToolResult {
                            tool_use_id: call.id.clone(),
                            content: "the prior process ended before this tool produced a durable terminal; Iteron did not replay it".into(),
                            is_error: true,
                            trust: Trust::Workspace,
                            latency_ms: 0,
                        })
                })
                .map(Block::ToolResult)
                .collect::<Vec<_>>();
            let mut content = results;
            content.extend(images);
            messages.push(Message {
                role: Role::User,
                content,
            });
        }
    }
    reconcile_transcript(messages)
}

/// Repair a resumed transcript into a provider-valid alternating message sequence.
pub(super) fn reconcile_transcript(mut messages: Vec<Message>) -> Vec<Message> {
    let mut merged = Vec::with_capacity(messages.len());
    for message in messages.drain(..) {
        merge_adjacent_user_message(&mut merged, message);
    }
    messages = merged;

    #[allow(clippy::while_let_loop)]
    loop {
        let Some(last) = messages.last() else {
            break;
        };
        let has_tool_use = last
            .content
            .iter()
            .any(|block| matches!(block, Block::ToolUse(_)));
        let has_tool_result = last
            .content
            .iter()
            .any(|block| matches!(block, Block::ToolResult(_)));
        match last.role {
            Role::Assistant if has_tool_use => {
                messages.pop();
            }
            Role::User if has_tool_result => {
                let valid = messages.len() >= 2
                    && matches!(messages[messages.len() - 2].role, Role::Assistant)
                    && messages[messages.len() - 2]
                        .content
                        .iter()
                        .any(|block| matches!(block, Block::ToolUse(_)));
                if valid {
                    break;
                }
                messages.pop();
            }
            _ => break,
        }
    }
    messages
}
