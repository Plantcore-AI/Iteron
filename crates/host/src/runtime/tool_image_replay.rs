//! Image witnesses retain physical origin while the transcript itself uses logical ordering.
//! Older/unscoped observations remain unavailable; text recovery continues independently.
use iteron_protocol::{Block, Event, EventKind, Message, tool_image::ToolImageObservationV1};
use iteron_record::ScopedEvent;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};

type TerminalKey = (
    String,
    String,
    u32,
    u64,
    String,
    iteron_protocol::tool_image::ToolImageScopeV1,
);
type WitnessKey = (String, String, u64, String, [u8; 32]);
const MAX_WITNESSES: usize = 256;

fn key(image: &ToolImageObservationV1, turn: u32) -> TerminalKey {
    (
        image.owner_tenant.0.clone(),
        image.owner_run.0.clone(),
        turn,
        image.terminal_seq.0,
        image.tool_use_id.clone(),
        image.scope,
    )
}
fn commitment(image: &ToolImageObservationV1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"iteron-replay-tool-image-v1\0");
    for field in [
        image.owner_tenant.0.as_bytes(),
        image.owner_run.0.as_bytes(),
        image.tool_use_id.as_bytes(),
        image.artifact_id.as_bytes(),
        image.source_url_display.as_bytes(),
        image.scope.as_str().as_bytes(),
        image.image.data.as_str().as_bytes(),
    ] {
        hash.update((field.len() as u64).to_le_bytes());
        hash.update(field);
    }
    for value in [
        u64::from(image.version),
        image.terminal_seq.0,
        image.observed_unix_ms,
        u64::from(image.width),
        u64::from(image.height),
    ] {
        hash.update(value.to_le_bytes());
    }
    hash.finalize().into()
}

pub(super) fn verified_image_events(rows: Vec<ScopedEvent>) -> Vec<Event> {
    let mut terminals = VecDeque::<TerminalKey>::new();
    let mut witnesses = BTreeMap::<WitnessKey, ()>::new();
    let mut witness_order = VecDeque::new();
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let mut event = row.event;
        match &mut event.kind {
            EventKind::ToolDone {
                tool: Some(tool),
                effect_id: Some(_),
                result,
                ..
            } if matches!(tool.as_str(), "browser" | "computer" | "desktop")
                && !result.is_error =>
            {
                terminals.push_back((
                    row.tenant.0.clone(),
                    row.run_id.0.clone(),
                    event.turn.0,
                    event.seq.0,
                    result.tool_use_id.clone(),
                    if tool == "desktop" {
                        iteron_protocol::tool_image::ToolImageScopeV1::NativeMacDesktop
                    } else {
                        iteron_protocol::tool_image::ToolImageScopeV1::IsolatedBrowserViewport
                    },
                ));
                if terminals.len() > MAX_WITNESSES {
                    terminals.pop_front();
                }
            }
            EventKind::ToolImageObservedV1 { observation } => {
                if observation.owner_tenant != row.tenant
                    || observation.owner_run != row.run_id
                    || observation.validate().is_err()
                    || !terminals.contains(&key(observation, event.turn.0))
                {
                    continue;
                }
                let witness_key = (
                    observation.owner_tenant.0.clone(),
                    observation.owner_run.0.clone(),
                    observation.terminal_seq.0,
                    observation.tool_use_id.clone(),
                    commitment(observation),
                );
                if witnesses.insert(witness_key.clone(), ()).is_none() {
                    witness_order.push_back(witness_key);
                }
                if witness_order.len() > MAX_WITNESSES
                    && let Some(old) = witness_order.pop_front()
                {
                    witnesses.remove(&old);
                }
            }
            EventKind::Message { message } | EventKind::MessageV2 { message } => {
                retain_witnessed(message, &witnesses)
            }
            EventKind::Compaction { messages } | EventKind::CompactionV2 { messages } => {
                for message in messages {
                    retain_witnessed(message, &witnesses);
                }
            }
            _ => {}
        }
        events.push(event);
    }
    events
}
fn retain_witnessed(message: &mut Message, witnesses: &BTreeMap<WitnessKey, ()>) {
    if !message
        .content
        .iter()
        .any(|block| matches!(block, Block::ToolImage(_)))
    {
        return;
    }
    let result_ids = message
        .content
        .iter()
        .filter_map(|block| match block {
            Block::ToolResult(result) if !result.is_error => Some(result.tool_use_id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    message.content.retain(|block| match block {
        Block::ToolImage(image) => {
            let key = (
                image.owner_tenant.0.clone(),
                image.owner_run.0.clone(),
                image.terminal_seq.0,
                image.tool_use_id.clone(),
                commitment(image),
            );
            image.validate().is_ok()
                && witnesses.contains_key(&key)
                && result_ids.contains(&image.tool_use_id)
        }
        _ => true,
    });
}
#[cfg(test)]
pub(super) fn remove_unverified_images(events: &mut Vec<Event>) {
    events.retain(|event| !matches!(event.kind, EventKind::ToolImageObservedV1 { .. }));
    for event in events {
        match &mut event.kind {
            EventKind::Message { message } | EventKind::MessageV2 { message } => message
                .content
                .retain(|block| !matches!(block, Block::ToolImage(_))),
            EventKind::Compaction { messages } | EventKind::CompactionV2 { messages } => {
                for message in messages {
                    message
                        .content
                        .retain(|block| !matches!(block, Block::ToolImage(_)));
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::verified_image_events;
    use iteron_protocol::{
        Block, Event, EventKind, ImageContent, ImageMediaType, Message, Role, RunId, Seq, TenantId,
        ToolResult, Trust, TurnId,
        tool_image::{ToolImageObservationV1, ToolImageScopeV1},
    };
    use iteron_record::ScopedEvent;
    fn image(run: &str) -> ToolImageObservationV1 {
        ToolImageObservationV1{version:1,owner_tenant:TenantId::default(),owner_run:RunId(run.into()),tool_use_id:"same-call".into(),terminal_seq:Seq(7),observed_unix_ms:42,source_url_display:"https://example.com/".into(),scope:ToolImageScopeV1::IsolatedBrowserViewport,artifact_id:"a38a4ff7320a3d8764ac959b264f15e335360d7c1e23a0627dee7f366c95c58f".into(),width:1,height:1,image:ImageContent::new(ImageMediaType::Png,"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=").unwrap()}
    }
    fn result() -> ToolResult {
        ToolResult {
            tool_use_id: "same-call".into(),
            content: "real screenshot".into(),
            is_error: false,
            trust: Trust::Untrusted,
            latency_ms: 1,
        }
    }
    fn row(run: &str, seq: u64, kind: EventKind) -> ScopedEvent {
        ScopedEvent {
            event: Event {
                seq: Seq(seq),
                turn: TurnId(0),
                kind,
            },
            tenant: TenantId::default(),
            run_id: RunId(run.into()),
        }
    }
    fn done(run: &str) -> ScopedEvent {
        row(
            run,
            7,
            EventKind::ToolDone {
                tool: Some("browser".into()),
                result: result(),
                effect_id: Some(iteron_protocol::EffectId("fixture-browser-effect".into())),
            },
        )
    }
    fn message(observation: ToolImageObservationV1) -> Message {
        Message {
            role: Role::User,
            content: vec![Block::ToolResult(result()), Block::ToolImage(observation)],
        }
    }
    #[test]
    fn inherited_identity_cannot_bind_a_child_terminal_with_same_sequence_turn_and_call() {
        let inherited = image("parent");
        let events = verified_image_events(vec![
            done("child"),
            row(
                "child",
                8,
                EventKind::ToolImageObservedV1 {
                    observation: inherited.clone(),
                },
            ),
            row(
                "child",
                9,
                EventKind::Message {
                    message: message(inherited),
                },
            ),
        ]);
        assert_eq!(events.len(), 2);
        let EventKind::Message { message } = &events[1].kind else {
            panic!()
        };
        assert!(
            !message
                .content
                .iter()
                .any(|block| matches!(block, Block::ToolImage(_)))
        );
    }
    #[test]
    fn verified_parent_observation_survives_child_compaction_but_changed_pixels_do_not() {
        let inherited = image("parent");
        let mut changed = inherited.clone();
        changed.observed_unix_ms += 1;
        let events = verified_image_events(vec![
            done("parent"),
            row(
                "parent",
                8,
                EventKind::ToolImageObservedV1 {
                    observation: inherited.clone(),
                },
            ),
            row(
                "child",
                1,
                EventKind::Compaction {
                    messages: vec![message(inherited), message(changed)],
                },
            ),
        ]);
        let EventKind::Compaction { messages } = &events[2].kind else {
            panic!()
        };
        assert!(
            messages[0]
                .content
                .iter()
                .any(|block| matches!(block, Block::ToolImage(_)))
        );
        assert!(
            !messages[1]
                .content
                .iter()
                .any(|block| matches!(block, Block::ToolImage(_)))
        );
    }
    #[test]
    fn actual_desktop_terminal_cannot_witness_browser_scope_or_relabelled_pixels() {
        let mut native = image("native");
        native.scope = ToolImageScopeV1::NativeMacDesktop;
        native.source_url_display = "macos-application://com.example.NativeFixture".into();
        let mut terminal = done("native");
        if let EventKind::ToolDone { tool, .. } = &mut terminal.event.kind {
            *tool = Some("desktop".into());
        }
        let mut relabelled = native.clone();
        relabelled.scope = ToolImageScopeV1::IsolatedBrowserViewport;
        relabelled.source_url_display = "https://example.com/".into();
        let events = verified_image_events(vec![
            terminal,
            row(
                "native",
                8,
                EventKind::ToolImageObservedV1 {
                    observation: native.clone(),
                },
            ),
            row(
                "native",
                9,
                EventKind::ToolImageObservedV1 {
                    observation: relabelled.clone(),
                },
            ),
            row(
                "child",
                1,
                EventKind::Compaction {
                    messages: vec![message(native), message(relabelled)],
                },
            ),
        ]);
        assert_eq!(events.len(), 3);
        let EventKind::Compaction { messages } = &events[2].kind else {
            panic!()
        };
        assert!(
            messages[0]
                .content
                .iter()
                .any(|block| matches!(block, Block::ToolImage(_)))
        );
        assert!(
            !messages[1]
                .content
                .iter()
                .any(|block| matches!(block, Block::ToolImage(_)))
        );
    }
}

#[cfg(test)]
mod multi_image_tests {
    use super::verified_image_events;
    use iteron_protocol::{
        Block, Event, EventKind, ImageContent, ImageMediaType, Message, Role, RunId, Seq, TenantId,
        ToolResult, Trust, TurnId,
        tool_image::{ToolImageObservationV1, ToolImageScopeV1},
    };
    use iteron_record::ScopedEvent;
    #[test]
    fn one_actual_terminal_retains_multiple_exact_observation_witnesses_and_refuses_forged_member()
    {
        let tenant = TenantId::default();
        let run = RunId("multi-pixels".into());
        let first=ToolImageObservationV1{version:1,owner_tenant:tenant.clone(),owner_run:run.clone(),tool_use_id:"pixels".into(),terminal_seq:Seq(7),observed_unix_ms:42,source_url_display:"https://example.com/".into(),scope:ToolImageScopeV1::IsolatedBrowserViewport,artifact_id:"a38a4ff7320a3d8764ac959b264f15e335360d7c1e23a0627dee7f366c95c58f".into(),width:1,height:1,image:ImageContent::new(ImageMediaType::Png,"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=").unwrap()};
        let mut second = first.clone();
        second.observed_unix_ms = 43;
        let mut forged = second.clone();
        forged.observed_unix_ms = 44;
        let result = ToolResult {
            tool_use_id: "pixels".into(),
            content: "actual frames".into(),
            is_error: false,
            trust: Trust::Untrusted,
            latency_ms: 1,
        };
        let row = |seq, kind| ScopedEvent {
            tenant: tenant.clone(),
            run_id: run.clone(),
            event: Event {
                seq: Seq(seq),
                turn: TurnId(0),
                kind,
            },
        };
        let events = verified_image_events(vec![
            row(
                7,
                EventKind::ToolDone {
                    tool: Some("computer".into()),
                    effect_id: Some(iteron_protocol::EffectId("multi-frame-effect".into())),
                    result: result.clone(),
                },
            ),
            row(
                8,
                EventKind::ToolImageObservedV1 {
                    observation: first.clone(),
                },
            ),
            row(
                9,
                EventKind::ToolImageObservedV1 {
                    observation: second.clone(),
                },
            ),
            row(
                10,
                EventKind::Message {
                    message: Message {
                        role: Role::User,
                        content: vec![
                            Block::ToolResult(result),
                            Block::ToolImage(first.clone()),
                            Block::ToolImage(second.clone()),
                            Block::ToolImage(forged),
                        ],
                    },
                },
            ),
        ]);
        let EventKind::Message { message } = &events[3].kind else {
            panic!()
        };
        let images = message
            .content
            .iter()
            .filter_map(|block| match block {
                Block::ToolImage(image) => Some(image),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(images, vec![&first, &second]);
    }
}
