//! Actual writer/private-CAS/reopen evidence for the versioned captured-pixel record boundary.
use iteron_protocol::tool_image::{ToolImageObservationV1, ToolImageScopeV1};
use iteron_protocol::{
    Block, Capability, EffectId, Event, EventKind, ImageContent, ImageMediaType, Message, Role,
    RunId, Seq, TenantId, ToolResult, Trust, TurnId,
};
use iteron_record::{Rollout, replay};
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn image(at: u64, terminal_seq: Seq) -> ToolImageObservationV1 {
    ToolImageObservationV1 {
        version:1,tool_use_id:"image-call".into(),owner_tenant:TenantId::default(),owner_run:RunId("versioned-images".into()),terminal_seq,observed_unix_ms:at,source_url_display:"https://example.com/".into(),scope:ToolImageScopeV1::IsolatedBrowserViewport,
        artifact_id:"a38a4ff7320a3d8764ac959b264f15e335360d7c1e23a0627dee7f366c95c58f".into(),width:1,height:1,
        image:ImageContent::new(ImageMediaType::Png,"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=").unwrap(),
    }
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum LegacyKind {
    Notice,
    ToolDone,
    #[serde(other)]
    Unknown,
}
#[test]
fn confirmed_images_and_compaction_keep_actual_order_through_private_cas_and_reopen() {
    let root = std::env::temp_dir().join(format!(
        "iteron-image-version-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let mut writer = Rollout::open(
        &root,
        &RunId("versioned-images".into()),
        TenantId::default(),
    )
    .unwrap();
    let event = |kind| Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind,
    };
    writer
        .append(&event(EventKind::Notice {
            text: "actual image fixture".into(),
        }))
        .unwrap();
    let effect_id = EffectId("fx1:t00000000:tt:0000".into());
    let intent_seq = writer
        .append(&event(EventKind::EffectIntent {
            id: effect_id.clone(),
            tool_use_id: "image-call".into(),
            tool: "browser".into(),
            capability: Capability::CodeExecuting,
            arguments: serde_json::json!({ "action": "observe" }),
            workspace: root.to_string_lossy().into_owned(),
            provider_route_attempt: None,
        }))
        .unwrap();
    let result = ToolResult {
        tool_use_id: "image-call".into(),
        content: "captured fixture pixels".into(),
        is_error: false,
        trust: Trust::Untrusted,
        latency_ms: 0,
    };
    let terminal_seq = writer
        .append(&event(EventKind::ToolDone {
            result,
            effect_id: Some(effect_id),
            tool: Some("browser".into()),
        }))
        .unwrap();
    assert!(intent_seq.0 < terminal_seq.0);
    let images = [image(1, terminal_seq), image(2, terminal_seq)];
    for observation in &images {
        observation.validate().unwrap();
        writer
            .append(&event(EventKind::ToolImageObservedV1 {
                observation: observation.clone(),
            }))
            .unwrap();
    }
    let message = Message {
        role: Role::User,
        content: images.iter().cloned().map(Block::ToolImage).collect(),
    };
    assert!(
        writer
            .append(&event(EventKind::Message {
                message: message.clone()
            }))
            .is_err()
    );
    assert!(
        writer
            .append(&event(EventKind::Compaction {
                messages: vec![message.clone()]
            }))
            .is_err()
    );
    let message_seq = writer
        .append(&event(EventKind::message(message.clone())))
        .unwrap();
    let compaction_seq = writer
        .append(&event(EventKind::compaction(vec![message.clone()])))
        .unwrap();
    let path = writer.path().to_owned();
    drop(writer);
    let reopened = replay(&path).unwrap();
    assert_eq!(reopened.len(), 7);
    let message_event = reopened
        .iter()
        .find(|event| event.seq == message_seq)
        .unwrap();
    let kind = &message_event.kind;
    assert!(matches!(kind, EventKind::MessageV2 { .. }));
    assert_eq!(
        serde_json::to_value(kind.message_value().unwrap()).unwrap(),
        serde_json::to_value(&message).unwrap()
    );
    let compaction_event = reopened
        .iter()
        .find(|event| event.seq == compaction_seq)
        .unwrap();
    assert!(matches!(
        &compaction_event.kind,
        EventKind::CompactionV2 { .. }
    ));
    assert_eq!(
        serde_json::to_value(compaction_event.kind.compaction_value().unwrap()).unwrap(),
        serde_json::to_value(vec![message]).unwrap()
    );
    let physical = std::fs::read_to_string(&path).unwrap();
    assert!(
        !physical.contains(images[0].image.data.as_str()),
        "private pixels are not inline payload text"
    );
    for line in physical.lines().skip(3) {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let old: LegacyKind = serde_json::from_value(row["payload"]["kind"].clone()).unwrap();
        assert!(matches!(old, LegacyKind::Unknown));
    }
    std::fs::remove_dir_all(root).unwrap();
}
