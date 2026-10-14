use super::ProductTools;
use crate::tui::App;
use iteron_protocol::{
    RunId, SessionId,
    product_contract::{
        ItemContentChannelV1, ItemKindV1, ItemStateV1, ProductEventKindV1, ProductEventV1,
        ProductTurnId,
    },
};
fn event(turn: Option<u64>, kind: ProductEventKindV1) -> ProductEventV1 {
    ProductEventV1 {
        event_seq: 1,
        source_event_seq: Some(1),
        thread_id: SessionId("thread".into()),
        run_id: RunId("run".into()),
        turn_id: turn.map(ProductTurnId),
        item_id: Some("item-1".into()),
        event: kind,
    }
}
#[test]
fn missing_old_terminal_and_reused_item_id_never_join_two_turns() {
    let mut app = App::new();
    let mut owner = ProductTools::default();
    owner.observe(
        &mut app,
        &event(
            Some(1),
            ProductEventKindV1::ItemStarted {
                kind: ItemKindV1::ToolCall,
                title: Some("old_tool".into()),
            },
        ),
    );
    owner.observe(
        &mut app,
        &event(
            Some(2),
            ProductEventKindV1::TurnStarted {
                submission_id: None,
            },
        ),
    );
    owner.observe(
        &mut app,
        &event(
            Some(2),
            ProductEventKindV1::ItemStarted {
                kind: ItemKindV1::ToolCall,
                title: Some("new_tool".into()),
            },
        ),
    );
    owner.observe(
        &mut app,
        &event(
            Some(1),
            ProductEventKindV1::ItemContent {
                channel: ItemContentChannelV1::ToolOutput,
                content: "old foreign bytes".into(),
            },
        ),
    );
    owner.observe(
        &mut app,
        &event(
            None,
            ProductEventKindV1::ItemContent {
                channel: ItemContentChannelV1::ToolOutput,
                content: "unscoped bytes".into(),
            },
        ),
    );
    owner.observe(
        &mut app,
        &event(
            Some(2),
            ProductEventKindV1::ItemContent {
                channel: ItemContentChannelV1::ToolOutput,
                content: "actual new bytes".into(),
            },
        ),
    );
    owner.observe(
        &mut app,
        &event(
            Some(1),
            ProductEventKindV1::ItemEnded {
                state: ItemStateV1::Completed,
            },
        ),
    );
    owner.observe(
        &mut app,
        &event(
            Some(2),
            ProductEventKindV1::ItemEnded {
                state: ItemStateV1::Completed,
            },
        ),
    );
    let text = app
        .history
        .blocks()
        .iter()
        .map(|block| block.to_text())
        .collect::<String>();
    assert!(text.contains("actual new bytes"));
    assert!(text.contains("new_tool"));
    assert!(!text.contains("old foreign bytes"));
    assert!(!text.contains("unscoped bytes"));
    assert!(owner.rows.is_empty());
}

#[test]
fn compact_transcript_remote_omission_and_unknown_terminal_remain_visible() {
    let mut app = App::new();
    let mut owner = ProductTools::default();
    for kind in [
        ProductEventKindV1::ItemStarted {
            kind: ItemKindV1::ToolCall,
            title: Some("read_file".into()),
        },
        ProductEventKindV1::ItemContent {
            channel: ItemContentChannelV1::ToolInputJson,
            content: "{\"path\":\"src/example.rs\"}".into(),
        },
        ProductEventKindV1::ItemContent {
            channel: ItemContentChannelV1::ToolOutput,
            content: "first line".into(),
        },
        ProductEventKindV1::ContentOmitted {
            channel: ItemContentChannelV1::ToolOutput,
            omitted_redacted_bytes: 42,
        },
        ProductEventKindV1::ItemEnded {
            state: ItemStateV1::InProgress,
        },
    ] {
        owner.observe(&mut app, &event(Some(1), kind));
    }
    let block = app
        .history
        .blocks()
        .iter()
        .find(|block| matches!(block.kind, crate::block::BlockKind::Tool(_)))
        .unwrap();
    let text = block
        .render(100, &crate::theme::Theme::mono(), 0)
        .into_iter()
        .flat_map(|line| line.spans.into_iter().map(|span| span.content.into_owned()))
        .collect::<String>();
    assert!(text.contains("failed") && text.contains("outcome unknown"));
    assert!(text.contains("output omitted") && text.contains("src/example.rs"));
    assert!(block.to_text().contains("first line"));
}
